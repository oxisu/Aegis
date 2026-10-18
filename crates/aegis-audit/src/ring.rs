//! 内存环形缓冲：给实时 UI 看的"最近 N 条"（§15「不长期驻留内存」）。
//!
//! # 它和落盘审计是两回事
//!
//! | | 内存环形缓冲 | 落盘审计 |
//! |---|---|---|
//! | 容量 | 有界，满了**丢最旧** | 全量 |
//! | 丢失 | 允许，但必须**可观测**（`dropped`） | 不允许 |
//! | 用途 | 实时连接表 | 证据链 / 检索 / 导出 |
//!
//! 混为一谈会出事：UI 上那张"最近 N 条"的表格会被当成全量，而缺口在哪、
//! 缺了多少，用户无从得知。所以丢弃必须计数并暴露出来。
//!
//! # 为什么不阻塞
//!
//! 审计事件从 WFP 回调路径上产出（与 `aegis-fuse` 的"回调即弃"同理）。
//! 落盘线程拿走时用 [`Self::drain`] 一次性换出整个缓冲，
//! **I/O 在锁外做**——否则一次磁盘抖动就能把内核回调堵住，
//! 后果是网络栈卡住而不是"慢一点"。

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

#[cfg(test)]
use std::sync::Arc;

use crate::event::AuditEvent;

/// 有界的审计事件缓冲。
#[derive(Debug)]
pub struct AuditRing {
    capacity: usize,
    buf: Mutex<VecDeque<AuditEvent>>,
    /// 被覆盖掉的事件数。**只增不减**：它回答"这块缓冲漏了多少"。
    dropped: AtomicU64,
}

impl AuditRing {
    /// 建一个最多容纳 `capacity` 条的缓冲。
    ///
    /// `capacity` 会被夹到至少 1：空缓冲没有任何意义，它唯一的用处就是
    /// 给 UI 看最近的记录。
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            buf: Mutex::new(VecDeque::new()),
            dropped: AtomicU64::new(0),
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// 当前堆积的条数。**并发下只是瞬时值**，不要拿它做容量判断。
    pub fn len(&self) -> usize {
        self.buf.lock().map(|b| b.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// 已经被覆盖丢弃的条数。
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// 从回调侧推入一条。满了就丢最旧的一条并计数。
    ///
    /// 这里刻意**不做**任何 I/O、格式化或哈希：那是消费者线程的事。
    pub fn push(&self, event: AuditEvent) {
        if let Ok(mut buf) = self.buf.lock() {
            if buf.len() == self.capacity {
                buf.pop_front();
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
            buf.push_back(event);
        }
    }

    /// 一次性取走全部事件（换出，不是复制）。
    ///
    /// 取走后缓冲归零，好让落盘线程在**锁外**慢慢写，
    /// 而回调侧继续往一个空缓冲里推。
    pub fn drain(&self) -> Vec<AuditEvent> {
        match self.buf.lock() {
            Ok(mut buf) => std::mem::take(&mut *buf).into_iter().collect(),
            Err(_) => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Action, Protocol};
    use aegis_core::InterfaceRole;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn event(n: u16) -> AuditEvent {
        AuditEvent {
            ts_ms: u64::from(n),
            pid: u32::from(n),
            process_path: format!(r"C:\App\app{n}.exe"),
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), n),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443),
            protocol: Protocol::Tcp,
            host: None,
            rule: None,
            luid: 42,
            role: InterfaceRole::CampusStrict,
            action: Action::Allow,
        }
    }

    #[test]
    fn capacity_is_at_least_one() {
        assert_eq!(AuditRing::new(0).capacity(), 1, "空缓冲没有意义");
        assert_eq!(AuditRing::new(7).capacity(), 7);
    }

    #[test]
    fn keeps_the_most_recent_and_counts_what_it_dropped() {
        let ring = AuditRing::new(3);
        for i in 0..5 {
            ring.push(event(i));
        }
        let got = ring.drain();
        assert_eq!(got.len(), 3, "满了只保留最近 3 条");
        assert_eq!(got[0].ts_ms, 2, "最旧的两条应已被覆盖");
        assert_eq!(got[2].ts_ms, 4);
        assert_eq!(ring.dropped(), 2, "丢弃必须可观测");
    }

    #[test]
    fn drain_empties_the_ring_but_not_the_drop_counter() {
        let ring = AuditRing::new(2);
        ring.push(event(0));
        ring.push(event(1));
        ring.push(event(2));
        assert_eq!(ring.drain().len(), 2);
        assert!(ring.is_empty());
        assert_eq!(ring.dropped(), 1, "丢弃计数是历史事实，不因取走而归零");
    }

    #[test]
    fn nothing_is_dropped_while_there_is_room() {
        let ring = AuditRing::new(4);
        for i in 0..4 {
            ring.push(event(i));
        }
        assert_eq!(ring.dropped(), 0);
        assert_eq!(ring.len(), 4);
    }

    /// 并发推入：在容量之内一条都不许丢。审计丢记录的代价是证据缺口。
    #[test]
    fn concurrent_pushes_within_capacity_lose_nothing() {
        let ring = Arc::new(AuditRing::new(1000));
        let handles: Vec<_> = (0..8u16)
            .map(|t| {
                let r = Arc::clone(&ring);
                std::thread::spawn(move || {
                    for i in 0..100u16 {
                        r.push(event(t * 100 + i));
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(ring.dropped(), 0, "容量之内不该丢");
        assert_eq!(ring.len(), 800);
    }

    /// 并发下**超过**容量时，丢弃数必须精确等于溢出量——
    /// 少记一条就等于谎报"我们没漏"。
    #[test]
    fn concurrent_overflow_drops_exactly_the_excess() {
        let ring = Arc::new(AuditRing::new(100));
        let handles: Vec<_> = (0..8u16)
            .map(|t| {
                let r = Arc::clone(&ring);
                std::thread::spawn(move || {
                    for i in 0..50u16 {
                        r.push(event(t * 100 + i));
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(ring.len(), 100, "缓冲应仍停在容量上");
        assert_eq!(ring.dropped(), 300, "400 条进 100 格 → 丢 300");
    }
}
