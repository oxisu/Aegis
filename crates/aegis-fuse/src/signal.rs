//! 回调与消费者之间的**无锁信号槽**（纯逻辑，不调用任何 Win32 API）。
//!
//! # 为什么需要它
//!
//! `NotifyIpInterfaceChange` 的回调运行在**系统线程池**上，而且协议栈在插拔
//! 网线时会**连续密集**地回调（§28.3「回调风暴」）。回调里做任何稍微重一点
//! 的事——分配内存、打日志、碰 WFP——都会把系统线程堵住；堵住的后果不是
//! "慢一点"，而是网络栈死锁。
//!
//! 所以回调只允许做一件事：把计数 +1。这也正是本模块存在的唯一理由。
//!
//! # 为什么是"计数"而不是"布尔标志"
//!
//! 布尔标志会**丢事件**：连续 30 次回调把同一个 true 写了 30 遍，消费者
//! 只看到一次。丢掉数量看起来无害，实际会丢掉判断依据——"震荡了 30 次"
//! 和"变动了 1 次"在日志与告警里的含义完全不同。
//!
//! # 并发约定
//!
//! - **多生产者**（系统线程池可能并发回调）、**单消费者**（Worker 线程）。
//!   单消费者由调用方保证；本 crate 的 [`crate::watch::InterfaceWatcher`]
//!   即是这个角色。
//! - `signal()` 只做一次 `fetch_add`，绝不阻塞。
//! - `take()` 用 `swap`，因此取走与回调之间**不会丢计数**。

use std::sync::atomic::{AtomicU64, Ordering};

/// 网口变动信号槽。
#[derive(Debug, Default)]
pub struct ChangeSignal {
    /// 尚未被取走的变动次数
    pending: AtomicU64,
    /// 累计观测到的变动次数（只增，供日志与自检）
    total: AtomicU64,
}

impl ChangeSignal {
    pub fn new() -> Self {
        Self::default()
    }

    /// **回调侧唯一允许做的事**：记一次变动。
    ///
    /// 这里绝不能分配内存、打日志、加锁、调 Win32——回调跑在系统线程池上，
    /// 堵住它的后果是网络栈死锁而不是"慢一点"。
    pub fn signal(&self) {
        self.pending.fetch_add(1, Ordering::Release);
        self.total.fetch_add(1, Ordering::Release);
    }

    /// 累积了多少次变动还没被取走。
    pub fn pending(&self) -> u64 {
        self.pending.load(Ordering::Acquire)
    }

    /// 累计观测到的变动次数（不受 `take` 影响）。
    pub fn total(&self) -> u64 {
        self.total.load(Ordering::Acquire)
    }

    /// **消费侧**取走计数并归零。返回本次取到的变动次数。
    ///
    /// 用 `swap` 而不是"读-算-写"：后者在并发回调下会丢掉中间那几次。
    pub fn take(&self) -> u64 {
        self.pending.swap(0, Ordering::AcqRel)
    }

    /// 是否从未观测到任何变动。
    pub fn is_idle(&self) -> bool {
        self.total() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn fresh_signal_is_idle() {
        let s = ChangeSignal::new();
        assert!(s.is_idle());
        assert_eq!(s.pending(), 0);
        assert_eq!(s.total(), 0);
        assert_eq!(s.take(), 0);
    }

    /// 布尔标志会丢事件，所以必须是计数：连续 30 次回调要数出 30。
    #[test]
    fn counts_every_signal_not_just_a_flag() {
        let s = ChangeSignal::new();
        for _ in 0..30 {
            s.signal();
        }
        assert_eq!(s.pending(), 30);
        assert_eq!(s.total(), 30);
    }

    /// 取走后 pending 归零，但 total 保留——总量是判断"这台机器震荡得厉不厉害"的依据。
    #[test]
    fn take_clears_pending_but_keeps_total() {
        let s = ChangeSignal::new();
        for _ in 0..5 {
            s.signal();
        }
        assert_eq!(s.take(), 5);
        assert_eq!(s.pending(), 0);
        assert_eq!(s.total(), 5, "total 不能被 take 清掉");
        assert!(!s.is_idle());
    }

    #[test]
    fn take_with_nothing_pending_returns_zero() {
        let s = ChangeSignal::new();
        s.signal();
        assert_eq!(s.take(), 1);
        assert_eq!(s.take(), 0);
    }

    /// 多次回调之间穿插取走，计数不能错。
    #[test]
    fn interleaved_signal_and_take_never_loses_count() {
        let s = ChangeSignal::new();
        s.signal();
        s.signal();
        assert_eq!(s.take(), 2);
        s.signal();
        assert_eq!(s.take(), 1);
        s.signal();
        s.signal();
        s.signal();
        assert_eq!(s.take(), 3);
        assert_eq!(s.total(), 6);
    }

    /// 多生产者并发：总次数必须精确等于线程数 × 每线程次数。
    /// 用 swap 取就不会丢；用"读-算-写"会丢，这条能把它钉住。
    #[test]
    fn concurrent_signals_are_not_lost() {
        let s = Arc::new(ChangeSignal::new());
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let s = Arc::clone(&s);
                thread::spawn(move || {
                    for _ in 0..1000 {
                        s.signal();
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().expect("生产者线程不应 panic");
        }
        assert_eq!(s.pending(), 8000, "并发回调不能丢计数");
        assert_eq!(s.total(), 8000);
        assert_eq!(s.take(), 8000);
        assert_eq!(s.pending(), 0);
    }

    /// 只增不减的 total 不会因为取走而回退——回退会让"累计震荡次数"失去意义。
    #[test]
    fn total_never_decreases_across_takes() {
        let s = ChangeSignal::new();
        s.signal();
        let before = s.total();
        s.take();
        assert_eq!(s.total(), before);
    }
}
