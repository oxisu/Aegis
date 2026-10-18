//! `aegis-audit` —— 审计与证据链（design-spec §F3 / §15）。
//!
//! # 它要解决的问题
//!
//! Aegis 会拦下大量连接。拦下的**理由**必须能事后拿出来看——被网络中心
//! 询问时，"我本地就把违规连接掐了"这句话需要证据支撑，而不是一句声明。
//! 所以审计不是日志，是**证据**。
//!
//! 这和"打日志"的区别决定了本 crate 的几个强约束：
//!
//! - **规范化编码**（[`encode`]）：哈希输入不能依赖序列化库的字节布局，
//!   否则一次依赖升级就让历史证据包全线校验失败。
//! - **哈希链**（[`chain`]）：改动可检测。但**尾部删不掉**这件事必须由
//!   文档和测试同时说清楚（见 [`chain`] 的模块文档），不许让人以为上了链
//!   就万事大吉。
//! - **有界内存**（[`ring`]）：UI 只看最近 N 条；丢弃必须计数并暴露，
//!   不许让一张"最近 N 条"的表格被误当成全量。
//!
//! # 模块分层
//!
//! | 模块 | 职责 | 特权 |
//! |---|---|---|
//! | [`event`] | 审计事件的数据模型 | 无 |
//! | [`encode`] | 规范化字节编码（哈希输入） | 无 |
//! | [`chain`] | SHA-256 哈希链与校验 | 无 |
//! | [`ring`] | 有界内存缓冲（实时视图） | 无 |
//! | [`store`] | 只追加的落盘文件（跨分片连续） | 写文件 |
//!
//! 本 crate **不含任何 Win32 调用**，也不需要管理员权限——
//! 证据链的构造与校验必须能在普通用户下完整推演。真正从 WFP ALE 层捕获
//! 事件是 `aegis-wfp` 的事，落在它那一层的 `unsafe` 里。
//!
//! ⚠ **本 crate 尚未接任何数据源**：没有 WFP ALE 捕获、没有落盘的调用方。
//! 先把"证据长什么样、怎么证明它没被改、重开怎么接得上"定死，再谈往哪读往哪写。

pub mod chain;
pub mod decode;
pub mod encode;
pub mod event;
pub mod export;
pub mod ring;
pub mod store;

pub use chain::{hex, verify, ChainError, EvidenceChain, Hash, Link, HASH_LEN, GENESIS};
pub use decode::{decode, DecodeError};
pub use encode::{canonical_bytes, CANONICAL_VERSION};
pub use event::{Action, AuditEvent, Protocol};
pub use ring::AuditRing;
pub use export::{iso8601_utc, to_csv, to_json, EvidencePackage, ExportFilter};
pub use store::{
    read_records, read_records_with, AuditLog, ReadCtx, ReadError, Record, LOG_MAGIC, LOG_VERSION,
};

// 审计记录里带着网卡角色，调用方构造事件时必然要用它。
// 与其让每个调用方再去依赖 aegis-core（然后各自 import 一份），
// 不如在这里透出同一个类型——只有一个定义，不会漂移。
pub use aegis_core::InterfaceRole;

use aegis_version as version;

/// 本 crate 所属项目的完整版本号。
pub fn full_version() -> String {
    version::full()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::InterfaceRole;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn event(n: u16, action: Action, role: InterfaceRole) -> AuditEvent {
        AuditEvent {
            ts_ms: 1_700_000_000_000 + u64::from(n),
            pid: 1000 + u32::from(n),
            process_path: format!(r"C:\App\app{n}.exe"),
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 50000 + n),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443),
            protocol: Protocol::Tcp,
            host: None,
            rule: None,
            luid: 42,
            role,
            action,
        }
    }

    #[test]
    fn full_version_is_the_project_version_not_a_placeholder() {
        let v = full_version();
        assert!(!v.is_empty());
        assert_ne!(v, "xyzzy");
        assert_eq!(v, version::full());
        assert!(v.starts_with("0."), "{v}");
    }

    /// 端到端：回调侧推入缓冲 → 落盘线程换出 → 建链 → 校验通过
    /// → 篡改一条 → 校验失败。这是整个 crate 要表达的东西。
    #[test]
    fn end_to_end_from_capture_to_evidence() {
        let ring = AuditRing::new(64);
        for i in 0..5u16 {
            ring.push(event(i, Action::Allow, InterfaceRole::FreeOutbound));
        }
        ring.push(event(5, Action::FirewallBlock, InterfaceRole::CampusStrict));
        assert_eq!(ring.dropped(), 0);

        // 落盘线程换出（I/O 在锁外做）
        let events = ring.drain();
        assert!(ring.is_empty());
        assert_eq!(events.len(), 6);

        // 建链
        let mut chain = EvidenceChain::new();
        let links: Vec<Link> = events.iter().map(|e| chain.append(e)).collect();
        assert_eq!(chain.len(), 6);
        assert_eq!(verify(&events, &links), Ok(()));

        // 篡改最后一条的"阻断"记录：把它改成放行
        let mut tampered = events.clone();
        tampered[5].action = Action::Allow;
        assert_eq!(
            verify(&tampered, &links),
            Err(ChainError::HashMismatch { seq: 6 })
        );
    }

    /// 审计算出来的哈希不能因为"换个等价的表示"而变：
    /// 同一条事实，走一遍 buffer 再取出来，哈希必须一致。
    #[test]
    fn an_event_survives_the_ring_with_its_hash_intact() {
        let e = event(1, Action::Reject, InterfaceRole::CampusStrict);
        let direct = EvidenceChain::new().append(&e).hash;

        let ring = AuditRing::new(4);
        ring.push(e);
        let round_tripped = ring.drain().remove(0);
        let via_ring = EvidenceChain::new().append(&round_tripped).hash;

        assert_eq!(direct, via_ring);
    }
}
