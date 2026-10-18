//! 审计事件：一次出站连接的**事实记录**（对应 design-spec §F3）。
//!
//! # 字段为什么这么定
//!
//! 审计要能回答"被网络中心询问时自证清白"，所以每条记录必须同时带上：
//!
//! - **谁**：`pid` + `process_path`
//! - **从哪来、到哪去**：`src` / `dst` / `protocol`
//! - **走的哪张网卡**：`luid` + `role`——同样是出网，走校园网和走热点的
//!   性质完全不同，缺了角色字段，审计表就只剩"连过"，无法自证
//! - **结果如何**：`action`
//!
//! # 两个可空字段
//!
//! `host`（域名）与 `rule`（命中规则）是**富化字段**，来自第二审计源
//! （§2A 的适配器元数据）。按 §12 F3 的修正：**拉不到不影响基本审计**，
//! 所以它们必须是 `Option`，绝不能为了凑齐而阻塞或丢弃这条记录。

use std::fmt;
use std::net::SocketAddr;

use aegis_core::InterfaceRole;

/// 这次连接被怎么处理了（§F3 审计视图里的 `action`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    /// 放行：走白名单（校园网）或自由出海网卡（热点）
    Allow,
    /// 规则拒绝：Clash `FINAL,REJECT` 之类，**本地掐握手**
    Reject,
    /// WFP 在**包离开真实网卡之前** DROP —— 首道防线（§4 / §7 的修正）
    FirewallBlock,
    /// 明文 HTTP(80) 被拦：校园网 DPI 场景的专视图
    PlaintextBlock,
}

impl Action {
    /// 是否被本地拦下了。审计视图的"被阻断记录"专视图按这个筛。
    pub fn is_blocked(self) -> bool {
        !matches!(self, Self::Allow)
    }

    /// 证据导出用的稳定标签。
    ///
    /// 刻意用英文短标签而不是中文 Display：证据包可能被拿到别的系统里
    /// 比对，中文在不同编码下会变形，标签变了就等于对不上。
    pub fn tag(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Reject => "reject",
            Self::FirewallBlock => "firewall-block",
            Self::PlaintextBlock => "plaintext-block",
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Allow => "放行",
            Self::Reject => "规则拒绝",
            Self::FirewallBlock => "内核阻断",
            Self::PlaintextBlock => "明文阻断",
        };
        f.write_str(s)
    }
}

/// 传输层协议。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    /// 未知协议保留原始号，不猜——猜错会让审计表出现一条指向错误协议的记录
    Other(u8),
}

impl Protocol {
    pub fn tag(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Icmp => "icmp",
            Self::Other(_) => "other",
        }
    }

    /// 协议号（IPPROTO_*）。`Other` 之外的都写死，便于与内核侧对账。
    pub fn number(self) -> u8 {
        match self {
            Self::Tcp => 6,
            Self::Udp => 17,
            Self::Icmp => 1,
            Self::Other(n) => n,
        }
    }

    pub fn from_number(n: u8) -> Self {
        match n {
            6 => Self::Tcp,
            17 => Self::Udp,
            1 => Self::Icmp,
            other => Self::Other(other),
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Other(n) => write!(f, "proto-{n}"),
            other => f.write_str(other.tag()),
        }
    }
}

/// 一条审计记录。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    /// 发生时刻（毫秒）。由调用方注入，不在这里读时钟——
    /// 审计要能重放历史，时间必须是数据而不是副作用。
    pub ts_ms: u64,
    pub pid: u32,
    /// 进程路径。拿不到就留空串，**不要**因此丢弃整条记录
    pub process_path: String,
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub protocol: Protocol,
    /// 域名（第二审计源富化，可空）
    pub host: Option<String>,
    /// 命中的规则（可空）
    pub rule: Option<String>,
    /// 出口网卡的 NET_LUID。用 LUID 而不是网卡名：名字会变，LUID 是稳定标识
    pub luid: u64,
    /// 该网卡当时的角色
    pub role: InterfaceRole,
    pub action: Action,
}

impl AuditEvent {
    /// 这条记录是不是"明文 HTTP(80)"——校园网 DPI 场景的专视图入口。
    pub fn is_plaintext_http(&self) -> bool {
        self.protocol == Protocol::Tcp && self.dst.port() == 80
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn addr(ip: [u8; 4], port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port)
    }

    fn event(dst_port: u16, action: Action) -> AuditEvent {
        AuditEvent {
            ts_ms: 1_700_000_000_000,
            pid: 4242,
            process_path: r"C:\Program Files\App\app.exe".to_string(),
            src: addr([10, 1, 2, 3], 51234),
            dst: addr([93, 184, 216, 34], dst_port),
            protocol: Protocol::Tcp,
            host: Some("example.com".to_string()),
            rule: Some("FINAL,REJECT".to_string()),
            luid: 1689395631011611136,
            role: InterfaceRole::CampusStrict,
            action,
        }
    }

    #[test]
    fn blocked_is_everything_but_allow() {
        assert!(Action::Reject.is_blocked());
        assert!(Action::FirewallBlock.is_blocked());
        assert!(Action::PlaintextBlock.is_blocked());
        assert!(!Action::Allow.is_blocked());
    }

    #[test]
    fn action_tags_are_ascii_and_stable() {
        // 证据包要跨系统比对，标签里不能出现中文
        for a in [
            Action::Allow,
            Action::Reject,
            Action::FirewallBlock,
            Action::PlaintextBlock,
        ] {
            assert!(a.tag().is_ascii(), "{a} 的标签必须是 ASCII：{}", a.tag());
            assert!(!a.tag().is_empty());
        }
    }

    #[test]
    fn protocol_number_roundtrips() {
        assert_eq!(Protocol::from_number(6), Protocol::Tcp);
        assert_eq!(Protocol::from_number(17), Protocol::Udp);
        assert_eq!(Protocol::from_number(1), Protocol::Icmp);
        assert_eq!(Protocol::from_number(47), Protocol::Other(47));
        assert_eq!(Protocol::Tcp.number(), 6);
        assert_eq!(Protocol::Other(47).number(), 47);
    }

    #[test]
    fn plaintext_http_is_tcp_port_80_only() {
        assert!(event(80, Action::Allow).is_plaintext_http());
        assert!(!event(443, Action::Allow).is_plaintext_http());
        // 同端口非 TCP 不算：审计专视图要是把它们混进来，
        // 用户看到"明文连接"却找不到对应的 HTTP 流
        let mut udp = event(80, Action::Allow);
        udp.protocol = Protocol::Udp;
        assert!(!udp.is_plaintext_http());
    }

    #[test]
    fn optional_enrichment_fields_can_be_empty_without_losing_the_record() {
        let mut e = event(443, Action::Allow);
        e.host = None;
        e.rule = None;
        // 第二审计源离线时正是这种记录；它仍然是可审计的完整事实
        assert!(e.host.is_none() && e.rule.is_none());
        assert_eq!(e.dst.port(), 443);
    }
}
