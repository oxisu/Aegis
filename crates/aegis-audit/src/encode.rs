//! 审计事件的**规范化字节编码**（哈希前必须先过这一层）。
//!
//! # 为什么不能直接用 `serde_json` / `bincode` 的字节当哈希输入
//!
//! 证据链的前提是"同一条事实，任何时候算出来的哈希都一样"。把这件命交给
//! 序列化库会同时踩三个坑：
//!
//! 1. **库升级会改字节布局**。库作者没义务为你的历史哈希负责，一次 minor
//!    升级就可能让旧证据包全线校验失败——而证据包是要拿出来给网络中心看的，
//!    那时候已经没法重算了。
//! 2. **字段顺序与可选字段的表示由派生宏决定**。给 struct 调一下字段顺序
//!    是再普通不过的重构，却会静默改变哈希。
//! 3. **分隔符注入**。若用 `\x1f` 之类拼字段，两个字段的内容可以互相"挪边界"
//!    而拼出相同的字节串（`("ab","c")` 与 `("a","bc")`）。进程路径是攻击者
//!    部分可控的，这正好是个可乘之机。
//!
//! 所以这里手写一套**版本化 + 长度前缀**的编码：边界由长度决定，与内容无关。
//!
//! # 版本
//!
//! [`CANONICAL_VERSION`] 会写进字节流。将来若确实要改布局，升版本号并把
//! 旧版本的编码器**保留**下来——否则历史证据包就永远对不上了。

use std::net::{IpAddr, SocketAddr};

use aegis_core::InterfaceRole;

use crate::event::{Action, AuditEvent};

/// 规范化编码的版本。改布局必须递增，并保留旧版本的编码器。
pub const CANONICAL_VERSION: u32 = 1;

/// 流头。带它是为了让"这不是审计事件的规范化编码"能被一眼看出来，
/// 而不是拿到一串字节还得猜它是哪个版本、哪个布局。
pub(crate) const MAGIC: &[u8] = b"AEGIS-AUDIT-CANON";

/// 把一条事件编码成规范化字节。
pub fn canonical_bytes(event: &AuditEvent) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&CANONICAL_VERSION.to_le_bytes());
    out.extend_from_slice(&event.ts_ms.to_le_bytes());
    out.extend_from_slice(&event.pid.to_le_bytes());
    put_str(&mut out, &event.process_path);
    put_addr(&mut out, event.src);
    put_addr(&mut out, event.dst);
    out.push(event.protocol.number());
    put_opt_str(&mut out, event.host.as_deref());
    put_opt_str(&mut out, event.rule.as_deref());
    out.extend_from_slice(&event.luid.to_le_bytes());
    out.push(role_tag(event.role));
    out.push(action_tag(event.action));
    out
}

/// 网卡角色的稳定编号。
///
/// ⚠ 与 [`InterfaceRole`] 的变体一一对应。**新增角色必须在这里加分支**，
/// 不要用 `as u8` 直接取判别值——判别值会随变体重排而变，而重排枚举是
/// 极其普通的重构，改完哈希就全变了，且没有任何报错。
pub fn role_tag(role: InterfaceRole) -> u8 {
    match role {
        InterfaceRole::CampusStrict => 1,
        InterfaceRole::FreeOutbound => 2,
        InterfaceRole::Aggregated => 3,
        InterfaceRole::Isolated => 4,
        InterfaceRole::Unknown => 5,
    }
}

/// 从编号还原角色；未知编号返回 `None`（**绝不**回退到某个默认值）。
///
/// 回退的代价是审计表里写着一个并不是当时裁决结果的角色——那正是证据
/// 存在的意义所在，不能猜。
pub fn role_from_tag(tag: u8) -> Option<InterfaceRole> {
    Some(match tag {
        1 => InterfaceRole::CampusStrict,
        2 => InterfaceRole::FreeOutbound,
        3 => InterfaceRole::Aggregated,
        4 => InterfaceRole::Isolated,
        5 => InterfaceRole::Unknown,
        _ => return None,
    })
}

/// 动作的编号，理由同 [`role_tag`]。
pub fn action_tag(action: Action) -> u8 {
    match action {
        Action::Allow => 1,
        Action::Reject => 2,
        Action::FirewallBlock => 3,
        Action::PlaintextBlock => 4,
        Action::Observed => 5,
    }
}

/// 从编号还原动作；未知编号返回 `None`。
pub fn action_from_tag(tag: u8) -> Option<Action> {
    Some(match tag {
        1 => Action::Allow,
        2 => Action::Reject,
        3 => Action::FirewallBlock,
        4 => Action::PlaintextBlock,
        5 => Action::Observed,
        _ => return None,
    })
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    let b = s.as_bytes();
    out.extend_from_slice(&(b.len() as u32).to_le_bytes());
    out.extend_from_slice(b);
}

/// `Option<String>`：先写一个存在位，再写长度与内容。
///
/// 少了存在位，`None` 与 `Some("")` 会编码成同一串字节——审计里"没富化到"
/// 和"富化到了空字符串"不是一回事，前者是数据缺失，后者是数据本身为空。
fn put_opt_str(out: &mut Vec<u8>, s: Option<&str>) {
    match s {
        Some(v) => {
            out.push(1);
            put_str(out, v);
        },
        None => out.push(0),
    }
}

fn put_addr(out: &mut Vec<u8>, addr: SocketAddr) {
    match addr.ip() {
        IpAddr::V4(v4) => {
            out.push(4);
            out.extend_from_slice(&v4.octets());
        },
        IpAddr::V6(v6) => {
            out.push(6);
            out.extend_from_slice(&v6.octets());
        },
    }
    out.extend_from_slice(&addr.port().to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Protocol;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn event() -> AuditEvent {
        AuditEvent {
            ts_ms: 1_700_000_000_000,
            pid: 4242,
            process_path: r"C:\App\app.exe".to_string(),
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)), 51234),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443),
            protocol: Protocol::Tcp,
            host: Some("example.com".to_string()),
            rule: None,
            luid: 1689395631011611136,
            role: InterfaceRole::CampusStrict,
            action: Action::Reject,
        }
    }

    #[test]
    fn encoding_starts_with_magic_and_version() {
        let b = canonical_bytes(&event());
        assert!(b.starts_with(MAGIC), "流头必须是 magic");
        let ver = u32::from_le_bytes(b[MAGIC.len()..MAGIC.len() + 4].try_into().unwrap());
        assert_eq!(ver, CANONICAL_VERSION);
    }

    /// 规范化编码的第一要义：同一条事实，永远得到同一串字节。
    #[test]
    fn same_event_encodes_identically_every_time() {
        let a = canonical_bytes(&event());
        let b = canonical_bytes(&event());
        assert_eq!(a, b);
    }

    /// 任意一个字段变了，字节都要变——否则两条不同的事实会有同一个哈希，
    /// 证据链等于没做。
    #[test]
    fn every_field_is_actually_hashed() {
        let base = canonical_bytes(&event());

        let mut e = event();
        e.ts_ms += 1;
        assert_ne!(canonical_bytes(&e), base, "ts_ms 没进哈希");

        let mut e = event();
        e.pid += 1;
        assert_ne!(canonical_bytes(&e), base, "pid 没进哈希");

        let mut e = event();
        e.process_path.push('x');
        assert_ne!(canonical_bytes(&e), base, "process_path 没进哈希");

        let mut e = event();
        e.dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 35)), 443);
        assert_ne!(canonical_bytes(&e), base, "dst 没进哈希");

        let mut e = event();
        e.protocol = Protocol::Udp;
        assert_ne!(canonical_bytes(&e), base, "protocol 没进哈希");

        let mut e = event();
        e.luid += 1;
        assert_ne!(canonical_bytes(&e), base, "luid 没进哈希");

        let mut e = event();
        e.role = InterfaceRole::FreeOutbound;
        assert_ne!(canonical_bytes(&e), base, "role 没进哈希");

        let mut e = event();
        e.action = Action::Allow;
        assert_ne!(canonical_bytes(&e), base, "action 没进哈希");
    }

    /// 长度前缀的意义：字段内容可以互相"挪边界"，但字节串必须不同。
    /// 进程路径是攻击者部分可控的，这正是可乘之机。
    #[test]
    fn length_prefixes_defeat_boundary_shifting() {
        let mut a = event();
        a.process_path = "ab".to_string();
        a.host = Some("c".to_string());

        let mut b = event();
        b.process_path = "a".to_string();
        b.host = Some("bc".to_string());

        assert_ne!(canonical_bytes(&a), canonical_bytes(&b));
    }

    /// `None` 与 `Some("")` 必须可区分：前者是"没富化到"（数据缺失），
    /// 后者是"富化到了空串"（数据本身为空）。审计里这两者不能混。
    #[test]
    fn none_and_empty_string_are_distinguishable() {
        let mut none = event();
        none.host = None;
        let mut empty = event();
        empty.host = Some(String::new());
        assert_ne!(canonical_bytes(&none), canonical_bytes(&empty));
    }

    #[test]
    fn v4_and_v6_of_the_same_port_differ() {
        let mut v4 = event();
        v4.src = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 80);
        let mut v6 = event();
        v6.src = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 80);
        assert_ne!(canonical_bytes(&v4), canonical_bytes(&v6));
    }

    /// 角色 / 动作编号与变体一一对应，且未知编号**不回退**。
    #[test]
    fn role_and_action_tags_roundtrip_and_reject_unknown() {
        for (role, tag) in [
            (InterfaceRole::CampusStrict, 1),
            (InterfaceRole::FreeOutbound, 2),
            (InterfaceRole::Aggregated, 3),
            (InterfaceRole::Isolated, 4),
            (InterfaceRole::Unknown, 5),
        ] {
            assert_eq!(role_tag(role), tag, "{role}");
            assert_eq!(role_from_tag(tag), Some(role), "{tag}");
        }
        for (action, tag) in [
            (Action::Allow, 1),
            (Action::Reject, 2),
            (Action::FirewallBlock, 3),
            (Action::PlaintextBlock, 4),
            (Action::Observed, 5),
        ] {
            assert_eq!(action_tag(action), tag, "{action}");
            assert_eq!(action_from_tag(tag), Some(action), "{tag}");
        }
        assert_eq!(role_from_tag(0), None, "未知编号不能回退到某个角色");
        assert_eq!(role_from_tag(6), None);
        assert_eq!(action_from_tag(0), None);
        assert_eq!(action_from_tag(9), None);
    }
}
