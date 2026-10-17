//! 拓扑指纹（对应 design-spec.md §20.4 拓扑指纹防伪）。
//!
//! ```text
//! Fingerprint = SHA256( version ‖ Σ( NET_LUID + MAC + SSID/Profile + Gateway_IP ) )
//! ```
//!
//! 语义：仅当"当前指纹 == 上次用户确认过的信任指纹"时编排器才自动放行；
//! 断开 / 新插网口 / 换 Wi-Fi 都会改变参与集合，从而判定为**拓扑漂移**并重新锁定。
//!
//! # 参与集合：只算物理网卡（收敛决策）
//!
//! 早期实现把**所有 Up 接口**都算进去，结果指纹会无故漂移：
//! WFP / QoS / 杀软等 NDIS 轻量过滤器会为每张物理网卡派生出若干伪接口
//! （`以太网 4-WFP Native MAC Layer LightWeight Filter-0000` 之类），
//! 它们的数量和 LUID 随驱动装卸载、系统更新、乃至幽灵网卡清理引起的
//! PnP 重枚举而变，但**物理环境其实一点没变**。
//!
//! 假漂移的代价很高：指纹一变就被判定为拓扑漂移，进而强制回
//! `[LOCKED]` 绝缘并要求用户重新确认——用户什么都没做却被反复打断，
//! 久了就会养成"无脑点确认"的习惯，**零信任模型直接失效**。
//!
//! 因此这里改为只计入**真实硬件网卡**（由 `NIIF_HARDWARE_INTERFACE` 位判定，
//! 且排除 `NIIF_FILTER_INTERFACE`）。降级链见 [`FingerprintScope`]。
//!
//! # 指纹版本
//! 参与集合变了，指纹值必然变。这里把版本字节从 1 升到 **2**，
//! 同版本内分量变更也照此递增，避免把"格式升级"误判成"拓扑漂移"。

use sha2::{Digest, Sha256};

use crate::model::{FingerprintScope, InterfaceInfo, InterfaceKind};

/// 指纹格式版本。**改动参与集合或分量时必须递增**，并同步更新本文件的说明。
pub const FINGERPRINT_VERSION: u8 = 2;

/// 计算结果：指纹值 + 它是在哪个作用域上算出来的。
///
/// 把作用域一起返回，是为了让上层能识别"当前指纹是收敛后的理想结果，
/// 还是降级兜底算出来的"——后者意味着感知数据异常，应告警而不是静默放行。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint {
    /// 小写十六进制 SHA-256
    pub value: String,
    /// 实际采用的参与集合
    pub scope: FingerprintScope,
    /// 参与计算的接口数
    pub participants: usize,
}

/// 计算当前拓扑指纹。
///
/// 参与集合按 [`FingerprintScope`] 依次放宽，直到非空为止。
/// 极端情况下（一张 Up 接口都没有）返回空集合指纹——此时 `participants == 0`，
/// 上层应视其为"采集异常/整机离线"，**绝不能**当作"拓扑未变"放行。
pub fn compute(interfaces: &[InterfaceInfo]) -> Fingerprint {
    let (scope, participants) = select_scope(interfaces);
    let count = participants.len();

    let mut hasher = Sha256::new();
    hasher.update([FINGERPRINT_VERSION]);
    // 作用域也进哈希：避免"物理集合"与"降级集合"恰好算出同一个值
    hasher.update([scope as u8]);

    for iface in participants {
        hasher.update(iface.luid.to_be_bytes());
        hasher.update(b"|");

        match &iface.mac {
            Some(mac) => hasher.update(mac.0),
            None => hasher.update(b"-"),
        }
        hasher.update(b"|");

        match &iface.ssid {
            Some(ssid) => hasher.update(ssid.as_bytes()),
            None => hasher.update(b"-"),
        }
        hasher.update(b"|");

        // 网关：换路由器 / 换热点会导致网关变化，属于真实拓扑变更。
        // 早期实现漏掉了这一分量（文档写了但代码没有），这里补上。
        if iface.gateway.is_empty() {
            hasher.update(b"-");
        } else {
            // 排序后再累加：网关列表顺序不应影响指纹，否则同一个拓扑
            // 会因为枚举顺序不同算出两个指纹，被误判成漂移。
            let mut gws = iface.gateway.clone();
            gws.sort_unstable();
            for gw in &gws {
                hasher.update(gw.octets());
                hasher.update(b",");
            }
        }
        hasher.update(b"|");
    }

    Fingerprint {
        value: hex(&hasher.finalize()),
        scope,
        participants: count,
    }
}

/// 按 `Physical → NonFilter → AllUp` 依次放宽，返回第一个非空的集合。
fn select_scope(interfaces: &[InterfaceInfo]) -> (FingerprintScope, Vec<&InterfaceInfo>) {
    const LADDER: [FingerprintScope; 3] = [
        FingerprintScope::Physical,
        FingerprintScope::NonFilter,
        FingerprintScope::AllUp,
    ];

    for scope in LADDER {
        let mut picked: Vec<&InterfaceInfo> = interfaces
            .iter()
            .filter(|i| i.is_up() && scope.includes(i.kind()))
            .collect();
        if !picked.is_empty() {
            // 必须排序：卡片枚举顺序在不同机器/不同时刻可能不同，
            // 不排序的话同一个拓扑会算出两个指纹，被误判成漂移。
            picked.sort_by_key(|i| i.luid);
            return (scope, picked);
        }
    }

    // 一张 Up 接口都没有（整机离线 / 采集异常）：用最强作用域、空集合兜底，
    // participants == 0 本身就是给上层的重要信号。
    (FingerprintScope::Physical, Vec::new())
}

/// 某类接口在当前 Up 接口里的数量，用于诊断（dry-run 展示）。
pub fn count_by_kind(interfaces: &[InterfaceInfo]) -> [(InterfaceKind, usize); 5] {
    const ALL: [InterfaceKind; 5] = [
        InterfaceKind::Physical,
        InterfaceKind::Filter,
        InterfaceKind::Tunnel,
        InterfaceKind::Loopback,
        InterfaceKind::Virtual,
    ];
    let mut out = [(InterfaceKind::Physical, 0usize); 5];
    for (idx, kind) in ALL.iter().enumerate() {
        out[idx] = (
            *kind,
            interfaces.iter().filter(|i| i.kind() == *kind).count(),
        );
    }
    out
}

/// 字节数组转小写十六进制字符串。
pub fn hex(bytes: &[u8]) -> String {
    const TBL: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(TBL[(b >> 4) as usize] as char);
        s.push(TBL[(b & 0x0f) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{if_flags, if_type, OperStatus};

    fn mk(luid: u64, flags: u8, if_type: u32, up: bool) -> InterfaceInfo {
        InterfaceInfo {
            luid,
            index: 0,
            alias: format!("iface-{luid}"),
            description: String::new(),
            mac: None,
            if_type,
            flags,
            access_type: 2,
            tunnel_type: 0,
            oper_status: if up { OperStatus::Up } else { OperStatus::Down },
            ipv4: Vec::new(),
            gateway: Vec::new(),
            dhcp_server: None,
            ssid: None,
        }
    }

    #[test]
    fn scope_prefers_physical_only() {
        let ifaces = vec![
            mk(1, if_flags::HARDWARE, if_type::ETHERNET_CSMACD, true),
            mk(
                2,
                if_flags::HARDWARE | if_flags::FILTER,
                if_type::ETHERNET_CSMACD,
                true,
            ),
        ];
        let fp = compute(&ifaces);
        assert_eq!(fp.scope, FingerprintScope::Physical);
        assert_eq!(fp.participants, 1, "过滤器伪接口不得参与指纹");
    }

    #[test]
    fn filter_interfaces_do_not_affect_fingerprint() {
        let base = vec![mk(1, if_flags::HARDWARE, if_type::ETHERNET_CSMACD, true)];
        let with_filters = vec![
            mk(1, if_flags::HARDWARE, if_type::ETHERNET_CSMACD, true),
            mk(
                9,
                if_flags::HARDWARE | if_flags::FILTER,
                if_type::ETHERNET_CSMACD,
                true,
            ),
            mk(
                10,
                if_flags::HARDWARE | if_flags::FILTER,
                if_type::ETHERNET_CSMACD,
                true,
            ),
        ];
        // 这正是本次收敛要消除的假漂移：伪接口增减不应改变指纹
        assert_eq!(compute(&base).value, compute(&with_filters).value);
    }

    #[test]
    fn scope_degrades_when_no_physical_up() {
        // 只有虚拟网卡 Up：应降级到 NonFilter，而不是对空集算指纹
        let ifaces = vec![
            mk(1, if_flags::HARDWARE, if_type::ETHERNET_CSMACD, false),
            mk(2, 0, if_type::OTHER, true),
        ];
        let fp = compute(&ifaces);
        assert_eq!(fp.scope, FingerprintScope::NonFilter);
        assert_eq!(fp.participants, 1);
    }

    #[test]
    fn empty_up_set_yields_zero_participants() {
        let ifaces = vec![mk(1, if_flags::HARDWARE, if_type::ETHERNET_CSMACD, false)];
        let fp = compute(&ifaces);
        assert_eq!(fp.participants, 0, "无 Up 接口时必须显式暴露为空集");
    }

    #[test]
    fn gateway_is_part_of_fingerprint() {
        let a = mk(1, if_flags::HARDWARE, if_type::ETHERNET_CSMACD, true);
        let mut b = a.clone();
        b.gateway = vec!["10.41.0.1".parse().unwrap()];
        assert_ne!(
            compute(std::slice::from_ref(&a)).value,
            compute(std::slice::from_ref(&b)).value
        );

        // 网关顺序不应影响结果（attach_route_info 已排序，这里再兜一层）
        let mut c = a.clone();
        c.gateway = vec!["10.41.0.1".parse().unwrap(), "10.41.0.2".parse().unwrap()];
        let mut d = a.clone();
        d.gateway = vec!["10.41.0.2".parse().unwrap(), "10.41.0.1".parse().unwrap()];
        assert_eq!(compute(&[c]).value, compute(&[d]).value);
    }

    #[test]
    fn fingerprint_is_stable_across_enumeration_order() {
        let a = mk(3, if_flags::HARDWARE, if_type::ETHERNET_CSMACD, true);
        let b = mk(1, if_flags::HARDWARE, if_type::IEEE80211, true);
        assert_eq!(
            compute(&[a.clone(), b.clone()]).value,
            compute(&[b, a]).value
        );
    }

    #[test]
    fn hex_encoding_is_lowercase() {
        assert_eq!(hex(&[0x00, 0x0f, 0xff]), "000fff");
    }
}
