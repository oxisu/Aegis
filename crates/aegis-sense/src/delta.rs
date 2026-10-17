//! 拓扑差分：比较两次快照，回答"拓扑到底变了没有、变在哪、需不需要用户重新确认"。
//!
//! 感知层采集的是**快照**，而编排层真正需要的是**变更事件**——
//! §26 状态机里"任意状态 + 网口变动 → 即刻回 [AIRGAP] + [LOCKED]"这一条，
//! 输入就是本模块的输出。
//!
//! # 设计取舍：区分"噪声"与"信号"
//! 一台装了 WFP / QoS / 虚拟机的机器上，Up 接口集合随时都在小幅抖动
//! （过滤器伪接口、临时隧道等）。若不加区分地把任何变化都上报，
//! 用户会被反复要求重新确认，最终演变成"无脑点确认"——
//! 那比不做零信任更糟。
//!
//! 因此本模块把变更分成两级：
//! - [`TopologyDelta::physical_changed`]：涉及**真实物理网卡**的增删改 → 必须重新确认
//! - 其余（虚拟/过滤器/隧道）变化 → 只记录，不触发锁定
//!
//! 指纹漂移单独看 [`TopologyDelta::fingerprint_changed`]，
//! 由于指纹已收敛为只算物理网卡（见 [`crate::fingerprint`]），
//! 它现在等价于"物理拓扑变了"。

use std::fmt;
use std::net::Ipv4Addr;

use crate::model::{InterfaceInfo, OperStatus, TopologySnapshot};

/// 一张网卡在两次快照之间的字段级变化。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceChange {
    /// 稳定标识（LUID → MAC → 别名）
    pub identity: String,
    pub alias: String,
    /// 该网卡是否为真实物理网卡（决定是否需要用户重新确认）
    pub physical: bool,
    pub oper_status: Option<(OperStatus, OperStatus)>,
    pub ipv4: Option<(Vec<Ipv4Addr>, Vec<Ipv4Addr>)>,
    pub gateway: Option<(Vec<Ipv4Addr>, Vec<Ipv4Addr>)>,
    pub ssid: Option<(Option<String>, Option<String>)>,
}

impl InterfaceChange {
    /// 变化是否发生在真实物理网卡上。
    pub fn is_physical(&self) -> bool {
        self.physical
    }
}

/// 两次拓扑快照之间的完整差异。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopologyDelta {
    pub fingerprint_before: String,
    pub fingerprint_after: String,
    /// 指纹是否漂移。**这是编排层最关心的字段**：漂移 = 需要重新确认。
    pub fingerprint_changed: bool,
    /// 指纹作用域是否退化（例如从"仅物理网卡"降级到"非过滤器接口"），
    /// 这通常意味着感知数据异常，应告警。
    pub scope_changed: bool,
    pub egress_before: u64,
    pub egress_after: u64,
    /// 默认出口是否换了一张网卡（换出口 = 走的是完全不同的通道，必须复核）
    pub egress_changed: bool,
    /// 新增的接口
    pub added: Vec<InterfaceInfo>,
    /// 消失的接口
    pub removed: Vec<InterfaceInfo>,
    /// 字段发生变化的接口
    pub changed: Vec<InterfaceChange>,
}

impl TopologyDelta {
    /// 是否**涉及真实物理网卡**的增删改。
    ///
    /// 这是"要不要打断用户"的判据：只有它为 true 时才应回 `[LOCKED]`。
    pub fn physical_changed(&self) -> bool {
        self.added.iter().any(InterfaceInfo::is_physical)
            || self.removed.iter().any(InterfaceInfo::is_physical)
            || self.changed.iter().any(InterfaceChange::is_physical)
    }

    /// 是否要求用户重新确认：指纹漂移、默认出口变更、物理网卡增删改，
    /// 任一成立即需要。
    pub fn needs_reconfirmation(&self) -> bool {
        self.fingerprint_changed || self.egress_changed || self.physical_changed()
    }

    /// 两次快照之间是否完全没有差异。
    pub fn is_empty(&self) -> bool {
        !self.fingerprint_changed
            && !self.scope_changed
            && !self.egress_changed
            && self.added.is_empty()
            && self.removed.is_empty()
            && self.changed.is_empty()
    }

    /// 一行摘要，供日志输出。
    pub fn summary(&self) -> String {
        if self.is_empty() {
            return "拓扑无变化".to_string();
        }
        let mut parts = Vec::new();
        if self.fingerprint_changed {
            parts.push("指纹漂移".to_string());
        }
        if self.egress_changed {
            parts.push("默认出口变更".to_string());
        }
        if !self.added.is_empty() {
            parts.push(format!("新增 {} 张网卡", self.added.len()));
        }
        if !self.removed.is_empty() {
            parts.push(format!("消失 {} 张网卡", self.removed.len()));
        }
        if !self.changed.is_empty() {
            parts.push(format!("{} 张网卡字段变化", self.changed.len()));
        }
        if self.scope_changed {
            parts.push("指纹作用域退化".to_string());
        }
        let verdict = if self.needs_reconfirmation() {
            "需重新确认"
        } else {
            "仅噪声，无需打断"
        };
        format!("{}（{}）", parts.join(" / "), verdict)
    }
}

impl fmt::Display for TopologyDelta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.summary())
    }
}

/// 比较两次快照。
///
/// 按 `identity()` 配对；只出现在其中一侧的即为新增/消失。
pub fn diff(before: &TopologySnapshot, after: &TopologySnapshot) -> TopologyDelta {
    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut changed = Vec::new();

    for a in &after.interfaces {
        let key = a.identity();
        if before.interfaces.iter().any(|b| b.identity() == key) {
            continue;
        }
        added.push(a.clone());
    }

    for b in &before.interfaces {
        let key = b.identity();
        match after.interfaces.iter().find(|a| a.identity() == key) {
            None => removed.push(b.clone()),
            Some(a) => {
                if let Some(c) = diff_one(b, a) {
                    changed.push(c);
                }
            },
        }
    }

    TopologyDelta {
        fingerprint_before: before.fingerprint.clone(),
        fingerprint_after: after.fingerprint.clone(),
        fingerprint_changed: before.fingerprint != after.fingerprint,
        scope_changed: before.fingerprint_scope != after.fingerprint_scope,
        egress_before: before.default_egress_luid,
        egress_after: after.default_egress_luid,
        egress_changed: before.default_egress_luid != after.default_egress_luid,
        added,
        removed,
        changed,
    }
}

/// 比较同一张网卡的两次状态；无差异返回 `None`。
fn diff_one(before: &InterfaceInfo, after: &InterfaceInfo) -> Option<InterfaceChange> {
    let mut c = InterfaceChange {
        identity: after.identity(),
        alias: after.alias.clone(),
        physical: after.is_physical() || before.is_physical(),
        oper_status: None,
        ipv4: None,
        gateway: None,
        ssid: None,
    };
    let mut any = false;

    if before.oper_status != after.oper_status {
        c.oper_status = Some((before.oper_status, after.oper_status));
        any = true;
    }
    if before.ipv4 != after.ipv4 {
        c.ipv4 = Some((before.ipv4.clone(), after.ipv4.clone()));
        any = true;
    }
    if before.gateway != after.gateway {
        c.gateway = Some((before.gateway.clone(), after.gateway.clone()));
        any = true;
    }
    if before.ssid != after.ssid {
        c.ssid = Some((before.ssid.clone(), after.ssid.clone()));
        any = true;
    }

    if any {
        Some(c)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{if_flags, if_type, FingerprintScope};

    fn mk(luid: u64, flags: u8, if_type: u32, up: bool, alias: &str) -> InterfaceInfo {
        InterfaceInfo {
            luid,
            index: 0,
            alias: alias.to_string(),
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

    fn snap(interfaces: Vec<InterfaceInfo>, egress: u64) -> TopologySnapshot {
        let fp = crate::fingerprint::compute(&interfaces);
        TopologySnapshot {
            fingerprint: fp.value,
            fingerprint_scope: fp.scope,
            fingerprint_participants: fp.participants,
            interfaces,
            default_egress_luid: egress,
        }
    }

    #[test]
    fn identical_snapshots_produce_empty_delta() {
        let s = snap(
            vec![mk(
                1,
                if_flags::HARDWARE,
                if_type::ETHERNET_CSMACD,
                true,
                "eth0",
            )],
            1,
        );
        let d = diff(&s, &s);
        assert!(d.is_empty());
        assert!(!d.needs_reconfirmation());
        assert_eq!(d.summary(), "拓扑无变化");
    }

    /// 本次收敛的核心收益：过滤器伪接口的增减**不触发**重新确认。
    #[test]
    fn filter_noise_does_not_require_reconfirmation() {
        let before = snap(
            vec![mk(
                1,
                if_flags::HARDWARE,
                if_type::ETHERNET_CSMACD,
                true,
                "eth0",
            )],
            1,
        );
        let after = snap(
            vec![
                mk(
                    1,
                    if_flags::HARDWARE,
                    if_type::ETHERNET_CSMACD,
                    true,
                    "eth0",
                ),
                mk(
                    9,
                    if_flags::HARDWARE | if_flags::FILTER,
                    if_type::ETHERNET_CSMACD,
                    true,
                    "eth0-WFP",
                ),
            ],
            1,
        );
        let d = diff(&before, &after);
        assert!(!d.fingerprint_changed, "指纹不应因伪接口而变化");
        assert!(!d.physical_changed(), "伪接口不应算作物理网卡变化");
        assert!(!d.needs_reconfirmation(), "纯噪声不应打断用户");
        assert_eq!(d.added.len(), 1, "但仍应如实记录新增了什么");
    }

    #[test]
    fn physical_nic_added_requires_reconfirmation() {
        let before = snap(
            vec![mk(
                1,
                if_flags::HARDWARE,
                if_type::ETHERNET_CSMACD,
                true,
                "eth0",
            )],
            1,
        );
        let after = snap(
            vec![
                mk(
                    1,
                    if_flags::HARDWARE,
                    if_type::ETHERNET_CSMACD,
                    true,
                    "eth0",
                ),
                mk(2, if_flags::HARDWARE, if_type::IEEE80211, true, "wlan0"),
            ],
            1,
        );
        let d = diff(&before, &after);
        assert!(d.fingerprint_changed);
        assert!(d.physical_changed());
        assert!(d.needs_reconfirmation());
    }

    #[test]
    fn egress_change_is_flagged_even_without_new_nics() {
        // 同一批网卡，但默认出口换了一张：必须复核（走的是完全不同的通道）
        let ifaces = || {
            vec![
                mk(
                    1,
                    if_flags::HARDWARE,
                    if_type::ETHERNET_CSMACD,
                    true,
                    "eth0",
                ),
                mk(2, if_flags::HARDWARE, if_type::IEEE80211, true, "wlan0"),
            ]
        };
        let before = snap(ifaces(), 1);
        let after = snap(ifaces(), 2);
        let d = diff(&before, &after);
        assert!(d.egress_changed);
        assert!(d.needs_reconfirmation());
        assert!(!d.fingerprint_changed, "网卡集合没变，指纹不应变");
    }

    #[test]
    fn field_level_change_is_detected() {
        let b = mk(
            1,
            if_flags::HARDWARE,
            if_type::ETHERNET_CSMACD,
            true,
            "eth0",
        );
        let mut a = b.clone();
        a.gateway = vec!["10.41.0.1".parse().unwrap()];
        // identity 相同，因此会被配对比较而不是算作一增一减
        assert_eq!(b.identity(), a.identity());
        let d = diff(&snap(vec![b.clone()], 1), &snap(vec![a], 1));
        assert_eq!(d.added.len(), 0);
        assert_eq!(d.removed.len(), 0);
        assert_eq!(d.changed.len(), 1);
        assert!(d.changed[0].gateway.is_some());
        assert!(d.physical_changed());
    }

    #[test]
    fn scope_degradation_is_reported() {
        let mut degraded = snap(
            vec![mk(
                1,
                if_flags::HARDWARE,
                if_type::ETHERNET_CSMACD,
                true,
                "eth0",
            )],
            1,
        );
        degraded.fingerprint_scope = FingerprintScope::NonFilter;
        let normal = snap(
            vec![mk(
                1,
                if_flags::HARDWARE,
                if_type::ETHERNET_CSMACD,
                true,
                "eth0",
            )],
            1,
        );
        let d = diff(&normal, &degraded);
        assert!(d.scope_changed);
    }
}
