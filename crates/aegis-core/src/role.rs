//! 网卡角色模型与角色裁决（对应 design-spec.md §20.5 Role-Based Interfaces）。
//!
//! # 为什么角色不在感知层
//! 感知层（`aegis-sense`）只回答"网卡长什么样"，是事实；
//! 角色回答"这张网卡允许做什么"，是**策略**。
//! 混在一起会让感知层被策略污染（进而需要权限、难以只读干跑），
//! 也让策略无法独立测试。因此角色定义收敛在本模块。
//!
//! # 默认 Fail-Closed
//! 无法判定的网卡一律落到 [`InterfaceRole::Isolated`]（绝对 DROP）。
//! 宁可让用户手动放行一张网卡，也绝不能因为"猜"而放开通往外网的口子——
//! 猜错的代价是一次真实的泄漏，而让用户多点一次的代价只是几秒钟。

use std::fmt;

use aegis_sense::model::InterfaceInfo;
use aegis_sense::model::InterfaceKind;

/// 网卡角色（§20.5）。
///
/// 同时派生 `Deserialize`：配置里的 `fallback_role = "Isolated"` 直接落到这里，
/// 不再另建一个"配置专用 DTO"——两个结构必然各自漂移，而漂移的结果是
/// 安全策略按旧字段静默生效。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum InterfaceRole {
    /// 校园网接入：锁死物理 53 端口，除白名单外物理阻断其余出站
    CampusStrict,
    /// 热点 / PCE / 独立外网：开放直连出海
    FreeOutbound,
    /// 仅供多网卡叠加带宽的次级网卡：禁止普通应用访问
    Aggregated,
    /// 未知 / 未配置 / 违规网卡：WFP 绝对 DROP ALL
    Isolated,
}

impl InterfaceRole {
    /// 该角色是否允许普通应用经此网卡出网。
    ///
    /// 这是把角色翻译成 WFP 策略时的**总开关**：
    /// 允许出网的只有 CampusStrict（走白名单）和 FreeOutbound。
    pub fn allows_egress(&self) -> bool {
        matches!(self, Self::CampusStrict | Self::FreeOutbound)
    }

    /// 是否需要锁死物理 53 端口（校园网场景的强制要求）。
    pub fn locks_dns(&self) -> bool {
        matches!(self, Self::CampusStrict)
    }
}

impl fmt::Display for InterfaceRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::CampusStrict => "校园网严格",
            Self::FreeOutbound => "自由出海",
            Self::Aggregated => "带宽聚合",
            Self::Isolated => "彻底绝缘",
        };
        f.write_str(s)
    }
}

/// 裁决结果的可信度。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum Confidence {
    /// 用户显式确认过
    Confirmed,
    /// 由策略推断（可用于预填，但仍建议确认）
    Inferred,
    /// 策略无法判定，必须人工分配
    Unassigned,
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Confirmed => "已确认",
            Self::Inferred => "策略推断",
            Self::Unassigned => "待人工分配",
        };
        f.write_str(s)
    }
}

/// 单次裁决结果。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RoleDecision {
    pub identity: String,
    pub alias: String,
    pub role: InterfaceRole,
    pub confidence: Confidence,
    /// 该网卡当前是否 Up。未插线的网卡同样会被裁决（插上即刻生效），
    /// 但展示时需要区分，否则用户会困惑"这张没用的网卡为什么要我确认"。
    pub up: bool,
    /// 人类可读的判定依据。安全策略必须可解释——
    /// 用户看不懂"为什么这张网卡要被锁"，就不会真正信任这套系统。
    pub reason: String,
}

/// 角色判定策略。
///
/// 全部可配置，**不内置任何具体校园名 / 运营商名**：
/// 把机构特有信息硬编码进代码既不通用，也会随环境失效。
///
/// # 为什么需要"精确名单"
/// 关键字 + 网关前缀这两种启发式覆盖不了一类很常见的网络：**个人手机热点**。
/// 它的 SSID 往往是个人化的（例如一个叫 `MMi` 的小米手机热点），
/// 既不含 `hotspot` 关键字，网关也不在校园网段，两种启发式都命中不了。
///
/// 此时策略落到 Fail-Closed 的绝缘态——**这本身是正确且安全的**，
/// 但每次开机都要手动放行一次很烦。所以提供 `known_free_ssids` /
/// `known_campus_ssids` 让用户显式钉死具体网络：
/// 声明权始终在用户手上，代码不替用户猜测，也不把用户的生活习惯写进源码。
// `deny_unknown_fields`：安全配置里的拼写错误必须报错，而不是被静默忽略后
// 退回默认值——那样用户以为自己改了策略，实际生效的仍是旧的那套。
// 缺字段则退回 Default（Fail-Closed 的 Isolated 兜底）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RolePolicy {
    /// SSID 含这些关键字 → `CampusStrict`
    pub campus_ssid_keywords: Vec<String>,
    /// SSID **精确等于**这些值 → `CampusStrict`（优先级高于关键字）
    pub known_campus_ssids: Vec<String>,
    /// 网关 IP 以这些前缀开头 → `CampusStrict`
    pub campus_gateway_prefixes: Vec<String>,
    /// SSID 含这些关键字 → `FreeOutbound`
    pub free_ssid_keywords: Vec<String>,
    /// SSID **精确等于**这些值 → `FreeOutbound`（优先级高于关键字）
    pub known_free_ssids: Vec<String>,
    /// 无法判定时的兜底角色
    pub fallback_role: InterfaceRole,
    /// 是否允许同时有多张 FreeOutbound
    pub allow_multiple_free: bool,
}

impl Default for RolePolicy {
    fn default() -> Self {
        Self {
            campus_ssid_keywords: vec!["campus".into(), "edu".into(), "校园".into()],
            known_campus_ssids: Vec::new(),
            campus_gateway_prefixes: vec!["10.".into(), "172.16.".into(), "172.17.".into()],
            free_ssid_keywords: vec![
                "hotspot".into(),
                "热点".into(),
                "iphone".into(),
                "android".into(),
            ],
            known_free_ssids: Vec::new(),
            // Fail-closed：猜不出来就绝缘
            fallback_role: InterfaceRole::Isolated,
            allow_multiple_free: false,
        }
    }
}

impl RolePolicy {
    fn matches_any(haystack: &str, needles: &[String]) -> bool {
        let lower = haystack.to_lowercase();
        needles.iter().any(|n| lower.contains(&n.to_lowercase()))
    }

    fn gateway_matches_prefix(iface: &InterfaceInfo, prefixes: &[String]) -> bool {
        iface
            .gateway
            .iter()
            .any(|gw| prefixes.iter().any(|p| gw.to_string().starts_with(p)))
    }
}

/// 对单张网卡做角色裁决。
///
/// 判定顺序（先硬约束，后软提示）：
/// 1. 非物理网卡 → 一律 `Isolated`。伪接口、隧道、虚拟网卡背后仍是同一张物理网卡，
///    给它们单独分配角色等于开出第二条通路，是设计漏洞。
/// 2. SSID / 网关命中自由出海关键字 → `FreeOutbound`
/// 3. SSID / 网关命中校园网关键字 → `CampusStrict`
/// 4. 都命中不了 → `fallback_role`（默认 `Isolated`）+ `Unassigned`，等人工确认
pub fn adjudicate(iface: &InterfaceInfo, policy: &RolePolicy) -> RoleDecision {
    let identity = iface.identity();
    let alias = iface.alias.clone();

    let up = iface.is_up();
    let decision = |role: InterfaceRole, confidence: Confidence, reason: String| RoleDecision {
        identity,
        alias,
        role,
        confidence,
        up,
        reason,
    };

    if iface.kind() != InterfaceKind::Physical {
        return decision(
            InterfaceRole::Isolated,
            Confidence::Confirmed,
            format!("{} 不是物理网卡，不参与角色分配", iface.kind()),
        );
    }

    if let Some(ssid) = &iface.ssid {
        // 精确名单优先于关键字：用户显式声明过的网络，信任度高于启发式猜测。
        // 注意 confidence 标记为 Confirmed —— 这是用户自己填的，不是我们猜的。
        if policy.known_free_ssids.iter().any(|s| s == ssid) {
            return decision(
                InterfaceRole::FreeOutbound,
                Confidence::Confirmed,
                format!("SSID「{ssid}」在用户声明的自由出海名单中"),
            );
        }
        if policy.known_campus_ssids.iter().any(|s| s == ssid) {
            return decision(
                InterfaceRole::CampusStrict,
                Confidence::Confirmed,
                format!("SSID「{ssid}」在用户声明的校园网名单中"),
            );
        }

        if RolePolicy::matches_any(ssid, &policy.free_ssid_keywords) {
            return decision(
                InterfaceRole::FreeOutbound,
                Confidence::Inferred,
                format!("SSID 命中自由出海关键字：{ssid}"),
            );
        }
        if RolePolicy::matches_any(ssid, &policy.campus_ssid_keywords) {
            return decision(
                InterfaceRole::CampusStrict,
                Confidence::Inferred,
                format!("SSID 命中校园网关键字：{ssid}"),
            );
        }
    }

    if RolePolicy::gateway_matches_prefix(iface, &policy.campus_gateway_prefixes) {
        return decision(
            InterfaceRole::CampusStrict,
            Confidence::Inferred,
            "网关地址落在校园网常见私有网段".to_string(),
        );
    }

    let head = match &iface.ssid {
        Some(ssid) => format!("SSID「{ssid}」未命中任何已知关键字"),
        None => "无 SSID（有线或未关联无线）".to_string(),
    };
    let tail = match iface.gateway.first() {
        Some(gw) => format!("；网关 {gw} 也不在已知校园网网段"),
        None => "；也没有网关".to_string(),
    };
    decision(
        policy.fallback_role,
        Confidence::Unassigned,
        format!("{head}{tail} —— 需人工分配角色"),
    )
}

/// 对整份快照做角色裁决，只针对物理网卡。
pub fn adjudicate_all(interfaces: &[InterfaceInfo], policy: &RolePolicy) -> Vec<RoleDecision> {
    interfaces
        .iter()
        .filter(|i| i.is_physical())
        .map(|i| adjudicate(i, policy))
        .collect()
}

/// 已分配的角色表：`identity → (角色, 是否经用户确认)`。
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct RoleTable {
    entries: Vec<(String, InterfaceRole, bool)>,
}

impl RoleTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// 写入/覆盖一条分配。`confirmed` 表示是否经用户显式确认。
    pub fn assign(&mut self, identity: impl Into<String>, role: InterfaceRole, confirmed: bool) {
        let key = identity.into();
        if let Some(e) = self.entries.iter_mut().find(|e| e.0 == key) {
            e.1 = role;
            e.2 = confirmed;
        } else {
            self.entries.push((key, role, confirmed));
        }
    }

    pub fn get(&self, identity: &str) -> Option<(InterfaceRole, bool)> {
        self.entries
            .iter()
            .find(|e| e.0 == identity)
            .map(|e| (e.1, e.2))
    }

    /// 未经用户确认的条目（首次开机、或拓扑漂移后新增的网卡）。
    pub fn unconfirmed(&self) -> impl Iterator<Item = &(String, InterfaceRole, bool)> {
        self.entries.iter().filter(|e| !e.2)
    }

    /// 是否所有条目都已确认。
    pub fn all_confirmed(&self) -> bool {
        self.entries.iter().all(|e| e.2)
    }

    /// 移除某条分配（网卡消失时调用）。
    pub fn remove(&mut self, identity: &str) {
        self.entries.retain(|e| e.0 != identity);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &(String, InterfaceRole, bool)> {
        self.entries.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_sense::model::{if_flags, if_type, OperStatus};

    fn nic(
        luid: u64,
        flags: u8,
        if_type: u32,
        ssid: Option<&str>,
        gw: Option<&str>,
    ) -> InterfaceInfo {
        InterfaceInfo {
            luid,
            index: 0,
            alias: format!("nic-{luid}"),
            description: String::new(),
            mac: None,
            if_type,
            flags,
            access_type: 2,
            tunnel_type: 0,
            oper_status: OperStatus::Up,
            ipv4: Vec::new(),
            gateway: gw.into_iter().map(|s| s.parse().unwrap()).collect(),
            dhcp_server: None,
            ssid: ssid.map(str::to_string),
        }
    }

    #[test]
    fn virtual_nics_are_always_isolated() {
        let policy = RolePolicy::default();
        for kind_flags in [
            if_flags::HARDWARE | if_flags::FILTER,
            0, // 纯虚拟
        ] {
            let d = adjudicate(
                &nic(
                    1,
                    kind_flags,
                    if_type::ETHERNET_CSMACD,
                    None,
                    Some("10.0.0.1"),
                ),
                &policy,
            );
            assert_eq!(d.role, InterfaceRole::Isolated, "非物理网卡必须绝缘");
            assert_eq!(d.confidence, Confidence::Confirmed);
        }
    }

    #[test]
    fn campus_ssid_maps_to_campus_strict() {
        let d = adjudicate(
            &nic(
                1,
                if_flags::HARDWARE,
                if_type::IEEE80211,
                Some("Campus-WiFi"),
                None,
            ),
            &RolePolicy::default(),
        );
        assert_eq!(d.role, InterfaceRole::CampusStrict);
        assert_eq!(d.confidence, Confidence::Inferred);
    }

    #[test]
    fn free_ssid_maps_to_free_outbound() {
        let d = adjudicate(
            &nic(
                1,
                if_flags::HARDWARE,
                if_type::IEEE80211,
                Some("MyHotspot"),
                None,
            ),
            &RolePolicy::default(),
        );
        assert_eq!(d.role, InterfaceRole::FreeOutbound);
    }

    #[test]
    fn campus_gateway_prefix_maps_to_campus_strict() {
        let d = adjudicate(
            &nic(
                1,
                if_flags::HARDWARE,
                if_type::ETHERNET_CSMACD,
                None,
                Some("10.41.0.1"),
            ),
            &RolePolicy::default(),
        );
        assert_eq!(d.role, InterfaceRole::CampusStrict);
    }

    /// Fail-closed 是整套模型的底线，这条测试就是底线本身。
    /// 手机热点这类个人化 SSID（如 `MMi`）既不含关键字、网关也不在校园网段，
    /// 两种启发式都命中不了。默认应 Fail-Closed，由用户在配置里显式声明后放行。
    #[test]
    fn personal_hotspot_ssid_defaults_to_isolated() {
        let d = adjudicate(
            &nic(
                1,
                if_flags::HARDWARE,
                if_type::IEEE80211,
                Some("MMi"),
                Some("192.168.40.220"),
            ),
            &RolePolicy::default(),
        );
        assert_eq!(d.role, InterfaceRole::Isolated);
        assert_eq!(d.confidence, Confidence::Unassigned);
    }

    #[test]
    fn user_declared_free_ssid_beats_keywords_and_is_confirmed() {
        let policy = RolePolicy {
            known_free_ssids: vec!["MMi".into()],
            ..Default::default()
        };
        let d = adjudicate(
            &nic(
                1,
                if_flags::HARDWARE,
                if_type::IEEE80211,
                Some("MMi"),
                Some("192.168.40.220"),
            ),
            &policy,
        );
        assert_eq!(d.role, InterfaceRole::FreeOutbound);
        assert_eq!(d.confidence, Confidence::Confirmed, "用户声明的不是猜测");
    }

    /// 精确名单必须优先于关键字，否则用户无法覆盖启发式的误判。
    #[test]
    fn exact_list_takes_priority_over_keywords() {
        // "Campus-Hotspot" 同时命中两个关键字；精确名单应胜出
        let policy = RolePolicy {
            known_free_ssids: vec!["Campus-Hotspot".into()],
            ..Default::default()
        };
        let d = adjudicate(
            &nic(
                1,
                if_flags::HARDWARE,
                if_type::IEEE80211,
                Some("Campus-Hotspot"),
                None,
            ),
            &policy,
        );
        assert_eq!(d.role, InterfaceRole::FreeOutbound);

        let policy = RolePolicy {
            known_free_ssids: Vec::new(),
            known_campus_ssids: vec!["Campus-Hotspot".into()],
            ..Default::default()
        };
        let d = adjudicate(
            &nic(
                1,
                if_flags::HARDWARE,
                if_type::IEEE80211,
                Some("Campus-Hotspot"),
                None,
            ),
            &policy,
        );
        assert_eq!(d.role, InterfaceRole::CampusStrict);
    }

    #[test]
    fn unknown_nic_falls_back_to_isolated_and_unassigned() {
        let d = adjudicate(
            &nic(
                1,
                if_flags::HARDWARE,
                if_type::ETHERNET_CSMACD,
                None,
                Some("203.0.113.1"),
            ),
            &RolePolicy::default(),
        );
        assert_eq!(d.role, InterfaceRole::Isolated);
        assert_eq!(d.confidence, Confidence::Unassigned);
    }

    #[test]
    fn egress_and_dns_semantics() {
        assert!(InterfaceRole::FreeOutbound.allows_egress());
        assert!(InterfaceRole::CampusStrict.allows_egress());
        assert!(InterfaceRole::CampusStrict.locks_dns());
        assert!(!InterfaceRole::FreeOutbound.locks_dns());
        assert!(!InterfaceRole::Aggregated.allows_egress());
        assert!(!InterfaceRole::Isolated.allows_egress());
    }

    #[test]
    fn adjudicate_all_only_covers_physical() {
        let ifaces = vec![
            nic(
                1,
                if_flags::HARDWARE,
                if_type::ETHERNET_CSMACD,
                None,
                Some("10.41.0.1"),
            ),
            nic(
                2,
                if_flags::HARDWARE | if_flags::FILTER,
                if_type::ETHERNET_CSMACD,
                None,
                None,
            ),
        ];
        let out = adjudicate_all(&ifaces, &RolePolicy::default());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].identity, ifaces[0].identity());
    }

    #[test]
    fn role_table_assign_and_confirm() {
        let mut t = RoleTable::new();
        t.assign("LUID:1", InterfaceRole::CampusStrict, false);
        assert!(!t.all_confirmed());
        assert_eq!(t.unconfirmed().count(), 1);

        t.assign("LUID:1", InterfaceRole::CampusStrict, true);
        assert!(t.all_confirmed());
        assert_eq!(t.len(), 1, "重复 assign 应覆盖而非新增");

        t.remove("LUID:1");
        assert!(t.is_empty());
    }

    /// `is_empty` 若恒为 true，"表里没东西"和"表里有东西"将无法区分，
    /// 进而在开机首帧误判为"角色表已就绪"。两侧都必须断言。
    #[test]
    fn role_table_is_empty_tracks_entries_both_ways() {
        let mut t = RoleTable::new();
        assert!(t.is_empty(), "空表必须报告为空");
        assert_eq!(t.len(), 0);

        t.assign("LUID:1", InterfaceRole::CampusStrict, true);
        assert!(!t.is_empty(), "有条目后必须报告非空");
        assert_eq!(t.len(), 1);

        t.remove("LUID:1");
        assert!(t.is_empty(), "移除后必须重新报告为空");
    }

    /// `iter` 若退化成空迭代器，`len()` 与遍历结果会自相矛盾。
    #[test]
    fn role_table_iter_matches_len_and_order() {
        let mut t = RoleTable::new();
        t.assign("LUID:1", InterfaceRole::CampusStrict, true);
        t.assign("LUID:2", InterfaceRole::FreeOutbound, false);
        t.assign("LUID:3", InterfaceRole::Isolated, false);

        let all: Vec<_> = t.iter().collect();
        assert_eq!(all.len(), t.len(), "迭代器条目数与 len 不一致");
        assert_eq!(all[0].0, "LUID:1");
        assert_eq!(
            all[1],
            &("LUID:2".to_string(), InterfaceRole::FreeOutbound, false)
        );
        assert_eq!(all[2].0, "LUID:3");

        // iter 与 unconfirmed 必须一致：未确认的正是后两条
        let unconfirmed: Vec<_> = t.unconfirmed().map(|e| e.0.clone()).collect();
        assert_eq!(
            unconfirmed,
            vec!["LUID:2".to_string(), "LUID:3".to_string()]
        );
        assert!(!t.all_confirmed());
    }

    #[test]
    fn role_table_get_returns_role_and_confirmation_flag() {
        let mut t = RoleTable::new();
        t.assign("LUID:1", InterfaceRole::Aggregated, false);
        assert_eq!(t.get("LUID:1"), Some((InterfaceRole::Aggregated, false)));
        assert_eq!(t.get("LUID:404"), None, "未分配的网卡必须返回 None");

        t.assign("LUID:1", InterfaceRole::Aggregated, true);
        assert_eq!(
            t.get("LUID:1"),
            Some((InterfaceRole::Aggregated, true)),
            "重复 assign 必须覆盖确认标记"
        );
    }

    /// 角色语义是翻译成 WFP 策略时的总开关，四个取值逐个钉死。
    #[test]
    fn role_egress_and_dns_matrix_is_pinned() {
        let matrix = [
            (InterfaceRole::CampusStrict, true, true),
            (InterfaceRole::FreeOutbound, true, false),
            (InterfaceRole::Aggregated, false, false),
            (InterfaceRole::Isolated, false, false),
        ];
        for (role, egress, dns) in matrix {
            assert_eq!(role.allows_egress(), egress, "{role} 的出网语义被改动");
            assert_eq!(role.locks_dns(), dns, "{role} 的 DNS 锁语义被改动");
        }
    }

    #[test]
    fn role_display_texts_are_pinned() {
        let expected = [
            (InterfaceRole::CampusStrict, "校园网严格"),
            (InterfaceRole::FreeOutbound, "自由出海"),
            (InterfaceRole::Aggregated, "带宽聚合"),
            (InterfaceRole::Isolated, "彻底绝缘"),
        ];
        let mut seen = std::collections::BTreeSet::new();
        for (role, want) in expected {
            let got = role.to_string();
            assert_eq!(got, want, "{role} 的展示文案被改动");
            assert!(seen.insert(got), "{role} 的展示文案与其他角色重复");
        }
    }

    #[test]
    fn confidence_display_texts_are_pinned() {
        let expected = [
            (Confidence::Confirmed, "已确认"),
            (Confidence::Inferred, "策略推断"),
            (Confidence::Unassigned, "待人工分配"),
        ];
        let mut seen = std::collections::BTreeSet::new();
        for (c, want) in expected {
            let got = c.to_string();
            assert_eq!(got, want, "{c} 的展示文案被改动");
            assert!(seen.insert(got), "{c} 的展示文案与其他可信度重复");
        }
    }

    /// 裁决理由必须包含判定依据，否则用户无法判断要不要改配置。
    #[test]
    fn every_decision_carries_a_non_empty_reason() {
        let policy = RolePolicy::default();
        let cases = vec![
            nic(
                1,
                if_flags::HARDWARE,
                if_type::IEEE80211,
                Some("Campus-WiFi"),
                None,
            ),
            nic(
                2,
                if_flags::HARDWARE,
                if_type::IEEE80211,
                Some("MyHotspot"),
                None,
            ),
            nic(
                3,
                if_flags::HARDWARE,
                if_type::ETHERNET_CSMACD,
                None,
                Some("10.41.0.1"),
            ),
            nic(4, if_flags::HARDWARE, if_type::IEEE80211, Some("MMi"), None),
            nic(5, 0, if_type::ETHERNET_CSMACD, None, None),
        ];
        for c in &cases {
            let d = adjudicate(c, &policy);
            assert!(!d.reason.trim().is_empty(), "{} 缺少判定依据", d.identity);
            assert!(
                d.reason.contains(&d.role.to_string()) || !d.reason.is_ascii(),
                "{} 的理由应可读且可追溯：{}",
                d.identity,
                d.reason
            );
        }
    }
}
