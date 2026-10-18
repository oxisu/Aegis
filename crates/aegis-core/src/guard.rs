//! **下游规则生效性守卫**（`docs/DOWNSTREAM-GUARD.md` 的可执行形式）。
//!
//! # 为什么要有这个模块
//!
//! 需求是"**检测到下游规则未生效 → 帮它兜底，全都拒绝**"。
//! 而"全都拒绝"那一半早就写死在 [`crate::state`] 里了：
//! `next(Controlled, ProxyUnhealthy) = Degraded`，`insulation(Degraded) = Full`，
//! 且被 `insulation_is_pinned_per_state` 逐状态钉死。
//!
//! 所以本模块**只解决剩下的那一半：怎么判"规则生效"**。
//!
//! # 难点不在兜底，在它大多是哑的
//!
//! 除"代理进程崩了"以外，其余失效形态**全部静默**：
//! TUN 网卡消失、默认路由没指向它、系统代理开关被别的软件改掉、
//! 规则集加载为空……都不报错、不崩溃、界面一切正常，只是"该走的没走"。
//! 于是"规则生效"不能是一个 `bool`，必须拆成**分别可验证的断言**。
//!
//! # ⚠ 三条容易被写反的地方（都写进了测试）
//!
//! 1. **判不了 ≠ 通过。** 证据不足（没配置 TUN LUID、读不到默认出口、
//!    系统代理模式下还没有可用断言）返回 [`GuardVerdict::Unknown`]，
//!    **不是** `Effective`。把它写成"通过"，守卫在没能力验证的时候
//!    会假装一切正常——那比没有守卫更危险。
//! 2. **单次失败不收紧。** 检测的误报代价是整机断网，所以必须连续
//!    [`GuardPolicy::failure_threshold`] 次失败才动作。
//! 3. **收紧自动、放宽过冷却。** 否则会在故障的代理上来回抽搐
//!    （断—通—断），比一直断还难受。
//!
//! 本模块**不碰 WFP、不起进程、不改路由**，纯逻辑，可在普通用户下单测。

use std::fmt;

use crate::state::Event;

/// 当前代理的工作模式。两种模式要的判据**不同**（HOURGLASS §4）。
///
/// `Deserialize` 是为了让 `aegis-config` 直接把它反序列化进配置，
/// 不另建一个必然漂移的镜像枚举（与 `role::RolePolicy` 的做法一致）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyMode {
    /// TUN 模式：应用 socket 仍连真实远端 IP，系统按路由把包送进 TUN。
    /// 判据是"默认出口是不是 TUN"。
    Tun,
    /// 系统代理（SOCKS/HTTP）模式：应用连 127.0.0.1，没有 TUN 可判。
    SystemProxy,
}

/// 一条可判断言。从弱到强：进程在 → 承载体在 → 路指向它。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Assertion {
    /// A：代理进程 / 控制端口可探测到。
    ProxyReachable,
    /// B：承载体（TUN 网卡）仍在拓扑中。
    BearerPresent,
    /// C：系统默认出口 == 承载体 LUID。
    EgressIsBearer,
}

impl fmt::Display for Assertion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::ProxyReachable => "代理可达",
            Self::BearerPresent => "承载体在",
            Self::EgressIsBearer => "默认出口指向承载体",
        };
        f.write_str(s)
    }
}

/// 守卫能拿到的**全部事实**。由感知层与适配器 SPI 填入，本模块不负责采集。
///
/// 为什么要单独一个结构体而不是散着传参：守卫的判据会随 SPI 落地而变，
/// 有了一个明确的"事实集"，新增断言时只改这里和 [`evaluate`]，
/// 调用方不会漏传。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuardFacts {
    pub mode: ProxyMode,
    /// A：代理控制端口可连吗。
    pub proxy_reachable: bool,
    /// 配置里期望的承载体 LUID（`proxy.tun_luid`）。
    pub expected_bearer_luid: Option<u64>,
    /// B：上面那个 LUID 现在还在拓扑里吗。
    pub bearer_present: bool,
    /// 系统**真正的**默认出口 LUID。
    ///
    /// ⚠ 必须是 `aegis-sense::route::default_egress()` 那种**合成度量**
    /// 的结果（接口度量 + 路由偏移），不能裸读 `MIB_IPFORWARD_ROW2.Metric`
    /// ——自动度量下它恒为 0，会把默认出口判成错的网卡。
    pub default_egress_luid: Option<u64>,
}

/// 一次评估的结论。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardVerdict {
    /// 全部可判断言都过：规则看起来生效。
    Effective,
    /// 有断言**明确失败**：规则未生效，必须兜底。
    Ineffective {
        failed: Vec<Assertion>,
        /// 给人看的原因。兜底会把整机网断掉，**必须说清为什么**。
        reason: String,
    },
    /// 证据不足，判不了。⚠ **这不是"通过"**（见模块头第 1 条）。
    Unknown { reason: String },
}

impl GuardVerdict {
    pub fn is_effective(&self) -> bool {
        matches!(self, Self::Effective)
    }

    /// 统一的展示文案，供 GUI 与审计使用。
    pub fn reason(&self) -> String {
        match self {
            Self::Effective => "下游规则生效".to_string(),
            Self::Ineffective { reason, .. } => reason.clone(),
            Self::Unknown { reason } => reason.clone(),
        }
    }
}

/// 从拓扑快照里取出守卫需要的两项原始事实：
/// `(当前存在的网卡 LUID 列表, 系统默认出口 LUID)`。
///
/// ⚠ **`default_egress_luid` 用 `0` 表示"没有默认路由"**，它**不是**一张
/// 合法网卡的 LUID。直接把 0 当 LUID 传下去，"整机离线"会被误判成
/// "默认出口是 LUID 0"，进而得出一个看起来正常的结论——而实际是
/// 根本没有出口。这里显式把 0 翻成 `None`。
pub fn topology_inputs(snap: &crate::model::TopologySnapshot) -> (Vec<u64>, Option<u64>) {
    let present = snap.interfaces.iter().map(|i| i.luid).collect();
    let egress = if snap.default_egress_luid == 0 {
        None
    } else {
        Some(snap.default_egress_luid)
    };
    (present, egress)
}

/// 从采集到的原始值组装事实集。
///
/// 单独提供一个构造函数、而不是让调用方直接填 [`GuardFacts`]，是为了把
/// `bearer_present` 这个**派生量**收在一处：它的含义是"期望的 LUID 在不在
/// 当前拓扑里"，让每个调用方各算一遍，必然有人算错（典型错误是在
/// `expected` 为 `None` 时照样拿一个默认值去比对，凭空造出"承载体在"）。
pub fn collect(
    mode: ProxyMode,
    proxy_reachable: bool,
    expected_bearer_luid: Option<u64>,
    present_luids: &[u64],
    default_egress_luid: Option<u64>,
) -> GuardFacts {
    GuardFacts {
        mode,
        proxy_reachable,
        expected_bearer_luid,
        bearer_present: expected_bearer_luid
            .map(|want| present_luids.contains(&want))
            .unwrap_or(false),
        default_egress_luid,
    }
}

/// 把事实翻译成结论。**纯函数，不碰系统。**
pub fn evaluate(facts: GuardFacts) -> GuardVerdict {
    let mut failed: Vec<Assertion> = Vec::new();
    let mut unknown: Vec<String> = Vec::new();

    if !facts.proxy_reachable {
        failed.push(Assertion::ProxyReachable);
    }

    match facts.mode {
        ProxyMode::Tun => match facts.expected_bearer_luid {
            None => unknown.push("未配置 TUN 网卡 LUID（proxy.tun_luid）".to_string()),
            Some(want) => {
                if !facts.bearer_present {
                    failed.push(Assertion::BearerPresent);
                }
                match facts.default_egress_luid {
                    None => unknown.push("读不到系统默认出口".to_string()),
                    Some(got) => {
                        if got != want {
                            failed.push(Assertion::EgressIsBearer);
                        }
                    },
                }
            },
        },
        // 系统代理模式下"该走代理"这件事写在系统代理开关里，
        // 而读它属于适配器 SPI —— 还没实现，所以**明确判不了**，
        // 不能顺手当成"生效"。
        ProxyMode::SystemProxy => unknown
            .push("系统代理模式下暂无可用断言（需要适配器 SPI 读代理开关）".to_string()),
    }

    if !failed.is_empty() {
        return GuardVerdict::Ineffective {
            reason: describe(&failed),
            failed,
        };
    }
    if !unknown.is_empty() {
        return GuardVerdict::Unknown {
            reason: unknown.join("；"),
        };
    }
    GuardVerdict::Effective
}

fn describe(failed: &[Assertion]) -> String {
    let names: Vec<String> = failed.iter().map(|a| a.to_string()).collect();
    format!("下游规则未生效：{} 断言失败", names.join("、"))
}

// ── 防抖 / 冷却 / 反复故障 ────────────────────────────────────────────

/// 连续失败多少次才收紧。单次失败就断网，代价太高（误报 = 整机断网）。
pub const DEFAULT_FAILURE_THRESHOLD: u32 = 3;
/// 放宽前必须等待的冷却期，避免在故障的代理上来回抽搐。
pub const DEFAULT_COOLDOWN_MS: u64 = 30_000;
/// 一个窗口内允许自动收紧的上限，超了就转人工。
pub const DEFAULT_FLAP_LIMIT_PER_HOUR: u32 = 3;
/// "反复故障"的统计窗口。
pub const FLAP_WINDOW_MS: u64 = 3_600_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuardPolicy {
    pub failure_threshold: u32,
    pub cooldown_ms: u64,
    pub flap_limit_per_hour: u32,
}

impl Default for GuardPolicy {
    fn default() -> Self {
        Self {
            failure_threshold: DEFAULT_FAILURE_THRESHOLD,
            cooldown_ms: DEFAULT_COOLDOWN_MS,
            flap_limit_per_hour: DEFAULT_FLAP_LIMIT_PER_HOUR,
        }
    }
}

/// 守卫要采取的动作。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardAction {
    /// 什么都不做（保持现状）。
    Nothing,
    /// 收紧：撤掉放行，回到"全部拒绝"。
    Tighten(Event),
    /// 放宽：恢复按角色放行。
    Relax(Event),
    /// 反复故障，停在收紧态**等人工**——不再自动开关。
    NeedsHuman { reason: String },
}

/// 带时间记忆的守卫状态。纯数据 + `now_ms`，可完整单测。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GuardTracker {
    /// 当前是否处于"已收紧"。
    tightened: bool,
    consecutive_failures: u32,
    /// 上一次状态翻转的时刻，冷却期从它起算。
    last_change_ms: Option<u64>,
    /// 最近几次收紧的时刻，用来判"反复故障"。
    recent_tightens: Vec<u64>,
}

impl GuardTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_tightened(&self) -> bool {
        self.tightened
    }

    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }

    /// 喂一次评估结论，返回该做什么。
    ///
    /// ⚠ `Unknown` **永远不改变状态**：判不了的时候收紧，会变成
    /// "只要 SPI 还没实现就永久断网"——那不是 fail-closed，是自锁死。
    /// （`Unknown` 要当成已知的能力缺口去补，见 `docs/DOWNSTREAM-GUARD.md`。）
    pub fn observe(
        &mut self,
        verdict: &GuardVerdict,
        now_ms: u64,
        policy: GuardPolicy,
    ) -> GuardAction {
        match verdict {
            GuardVerdict::Unknown { .. } => GuardAction::Nothing,

            GuardVerdict::Effective => {
                self.consecutive_failures = 0;
                if !self.tightened {
                    return GuardAction::Nothing;
                }
                let changed_at = self.last_change_ms.unwrap_or(0);
                if now_ms < changed_at.saturating_add(policy.cooldown_ms) {
                    return GuardAction::Nothing;
                }
                self.tightened = false;
                self.last_change_ms = Some(now_ms);
                GuardAction::Relax(Event::ProxyRecovered)
            },

            GuardVerdict::Ineffective { failed, .. } => {
                self.consecutive_failures = self.consecutive_failures.saturating_add(1);
                // 已经收紧了就不再发第二次：重复"撤放行"没有意义，
                // 而 id 复用下重复删除可能误伤别人的规则。
                if self.tightened {
                    return GuardAction::Nothing;
                }
                if self.consecutive_failures < policy.failure_threshold {
                    return GuardAction::Nothing;
                }
                self.recent_tightens
                    .retain(|t| now_ms.saturating_sub(*t) < FLAP_WINDOW_MS);
                if self.recent_tightens.len() as u32 >= policy.flap_limit_per_hour {
                    return GuardAction::NeedsHuman {
                        reason: format!(
                            "一小时内已自动收紧 {} 次（{}），停止自动恢复，等待人工处理",
                            self.recent_tightens.len(),
                            failed
                                .iter()
                                .map(|a| a.to_string())
                                .collect::<Vec<_>>()
                                .join("、")
                        ),
                    };
                }
                self.tightened = true;
                self.last_change_ms = Some(now_ms);
                self.recent_tightens.push(now_ms);
                GuardAction::Tighten(Event::ProxyRulesIneffective)
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 一个"一切都对"的事实集，各条测试在此基础上改一项。
    fn ok() -> GuardFacts {
        GuardFacts {
            mode: ProxyMode::Tun,
            proxy_reachable: true,
            expected_bearer_luid: Some(0x600_8008_0000_0000),
            bearer_present: true,
            default_egress_luid: Some(0x600_8008_0000_0000),
        }
    }

    fn failed_of(v: &GuardVerdict) -> Vec<Assertion> {
        match v {
            GuardVerdict::Ineffective { failed, .. } => failed.clone(),
            _ => panic!("期望 Ineffective，得到 {v:?}"),
        }
    }

    // ── topology_inputs：0 不是一张网卡 ───────────────────────────────

    fn snap(egress: u64, luids: &[u64]) -> crate::model::TopologySnapshot {
        use crate::model::{if_flags, if_type, FingerprintScope, InterfaceInfo, OperStatus};
        crate::model::TopologySnapshot {
            interfaces: luids
                .iter()
                .map(|l| InterfaceInfo {
                    luid: *l,
                    index: 0,
                    alias: String::new(),
                    description: String::new(),
                    mac: None,
                    if_type: if_type::ETHERNET_CSMACD,
                    flags: if_flags::HARDWARE,
                    access_type: 2,
                    tunnel_type: 0,
                    oper_status: OperStatus::Up,
                    ipv4: Vec::new(),
                    gateway: Vec::new(),
                    dhcp_server: None,
                    ssid: None,
                })
                .collect(),
            default_egress_luid: egress,
            fingerprint: String::new(),
            fingerprint_scope: FingerprintScope::Physical,
            fingerprint_participants: 0,
        }
    }

    /// ⚠ 这条是 `topology_inputs` 存在的全部理由：0 表示"无默认路由"，
    /// 必须翻成 `None`；传成 `Some(0)` 会让"离线"被当成"出口是 LUID 0"。
    #[test]
    fn a_zero_default_egress_means_none_not_a_nic_called_zero() {
        let (_, egress) = topology_inputs(&snap(0, &[1, 7]));
        assert_eq!(egress, None);
    }

    #[test]
    fn topology_inputs_report_present_luids_and_the_real_egress() {
        let (present, egress) = topology_inputs(&snap(7, &[1, 7, 9]));
        assert_eq!(present, vec![1, 7, 9]);
        assert_eq!(egress, Some(7));
    }

    /// 端到端：拓扑 → 事实 → 判决。整机离线（没有默认路由）时
    /// 不该给出"生效"的结论。
    #[test]
    fn an_offline_machine_is_not_reported_as_effective() {
        let (present, egress) = topology_inputs(&snap(0, &[1, 7]));
        let f = collect(ProxyMode::Tun, true, Some(7), &present, egress);
        assert!(!evaluate(f).is_effective());
    }

    // ── collect：派生量只算一次 ───────────────────────────────────────

    #[test]
    fn collect_marks_the_bearer_present_only_when_the_luid_is_in_the_topology() {
        let f = collect(
            ProxyMode::Tun,
            true,
            Some(7),
            &[1, 7, 9],
            Some(7),
        );
        assert!(f.bearer_present);
        assert_eq!(evaluate(f), GuardVerdict::Effective);
    }

    /// TUN 没了之后"默认出口 == TUN"也必然不成立，所以**两条都会失败**。
    /// 只报第一条会让运维以为只是网卡掉了、而路由没改——信息量就丢了。
    #[test]
    fn collect_marks_the_bearer_absent_when_its_luid_vanished() {
        let f = collect(ProxyMode::Tun, true, Some(7), &[1, 9], Some(1));
        assert!(!f.bearer_present);
        assert_eq!(
            failed_of(&evaluate(f)),
            vec![Assertion::BearerPresent, Assertion::EgressIsBearer]
        );
    }

    /// 没有期望的 LUID 时**不能**凭空声称"承载体在"——那会让守卫在
    /// 完全没配好的情况下少报一条失败。
    #[test]
    fn collect_without_an_expected_luid_cannot_claim_presence() {
        let f = collect(ProxyMode::Tun, true, None, &[1, 7], Some(1));
        assert!(!f.bearer_present);
        assert!(!evaluate(f).is_effective(), "没配置就该是 Unknown");
    }

    // ── 评估：明确失败 ────────────────────────────────────────────────

    #[test]
    fn everything_checked_out_is_effective() {
        assert_eq!(evaluate(ok()), GuardVerdict::Effective);
        assert!(evaluate(ok()).is_effective());
    }

    #[test]
    fn an_unreachable_proxy_is_ineffective() {
        let f = GuardFacts {
            proxy_reachable: false,
            ..ok()
        };
        let v = evaluate(f);
        assert_eq!(failed_of(&v), vec![Assertion::ProxyReachable]);
        assert!(v.reason().contains("代理可达"));
    }

    /// TUN 网卡没了：这是**静默失效**，界面上什么都看不出来。
    #[test]
    fn a_vanished_tun_is_ineffective() {
        let f = GuardFacts {
            bearer_present: false,
            ..ok()
        };
        assert_eq!(failed_of(&evaluate(f)), vec![Assertion::BearerPresent]);
    }

    /// 最值钱的一条：TUN 在，但默认路由没指向它。
    #[test]
    fn a_default_egress_that_is_not_the_tun_is_ineffective() {
        let f = GuardFacts {
            default_egress_luid: Some(0x111_2222_3333_4444),
            ..ok()
        };
        assert_eq!(failed_of(&evaluate(f)), vec![Assertion::EgressIsBearer]);
    }

    /// 多条断言同时失败要**都报出来**，GUI 才知道修哪个。
    #[test]
    fn every_failed_assertion_is_reported_not_just_the_first() {
        let f = GuardFacts {
            proxy_reachable: false,
            bearer_present: false,
            default_egress_luid: Some(1),
            ..ok()
        };
        assert_eq!(
            failed_of(&evaluate(f)),
            vec![
                Assertion::ProxyReachable,
                Assertion::BearerPresent,
                Assertion::EgressIsBearer
            ]
        );
    }

    // ── 评估：判不了 ≠ 通过（模块头第 1 条）────────────────────────────

    /// ⚠ 这条是守卫的命门：没配置 TUN LUID 时若返回 `Effective`，
    /// 守卫就会在**完全没有验证能力**的情况下宣称一切正常。
    #[test]
    fn a_missing_tun_config_is_unknown_not_effective() {
        let f = GuardFacts {
            expected_bearer_luid: None,
            ..ok()
        };
        let v = evaluate(f);
        assert!(!v.is_effective(), "判不了绝不能当成通过");
        match v {
            GuardVerdict::Unknown { reason } => assert!(reason.contains("未配置 TUN 网卡 LUID")),
            other => panic!("期望 Unknown，得到 {other:?}"),
        }
    }

    #[test]
    fn an_unreadable_default_egress_is_unknown_not_effective() {
        let f = GuardFacts {
            default_egress_luid: None,
            ..ok()
        };
        assert!(!evaluate(f).is_effective());
    }

    /// 系统代理模式下还没有可用断言 → 明确 Unknown，不能顺手当生效。
    #[test]
    fn system_proxy_mode_is_unknown_until_the_spi_exists() {
        let f = GuardFacts {
            mode: ProxyMode::SystemProxy,
            ..ok()
        };
        match evaluate(f) {
            GuardVerdict::Unknown { reason } => assert!(reason.contains("适配器 SPI")),
            other => panic!("期望 Unknown，得到 {other:?}"),
        }
    }

    /// 明确的失败优先于"判不了"：代理都不可达了，没配 LUID 也得收紧。
    #[test]
    fn a_definite_failure_outranks_an_unknown() {
        let f = GuardFacts {
            proxy_reachable: false,
            expected_bearer_luid: None,
            ..ok()
        };
        assert_eq!(failed_of(&evaluate(f)), vec![Assertion::ProxyReachable]);
    }

    #[test]
    fn each_assertion_has_a_human_readable_name() {
        assert_eq!(Assertion::ProxyReachable.to_string(), "代理可达");
        assert_eq!(Assertion::BearerPresent.to_string(), "承载体在");
        assert_eq!(
            Assertion::EgressIsBearer.to_string(),
            "默认出口指向承载体"
        );
    }

    // ── 防抖：单次失败不收紧（模块头第 2 条）──────────────────────────

    fn bad() -> GuardVerdict {
        evaluate(GuardFacts {
            bearer_present: false,
            ..ok()
        })
    }

    #[test]
    fn a_single_failure_does_not_tighten() {
        let mut t = GuardTracker::new();
        let p = GuardPolicy::default();
        assert_eq!(t.observe(&bad(), 1_000, p), GuardAction::Nothing);
        assert!(!t.is_tightened());
        assert_eq!(t.consecutive_failures(), 1);
    }

    #[test]
    fn the_threshold_consecutive_failures_tighten() {
        let mut t = GuardTracker::new();
        let p = GuardPolicy::default();
        assert_eq!(t.observe(&bad(), 1_000, p), GuardAction::Nothing);
        assert_eq!(t.observe(&bad(), 2_000, p), GuardAction::Nothing);
        assert_eq!(
            t.observe(&bad(), 3_000, p),
            GuardAction::Tighten(Event::ProxyRulesIneffective)
        );
        assert!(t.is_tightened());
    }

    /// 中途成功一次必须清零——否则三次偶然抖动也会断网。
    #[test]
    fn one_success_resets_the_streak() {
        let mut t = GuardTracker::new();
        let p = GuardPolicy::default();
        t.observe(&bad(), 1_000, p);
        t.observe(&bad(), 2_000, p);
        t.observe(&GuardVerdict::Effective, 3_000, p);
        assert_eq!(t.consecutive_failures(), 0);
        assert_eq!(t.observe(&bad(), 4_000, p), GuardAction::Nothing);
        assert_eq!(t.observe(&bad(), 5_000, p), GuardAction::Nothing);
        assert!(!t.is_tightened());
    }

    #[test]
    fn repeated_failures_while_tightened_do_not_emit_again() {
        let mut t = GuardTracker::new();
        let p = GuardPolicy::default();
        for i in 0..3 {
            t.observe(&bad(), 1_000 + i, p);
        }
        assert_eq!(t.observe(&bad(), 9_000, p), GuardAction::Nothing,
                   "已收紧后再失败不该重复发收紧动作");
    }

    // ── 冷却：收紧自动，放宽要等（模块头第 3 条）──────────────────────

    fn tightened(p: GuardPolicy) -> GuardTracker {
        let mut t = GuardTracker::new();
        for i in 0..p.failure_threshold as u64 {
            t.observe(&bad(), 1_000 + i, p);
        }
        assert!(t.is_tightened());
        t
    }

    #[test]
    fn relaxing_waits_for_the_cooldown() {
        let p = GuardPolicy::default();
        let mut t = tightened(p);
        // 最后一次收紧发生在 1000+2 = 1002，冷却 30s → 31002 之前不放宽
        assert_eq!(t.observe(&GuardVerdict::Effective, 3_000, p), GuardAction::Nothing);
        assert!(t.is_tightened(), "冷却期内不能放宽");
    }

    #[test]
    fn relaxing_happens_once_the_cooldown_has_passed() {
        let p = GuardPolicy::default();
        let mut t = tightened(p);
        assert_eq!(
            t.observe(&GuardVerdict::Effective, 3_002 + p.cooldown_ms, p),
            GuardAction::Relax(Event::ProxyRecovered)
        );
        assert!(!t.is_tightened());
    }

    /// 冷却期的边界：正好到点是"已过"，早一毫秒是"未过"。
    /// 这种边界最容易被写反（`<` 写成 `<=`），而写反的后果是抽搐。
    #[test]
    fn the_cooldown_boundary_is_inclusive_of_the_deadline() {
        let p = GuardPolicy {
            cooldown_ms: 100,
            ..GuardPolicy::default()
        };
        let mut t = GuardTracker::new();
        for i in 0..p.failure_threshold as u64 {
            t.observe(&bad(), 1_000 + i, p);
        }
        let changed = 1_000 + p.failure_threshold as u64 - 1;
        assert_eq!(
            t.observe(&GuardVerdict::Effective, changed + 99, p),
            GuardAction::Nothing
        );
        assert_eq!(
            t.observe(&GuardVerdict::Effective, changed + 100, p),
            GuardAction::Relax(Event::ProxyRecovered)
        );
    }

    // ── 反复故障：转人工 ──────────────────────────────────────────────

    /// 一小时内反复收紧说明代理在反复故障，再自动开关只会让用户体验更差，
    /// 应该停在收紧态等人。
    #[test]
    fn flapping_beyond_the_limit_stops_and_asks_for_a_human() {
        let p = GuardPolicy::default();
        let mut t = GuardTracker::new();
        let mut now = 1_000u64;
        let mut tightens = 0;
        let mut human_calls = 0;
        for _ in 0..12 {
            // 先攒够 threshold 次失败
            for _ in 0..p.failure_threshold {
                now += 1;
                match t.observe(&bad(), now, p) {
                    GuardAction::Tighten(Event::ProxyRulesIneffective) => tightens += 1,
                    GuardAction::NeedsHuman { .. } => human_calls += 1,
                    _ => {},
                }
            }
            // 收紧了的话，过冷却期后放宽，才会进入下一轮
            if t.is_tightened() {
                now += p.cooldown_ms + 1;
                assert_eq!(
                    t.observe(&GuardVerdict::Effective, now, p),
                    GuardAction::Relax(Event::ProxyRecovered)
                );
                now += 1;
            }
        }
        assert_eq!(tightens, p.flap_limit_per_hour, "超过上限后不再自动收紧");
        assert!(human_calls > 0, "超限后应当停在原地转人工，而不是继续自动开关");
    }

    #[test]
    fn the_flap_window_expires() {
        let p = GuardPolicy::default();
        let mut t = GuardTracker::new();
        for i in 0..p.failure_threshold as u64 {
            t.observe(&bad(), 1_000 + i, p);
        }
        // 窗口外（超过 1 小时）的旧记录要被丢掉
        t.observe(&GuardVerdict::Effective, 1_002 + p.cooldown_ms, p);
        let start = 1_002 + p.cooldown_ms + FLAP_WINDOW_MS + 10;
        let mut tightens = 0;
        for later in start..start + p.failure_threshold as u64 {
            if t.observe(&bad(), later, p) == GuardAction::Tighten(Event::ProxyRulesIneffective) {
                tightens += 1;
            }
        }
        assert_eq!(tightens, 1, "窗口过了就该重新计次");
    }

    // ── Unknown 永不动状态 ────────────────────────────────────────────

    /// ⚠ `Unknown` 若触发收紧，等于"SPI 没实现期间永久断网"。
    #[test]
    fn an_unknown_verdict_never_moves_the_tracker() {
        let p = GuardPolicy::default();
        let mut t = GuardTracker::new();
        let u = GuardVerdict::Unknown {
            reason: "x".to_string(),
        };
        for i in 0..10 {
            assert_eq!(t.observe(&u, 1_000 + i, p), GuardAction::Nothing);
        }
        assert!(!t.is_tightened());
        assert_eq!(t.consecutive_failures(), 0);
    }

    #[test]
    fn the_default_policy_is_the_documented_one() {
        let p = GuardPolicy::default();
        assert_eq!(p.failure_threshold, 3);
        assert_eq!(p.cooldown_ms, 30_000);
        assert_eq!(p.flap_limit_per_hour, 3);
    }
}
