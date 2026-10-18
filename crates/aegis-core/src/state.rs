//! 编排器状态机（对应 design-spec.md §26）。
//!
//! # 编码进去的两条铁律
//!
//! 1. **不存在"半配置放行"窗口**：从 `Boot` 起的任何瞬间，只要不在 `Controlled`，
//!    网络就必须处于绝缘状态。这条不再是注释里的口号，而是由
//!    [`insulation()`] 这个纯函数保证——任何状态都能问出"现在该不该绝缘"，
//!    且答案不可能出现"部分放行"。
//! 2. **降级不降级安全**：`Degraded` 只表示**监控面**失效（Clash/HypoMux 不可达），
//!    WFP 绝缘与角色策略仍然强制生效。因此 `Degraded` 的绝缘等级仍是 `Full`。
//!
//! 把这两条写成函数而非文档，是为了让它们可被单测覆盖——
//! 文档会被忽略，测试不会。

use std::fmt;

/// 编排器状态（§26）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum State {
    /// 服务启动首行
    Boot,
    /// 五阶段自检中
    Preflight,
    /// 指纹吻合但等待用户显式授权（本地账户零信任的核心）
    PendingApproval,
    /// 已按角色放行
    Controlled,
    /// 首次 / 拓扑漂移 / 未确认：保持绝缘，等待确认
    Locked,
    /// 网口变动触发的即时熔断
    Airgap,
    /// 监控面失效（Clash/HypoMux 不可达）
    Degraded,
    /// 校园网未认证：临时沙盒，仅放行浏览器 → 网关 80/443
    CaptivePortal,
    /// 确认倒计时归零
    TimeoutFallback,
    /// 守护进程无法启动且 Boot-Time 背板仍在 DENY（物理砖机）
    Bricked,
    /// 清背板后的裸连排查态
    Recovery,
}

/// 绝缘等级。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum Insulation {
    /// 完全绝缘：WFP 背板 DENY 全部出站
    Full,
    /// 仅放行认证沙盒：浏览器 → 网关 80/443，其余仍 DENY
    CaptiveSandbox,
    /// 按角色放行
    None,
}

impl fmt::Display for Insulation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Full => "完全绝缘",
            Self::CaptiveSandbox => "仅认证沙盒",
            Self::None => "按角色放行",
        };
        f.write_str(s)
    }
}

/// 状态迁移事件（§26 图上的各条边）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// 自检通过，指纹吻合且已授权
    PreflightPassed,
    /// 需要用户显式点击授权
    RequireManualApproval,
    /// 用户点击【确认并放行】
    ManualApprove,
    /// 用户拒绝 / 未点击
    ManualReject,
    /// 首次开机 / 拓扑漂移 / 未确认
    TopologyUntrusted,
    /// 用户确认当前拓扑
    AcknowledgeTopology,
    /// 网口变动
    TopologyChanged,
    /// 上层代理**不可达**（进程没了 / 控制端口连不上）
    ProxyUnhealthy,
    /// 上层代理**可达但它的规则没生效**（`docs/DOWNSTREAM-GUARD.md`）
    ///
    /// 与 [`Self::ProxyUnhealthy`] 的区别不是措辞：两者恢复动作不同
    /// （前者等它起来，后者通常要人去改配置），混在一个事件里
    /// GUI 就说不清"到底为什么断"。这里**落到同一个 `Degraded` 状态**——
    /// 状态不变，原因可辨。
    ProxyRulesIneffective,
    /// 代理恢复
    ProxyRecovered,
    /// 检测到校园网未认证
    CaptiveDetected,
    /// 认证成功
    CaptiveSolved,
    /// 沙盒租约超时
    CaptiveTimeout,
    /// 确认倒计时归零
    ApprovalTimeout,
    /// 进程崩溃 / 连续启动失败
    FatalFailure,
    /// 救砖完成
    Rescued,
}

/// 该状态下网络应处于的绝缘等级。
///
/// **这是 §26 两条铁律的可执行形式**：除 `Controlled` 外一律不放行；
/// `Degraded` 虽然叫"降级"，降的是监控不是防护，因此仍是 `Full`。
pub fn insulation(state: State) -> Insulation {
    match state {
        State::Controlled => Insulation::None,
        State::CaptivePortal => Insulation::CaptiveSandbox,
        // 其余全部完全绝缘：Boot / Preflight / PendingApproval / Locked /
        // Airgap / Degraded / TimeoutFallback / Bricked / Recovery
        _ => Insulation::Full,
    }
}

/// 该状态是否要求用户介入（弹窗确认）。
pub fn awaits_user(state: State) -> bool {
    matches!(
        state,
        State::PendingApproval | State::Locked | State::TimeoutFallback
    )
}

/// 状态迁移。返回新状态；事件在当前状态下不适用时返回 `None`（忽略该事件）。
pub fn next(state: State, event: Event) -> Option<State> {
    use Event as E;
    use State as S;

    let out = match (state, event) {
        (S::Boot, E::PreflightPassed) => S::Preflight,
        (S::Boot, E::FatalFailure) => S::Bricked,

        (S::Preflight, E::RequireManualApproval) => S::PendingApproval,
        (S::Preflight, E::ManualApprove) => S::Controlled,
        (S::Preflight, E::TopologyUntrusted) => S::Locked,
        (S::Preflight, E::FatalFailure) => S::Bricked,

        (S::PendingApproval, E::ManualApprove) => S::Controlled,
        (S::PendingApproval, E::ManualReject) => S::Locked,
        (S::PendingApproval, E::ApprovalTimeout) => S::TimeoutFallback,
        (S::PendingApproval, E::TopologyChanged) => S::Airgap,

        (S::Locked, E::AcknowledgeTopology) => S::Preflight,
        (S::Locked, E::ApprovalTimeout) => S::TimeoutFallback,
        (S::Locked, E::TopologyChanged) => S::Airgap,

        // 网口变动的即时熔断：先 Airgap 重拉绝缘笼，再回 Locked 等确认
        (S::Airgap, E::TopologyUntrusted) => S::Locked,
        (S::Airgap, E::AcknowledgeTopology) => S::Preflight,

        (S::Controlled, E::ProxyUnhealthy) => S::Degraded,
        // 兜底：下游软件自己漏了（规则没生效），Aegis 替它把门关上。
        // 与 ProxyUnhealthy 落到同一个状态——`insulation(Degraded) = Full`，
        // 也就是"全都拒绝"（见 `docs/DOWNSTREAM-GUARD.md` §1）。
        (S::Controlled, E::ProxyRulesIneffective) => S::Degraded,
        (S::Controlled, E::CaptiveDetected) => S::CaptivePortal,
        (S::Controlled, E::TopologyChanged) => S::Airgap,
        (S::Controlled, E::FatalFailure) => S::Bricked,

        (S::Degraded, E::ProxyRecovered) => S::Controlled,
        (S::Degraded, E::TopologyChanged) => S::Airgap,
        (S::Degraded, E::FatalFailure) => S::Bricked,

        (S::CaptivePortal, E::CaptiveSolved) => S::Controlled,
        (S::CaptivePortal, E::CaptiveTimeout) => S::Locked,
        (S::CaptivePortal, E::TopologyChanged) => S::Airgap,

        (S::TimeoutFallback, E::AcknowledgeTopology) => S::Preflight,
        (S::TimeoutFallback, E::TopologyChanged) => S::Airgap,

        (S::Bricked, E::Rescued) => S::Recovery,
        (S::Recovery, E::PreflightPassed) => S::Preflight,

        _ => return None,
    };
    Some(out)
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Boot => "启动",
            Self::Preflight => "自检",
            Self::PendingApproval => "待人工授权",
            Self::Controlled => "受控放行",
            Self::Locked => "已锁定绝缘",
            Self::Airgap => "熔断中",
            Self::Degraded => "监控降级（仍绝缘）",
            Self::CaptivePortal => "认证沙盒",
            Self::TimeoutFallback => "超时降级",
            Self::Bricked => "砖机",
            Self::Recovery => "裸连排查",
        };
        f.write_str(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_states() -> [State; 11] {
        [
            State::Boot,
            State::Preflight,
            State::PendingApproval,
            State::Controlled,
            State::Locked,
            State::Airgap,
            State::Degraded,
            State::CaptivePortal,
            State::TimeoutFallback,
            State::Bricked,
            State::Recovery,
        ]
    }

    fn all_events() -> [Event; 16] {
        [
            Event::PreflightPassed,
            Event::RequireManualApproval,
            Event::ManualApprove,
            Event::ManualReject,
            Event::TopologyUntrusted,
            Event::AcknowledgeTopology,
            Event::TopologyChanged,
            Event::ProxyUnhealthy,
            Event::ProxyRulesIneffective,
            Event::ProxyRecovered,
            Event::CaptiveDetected,
            Event::CaptiveSolved,
            Event::CaptiveTimeout,
            Event::ApprovalTimeout,
            Event::FatalFailure,
            Event::Rescued,
        ]
    }

    /// §26 状态图的**可执行副本**：全部合法迁移边。
    ///
    /// 为什么要把整张表抄进测试：只测"快乐路径"时，删掉任何一条
    /// `next()` 里的 match arm 都能让测试全绿——那意味着用户真的
    /// 遇到那条边时系统不会迁移，而测试却毫不知情。逐边穷举才能
    /// 让"少一条边"立刻变红。
    const EDGES: &[(State, Event, State)] = &[
        (State::Boot, Event::PreflightPassed, State::Preflight),
        (State::Boot, Event::FatalFailure, State::Bricked),
        (
            State::Preflight,
            Event::RequireManualApproval,
            State::PendingApproval,
        ),
        (State::Preflight, Event::ManualApprove, State::Controlled),
        (State::Preflight, Event::TopologyUntrusted, State::Locked),
        (State::Preflight, Event::FatalFailure, State::Bricked),
        (
            State::PendingApproval,
            Event::ManualApprove,
            State::Controlled,
        ),
        (State::PendingApproval, Event::ManualReject, State::Locked),
        (
            State::PendingApproval,
            Event::ApprovalTimeout,
            State::TimeoutFallback,
        ),
        (
            State::PendingApproval,
            Event::TopologyChanged,
            State::Airgap,
        ),
        (State::Locked, Event::AcknowledgeTopology, State::Preflight),
        (
            State::Locked,
            Event::ApprovalTimeout,
            State::TimeoutFallback,
        ),
        (State::Locked, Event::TopologyChanged, State::Airgap),
        (State::Airgap, Event::TopologyUntrusted, State::Locked),
        (State::Airgap, Event::AcknowledgeTopology, State::Preflight),
        (State::Controlled, Event::ProxyUnhealthy, State::Degraded),
        (
            State::Controlled,
            Event::ProxyRulesIneffective,
            State::Degraded,
        ),
        (
            State::Controlled,
            Event::CaptiveDetected,
            State::CaptivePortal,
        ),
        (State::Controlled, Event::TopologyChanged, State::Airgap),
        (State::Controlled, Event::FatalFailure, State::Bricked),
        (State::Degraded, Event::ProxyRecovered, State::Controlled),
        (State::Degraded, Event::TopologyChanged, State::Airgap),
        (State::Degraded, Event::FatalFailure, State::Bricked),
        (
            State::CaptivePortal,
            Event::CaptiveSolved,
            State::Controlled,
        ),
        (State::CaptivePortal, Event::CaptiveTimeout, State::Locked),
        (State::CaptivePortal, Event::TopologyChanged, State::Airgap),
        (
            State::TimeoutFallback,
            Event::AcknowledgeTopology,
            State::Preflight,
        ),
        (
            State::TimeoutFallback,
            Event::TopologyChanged,
            State::Airgap,
        ),
        (State::Bricked, Event::Rescued, State::Recovery),
        (State::Recovery, Event::PreflightPassed, State::Preflight),
    ];

    /// 逐边穷举：合法边必须迁移到表中目标，表外组合必须被忽略。
    #[test]
    fn transition_table_is_exhaustive_and_exact() {
        // 先自检测试表本身没有重复键，否则"表里查到"失去意义
        let mut seen: Vec<(State, Event)> = Vec::new();
        for (s, e, _) in EDGES {
            assert!(!seen.contains(&(*s, *e)), "状态图定义重复：{s} + {e:?}");
            seen.push((*s, *e));
        }

        for s in all_states() {
            for e in all_events() {
                let expected = EDGES
                    .iter()
                    .find(|(fs, fe, _)| *fs == s && *fe == e)
                    .map(|(_, _, t)| *t);
                assert_eq!(next(s, e), expected, "{s} 下收到 {e:?} 的迁移不符合状态图");
            }
        }
    }

    /// 每个状态都必须至少有一条出边——砖机也不例外，否则就是死锁。
    #[test]
    fn no_state_is_a_dead_end() {
        for s in all_states() {
            let outs = all_events()
                .iter()
                .filter(|e| next(s, **e).is_some())
                .count();
            assert!(outs > 0, "{s} 没有任何出边，会成为死锁状态");
        }
    }

    /// 从任何状态出发都必须能回到 `Controlled`（唯一放行态）。
    /// 这条保证"锁死之后无法恢复"这类事故不可能由状态图本身造成。
    #[test]
    fn every_state_can_reach_controlled() {
        for start in all_states() {
            let mut seen = vec![start];
            let mut queue = vec![start];
            let mut reached = false;
            while let Some(s) = queue.pop() {
                if s == State::Controlled {
                    reached = true;
                    break;
                }
                for e in all_events() {
                    if let Some(t) = next(s, e) {
                        if !seen.contains(&t) {
                            seen.push(t);
                            queue.push(t);
                        }
                    }
                }
            }
            assert!(reached, "{start} 无法回到受控放行态，存在不可恢复路径");
        }
    }

    /// 绝缘等级逐状态钉死，而不是只断言"不是 None"。
    #[test]
    fn insulation_is_pinned_per_state() {
        let expected = [
            (State::Boot, Insulation::Full),
            (State::Preflight, Insulation::Full),
            (State::PendingApproval, Insulation::Full),
            (State::Controlled, Insulation::None),
            (State::Locked, Insulation::Full),
            (State::Airgap, Insulation::Full),
            (State::Degraded, Insulation::Full),
            (State::CaptivePortal, Insulation::CaptiveSandbox),
            (State::TimeoutFallback, Insulation::Full),
            (State::Bricked, Insulation::Full),
            (State::Recovery, Insulation::Full),
        ];
        for (s, want) in expected {
            assert_eq!(insulation(s), want, "{s} 的绝缘等级被改动");
        }
    }

    /// `awaits_user` 若恒为 true，UI 会在 Boot/Airgap 下也弹窗，
    /// 反过来若恒为 false，用户永远等不到确认入口——两边都要钉死。
    #[test]
    fn awaits_user_only_for_the_three_interactive_states() {
        for s in all_states() {
            let want = matches!(
                s,
                State::PendingApproval | State::Locked | State::TimeoutFallback
            );
            assert_eq!(awaits_user(s), want, "{s} 是否需要用户介入被改动");
        }
    }

    /// 展示文案是给运维看的诊断信息，串了会误导排障，因此逐条钉死。
    #[test]
    fn state_display_texts_are_pinned() {
        let expected = [
            (State::Boot, "启动"),
            (State::Preflight, "自检"),
            (State::PendingApproval, "待人工授权"),
            (State::Controlled, "受控放行"),
            (State::Locked, "已锁定绝缘"),
            (State::Airgap, "熔断中"),
            (State::Degraded, "监控降级（仍绝缘）"),
            (State::CaptivePortal, "认证沙盒"),
            (State::TimeoutFallback, "超时降级"),
            (State::Bricked, "砖机"),
            (State::Recovery, "裸连排查"),
        ];
        let mut seen = std::collections::BTreeSet::new();
        for (s, want) in expected {
            let got = s.to_string();
            assert_eq!(got, want, "{s} 的展示文案被改动");
            assert!(seen.insert(got), "{s} 的展示文案与其他状态重复");
        }
    }

    #[test]
    fn insulation_display_texts_are_pinned() {
        let expected = [
            (Insulation::Full, "完全绝缘"),
            (Insulation::CaptiveSandbox, "仅认证沙盒"),
            (Insulation::None, "按角色放行"),
        ];
        let mut seen = std::collections::BTreeSet::new();
        for (i, want) in expected {
            let got = i.to_string();
            assert_eq!(got, want, "{i} 的展示文案被改动");
            assert!(seen.insert(got), "{i} 的展示文案与其他等级重复");
        }
    }

    /// 铁律一：不存在"半配置放行"窗口 —— 只有 Controlled 才不绝缘。
    #[test]
    fn only_controlled_is_not_insulated() {
        for s in all_states() {
            let insulated = insulation(s) != Insulation::None;
            assert_eq!(
                insulated,
                s != State::Controlled,
                "{s} 的绝缘等级违反铁律一"
            );
        }
    }

    /// 铁律二：降级不降级安全 —— Degraded 降的是监控，防护仍是完全绝缘。
    #[test]
    fn degraded_stays_fully_insulated() {
        assert_eq!(insulation(State::Degraded), Insulation::Full);
        assert_eq!(insulation(State::Controlled), Insulation::None);
    }

    /// **需求「下游规则未生效 → 全都拒绝」的端到端钉死**
    /// （`docs/DOWNSTREAM-GUARD.md`）。
    ///
    /// 只断言"状态是 Degraded"是不够的：真正要的是**从受控放行出发收到这个
    /// 事件之后，绝缘等级变成全部拒绝**。中间任何一环被改动，这条就红。
    #[test]
    fn ineffective_downstream_rules_end_up_fully_insulated() {
        let after = next(State::Controlled, Event::ProxyRulesIneffective)
            .expect("受控放行态下必须能响应『规则未生效』");
        assert_eq!(after, State::Degraded);
        assert_eq!(insulation(after), Insulation::Full);
    }

    /// 「不可达」与「未生效」是两个事件，但落到**同一个状态**——
    /// 区别只体现在原因上，防护强度必须一样。改成一个强一个弱是危险的。
    #[test]
    fn both_proxy_failure_events_land_on_the_same_insulation() {
        let a = next(State::Controlled, Event::ProxyUnhealthy).unwrap();
        let b = next(State::Controlled, Event::ProxyRulesIneffective).unwrap();
        assert_eq!(a, b);
        assert_eq!(insulation(a), insulation(b));
        assert_ne!(Event::ProxyUnhealthy, Event::ProxyRulesIneffective);
    }

    #[test]
    fn captive_portal_is_only_a_sandbox() {
        assert_eq!(insulation(State::CaptivePortal), Insulation::CaptiveSandbox);
    }

    /// 网口变动必须能从任何"可放行"的状态立刻熔断。
    #[test]
    fn topology_change_always_airgaps() {
        for s in [
            State::Controlled,
            State::Degraded,
            State::PendingApproval,
            State::Locked,
            State::CaptivePortal,
            State::TimeoutFallback,
        ] {
            assert_eq!(
                next(s, Event::TopologyChanged),
                Some(State::Airgap),
                "{s} 下发生网口变动必须立刻熔断"
            );
        }
    }

    #[test]
    fn boot_to_controlled_happy_path() {
        let s = next(State::Boot, Event::PreflightPassed).unwrap();
        assert_eq!(s, State::Preflight);
        let s = next(s, Event::ManualApprove).unwrap();
        assert_eq!(s, State::Controlled);
        assert_eq!(insulation(s), Insulation::None);
    }

    #[test]
    fn manual_approval_is_required_before_release() {
        let s = next(State::Preflight, Event::RequireManualApproval).unwrap();
        assert_eq!(s, State::PendingApproval);
        assert_eq!(insulation(s), Insulation::Full, "未点确认前必须绝缘");
        assert!(awaits_user(s));

        // 拒绝或超时都不会放行
        assert_eq!(next(s, Event::ManualReject), Some(State::Locked));
        assert_eq!(
            next(s, Event::ApprovalTimeout),
            Some(State::TimeoutFallback)
        );
    }

    #[test]
    fn bricked_requires_rescue_before_recovery() {
        assert_eq!(
            next(State::Controlled, Event::FatalFailure),
            Some(State::Bricked)
        );
        assert_eq!(insulation(State::Bricked), Insulation::Full);
        assert_eq!(next(State::Bricked, Event::Rescued), Some(State::Recovery));
    }

    #[test]
    fn inapplicable_events_are_ignored() {
        assert_eq!(next(State::Boot, Event::ManualApprove), None);
        assert_eq!(next(State::Controlled, Event::ManualApprove), None);
    }
}
