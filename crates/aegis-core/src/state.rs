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
    /// 上层代理不健康
    ProxyUnhealthy,
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
