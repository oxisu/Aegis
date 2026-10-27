//! 拓扑震荡熔断 → WFP 绝缘笼 的**决策层**（B7 · §20.3 / §27.1）。
//!
//! # 为什么这层要纯逻辑、不碰 WFP
//!
//! [`aegis_fuse::ShockDebouncer`] 只做"先断后分析"的状态机（纯逻辑），
//! 真正"落笼"（调 [`aegis_wfp::apply`] 注入动态会话绝缘笼）由守护进程的
//! 监控线程去做——因为那一步要提权、要碰内核。把这层决策单独抽出来，
//! 就能**不依赖 WFP 引擎**完整单测"什么时候该落笼、什么时候该复位"。
//!
//! # 关键不变式
//!
//! - **熔断是 fail-closed**：第一个网口变动**立刻**要求落笼，不等去抖。
//! - **落笼后不自动放行**：B7 不做指纹重算（那是后续阶段），所以熔断落笼
//!   后保持断网，直到**人**用 `rollback` 一键复原——绝不能自己 silently
//!   把网放开（那是零信任失效）。
//! - 因此本层只有两个出口：[`FuseDecision::Arm`]（要求落笼）与
//!   [`FuseDecision::Idle`]（维持现状）。复位由 [`FuseGuard::reset`] 在
//!   "笼被人工回滚"后由监控线程调用。

use aegis_fuse::{Reaction, ShockDebouncer};

/// 一次轮询后，熔断决策层要求守护进程做什么。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuseDecision {
    /// **立即落绝缘笼**（拓扑震荡，先断后分析）。
    Arm,
    /// 维持现状：要么没变动，要么已经熔断且在等人处理。
    Idle,
}

/// 熔断决策器：把 [`ShockDebouncer`] 的"是否绝缘"翻译成"是否要落 WFP 笼"。
pub struct FuseGuard {
    debouncer: ShockDebouncer,
}

impl FuseGuard {
    pub fn new() -> Self {
        Self {
            debouncer: ShockDebouncer::with_default_window(),
        }
    }

    /// 喂入这一轮采集到的网口变动次数，给出决策。
    ///
    /// `n_changes == 0` 表示本轮没动静；`> 0` 表示有变动（计数只影响"是否
    /// 触发第一次熔断"，后续震荡已被去抖合并，无需逐条喂）。
    ///
    /// # 不变式
    /// - 第一个变动 → [`FuseDecision::Arm`](立刻落笼，不等去抖)。
    /// - 已熔断状态 → [`FuseDecision::Idle`]：B7 不自动放行，保持断网等人。
    pub fn poll(&mut self, now_ms: u64, n_changes: u64) -> FuseDecision {
        if n_changes > 0 {
            // 只喂一次：去抖器保证第一个事件必 Trip，其余被合并。
            if self.debouncer.on_change(now_ms) == Reaction::Trip {
                return FuseDecision::Arm;
            }
        }
        // 已处于熔断态：不自动放行（等人工 rollback）。
        if self.debouncer.is_insulated() {
            return FuseDecision::Idle;
        }
        FuseDecision::Idle
    }

    /// 复位：在"熔断笼被人工回滚"后调用，使下一次拓扑震荡能重新落笼。
    pub fn reset(&mut self) {
        // `ShockDebouncer` 没有公开 reset，重建状态机最干净。
        self.debouncer = ShockDebouncer::with_default_window();
    }

    /// 当前是否已处于熔断态（已要求落笼）。
    pub fn is_insulated(&self) -> bool {
        self.debouncer.is_insulated()
    }
}

impl Default for FuseGuard {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_change_arms_immediately() {
        let mut g = FuseGuard::new();
        assert_eq!(g.poll(1000, 1), FuseDecision::Arm, "第一个变动必须立刻落笼");
        assert!(g.is_insulated());
    }

    #[test]
    fn no_change_stays_idle() {
        let mut g = FuseGuard::new();
        assert_eq!(g.poll(1000, 0), FuseDecision::Idle);
        assert!(!g.is_insulated());
    }

    #[test]
    fn already_insulated_does_not_rearm() {
        let mut g = FuseGuard::new();
        assert_eq!(g.poll(1000, 3), FuseDecision::Arm);
        // 后续震荡：合并掉，不再发 Arm（否则每次震荡都重落笼，等于没去抖）。
        assert_eq!(g.poll(1010, 10), FuseDecision::Idle);
        assert!(g.is_insulated());
    }

    #[test]
    fn reset_clears_insulation() {
        let mut g = FuseGuard::new();
        assert_eq!(g.poll(1000, 1), FuseDecision::Arm);
        g.reset();
        assert!(!g.is_insulated(), "复位后不再是熔断态");
        // 复位后下一次变动重新落笼。
        assert_eq!(g.poll(2000, 1), FuseDecision::Arm);
    }

    #[test]
    fn many_changes_in_one_poll_still_arms_once() {
        let mut g = FuseGuard::new();
        // 一次轮询里累积了 30 次变动：仍只落一次笼。
        assert_eq!(g.poll(1000, 30), FuseDecision::Arm);
        assert_eq!(g.poll(1001, 0), FuseDecision::Idle);
    }
}
