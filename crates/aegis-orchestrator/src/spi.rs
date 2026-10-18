//! 适配器 SPI 本体：**所有调用都必须经过 [`invoke_checked`]**（design-spec §2A.4 ①③）。
//!
//! # 为什么不让调用方直接 `adapter.invoke(...)`
//!
//! 两件事必须由底座保证，而不能指望每个适配器自觉：
//!
//! 1. **未声明的能力调用即 `Unsupported`**。如果靠适配器自己检查，
//!    那么每写一个新适配器就多一次漏检的机会，而漏检的表现是
//!    "调用静默成功"或"抛出一个含糊的错误"——两种都危险。
//! 2. **答非所问即故障**。问 DNS 却回了个 `Healthy`，说明适配器把
//!    请求和能力对错了（常见于复制粘贴出来的适配器实现）。
//!    这种错不会表现为失败，只会表现为"结果看起来不对"。

use crate::capability::{Capability, Fallback};
use crate::error::AdapterError;
use crate::op::{Op, Outcome};

/// 一个应用层适配器的能力接口。
///
/// ⚠ **刻意只有三个方法**。方法越多，越容易退化成"这个软件的接口"，
/// 那就回到了 §2A.2 那个按软件类别切 trait 的老路。
pub trait Adapter: Send + Sync {
    /// 适配器名字（写进日志与告警）。
    fn name(&self) -> &'static str;

    /// **声明**支持哪些能力。Aegis 只使用双方都声明的能力。
    fn capabilities(&self) -> &[Capability];

    /// 真正做事。未声明的能力调用即 `Err(Unsupported)`，不是"失败"。
    ///
    /// 实现方**不需要**自己检查能力是否被声明——那是 [`invoke_checked`] 的事；
    /// 这里只管在能力确实被声明的前提下把事做对。
    fn invoke(&self, op: Op<'_>) -> Result<Outcome, AdapterError>;
}

/// 唯一的调用入口。直接调 `adapter.invoke(...)` 是错的。
pub fn invoke_checked(adapter: &dyn Adapter, op: Op<'_>) -> Result<Outcome, AdapterError> {
    let wanted = op.capability();

    if !adapter.capabilities().contains(&wanted) {
        return Err(AdapterError::Unsupported(wanted));
    }

    let outcome = adapter.invoke(op)?;

    // 答非所问：适配器把请求和能力对错了。这不是"失败"那么简单——
    // 它返回了一个看起来成功、但属于另一个能力的结果，调用方会照着用。
    if outcome.capability() != wanted {
        return Err(AdapterError::Failed {
            capability: wanted,
            reason: format!(
                "适配器答非所问：请求 {}，返回了 {} 的结果",
                wanted.tag(),
                outcome.capability().tag()
            ),
        });
    }

    Ok(outcome)
}

// ── 能力矩阵：把"声明了什么 / 缺什么 / 缺了怎么办"一次算清 ──────────────

/// 能力矩阵的一行。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MatrixRow {
    pub capability: Capability,
    pub declared: bool,
    /// 未声明时的处置（声明了也给出来：调用失败时要用同一张表）。
    pub fallback: Fallback,
}

/// 某个适配器的完整能力矩阵。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Matrix<'a> {
    pub adapter: &'a str,
    pub rows: Vec<MatrixRow>,
}

impl Matrix<'_> {
    pub fn row(&self, capability: Capability) -> Option<&MatrixRow> {
        self.rows.iter().find(|r| r.capability == capability)
    }

    /// 没声明的能力。
    pub fn missing(&self) -> Vec<Capability> {
        self.rows
            .iter()
            .filter(|r| !r.declared)
            .map(|r| r.capability)
            .collect()
    }

    /// 缺失**且**该能力是 Fail-Closed 的——这些缺口意味着出口不可用。
    pub fn fail_closed_gaps(&self) -> Vec<Capability> {
        self.rows
            .iter()
            .filter(|r| !r.declared && r.fallback.is_fail_closed())
            .map(|r| r.capability)
            .collect()
    }

    /// 这个适配器能不能撑起一个出口。
    ///
    /// 判据只有一个：有没有 Fail-Closed 缺口。降级项不影响——
    /// "少了健康检查"不等于"在漏流量"。
    pub fn usable(&self) -> bool {
        self.fail_closed_gaps().is_empty()
    }
}

/// 计算一个适配器的能力矩阵。
///
/// 声明里写了重复能力也不会出错（矩阵按 [`Capability::ALL`] 遍历，
/// 声明只用来判断 declared）——宁可容忍啰嗦的声明，也不要因为去重
/// 把"声明了两次"这种笔误变成静默忽略。
pub fn matrix(adapter: &dyn Adapter) -> Matrix<'_> {
    let declared = adapter.capabilities();
    Matrix {
        adapter: adapter.name(),
        rows: Capability::ALL
            .iter()
            .map(|c| MatrixRow {
                capability: *c,
                declared: declared.contains(c),
                fallback: c.fallback(),
            })
            .collect(),
    }
}

// ── 声明 ≠ 事实：启动后真的一次（§2A.4 ③）────────────────────────────

const NO_CANDIDATES: &[String] = &[];
/// 自检用的 profile 名：刻意带前缀，避免和真实 profile 撞上。
pub const SELFCHECK_PROFILE: &str = "__aegis_selfcheck__";

/// 这个能力能不能在**不产生副作用**的前提下自检。
///
/// `DefaultEgress` 不行：它会真的改路由表，"试一下"就等于接管一次出口。
/// 把不能自检的能力也塞进自检，结果只能是"每次启动都假装验证过"。
pub fn has_harmless_probe(capability: Capability) -> bool {
    !matches!(capability, Capability::DefaultEgress)
}

fn probe_op(capability: Capability) -> Op<'static> {
    match capability {
        Capability::TunInterfacePresent => Op::TunPresent {
            candidates: NO_CANDIDATES,
        },
        Capability::DefaultEgress => Op::DefaultEgress { interface: "" },
        Capability::ConfigFragmentGenerate => Op::Fragment {
            profile: SELFCHECK_PROFILE,
        },
        Capability::HealthProbe => Op::Health,
        Capability::Reload => Op::Reload,
        Capability::DnsOwnership => Op::Dns,
        Capability::RuleEffectiveness => Op::RulesEffective,
    }
}

/// 声明自检的结果。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeclarationCheck {
    /// 声明了，也真的做得到。
    Honest(Capability),
    /// **声明了却回 `Unsupported`** —— 适配器在撒谎，必须按 `Failed` 处置。
    Lie { capability: Capability },
    /// 声明了、也认这个能力，但这次做失败了。是故障，不是撒谎。
    Broken {
        capability: Capability,
        reason: String,
    },
    /// 这个能力没法无害自检，只能等真正调用时验证。
    Unverifiable {
        capability: Capability,
        reason: &'static str,
    },
}

impl DeclarationCheck {
    pub fn capability(&self) -> Capability {
        match self {
            Self::Honest(c) | Self::Lie { capability: c } => *c,
            Self::Broken { capability, .. } => *capability,
            Self::Unverifiable { capability, .. } => *capability,
        }
    }

    /// 声明与事实是否对得上。`Unverifiable` 算通过——
    /// 它只是没验证，不是验证出矛盾。
    pub fn is_honest(&self) -> bool {
        matches!(self, Self::Honest(_) | Self::Unverifiable { .. })
    }
}

/// 对每个**已声明**的能力真打一次。
///
/// 只查声明过的能力：没声明的能力根本不会被调用，验它没有意义。
///
/// ⚠ **自检有副作用，且这是故意的。** 声称支持 `Reload`，自检就必须真的
/// reload 一次——否则"验证"只是又问了一遍"你支持吗"。副作用是：
/// 自检之后适配器报的配置版本号会变。**因此自检必须排在契约测试之后**，
/// 反过来会让契约里"健康检查报旧版本号"这条用例假红。
/// 假红比漏测更伤，因为它会让人习惯于忽略契约结果。
pub fn audit_declaration(adapter: &dyn Adapter) -> Vec<DeclarationCheck> {
    adapter
        .capabilities()
        .iter()
        .map(|c| audit_one(adapter, *c))
        .collect()
}

fn audit_one(adapter: &dyn Adapter, capability: Capability) -> DeclarationCheck {
    if !has_harmless_probe(capability) {
        return DeclarationCheck::Unverifiable {
            capability,
            reason: "该能力无法无害自检（会真的改系统状态），只能等真正调用时验证",
        };
    }

    match invoke_checked(adapter, probe_op(capability)) {
        Ok(outcome) => verify_outcome(adapter, capability, &outcome),
        Err(AdapterError::Unsupported(_)) => DeclarationCheck::Lie { capability },
        Err(e) => DeclarationCheck::Broken {
            capability,
            reason: e.to_string(),
        },
    }
}

/// 光"调用返回 Ok"还不够：§2A.4 ③ 的原话是"做一次无害的 reload 看**配置
/// 版本号是否变化**"。只回了个 `Reloaded` 但版本纹丝不动的适配器，
/// 它的 Reload 是假的——而假 Reload 的后果是"以为配置生效了，其实没有"。
///
/// 只有同时声明了 `HealthProbe` 才验：没有探针就无从观察版本。
fn verify_outcome(
    adapter: &dyn Adapter,
    capability: Capability,
    outcome: &Outcome,
) -> DeclarationCheck {
    let Outcome::Reloaded { version } = outcome else {
        return DeclarationCheck::Honest(capability);
    };
    if !adapter.capabilities().contains(&Capability::HealthProbe) {
        return DeclarationCheck::Honest(capability);
    }

    match invoke_checked(adapter, Op::Health) {
        Ok(Outcome::Healthy { version: current }) if current != *version => {
            DeclarationCheck::Broken {
                capability,
                reason: format!(
                    "reload 报了 {version}，但健康检查仍报 {current} —— 这个 Reload 是假的"
                ),
            }
        }
        _ => DeclarationCheck::Honest(capability),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference::ReferenceAdapter;
    use crate::reference::Scenario;

    /// 只声明 `Reload`，但 `invoke` 对 Reload 也回 Unsupported —— 撒谎的适配器。
    struct Liar;

    impl Adapter for Liar {
        fn name(&self) -> &'static str {
            "liar"
        }
        fn capabilities(&self) -> &[Capability] {
            &[Capability::Reload]
        }
        fn invoke(&self, _op: Op<'_>) -> Result<Outcome, AdapterError> {
            Err(AdapterError::Unsupported(Capability::Reload))
        }
    }

    /// 声明了全部能力，但问 DNS 回 Healthy —— 答非所问。
    struct Confused;

    impl Adapter for Confused {
        fn name(&self) -> &'static str {
            "confused"
        }
        fn capabilities(&self) -> &[Capability] {
            &Capability::ALL
        }
        fn invoke(&self, op: Op<'_>) -> Result<Outcome, AdapterError> {
            match op {
                Op::Dns => Ok(Outcome::Healthy { version: "1".into() }),
                _ => Ok(Outcome::DnsNotOwned),
            }
        }
    }

    fn full() -> ReferenceAdapter {
        ReferenceAdapter::new("ref", Scenario::sample())
    }

    #[test]
    fn calling_an_undeclared_capability_is_unsupported_not_a_failure() {
        let mut a = full();
        a.declare(&[Capability::HealthProbe]);

        let e = invoke_checked(&a, Op::Reload).unwrap_err();
        assert_eq!(e, AdapterError::Unsupported(Capability::Reload));
        assert!(!e.is_fault(), "不支持不该被当成故障");
    }

    /// 这条是 `invoke_checked` 存在的理由：适配器答非所问必须变成故障，
    /// 而不是一个"看起来成功"的结果被上层照着用。
    #[test]
    fn answering_with_another_capabilitys_outcome_is_a_fault() {
        let a = Confused;
        let e = invoke_checked(&a, Op::Dns).unwrap_err();
        assert!(e.is_fault());
        assert!(matches!(
            e,
            AdapterError::Failed {
                capability: Capability::DnsOwnership,
                ..
            }
        ));
        assert!(e.to_string().contains("答非所问"), "{e}");
    }

    #[test]
    fn a_declared_capability_passes_through() {
        let mut a = full();
        a.declare(&[Capability::DnsOwnership]);
        assert_eq!(
            invoke_checked(&a, Op::Dns).unwrap(),
            Outcome::DnsOwned {
                owner: "sing-box".into()
            }
        );
    }

    #[test]
    fn the_matrix_lists_every_capability_and_flags_what_is_missing() {
        let mut a = full();
        a.declare(&[
            Capability::TunInterfacePresent,
            Capability::HealthProbe,
            Capability::Reload,
        ]);

        let m = matrix(&a);
        assert_eq!(m.rows.len(), Capability::ALL.len());
        assert_eq!(
            m.missing(),
            vec![
                Capability::DefaultEgress,
                Capability::ConfigFragmentGenerate,
                Capability::DnsOwnership,
                Capability::RuleEffectiveness,
            ]
        );
    }

    /// ⚠ 这条钉住"规则生效"缺了之后**出口仍可用**：
    /// 它只是让 Aegis 少一组断言，而 Aegis 自己的出口断言还在，
    /// 因此不能变成 Fail-Closed 缺口（那样 SPI 没实现时会永久断网）。
    #[test]
    fn missing_rule_effectiveness_does_not_make_the_egress_unusable() {
        let mut a = full();
        a.declare(&[
            Capability::TunInterfacePresent,
            Capability::DefaultEgress,
            Capability::DnsOwnership,
        ]);
        let m = matrix(&a);
        assert!(m.missing().contains(&Capability::RuleEffectiveness));
        assert!(
            m.fail_closed_gaps().is_empty(),
            "规则生效只该降级，不该成为 Fail-Closed 缺口：{:?}",
            m.fail_closed_gaps()
        );
        assert!(m.usable());
    }

    /// 缺了 Reload / ConfigFragmentGenerate 只降级，出口仍可用。
    #[test]
    fn degrading_gaps_do_not_make_the_egress_unusable() {
        let mut a = full();
        a.declare(&[
            Capability::TunInterfacePresent,
            Capability::DefaultEgress,
            Capability::DnsOwnership,
        ]);
        let m = matrix(&a);
        assert!(m.fail_closed_gaps().is_empty());
        assert!(m.usable());
    }

    /// 缺 DNS 所有权就必须判不可用 —— 这是 §2A.4 ② 表最要紧的一条。
    #[test]
    fn a_missing_fail_closed_capability_makes_the_egress_unusable() {
        let mut a = full();
        a.declare(&[Capability::TunInterfacePresent, Capability::DefaultEgress]);
        let m = matrix(&a);
        assert_eq!(m.fail_closed_gaps(), vec![Capability::DnsOwnership]);
        assert!(!m.usable());
    }

    #[test]
    fn duplicate_declarations_do_not_break_the_matrix() {
        let mut a = full();
        a.declare(&[
            Capability::HealthProbe,
            Capability::HealthProbe,
            Capability::DnsOwnership,
        ]);
        let m = matrix(&a);
        assert_eq!(m.rows.len(), Capability::ALL.len());
        assert!(m.row(Capability::HealthProbe).unwrap().declared);
    }

    /// §2A.4 ③：声明了却回 Unsupported = 撒谎，必须被抓出来。
    #[test]
    fn an_adapter_that_declares_but_returns_unsupported_is_lying() {
        let checks = audit_declaration(&Liar);
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0], DeclarationCheck::Lie {
            capability: Capability::Reload
        });
        assert!(!checks[0].is_honest());
    }

    /// 声明了 Reload 也确实回 `Reloaded`，但版本纹丝不动的适配器。
    struct FakeReload;

    impl Adapter for FakeReload {
        fn name(&self) -> &'static str {
            "fake-reload"
        }
        fn capabilities(&self) -> &[Capability] {
            &[Capability::Reload, Capability::HealthProbe]
        }
        fn invoke(&self, op: Op<'_>) -> Result<Outcome, AdapterError> {
            match op {
                Op::Reload => Ok(Outcome::Reloaded {
                    version: "2".into(),
                }),
                Op::Health => Ok(Outcome::Healthy {
                    version: "1".into(),
                }),
                _ => Err(AdapterError::Unsupported(op.capability())),
            }
        }
    }

    /// 假 Reload 比不支持更危险：不支持会让能力矩阵直接判不可用，
    /// 假 Reload 会让上层以为"配置已经生效了"。
    #[test]
    fn a_reload_that_does_not_move_the_version_is_broken() {
        let checks = audit_declaration(&FakeReload);
        let reload = checks
            .iter()
            .find(|c| c.capability() == Capability::Reload)
            .unwrap();
        assert!(matches!(reload, DeclarationCheck::Broken { .. }), "{reload:?}");
    }

    /// 把自检的副作用钉住：它会**真的** reload 一次，之后 Health 报新版本。
    /// 谁要是"优化"掉这个副作用，自检就退化成又问了一遍"你支持吗"。
    #[test]
    fn the_declaration_audit_really_reloads_and_moves_the_version() {
        let mut a = full();
        a.declare(&[Capability::HealthProbe, Capability::Reload]);

        assert_eq!(
            invoke_checked(&a, Op::Health).unwrap(),
            Outcome::Healthy {
                version: "2026.10.18-1".into()
            }
        );
        assert!(audit_declaration(&a).iter().all(DeclarationCheck::is_honest));
        assert_eq!(
            invoke_checked(&a, Op::Health).unwrap(),
            Outcome::Healthy {
                version: "2026.10.18-2".into()
            }
        );
    }

    #[test]
    fn an_honest_adapter_passes_its_own_declaration_audit() {
        let mut a = full();
        a.declare(&[
            Capability::TunInterfacePresent,
            Capability::ConfigFragmentGenerate,
            Capability::HealthProbe,
            Capability::Reload,
            Capability::DnsOwnership,
        ]);
        let checks = audit_declaration(&a);
        assert!(checks.iter().all(DeclarationCheck::is_honest), "{checks:?}");
    }

    /// 默认出口不能无害自检——"试一下"就等于真的接管一次出口。
    #[test]
    fn default_egress_has_no_harmless_probe() {
        assert!(!has_harmless_probe(Capability::DefaultEgress));
        assert!(has_harmless_probe(Capability::HealthProbe));
        assert!(has_harmless_probe(Capability::DnsOwnership));
    }

    #[test]
    fn unverifiable_is_treated_as_passing_but_is_distinguishable() {
        let mut a = full();
        a.declare(&[Capability::DefaultEgress]);
        let checks = audit_declaration(&a);
        assert_eq!(
            checks[0],
            DeclarationCheck::Unverifiable {
                capability: Capability::DefaultEgress,
                reason: "该能力无法无害自检（会真的改系统状态），只能等真正调用时验证",
            }
        );
        assert!(checks[0].is_honest());
    }
}
