//! 契约测试夹具（design-spec §2A.4 ③）。
//!
//! # "适配"必须是个可判定的命题
//!
//! 薄适配器**无法**保证适配任何软件：Clash、sing-box、网卡融合工具的内部
//! 配置格式与生命周期差异太大。追求"确保适配"只会被逼回源码内嵌。
//! 所以正确的目标不是"确保能适配"，而是把适配变成一句可判定的话：
//!
//! > **适配 = 这组 fixture 过没过。**
//!
//! [`suite`] 生成的就是这组 fixture：**同一个场景 + 同一份声明 → 同一批期望**。
//! 以后每接一个新适配器，让它跑同一组用例；过了就叫适配，没过就把差异摆出来，
//! 而不是靠"看起来能对上"来判断。

use crate::capability::Capability;
use crate::error::{invariant, AdapterError};
use crate::op::{Op, Outcome};
use crate::reference::{fragment_text, RuleState, Scenario};
use crate::spi::{invoke_checked, Adapter};

/// 用例的输入。**拥有数据**（不是借用），因为夹具要能被存下来、传出去。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Input {
    /// `candidates` = Aegis 放行列表里认可的 TUN 名。
    Tun { candidates: Vec<String> },
    Egress { interface: String },
    Fragment { profile: String },
    Health,
    Reload,
    Dns,
    /// 问适配器："你的规则现在真的生效吗？"
    RulesEffective,
}

impl Input {
    pub fn capability(&self) -> Capability {
        match self {
            Self::Tun { .. } => Capability::TunInterfacePresent,
            Self::Egress { .. } => Capability::DefaultEgress,
            Self::Fragment { .. } => Capability::ConfigFragmentGenerate,
            Self::Health => Capability::HealthProbe,
            Self::Reload => Capability::Reload,
            Self::Dns => Capability::DnsOwnership,
            Self::RulesEffective => Capability::RuleEffectiveness,
        }
    }

    pub fn op(&self) -> Op<'_> {
        match self {
            Self::Tun { candidates } => Op::TunPresent { candidates },
            Self::Egress { interface } => Op::DefaultEgress { interface },
            Self::Fragment { profile } => Op::Fragment { profile },
            Self::Health => Op::Health,
            Self::Reload => Op::Reload,
            Self::Dns => Op::Dns,
            Self::RulesEffective => Op::RulesEffective,
        }
    }
}

/// 期望的结果。
///
/// ⚠ `Unsupported` 也是一个**正当期望**。把"不支持"从"失败"里分出来，
/// 是这套契约能不能用的前提——否则一个只实现了三个能力的适配器
/// 会在另外三个能力上"契约失败"，逼得实现方去写假装支持的桩。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Expect {
    Outcome(Outcome),
    Unsupported,
    Failed,
    Invariant(&'static str),
}

/// 一条契约用例。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContractCase {
    pub name: String,
    pub input: Input,
    pub expect: Expect,
}

/// 单条用例的结果。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaseResult {
    pub name: String,
    pub pass: bool,
    pub want: String,
    pub got: String,
}

/// 一份契约测试报告。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContractReport {
    pub adapter: String,
    pub results: Vec<CaseResult>,
}

impl ContractReport {
    pub fn total(&self) -> usize {
        self.results.len()
    }

    pub fn passed_count(&self) -> usize {
        self.results.iter().filter(|r| r.pass).count()
    }

    pub fn passed(&self) -> bool {
        self.results.iter().all(|r| r.pass)
    }

    pub fn failures(&self) -> impl Iterator<Item = &CaseResult> {
        self.results.iter().filter(|r| !r.pass)
    }

    /// 给人看的摘要。失败要打印"期望什么 / 实际什么"——
    /// 只说"契约不过"等于没说。
    pub fn summary(&self) -> String {
        let mut s = format!(
            "适配器「{}」：{}/{} 通过",
            self.adapter,
            self.passed_count(),
            self.total()
        );
        for f in self.failures() {
            s.push_str(&format!("\n  ✗ {}\n      期望 {}\n      实际 {}", f.name, f.want, f.got));
        }
        s
    }
}

/// 跑一组契约用例。
pub fn run(adapter: &dyn Adapter, cases: &[ContractCase]) -> ContractReport {
    ContractReport {
        adapter: adapter.name().to_string(),
        results: cases.iter().map(|c| run_case(adapter, c)).collect(),
    }
}

fn run_case(adapter: &dyn Adapter, case: &ContractCase) -> CaseResult {
    let got = invoke_checked(adapter, case.input.op());
    CaseResult {
        name: case.name.clone(),
        pass: matches_expect(&got, &case.expect),
        want: describe_expect(&case.expect),
        got: describe_got(&got),
    }
}

fn matches_expect(got: &Result<Outcome, AdapterError>, expect: &Expect) -> bool {
    match (got, expect) {
        (Ok(outcome), Expect::Outcome(want)) => outcome == want,
        (Err(AdapterError::Unsupported(_)), Expect::Unsupported) => true,
        (Err(AdapterError::Failed { .. }), Expect::Failed) => true,
        (Err(AdapterError::InvariantViolation { invariant, .. }), Expect::Invariant(code)) => {
            invariant == code
        }
        _ => false,
    }
}

fn describe_expect(expect: &Expect) -> String {
    match expect {
        Expect::Outcome(o) => format!("Ok({o:?})"),
        Expect::Unsupported => "Err(Unsupported)".to_string(),
        Expect::Failed => "Err(Failed)".to_string(),
        Expect::Invariant(code) => format!("Err(InvariantViolation({code}))"),
    }
}

fn describe_got(got: &Result<Outcome, AdapterError>) -> String {
    match got {
        Ok(o) => format!("Ok({o:?})"),
        Err(e) => format!("Err({e})"),
    }
}

// ── 生成契约套件 ────────────────────────────────────────────────────────

/// 套件遍历能力的顺序。
///
/// ⚠ **`Reload` 必须排在 `HealthProbe` 之后**：热重载会把配置版本推到
/// `next_version`，而健康检查用例期望的是 `version`。顺序反了会让一条
/// 完全正确的实现被判失败——这种"假红"比漏测更伤，因为它会让人习惯于
/// 忽略契约结果。
pub const SUITE_ORDER: [Capability; 7] = [
    Capability::TunInterfacePresent,
    Capability::DefaultEgress,
    Capability::ConfigFragmentGenerate,
    Capability::HealthProbe,
    Capability::DnsOwnership,
    Capability::Reload,
    Capability::RuleEffectiveness,
];

/// 契约里用来表示"一张没被放行的 TUN"的哨兵名。
pub const UNPERMITTED_TUN: &str = "__aegis_unpermitted_tun__";

/// 给一个场景 + 一份能力声明，生成**完整**的契约用例。
///
/// 声明里的能力 → 期望它真的做对；没声明的能力 → 期望 `Unsupported`。
/// 这样"少实现一个能力"不会让契约红，而"声明了却做不到"一定会红。
pub fn suite(scenario: &Scenario, declared: &[Capability]) -> Vec<ContractCase> {
    let mut cases = Vec::new();

    for capability in SUITE_ORDER {
        let honest = honest_cases(scenario, capability);
        if declared.contains(&capability) {
            for (label, input, expect) in honest {
                cases.push(ContractCase {
                    name: format!("{}/{label}", capability.tag()),
                    input,
                    expect,
                });
            }
        } else {
            // 没声明：拿该能力的第一个输入，期望 Unsupported。
            let (_, input, _) = honest
                .into_iter()
                .next()
                .unwrap_or_else(|| unreachable_probe(capability));
            cases.push(ContractCase {
                name: format!("{}/undeclared_is_unsupported", capability.tag()),
                input,
                expect: Expect::Unsupported,
            });
        }
    }

    cases
}

/// 便捷入口：按适配器**自己的声明**生成并跑完契约。
pub fn check(adapter: &dyn Adapter, scenario: &Scenario) -> ContractReport {
    let declared = adapter.capabilities().to_vec();
    run(adapter, &suite(scenario, &declared))
}

type HonestCase = (&'static str, Input, Expect);

fn unreachable_probe(capability: Capability) -> HonestCase {
    // 每个能力都至少有一条 honest 用例，这里只为兜住"将来新增能力忘了补"。
    // 与其 panic，不如明确暴露成一个必然失败的用例名。
    (
        "missing_contract_case",
        Input::Health,
        Expect::Outcome(Outcome::Healthy {
            version: format!("<未为 {} 编写契约用例>", capability.tag()),
        }),
    )
}

fn honest_cases(scenario: &Scenario, capability: Capability) -> Vec<HonestCase> {
    match capability {
        Capability::TunInterfacePresent => {
            let mut cases = vec![(
                "permitted_tun_is_reported_present",
                Input::Tun {
                    candidates: scenario.tun_names.clone(),
                },
                match scenario.tun_names.first() {
                    Some(first) => Expect::Outcome(Outcome::TunPresent { name: first.clone() }),
                    None => Expect::Outcome(Outcome::TunAbsent),
                },
            )];
            if !scenario.tun_names.is_empty() {
                cases.push((
                    "tun_up_but_not_permitted_is_a_violation",
                    Input::Tun {
                        candidates: vec![UNPERMITTED_TUN.to_string()],
                    },
                    Expect::Invariant(invariant::TUN_NOT_PERMITTED),
                ));
            }
            cases
        }

        Capability::DefaultEgress => match &scenario.egress {
            Some(nic) => vec![
                (
                    "egress_lands_on_the_right_nic",
                    Input::Egress {
                        interface: nic.clone(),
                    },
                    Expect::Outcome(Outcome::EgressTaken {
                        interface: nic.clone(),
                    }),
                ),
                (
                    "egress_elsewhere_is_a_failure",
                    Input::Egress {
                        interface: "__other_nic__".to_string(),
                    },
                    Expect::Failed,
                ),
            ],
            None => vec![(
                "no_egress_owner_is_a_failure",
                Input::Egress {
                    interface: "__any_nic__".to_string(),
                },
                Expect::Failed,
            )],
        },

        Capability::ConfigFragmentGenerate => vec![(
            "fragment_is_generated_for_a_profile",
            Input::Fragment {
                profile: "campus".to_string(),
            },
            Expect::Outcome(Outcome::Fragment {
                text: fragment_text("campus"),
                notes: Vec::new(),
            }),
        )],

        Capability::HealthProbe => vec![(
            "health_reports_the_current_version",
            Input::Health,
            Expect::Outcome(Outcome::Healthy {
                version: scenario.version.clone(),
            }),
        )],

        Capability::Reload => vec![(
            "reload_reports_the_new_version",
            Input::Reload,
            Expect::Outcome(Outcome::Reloaded {
                version: scenario.next_version.clone(),
            }),
        )],

        Capability::DnsOwnership => match &scenario.dns_owner {
            Some(owner) if scenario.aegis_dns_lock => vec![(
                "both_owning_53_is_a_conflict",
                Input::Dns,
                Expect::Invariant(invariant::DNS_OWNERSHIP_CONFLICT),
            )],
            Some(owner) => vec![(
                "dns_owner_is_reported",
                Input::Dns,
                Expect::Outcome(Outcome::DnsOwned {
                    owner: owner.clone(),
                }),
            )],
            None => vec![(
                "nobody_owns_53_is_a_fact",
                Input::Dns,
                Expect::Outcome(Outcome::DnsNotOwned),
            )],
        },

        // ⚠ 三态都要有契约用例。"不知道"必须是一个**正当答案**：
        // 适配器被逼着在"生效/没生效"里二选一，就会猜一个，
        // 而守卫对两种结论的处理是相反的（保持现状 vs 收紧）——
        // 猜错方向就是误断网或漏放行。
        Capability::RuleEffectiveness => match &scenario.rules {
            RuleState::Effective => vec![(
                "rules_are_reported_effective",
                Input::RulesEffective,
                Expect::Outcome(Outcome::RulesEffective),
            )],
            RuleState::Ineffective { failed } => vec![(
                "ineffective_rules_are_reported_as_a_fact",
                Input::RulesEffective,
                Expect::Outcome(Outcome::RulesIneffective {
                    failed: failed.clone(),
                }),
            )],
            RuleState::Unknown { why } => vec![(
                "not_knowing_is_an_honest_answer",
                Input::RulesEffective,
                Expect::Outcome(Outcome::RulesUnknown { why: why.clone() }),
            )],
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference::ReferenceAdapter;

    fn honest_reference() -> ReferenceAdapter {
        ReferenceAdapter::new("ref", Scenario::sample())
    }

    #[test]
    fn suite_order_covers_every_capability_exactly_once() {
        let mut sorted = SUITE_ORDER;
        sorted.sort();
        let mut all = Capability::ALL;
        all.sort();
        assert_eq!(sorted, all);
    }

    /// 顺序敏感性的具体理由：热重载会把版本推到 next_version，
    /// 健康检查期望的是旧版本，所以 Reload 必须排在后面。
    #[test]
    fn reload_comes_after_health_probe_in_the_suite() {
        let hp = SUITE_ORDER
            .iter()
            .position(|c| *c == Capability::HealthProbe)
            .unwrap();
        let rl = SUITE_ORDER.iter().position(|c| *c == Capability::Reload).unwrap();
        assert!(hp < rl);
    }

    #[test]
    fn the_reference_adapter_passes_its_own_contract() {
        let a = honest_reference();
        let report = check(&a, &Scenario::sample());
        assert!(report.passed(), "{}", report.summary());
        assert!(report.total() >= Capability::ALL.len());
    }

    /// 只声明两个能力：其余四个必须是 `Unsupported`，契约仍然全绿。
    /// 这条保证"少实现"不会被误判成"实现错了"。
    #[test]
    fn a_partial_adapter_passes_as_long_as_it_is_honest() {
        let mut a = honest_reference();
        a.declare(&[Capability::HealthProbe, Capability::DnsOwnership]);

        let cases = suite(&Scenario::sample(), a.capabilities());
        let report = run(&a, &cases);
        assert!(report.passed(), "{}", report.summary());

        let undeclared = cases
            .iter()
            .filter(|c| c.expect == Expect::Unsupported)
            .count();
        assert_eq!(undeclared, Capability::ALL.len() - 2);
    }

    /// **这条是整个新增能力的意义所在**：进程好好活着（HealthProbe 报 Healthy），
    /// 但规则没生效。只看健康检查永远抓不到它——那类最阴的静默失效。
    #[test]
    fn a_live_adapter_with_dead_rules_is_caught_only_by_rule_effectiveness() {
        let s = Scenario::sample_with_ineffective_rules();
        let a = ReferenceAdapter::new("ref", s.clone());

        assert!(check(&a, &s).passed(), "{}", check(&a, &s).summary());

        // ⚠ 直接调用要另起一个适配器：`check` 跑的是**完整**契约套件，
        // 里面包含 Reload，跑完之后 Health 报的就是 next_version 了
        // （这正是"Reload 必须排在 Health 之后"那条顺序约束的意义）。
        let fresh = ReferenceAdapter::new("ref", s.clone());

        // 健康检查照样是"活的"
        assert_eq!(
            invoke_checked(&fresh, Op::Health).unwrap(),
            Outcome::Healthy {
                version: "2026.10.18-1".into()
            }
        );
        // 只有规则生效性说"没生效"
        match invoke_checked(&fresh, Op::RulesEffective).unwrap() {
            Outcome::RulesIneffective { failed } => assert_eq!(
                failed,
                vec!["规则集加载为空（FINAL 走直连）".to_string()]
            ),
            other => panic!("期望 RulesIneffective，得到 {other:?}"),
        }
    }

    /// "不知道"必须是**正当答案**：契约要绿，且不能被当成失败或撒谎。
    /// 适配器被逼着二选一就会猜，而守卫对两种结论的处理是相反的。
    #[test]
    fn an_adapter_may_honestly_say_it_does_not_know() {
        let s = Scenario::sample_with_unknown_rules();
        let a = ReferenceAdapter::new("ref", s.clone());

        assert!(check(&a, &s).passed(), "{}", check(&a, &s).summary());
        match invoke_checked(&a, Op::RulesEffective).unwrap() {
            Outcome::RulesUnknown { why } => {
                assert_eq!(why, "无法读取当前生效的规则集")
            },
            other => panic!("期望 RulesUnknown，得到 {other:?}"),
        }
    }

    /// 撒谎的适配器：声明了 Reload，却回 Unsupported。契约必须红。
    struct Liar;

    impl Adapter for Liar {
        fn name(&self) -> &'static str {
            "liar"
        }
        fn capabilities(&self) -> &[Capability] {
            &Capability::ALL
        }
        fn invoke(&self, op: Op<'_>) -> Result<Outcome, AdapterError> {
            if matches!(op, Op::Reload) {
                return Err(AdapterError::Unsupported(Capability::Reload));
            }
            ReferenceAdapter::new("inner", Scenario::sample()).invoke(op)
        }
    }

    #[test]
    fn declaring_reload_but_returning_unsupported_fails_the_contract() {
        let report = check(&Liar, &Scenario::sample());
        assert!(!report.passed());
        let failed: Vec<&str> = report.failures().map(|f| f.name.as_str()).collect();
        assert_eq!(failed, vec!["reload/reload_reports_the_new_version"]);
        assert!(report.summary().contains("期望"), "{}", report.summary());
    }

    /// 换了场景（Aegis 也锁 53）就该换成对应的期望——
    /// 契约不是写死的一组断言，它由场景生成。
    #[test]
    fn the_suite_follows_the_scenario() {
        let scenario = Scenario::sample_with_dns_conflict();
        let cases = suite(&scenario, &Capability::ALL);
        let dns_case = cases
            .iter()
            .find(|c| c.name.starts_with("dns_ownership/"))
            .unwrap();
        assert_eq!(
            dns_case.expect,
            Expect::Invariant(invariant::DNS_OWNERSHIP_CONFLICT)
        );

        let a = ReferenceAdapter::new("ref", scenario.clone());
        assert!(run(&a, &cases).passed());
    }

    #[test]
    fn without_a_tun_the_suite_drops_the_unpermitted_case() {
        let scenario = Scenario::sample_without_tun();
        let cases = suite(&scenario, &Capability::ALL);
        let tun_cases: Vec<&str> = cases
            .iter()
            .filter(|c| c.name.starts_with("tun_interface_present/"))
            .map(|c| c.name.as_str())
            .collect();
        assert_eq!(
            tun_cases,
            vec!["tun_interface_present/permitted_tun_is_reported_present"]
        );
    }

    #[test]
    fn input_capability_matches_the_op_it_builds() {
        let inputs = [
            Input::Tun { candidates: vec![] },
            Input::Egress { interface: "x".into() },
            Input::Fragment { profile: "p".into() },
            Input::Health,
            Input::Reload,
            Input::Dns,
        ];
        for i in &inputs {
            assert_eq!(i.capability(), i.op().capability());
        }
    }

    /// 报告必须能说清"期望什么 / 实际什么"，否则调试契约要去看源码。
    #[test]
    fn a_failure_report_names_the_expectation_and_the_reality() {
        let mut a = honest_reference();
        a.declare(&[Capability::DnsOwnership]);
        let report = run(
            &a,
            &[ContractCase {
                name: "bogus".into(),
                input: Input::Dns,
                expect: Expect::Outcome(Outcome::DnsNotOwned),
            }],
        );
        assert!(!report.passed());
        let summary = report.summary();
        assert!(summary.contains("bogus"));
        assert!(summary.contains("期望"));
        assert!(summary.contains("实际"));
    }
}
