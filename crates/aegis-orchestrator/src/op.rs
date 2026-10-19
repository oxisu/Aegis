//! 能力调用的请求与结果（design-spec §2A.4 ①）。
//!
//! 每个 [`Op`] 恰好对应一个 [`Capability`]，每个 [`Outcome`] 也恰好对应一个。
//! 这个"一一对应"不是文档约定，是 [`Op::capability`] / [`Outcome::capability`]
//! 两个函数强制的——底座靠它就能发现"适配器答非所问"。

use crate::capability::Capability;

/// 一次能力调用。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op<'a> {
    /// TUN 是否起来了。
    ///
    /// ⚠ `candidates` 是 **Aegis 放行列表里认可的 TUN 名**（来自配置），
    /// 不是"适配器自己报上来的网卡"。适配器说"我有 TUN"没有意义，
    /// 有意义的是"Aegis 认可的那张 TUN 起来了"。
    TunPresent { candidates: &'a [String] },

    /// 让默认出口落到这张网卡上。
    DefaultEgress { interface: &'a str },

    /// 产出**配置片段**（不是全量配置）。
    Fragment { profile: &'a str },

    /// 健康检查。
    Health,

    /// 热重载。
    Reload,

    /// 谁在管 53。
    Dns,

    /// 你自己的规则**当前是否真的生效**（`docs/DOWNSTREAM-GUARD.md`）。
    ///
    /// ⚠ 与 `Health` 的区别：`Health` 只回答"进程活着吗"，而
    /// "活着但规则没生效"正是那类最阴的静默失效。这里要的是
    /// "你的规则此刻有没有真的在拦该拦的东西"。
    RulesEffective,
}

impl Op<'_> {
    /// 这次调用需要哪个能力。
    pub fn capability(&self) -> Capability {
        match self {
            Self::TunPresent { .. } => Capability::TunInterfacePresent,
            Self::DefaultEgress { .. } => Capability::DefaultEgress,
            Self::Fragment { .. } => Capability::ConfigFragmentGenerate,
            Self::Health => Capability::HealthProbe,
            Self::Reload => Capability::Reload,
            Self::Dns => Capability::DnsOwnership,
            Self::RulesEffective => Capability::RuleEffectiveness,
        }
    }
}

/// 能力调用的结果。
///
/// ⚠ `TunAbsent` / `DnsNotOwned` 是**事实**，不是错误。
/// 适配器声明了 `TunInterfacePresent`、然后如实回答"TUN 没起来"，
/// 是正常且必须被允许的表达——否则适配器只能靠"失败"来传达"没有"，
/// 调用方就分不清"没起来"和"适配器坏了"。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// 放行列表里有一张 TUN 起来了。
    TunPresent {
        name: String,
    },
    /// 放行列表里的 TUN 一张都没起来。
    TunAbsent,
    /// 默认出口已落到该网卡。
    EgressTaken {
        interface: String,
    },
    /// 产出的配置片段。
    Fragment {
        text: String,
        /// 适配器自己加的注解（不参与 Aegis 的校验，只给人看）。
        notes: Vec<String>,
    },
    Healthy {
        version: String,
    },
    Reloaded {
        version: String,
    },
    /// 53 归它管。
    DnsOwned {
        owner: String,
    },
    /// 没人管 53。
    DnsNotOwned,
    /// 规则确认生效。
    RulesEffective,
    /// 规则**没生效**。⚠ 这是**事实**不是错误——适配器如实说"我的规则
    /// 没生效"是必须被允许的表达，否则它只能靠"调用失败"来传达，
    /// 调用方就分不清"没生效"和"适配器坏了"。
    RulesIneffective {
        /// 哪些断言没过（给人看，进审计）。
        failed: Vec<String>,
    },
    /// 适配器自己**也不知道**规则生没生效。
    ///
    /// 三态缺一不可：把"不知道"塞进前两者之一，会造出一个假的确定性——
    /// 而守卫对"判不了"的处理（保持现状）与对"没生效"的处理（收紧）
    /// 是**相反**的，猜错方向就是误断网或漏放行。
    RulesUnknown {
        why: String,
    },
}

impl Outcome {
    /// 这个结果属于哪个能力。
    pub fn capability(&self) -> Capability {
        match self {
            Self::TunPresent { .. } | Self::TunAbsent => Capability::TunInterfacePresent,
            Self::EgressTaken { .. } => Capability::DefaultEgress,
            Self::Fragment { .. } => Capability::ConfigFragmentGenerate,
            Self::Healthy { .. } => Capability::HealthProbe,
            Self::Reloaded { .. } => Capability::Reload,
            Self::DnsOwned { .. } | Self::DnsNotOwned => Capability::DnsOwnership,
            Self::RulesEffective | Self::RulesIneffective { .. } | Self::RulesUnknown { .. } => {
                Capability::RuleEffectiveness
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_op_maps_to_exactly_one_capability() {
        assert_eq!(
            Op::TunPresent { candidates: &[] }.capability(),
            Capability::TunInterfacePresent
        );
        assert_eq!(
            Op::DefaultEgress { interface: "eth0" }.capability(),
            Capability::DefaultEgress
        );
        assert_eq!(
            Op::Fragment { profile: "campus" }.capability(),
            Capability::ConfigFragmentGenerate
        );
        assert_eq!(Op::Health.capability(), Capability::HealthProbe);
        assert_eq!(Op::Reload.capability(), Capability::Reload);
        assert_eq!(Op::Dns.capability(), Capability::DnsOwnership);
        assert_eq!(
            Op::RulesEffective.capability(),
            Capability::RuleEffectiveness
        );
    }

    /// 三态同属一个能力：适配器必须能分别表达"生效 / 没生效 / 不知道"，
    /// 而它们都归 `RuleEffectiveness`，不能被当成答非所问。
    #[test]
    fn all_three_rule_states_belong_to_one_capability() {
        let c = Capability::RuleEffectiveness;
        assert_eq!(Outcome::RulesEffective.capability(), c);
        assert_eq!(
            Outcome::RulesIneffective {
                failed: vec!["x".into()]
            }
            .capability(),
            c
        );
        assert_eq!(Outcome::RulesUnknown { why: "y".into() }.capability(), c);
    }

    /// "适配器答非所问"要靠这个不变式抓出来：
    /// 问 DNS，回了个 Healthy，两者能力不同 —— 底座必须升级成故障。
    #[test]
    fn outcomes_of_different_capabilities_are_distinguishable() {
        let asked = Op::Dns.capability();
        let answered = Outcome::Healthy {
            version: "1".into(),
        }
        .capability();
        assert_ne!(asked, answered);
    }

    #[test]
    fn absent_and_not_owned_are_facts_of_the_same_capability() {
        assert_eq!(
            Outcome::TunAbsent.capability(),
            Capability::TunInterfacePresent
        );
        assert_eq!(
            Outcome::TunPresent {
                name: "utun".into()
            }
            .capability(),
            Capability::TunInterfacePresent
        );
        assert_eq!(Outcome::DnsNotOwned.capability(), Capability::DnsOwnership);
    }
}
