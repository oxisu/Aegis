//! 适配器错误：**不支持**与**失败**必须分开（design-spec §2A.4 ①⑤）。
//!
//! 这不是洁癖。混在一起的后果很具体：
//!
//! - `Unsupported` 被当成 `Failed` → Aegis 一直在重试一个永远不可能成功的能力，
//!   告警刷屏，真正的故障被淹掉。
//! - `Failed` 被当成 `Unsupported` → 适配器真的挂了，却被当成"本来就不支持"
//!   静默吞掉，于是一个该 Fail-Closed 的出口悄悄变成放行。
//!
//! 所以 [`AdapterError`] 的构造子上就带着这个区分，
//! [`AdapterError::is_fault`] 是运维侧唯一该用来判断"要不要告警"的入口。

use crate::capability::{Capability, Fallback};
use std::fmt;

/// 安全不变量的名字。**它同时就是违反它时的错误码**——
/// 一个不变量只有一个名字，不会出现"同一个问题两个码"的对不上账。
pub mod invariant {
    /// TUN 网卡不在 Aegis 放行列表里 → 流量会被默认拒绝吃掉。
    pub const TUN_NOT_PERMITTED: &str = "TUN_NOT_PERMITTED";
    /// 两边都要管 53 → 必然有一边静默失效。
    pub const DNS_OWNERSHIP_CONFLICT: &str = "DNS_OWNERSHIP_CONFLICT";
    /// 配置片段本身违反了 Aegis 的安全不变量。
    pub const FRAGMENT_CONFLICTS_INVARIANT: &str = "FRAGMENT_CONFLICTS_INVARIANT";
}

/// 适配器返回的错误。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdapterError {
    /// 适配器没声明过这个能力 —— **不是故障**，是契约信息。
    Unsupported(Capability),
    /// 声明了但做失败了 —— 这才是故障。
    Failed {
        capability: Capability,
        reason: String,
    },
    /// 做了，但结果违反 Aegis 的安全不变量。
    ///
    /// 与 `Failed` 的区别：失败是"这事没做成"，不变量违反是"做成了，但做错了"——
    /// 后者更危险，因为它不会自动表现为错误。
    InvariantViolation {
        capability: Capability,
        /// 见 [`invariant`] 模块的常量。
        invariant: &'static str,
        detail: String,
    },
}

impl AdapterError {
    /// 这条错误属于哪个能力。
    pub fn capability(&self) -> Capability {
        match self {
            Self::Unsupported(c) | Self::Failed { capability: c, .. } => *c,
            Self::InvariantViolation { capability, .. } => *capability,
        }
    }

    /// 是不是**真故障**。
    ///
    /// `Unsupported` 不是故障，不该触发告警；另外两个必须。
    /// 调用方判断"要不要告警"只许用这一个入口，不许自己 match。
    pub fn is_fault(&self) -> bool {
        !matches!(self, Self::Unsupported(_))
    }

    /// §2A.4 ⑤ 的错误码。
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unsupported(_) => "CAPABILITY_MISSING",
            Self::Failed { .. } => "ADAPTER_FAILED",
            Self::InvariantViolation { invariant, .. } => invariant,
        }
    }

    /// §2A.4 ⑤ 的处置建议。
    ///
    /// 返回 `String` 而不是 `&'static str`，因为它要把该能力的
    /// [`Fallback`] 说明拼进去——运维看到的是"怎么办"，不是"出了什么码"。
    pub fn disposition(&self) -> String {
        match self {
            Self::Unsupported(c) => {
                let f = c.fallback();
                if f.is_fail_closed() {
                    format!("换适配器，或接受不可用：{}", f.note())
                } else {
                    format!("换适配器，或接受降级：{}", f.note())
                }
            }
            Self::Failed { capability, .. } => {
                let f = capability.fallback();
                if f.is_fail_closed() {
                    format!("声明了该能力却失败，按不可用处置：{}", f.note())
                } else {
                    format!("声明了该能力却失败，按降级处置：{}", f.note())
                }
            }
            Self::InvariantViolation {
                invariant, detail, ..
            } => match *invariant {
                invariant::TUN_NOT_PERMITTED => {
                    format!("把该 TUN 加入放行列表，否则流量会被默认拒绝吃掉：{detail}")
                }
                invariant::DNS_OWNERSHIP_CONFLICT => {
                    format!("确定唯一的 53 所有者，两边都管必然有一边静默失效：{detail}")
                }
                _ => format!("指出冲突的具体不变量，不改就拒绝下发：{detail}"),
            },
        }
    }

    /// 该能力缺失时的处置（仅对 `Unsupported` 有意义）。
    pub fn fallback(&self) -> Fallback {
        self.capability().fallback()
    }
}

impl fmt::Display for AdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(c) => write!(f, "[{}] 适配器不支持 {}", c.tag(), c.description()),
            Self::Failed {
                capability,
                reason,
            } => write!(f, "[{}] 适配器执行 {} 失败：{reason}", self.code(), capability.tag()),
            Self::InvariantViolation {
                capability,
                invariant,
                detail,
            } => write!(
                f,
                "[{invariant}] {} 的结果违反安全不变量：{detail}",
                capability.tag()
            ),
        }
    }
}

impl std::error::Error for AdapterError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_is_not_a_fault_and_the_other_two_are() {
        assert!(!AdapterError::Unsupported(Capability::Reload).is_fault());
        assert!(AdapterError::Failed {
            capability: Capability::Reload,
            reason: "进程没了".into()
        }
        .is_fault());
        assert!(AdapterError::InvariantViolation {
            capability: Capability::TunInterfacePresent,
            invariant: invariant::TUN_NOT_PERMITTED,
            detail: "utun 不在放行列表".into(),
        }
        .is_fault());
    }

    /// 这条是 §2A.4 ① 的核心：`Unsupported` 与 `Failed` 的码必须不同，
    /// 否则监控系统无法区分"本来就不支持"和"真的挂了"。
    #[test]
    fn unsupported_and_failed_carry_different_codes() {
        let unsup = AdapterError::Unsupported(Capability::HealthProbe);
        let failed = AdapterError::Failed {
            capability: Capability::HealthProbe,
            reason: "超时".into(),
        };
        assert_eq!(unsup.code(), "CAPABILITY_MISSING");
        assert_eq!(failed.code(), "ADAPTER_FAILED");
        assert_ne!(unsup.code(), failed.code());
    }

    #[test]
    fn invariant_violations_report_the_invariant_name_as_the_code() {
        let e = AdapterError::InvariantViolation {
            capability: Capability::DnsOwnership,
            invariant: invariant::DNS_OWNERSHIP_CONFLICT,
            detail: "两边都要管 53".into(),
        };
        assert_eq!(e.code(), "DNS_OWNERSHIP_CONFLICT");
    }

    /// 处置建议必须带上具体能力的后果，不能是"请联系管理员"这种空的。
    #[test]
    fn disposition_names_the_concrete_consequence() {
        let e = AdapterError::Unsupported(Capability::DnsOwnership);
        assert!(e.disposition().contains("不可用"), "{}", e.disposition());
        assert!(e.disposition().contains("53"), "{}", e.disposition());

        let e = AdapterError::Unsupported(Capability::Reload);
        assert!(e.disposition().contains("降级"), "{}", e.disposition());
    }

    #[test]
    fn capability_is_reported_consistently_across_all_variants() {
        let c = Capability::DefaultEgress;
        assert_eq!(AdapterError::Unsupported(c).capability(), c);
        assert_eq!(
            AdapterError::Failed {
                capability: c,
                reason: "x".into()
            }
            .capability(),
            c
        );
        assert_eq!(
            AdapterError::InvariantViolation {
                capability: c,
                invariant: invariant::TUN_NOT_PERMITTED,
                detail: "x".into(),
            }
            .capability(),
            c
        );
    }
}
