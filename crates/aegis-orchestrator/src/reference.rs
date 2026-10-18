//! **参考适配器**：一个确定性的、不碰系统的适配器模型（design-spec §2A.4 ③）。
//!
//! # 为什么参考实现必须是个"模型"而不是真连 sing-box
//!
//! 契约测试要回答的问题是"适配器的**语义**对不对"，不是"sing-box 装没装"。
//! 真连一次进程会带来三个麻烦：
//!
//! 1. 需要本机装了 sing-box，CI 上跑不了；
//! 2. 需要它真的接管出口——那是要提权、会断网的动作，**绝不能出现在测试里**；
//! 3. 结果依赖进程状态，今天过明天不过，等于没有契约。
//!
//! 所以参考适配器是一个**由 [`Scenario`] 驱动的纯函数**：
//! 输入是"这台机器现在是什么样"，输出是"适配器该回答什么"。
//! 以后接真实的 sing-box 适配器时，让它跑**同一组契约**（见 [`crate::contract`]）。

use crate::capability::Capability;
use crate::error::{invariant, AdapterError};
use crate::op::{Op, Outcome};
use crate::spi::Adapter;
use std::sync::atomic::{AtomicBool, Ordering};

/// 适配器所处的场景：把"这台机器现在是什么样"固化下来。
///
/// 之所以叫"场景"而不是"配置"：它是**事实快照**（哪些 TUN 起来了、53 归谁管），
/// 不是 Aegis 的策略。适配器只该读事实，不该读策略。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scenario {
    /// 本机当前存在的 TUN / 虚拟网卡名。
    pub tun_names: Vec<String>,
    /// 默认出口落在哪张网卡上（`None` = 无人接管）。
    pub egress: Option<String>,
    /// 谁在管 53（`None` = 无人接管）。
    pub dns_owner: Option<String>,
    /// Aegis 自己是否也接管 53（§20 的 53 封锁）。
    /// 两边都管 53 → 必然有一边静默失效，这不是配置问题，是冲突。
    pub aegis_dns_lock: bool,
    /// 当前配置版本号。
    pub version: String,
    /// 热重载之后的版本号。
    pub next_version: String,
}

impl Scenario {
    /// 契约测试用的标准场景：sing-box 起来了、接管了出口和 53、Aegis 不抢 53。
    pub fn sample() -> Self {
        Self {
            tun_names: vec!["sing-box-tun".to_string(), "utun7".to_string()],
            egress: Some("sing-box-tun".to_string()),
            dns_owner: Some("sing-box".to_string()),
            aegis_dns_lock: false,
            version: "2026.10.18-1".to_string(),
            next_version: "2026.10.18-2".to_string(),
        }
    }

    /// 场景：适配器起来了但 Aegis 也锁了 53 —— DNS 所有权冲突。
    pub fn sample_with_dns_conflict() -> Self {
        Self {
            aegis_dns_lock: true,
            ..Self::sample()
        }
    }

    /// 场景：一张 TUN 都没起来。
    pub fn sample_without_tun() -> Self {
        Self {
            tun_names: Vec::new(),
            egress: None,
            ..Self::sample()
        }
    }
}

/// 参考适配器。**不碰系统、不启进程、不提权。**
pub struct ReferenceAdapter {
    name: &'static str,
    declared: Vec<Capability>,
    scenario: Scenario,
    /// 是否发生过热重载。`Health` 的返回值依赖它——
    /// 这样"声称支持 Reload 就真的会让版本号变化"才能被验证。
    reloaded: AtomicBool,
}

impl ReferenceAdapter {
    pub fn new(name: &'static str, scenario: Scenario) -> Self {
        Self {
            name,
            declared: Capability::ALL.to_vec(),
            scenario,
            reloaded: AtomicBool::new(false),
        }
    }

    /// 覆盖能力声明（替换，不是追加）。
    pub fn declare(&mut self, capabilities: &[Capability]) {
        self.declared = capabilities.to_vec();
    }

    pub fn scenario(&self) -> &Scenario {
        &self.scenario
    }

    pub fn has_reloaded(&self) -> bool {
        self.reloaded.load(Ordering::SeqCst)
    }

    /// 当前生效的配置版本号：热重载过就是新版本。
    pub fn version(&self) -> String {
        if self.reloaded.load(Ordering::SeqCst) {
            self.scenario.next_version.clone()
        } else {
            self.scenario.version.clone()
        }
    }
}

impl Adapter for ReferenceAdapter {
    fn name(&self) -> &'static str {
        self.name
    }

    fn capabilities(&self) -> &[Capability] {
        &self.declared
    }

    fn invoke(&self, op: Op<'_>) -> Result<Outcome, AdapterError> {
        match op {
            Op::TunPresent { candidates } => self.tun(candidates),
            Op::DefaultEgress { interface } => self.egress(interface),
            Op::Fragment { profile } => Ok(Outcome::Fragment {
                text: fragment_text(profile),
                // 契约要逐字节比对结果，所以参考实现不带注解；
                // 真实适配器可以在这里给人看的说明，契约不校验它。
                notes: Vec::new(),
            }),
            Op::Health => Ok(Outcome::Healthy {
                version: self.version(),
            }),
            Op::Reload => {
                self.reloaded.store(true, Ordering::SeqCst);
                Ok(Outcome::Reloaded {
                    version: self.scenario.next_version.clone(),
                })
            }
            Op::Dns => self.dns(),
        }
    }
}

impl ReferenceAdapter {
    /// TUN 的三态：**起来了且被放行** / **起来了但没被放行** / **一张都没起来**。
    ///
    /// 第二种必须是显式错误而不是 `TunAbsent`：适配器有张 TUN 起来了、
    /// 却不在 Aegis 放行列表里，流量会被默认拒绝吃掉，而上层看到的
    /// 是"适配器说没有 TUN"——一个彻底误导的事实。
    fn tun(&self, candidates: &[String]) -> Result<Outcome, AdapterError> {
        if let Some(name) = candidates
            .iter()
            .find(|n| self.scenario.tun_names.contains(n))
        {
            return Ok(Outcome::TunPresent { name: name.clone() });
        }

        if !candidates.is_empty() && !self.scenario.tun_names.is_empty() {
            return Err(AdapterError::InvariantViolation {
                capability: Capability::TunInterfacePresent,
                invariant: invariant::TUN_NOT_PERMITTED,
                detail: format!(
                    "本机有 TUN 起来了（{}），但没有一张在放行列表里（{}）",
                    self.scenario.tun_names.join(", "),
                    candidates.join(", ")
                ),
            });
        }

        Ok(Outcome::TunAbsent)
    }

    fn egress(&self, interface: &str) -> Result<Outcome, AdapterError> {
        match &self.scenario.egress {
            Some(current) if current == interface => Ok(Outcome::EgressTaken {
                interface: interface.to_string(),
            }),
            Some(current) => Err(AdapterError::Failed {
                capability: Capability::DefaultEgress,
                reason: format!("默认出口在 {current} 上，不在 {interface} 上"),
            }),
            None => Err(AdapterError::Failed {
                capability: Capability::DefaultEgress,
                reason: format!("当前没有网卡接管默认出口，无法落到 {interface}"),
            }),
        }
    }

    fn dns(&self) -> Result<Outcome, AdapterError> {
        match &self.scenario.dns_owner {
            Some(owner) if self.scenario.aegis_dns_lock => {
                Err(AdapterError::InvariantViolation {
                    capability: Capability::DnsOwnership,
                    invariant: invariant::DNS_OWNERSHIP_CONFLICT,
                    detail: format!("{owner} 与 Aegis 都要管 53，必然有一边静默失效"),
                })
            }
            Some(owner) => Ok(Outcome::DnsOwned {
                owner: owner.clone(),
            }),
            None => Ok(Outcome::DnsNotOwned),
        }
    }
}

/// 参考适配器产出的配置片段。
///
/// ⚠ 刻意**不解析、不生成对方的全部规则**，只给出片段本身——
/// Aegis 只验证片段是否违反安全不变量，绝不替对方写全量配置
/// （§2A.4 ④：解析对方的全部规则 = 依赖对方内部格式 = 版本一升级就崩）。
pub fn fragment_text(profile: &str) -> String {
    format!("# aegis fragment: profile={profile}\n# 由适配器生成，Aegis 只校验不变量\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adapter() -> ReferenceAdapter {
        ReferenceAdapter::new("ref", Scenario::sample())
    }

    #[test]
    fn a_permitted_tun_that_is_up_is_reported_as_present() {
        let a = adapter();
        let names = ["sing-box-tun".to_string()];
        assert_eq!(
            a.invoke(Op::TunPresent { candidates: &names }).unwrap(),
            Outcome::TunPresent {
                name: "sing-box-tun".into()
            }
        );
    }

    #[test]
    fn a_tun_that_is_up_but_not_permitted_is_an_invariant_violation() {
        let a = adapter();
        let names = ["wireguard-tun".to_string()];
        let e = a.invoke(Op::TunPresent { candidates: &names }).unwrap_err();
        assert_eq!(e.code(), invariant::TUN_NOT_PERMITTED);
        assert!(e.disposition().contains("放行列表"), "{}", e.disposition());
    }

    /// 没给候选就问 TUN：这不是"有未放行的 TUN"，而是"没问"——
    /// 自检探针依赖这个语义，否则每次自检都会被判成不变量违反。
    #[test]
    fn asking_with_no_candidates_is_absent_not_a_violation() {
        let a = adapter();
        assert_eq!(
            a.invoke(Op::TunPresent { candidates: &[] }).unwrap(),
            Outcome::TunAbsent
        );
    }

    #[test]
    fn with_no_tun_up_at_all_the_answer_is_absent() {
        let a = ReferenceAdapter::new("ref", Scenario::sample_without_tun());
        let names = ["sing-box-tun".to_string()];
        assert_eq!(
            a.invoke(Op::TunPresent { candidates: &names }).unwrap(),
            Outcome::TunAbsent
        );
    }

    #[test]
    fn taking_the_egress_on_the_right_nic_succeeds() {
        let a = adapter();
        assert_eq!(
            a.invoke(Op::DefaultEgress {
                interface: "sing-box-tun"
            })
            .unwrap(),
            Outcome::EgressTaken {
                interface: "sing-box-tun".into()
            }
        );
    }

    #[test]
    fn taking_the_egress_elsewhere_is_a_failure_not_a_silent_success() {
        let a = adapter();
        let e = a
            .invoke(Op::DefaultEgress { interface: "eth0" })
            .unwrap_err();
        assert!(e.is_fault());
        assert_eq!(e.code(), "ADAPTER_FAILED");
    }

    /// 关键：热重载之后，**健康检查**报的版本号必须变。
    /// 声称支持 Reload 却看不到版本变化 = 这个 Reload 是假的。
    #[test]
    fn reload_changes_the_version_reported_by_health() {
        let a = adapter();
        let before = a.invoke(Op::Health).unwrap();
        assert_eq!(
            before,
            Outcome::Healthy {
                version: "2026.10.18-1".into()
            }
        );

        a.invoke(Op::Reload).unwrap();
        assert!(a.has_reloaded());

        let after = a.invoke(Op::Health).unwrap();
        assert_eq!(
            after,
            Outcome::Healthy {
                version: "2026.10.18-2".into()
            }
        );
        assert_ne!(before, after);
    }

    #[test]
    fn dns_ownership_is_reported_when_aegis_does_not_lock_53() {
        let a = adapter();
        assert_eq!(
            a.invoke(Op::Dns).unwrap(),
            Outcome::DnsOwned {
                owner: "sing-box".into()
            }
        );
    }

    /// 两边都管 53 是冲突，不是"以谁为准"——以谁为准的结果一定是有一边静默失效。
    #[test]
    fn both_owning_53_is_a_conflict_not_a_precedence_question() {
        let a = ReferenceAdapter::new("ref", Scenario::sample_with_dns_conflict());
        let e = a.invoke(Op::Dns).unwrap_err();
        assert_eq!(e.code(), invariant::DNS_OWNERSHIP_CONFLICT);
        assert!(e.disposition().contains("53"), "{}", e.disposition());
    }

    #[test]
    fn the_reference_adapter_declares_everything_by_default() {
        let a = adapter();
        assert_eq!(a.capabilities(), &Capability::ALL);
    }

    #[test]
    fn fragment_text_is_deterministic_and_carries_the_profile() {
        assert_eq!(fragment_text("campus"), fragment_text("campus"));
        assert!(fragment_text("campus").contains("campus"));
        assert_ne!(fragment_text("campus"), fragment_text("free"));
    }
}
