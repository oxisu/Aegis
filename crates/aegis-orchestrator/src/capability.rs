//! 能力枚举与**逐能力的失败模式表**（design-spec §2A.4 ①②）。
//!
//! # 为什么是"能力"而不是"软件"
//!
//! 早期按软件类别切 trait（`ProxyAdapter` / `MultiWanAdapter` / `AuditEnricher`），
//! 方法名里带着"代理""多 WAN"。换个软件就得改 trait——那不叫可插拔，叫改名。
//! 更致命的是 `Result<()>` 无法表达"这个能力我不支持"，
//! 于是**不支持**和**失败**混为一谈：调用方要么假装成功，
//! 要么把"本来就不支持"当成致命错误反复重试。
//!
//! 所以 SPI 的切分维度改成**能力**，与具体软件无关。
//!
//! # 为什么失败模式要预先定死
//!
//! [`Capability::fallback`] 这张表必须在代码里写死，不能运行时再选。
//! "Fail-Closed 或告警"这个二选一一旦留给运行时判断，
//! 就会出现"本该断网的时候只是弹了个提示"这种致命的摇摆。

/// 适配器可以提供的**能力**，与具体软件无关。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Capability {
    /// 是否有 TUN / 虚拟网卡，且能被 Aegis 识别
    TunInterfacePresent,
    /// 能否接管默认出口
    DefaultEgress,
    /// 能否产出**配置片段**（而非 Aegis 替它写全量配置）
    ConfigFragmentGenerate,
    /// 能否被健康检查
    HealthProbe,
    /// 能否热重载（不重启进程就让配置生效）
    Reload,
    /// 它是否接管 DNS（与 Aegis 的 53 封锁是否冲突）
    DnsOwnership,
}

impl Capability {
    /// 全部能力。能力矩阵与"缺了什么"的对账都从这里出发——
    /// 加新能力时只改这一处，矩阵和自检自动跟上。
    pub const ALL: [Capability; 6] = [
        Capability::TunInterfacePresent,
        Capability::DefaultEgress,
        Capability::ConfigFragmentGenerate,
        Capability::HealthProbe,
        Capability::Reload,
        Capability::DnsOwnership,
    ];

    /// ASCII 稳定标签：写进配置、日志、错误码。
    ///
    /// 刻意不做成 `Display`——标签是**协议的一部分**，改一个字母就是破坏性变更；
    /// `Display` 会被当成"给人看的文案"随手改。
    pub fn tag(self) -> &'static str {
        match self {
            Self::TunInterfacePresent => "tun_interface_present",
            Self::DefaultEgress => "default_egress",
            Self::ConfigFragmentGenerate => "config_fragment_generate",
            Self::HealthProbe => "health_probe",
            Self::Reload => "reload",
            Self::DnsOwnership => "dns_ownership",
        }
    }

    /// 从标签反解。**未知标签返回 `None`，绝不退化成某个默认值**——
    /// 配置文件里写了个拼错的能力名，静默当成"不支持"会让该 Fail-Closed 的
    /// 出口变成"看起来没配"，这正是要防的静默降级。
    pub fn from_tag(tag: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|c| c.tag() == tag)
    }

    /// 一句话说明这个能力是什么。
    pub fn description(self) -> &'static str {
        match self {
            Self::TunInterfacePresent => "有 TUN / 虚拟网卡，且能被 Aegis 识别",
            Self::DefaultEgress => "能接管默认出口",
            Self::ConfigFragmentGenerate => "能产出配置片段（不是全量配置）",
            Self::HealthProbe => "能被健康检查",
            Self::Reload => "能热重载（不重启进程就让配置生效）",
            Self::DnsOwnership => "接管 DNS（关系到 53 封锁会不会被绕过）",
        }
    }

    /// §2A.4 ② —— 这个能力缺失时该怎么办。**写死，不可运行时选择。**
    pub fn fallback(self) -> Fallback {
        match self {
            Self::TunInterfacePresent => Fallback::FailClosed {
                consequence: "TUN 没起来却以为起来了 = 流量走物理网卡直连，\
                               因此不认为该出口可用",
            },
            Self::DefaultEgress => Fallback::FailClosed {
                consequence: "无法接管出口就等于没有绝缘，因此不认为该出口可用",
            },
            Self::DnsOwnership => Fallback::FailClosed {
                consequence: "不知道谁管 DNS，就可能出现绕过 53 封锁的直连 DNS \
                               泄漏，因此拒绝放行该出口",
            },
            Self::Reload => Fallback::Degrade {
                action: "降级为重启进程：只是切换慢一点，不漏流量",
            },
            Self::HealthProbe => Fallback::Degrade {
                action: "少一个健康检查不等于有泄漏，继续运行",
            },
            Self::ConfigFragmentGenerate => Fallback::Degrade {
                action: "只用 Aegis 自带的粗粒度规则：精细路由没了，\
                         但 53 / 广播 / 默认拒绝仍在",
            },
        }
    }
}

/// 能力缺失时的处置。
///
/// 只有两种：**断**或**降级**。没有第三种"看情况"——
/// "看情况"在代码里的样子就是一个运行时 if，而这个 if 迟早会被改错。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fallback {
    /// 缺失即断：这个能力是"不漏流量"的前提，没有它就拒绝放行。
    FailClosed { consequence: &'static str },
    /// 缺失只影响体验或精细度：告警并降级，不阻断。
    Degrade { action: &'static str },
}

impl Fallback {
    /// 是不是"缺失就必须断"。
    pub fn is_fail_closed(self) -> bool {
        matches!(self, Self::FailClosed { .. })
    }

    /// 处置说明：Fail-Closed 给的是"为什么必须断"，Degrade 给的是"降级成什么"。
    pub fn note(self) -> &'static str {
        match self {
            Self::FailClosed { consequence } => consequence,
            Self::Degrade { action } => action,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_capability_round_trips_through_its_tag() {
        for c in Capability::ALL {
            assert_eq!(Capability::from_tag(c.tag()), Some(c), "{}", c.tag());
        }
    }

    #[test]
    fn an_unknown_tag_is_rejected_instead_of_silently_defaulting() {
        assert_eq!(Capability::from_tag("tun_present"), None);
        assert_eq!(Capability::from_tag(""), None);
        assert_eq!(Capability::from_tag("TUN_INTERFACE_PRESENT"), None);
    }

    /// 能力列表不能出现重复——重复会让"缺了什么"的对账多算一次。
    #[test]
    fn the_capability_list_has_no_duplicates() {
        let mut seen = Vec::new();
        for c in Capability::ALL {
            assert!(!seen.contains(&c), "重复的能力：{}", c.tag());
            seen.push(c);
        }
        assert_eq!(seen.len(), Capability::ALL.len());
    }

    /// §2A.4 ② 的三条 Fail-Closed 是这份设计的核心承诺：
    /// TUN / 默认出口 / DNS 所有权。少一条就会出现"看起来通了其实在漏"。
    #[test]
    fn the_three_leak_critical_capabilities_are_fail_closed() {
        let fail_closed: Vec<Capability> = Capability::ALL
            .into_iter()
            .filter(|c| c.fallback().is_fail_closed())
            .collect();
        assert_eq!(
            fail_closed,
            vec![
                Capability::TunInterfacePresent,
                Capability::DefaultEgress,
                Capability::DnsOwnership,
            ]
        );
    }

    #[test]
    fn degrade_capabilities_are_the_three_that_only_cost_convenience() {
        let degrade: Vec<Capability> = Capability::ALL
            .into_iter()
            .filter(|c| !c.fallback().is_fail_closed())
            .collect();
        assert_eq!(
            degrade,
            vec![
                Capability::ConfigFragmentGenerate,
                Capability::HealthProbe,
                Capability::Reload,
            ]
        );
    }

    /// fallback 的说明文字不能是空的占位——它会直接打进运维告警里。
    #[test]
    fn every_fallback_explains_itself() {
        for c in Capability::ALL {
            assert!(!c.fallback().note().is_empty(), "{}", c.tag());
            assert!(c.fallback().note().chars().count() > 8, "{}", c.tag());
        }
    }
}
