//! WFP 对象的只读摘要与"持久背板"审计（纯逻辑，不调用 Win32 API）。
//!
//! # 为什么要做"持久背板"审计
//! design-spec.md §28.2 记着一条能让整机变砖的地雷：**装了一个清理不掉的
//! 持久（Persistent）/ Boot-Time 过滤器**。这类过滤器不随进程退出消失，
//! 只要它写的是"全部 DROP"，服务崩了、卸载了、重启了，网照样不通——
//! 而用户此时已经没有任何界面可以把它删掉。
//!
//! 所以 Aegis 在下发任何规则之前，必须先回答一个问题：
//! **这台机器上现在已经有哪些"清不掉"的东西？**
//! 这一步完全是只读的，不需要任何权限，也因此必须最先做、最先测。
//!
//! # 为什么必须按"归属"再分一层
//! 首版实现只要见到 persistent/boottime + 阻断就报"可导致变砖"。
//! 在本机实测立刻翻车：48 条持久 / 引导时间过滤器**全是 Windows 自带的
//! 引导时间底板**（归属 `@bfe.dll,-1211`，服务 `mpssvc`），BFE 启动后
//! 自行撤销，属于系统正常行为。把它们报成雷就是**假警报**。
//!
//! 假警报的代价和假漂移（见 `aegis-sense` 指纹收敛）是同一类：
//! 用户被无意义的告警淹没后，会养成不看告警的习惯，
//! 真正危险的那一次也就一起被忽略了。所以这里按归属再分一层——
//! 系统组件自带的算基线，只有第三方 / 未知归属的才算雷。

// 以下常量镜像 WFP 头文件里的 FWPM_FILTER_FLAG_*。
// 之所以在模型层用裸 u32 复述一份：模型要能脱离 windows crate 被推演，
// 而镜像是否漂移由 tests::flag_constants_match_windows_headers 守着。
pub const FLAG_PERSISTENT: u32 = 0x0001;
pub const FLAG_BOOTTIME: u32 = 0x0002;
pub const FLAG_HAS_PROVIDER_CONTEXT: u32 = 0x0004;
pub const FLAG_CLEAR_ACTION_RIGHT: u32 = 0x0008;
pub const FLAG_PERMIT_IF_CALLOUT_UNREGISTERED: u32 = 0x0010;
pub const FLAG_DISABLED: u32 = 0x0020;
pub const FLAG_INDEXED: u32 = 0x0040;

/// Windows 自带的、会安装持久 / 引导时间过滤器的服务名。
///
/// 用**服务名**而不是厂商名做判据：服务名是稳定的系统标识符，
/// 而"Microsoft"这类字样属于显示层文案，可能因本地化或版本而变。
/// 这里不写任何第三方厂商——装了什么第三方底座，交给实测去发现。
// 拼写以本机 `wfp_inspect` 实测输出为准：mpssvc / IKEEXT / NDU / MPSSVC。
// 注意是 IKE**E**XT（IKE and AuthIP IPsec Keying Modules），不是 ikkext。
pub const SYSTEM_SERVICES: &[&str] = &["mpssvc", "ikeext", "ndu", "bfe", "wfp"];

/// Windows 自身资源字符串引用的前缀（形如 `@bfe.dll,-1211`）。
///
/// 这类名字不是人类可读文本，但它是**系统组件**的强特征：
/// 第三方产品通常直接写自己的产品名。
pub const SYSTEM_RESOURCE_PREFIXES: &[&str] = &["@bfe.dll", "@mpssvc.dll", "@wfplogsf.dll"];

/// 过滤器标志位。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FilterFlags(pub u32);

impl FilterFlags {
    /// **持久**：不随进程退出消失，重启后仍在。
    pub fn persistent(self) -> bool {
        self.0 & FLAG_PERSISTENT != 0
    }

    /// **Boot-Time**：在 TCP/IP 栈启动之前就生效。
    pub fn boottime(self) -> bool {
        self.0 & FLAG_BOOTTIME != 0
    }

    pub fn disabled(self) -> bool {
        self.0 & FLAG_DISABLED != 0
    }

    /// 是否属于"进程死了也不会消失"的那一类。
    ///
    /// 这正是 fail-closed 的反面：Aegis 自己要用动态会话（崩溃自动清空），
    /// 而任何 persistent / boottime 的东西都必须被显式清点、显式清理。
    pub fn survives_reboot(self) -> bool {
        self.persistent() || self.boottime()
    }
}

/// 一条过滤器的只读摘要。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterSummary {
    pub id: u64,
    /// 展示名；很多系统过滤器没有名字，此时为空串
    pub name: String,
    /// 层（已知层为可读名，未知层为 GUID）
    pub layer: String,
    /// 动作（"阻断" / "放行" / "终结型 Callout" …）
    pub action: String,
    /// 该动作是否会终止数据包
    pub terminal: bool,
    pub flags: FilterFlags,
    /// 归属 Provider 的展示名（能解析出来才有）
    pub provider: Option<String>,
    /// 归属 Provider 关联的 Windows 服务名。**判断"是不是系统自带"靠它**，
    /// 而不是靠展示名——展示名可能是本地化文案，服务名才是稳定标识符。
    pub provider_service: Option<String>,
}

impl FilterSummary {
    /// 是否由 Windows 自带组件安装。
    ///
    /// 判据（任一成立即可）：
    /// 1. 归属服务名在 [`SYSTEM_SERVICES`] 内
    /// 2. 归属展示名是系统资源字符串引用（`@bfe.dll,-1211` 这类）
    ///
    /// **判定不出来的一律算"非系统"**：宁可让第三方底座被当成雷报一次，
    /// 也不能让真正的第三方底板被当成系统基线放过。
    pub fn is_system_owned(&self) -> bool {
        if let Some(svc) = &self.provider_service {
            if SYSTEM_SERVICES.iter().any(|s| svc.eq_ignore_ascii_case(s)) {
                return true;
            }
        }
        if let Some(name) = &self.provider {
            if SYSTEM_RESOURCE_PREFIXES
                .iter()
                .any(|p| name.to_lowercase().starts_with(p))
            {
                return true;
            }
        }
        false
    }
}

/// Provider 的只读摘要。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderSummary {
    pub name: String,
    /// 关联的 Windows 服务名
    pub service: String,
    pub raw_flags: u32,
}

impl ProviderSummary {
    pub fn persistent(&self) -> bool {
        self.raw_flags & FLAG_PERSISTENT != 0
    }
}

/// 一次只读勘察的结果。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub filters: Vec<FilterSummary>,
    pub providers: Vec<ProviderSummary>,
}

impl Snapshot {
    /// 挑出"进程死了也不会消失"的过滤器（§28.2 地雷的候选）。
    pub fn surviving_filters(&self) -> impl Iterator<Item = &FilterSummary> {
        self.filters.iter().filter(|f| f.flags.survives_reboot())
    }

    pub fn persistent_providers(&self) -> impl Iterator<Item = &ProviderSummary> {
        self.providers.iter().filter(|p| p.persistent())
    }

    /// 持久且会终止数据包的过滤器数量。
    pub fn bricking_candidates(&self) -> usize {
        self.surviving_filters().filter(|f| f.terminal).count()
    }

    /// 其中**非系统归属**的数量——只有这些才是 §28.2 说的那颗雷。
    pub fn thirdparty_bricking_candidates(&self) -> usize {
        self.surviving_filters()
            .filter(|f| f.terminal && !f.is_system_owned())
            .count()
    }
}

/// 持久背板审计结论。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Risk {
    /// 没有任何持久对象
    Clean,
    /// 有持久对象，但没有一条会终止数据包（多半是杀软/防火墙的正常驻留）
    PersistentOnly,
    /// 有持久阻断规则，但**全部由 Windows 自带组件安装**（引导时间底板等）。
    /// 这是系统正常行为，BFE 启动后自行撤销，不是雷。
    SystemBaseline,
    /// **存在第三方 / 未知归属的持久阻断过滤器**：这才是 §28.2 说的那颗雷。
    Bricking,
}

impl Risk {
    pub fn label(self) -> &'static str {
        match self {
            Self::Clean => "无持久背板",
            Self::PersistentOnly => "有持久对象但不阻断",
            Self::SystemBaseline => "仅系统自带引导时间底板（正常）",
            Self::Bricking => "存在第三方持久阻断规则（可导致变砖）",
        }
    }

    /// 是否需要立刻停下来人工确认。
    pub fn needs_attention(self) -> bool {
        matches!(self, Self::Bricking)
    }
}

/// 对一份快照做持久背板审计。
pub fn audit_backbone(snap: &Snapshot) -> Risk {
    let surviving: Vec<&FilterSummary> = snap.surviving_filters().collect();
    if surviving.is_empty() && snap.persistent_providers().next().is_none() {
        return Risk::Clean;
    }

    let blocking: Vec<&&FilterSummary> = surviving.iter().filter(|f| f.terminal).collect();
    if blocking.is_empty() {
        return Risk::PersistentOnly;
    }

    if blocking.iter().any(|f| !f.is_system_owned()) {
        Risk::Bricking
    } else {
        Risk::SystemBaseline
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::NetworkManagement::WindowsFilteringPlatform as wfp;

    fn filter(flags: u32, action_terminal: bool) -> FilterSummary {
        FilterSummary {
            id: 1,
            name: "f".into(),
            layer: "ALE_AUTH_CONNECT_V4".into(),
            action: if action_terminal { "阻断" } else { "放行" }.into(),
            terminal: action_terminal,
            flags: FilterFlags(flags),
            provider: None,
            provider_service: None,
        }
    }

    /// 造一条带归属的过滤器——归属决定了它是"系统基线"还是"雷"。
    fn owned_filter(
        flags: u32,
        terminal: bool,
        name: Option<&str>,
        svc: Option<&str>,
    ) -> FilterSummary {
        FilterSummary {
            provider: name.map(str::to_string),
            provider_service: svc.map(str::to_string),
            ..filter(flags, terminal)
        }
    }

    /// 镜像常量必须与头文件一致，否则审计会把 persistent 判成别的位。
    #[test]
    fn flag_constants_match_windows_headers() {
        assert_eq!(FLAG_PERSISTENT, wfp::FWPM_FILTER_FLAG_PERSISTENT.0);
        assert_eq!(FLAG_BOOTTIME, wfp::FWPM_FILTER_FLAG_BOOTTIME.0);
        assert_eq!(FLAG_DISABLED, wfp::FWPM_FILTER_FLAG_DISABLED.0);
        assert_eq!(FLAG_INDEXED, wfp::FWPM_FILTER_FLAG_INDEXED.0);
    }

    #[test]
    fn survives_reboot_covers_both_persistent_and_boottime() {
        assert!(FilterFlags(FLAG_PERSISTENT).survives_reboot());
        assert!(FilterFlags(FLAG_BOOTTIME).survives_reboot());
        assert!(!FilterFlags(0).survives_reboot());
        assert!(!FilterFlags(FLAG_DISABLED).survives_reboot());
        // 组合位不能被误判
        assert!(FilterFlags(FLAG_PERSISTENT | FLAG_DISABLED).survives_reboot());
    }

    /// `disabled()` 之前一个测试都没碰过，变异测试一口气放了 5 个变异体
    /// 全活下来。位运算必须**两个方向**都钉住：置位为真、未置位为假。
    #[test]
    fn disabled_flag_is_read_exactly() {
        assert!(FilterFlags(FLAG_DISABLED).disabled());
        assert!(!FilterFlags(0).disabled());
        assert!(!FilterFlags(FLAG_PERSISTENT).disabled());
        assert!(!FilterFlags(FLAG_BOOTTIME).disabled());
        // 组合位不能被别的标志带偏
        assert!(FilterFlags(FLAG_PERSISTENT | FLAG_DISABLED).disabled());
        assert!(!FilterFlags(FLAG_PERSISTENT | FLAG_BOOTTIME).disabled());
    }

    #[test]
    fn provider_persistent_flag_is_read_exactly() {
        let p = |flags: u32| ProviderSummary {
            name: "p".into(),
            service: "s".into(),
            raw_flags: flags,
        };
        assert!(p(FLAG_PERSISTENT).persistent());
        assert!(!p(0).persistent());
        assert!(!p(FLAG_BOOTTIME).persistent(), "boottime 不等于 persistent");
        assert!(!p(FLAG_DISABLED).persistent());
        assert!(p(FLAG_PERSISTENT | FLAG_DISABLED).persistent());
    }

    /// 非持久 Provider 不能被算进"持久背板"候选里。
    #[test]
    fn non_persistent_provider_is_not_counted() {
        let snap = Snapshot {
            filters: Vec::new(),
            providers: vec![ProviderSummary {
                name: "p".into(),
                service: "s".into(),
                raw_flags: 0,
            }],
        };
        assert_eq!(snap.persistent_providers().count(), 0);
        assert_eq!(audit_backbone(&snap), Risk::Clean);
    }

    #[test]
    fn empty_snapshot_is_clean() {
        assert_eq!(audit_backbone(&Snapshot::default()), Risk::Clean);
    }

    /// 关键区分：持久但"放行"的过滤器是杀软的常态，不构成变砖风险；
    /// 持久且"阻断"的才是雷。混为一谈会让用户被无用告警淹没。
    #[test]
    fn persistent_permit_filters_are_not_bricking() {
        let snap = Snapshot {
            filters: vec![filter(FLAG_PERSISTENT, false)],
            providers: Vec::new(),
        };
        assert_eq!(audit_backbone(&snap), Risk::PersistentOnly);
        assert_eq!(snap.bricking_candidates(), 0);
    }

    #[test]
    fn persistent_block_filters_are_bricking() {
        let snap = Snapshot {
            filters: vec![filter(FLAG_PERSISTENT, true)],
            providers: Vec::new(),
        };
        assert_eq!(audit_backbone(&snap), Risk::Bricking);
        assert_eq!(snap.bricking_candidates(), 1);
    }

    #[test]
    fn boottime_blocking_counts_even_without_persistent() {
        let snap = Snapshot {
            filters: vec![filter(FLAG_BOOTTIME, true)],
            providers: Vec::new(),
        };
        assert_eq!(audit_backbone(&snap), Risk::Bricking);
    }

    #[test]
    fn transient_filters_are_ignored() {
        let snap = Snapshot {
            filters: vec![filter(0, true), filter(FLAG_DISABLED, true)],
            providers: Vec::new(),
        };
        assert_eq!(audit_backbone(&snap), Risk::Clean);
    }

    #[test]
    fn persistent_provider_alone_is_flagged() {
        let snap = Snapshot {
            filters: Vec::new(),
            providers: vec![ProviderSummary {
                name: "p".into(),
                service: "svc".into(),
                raw_flags: FLAG_PERSISTENT,
            }],
        };
        assert_eq!(audit_backbone(&snap), Risk::PersistentOnly);
        assert_eq!(snap.persistent_providers().count(), 1);
    }

    #[test]
    fn risk_labels_are_actionable() {
        assert_eq!(Risk::Clean.label(), "无持久背板");
        assert!(Risk::Bricking.label().contains("变砖"));
        assert!(Risk::SystemBaseline.label().contains("正常"));
    }

    #[test]
    fn only_bricking_needs_attention() {
        assert!(Risk::Bricking.needs_attention());
        assert!(!Risk::SystemBaseline.needs_attention());
        assert!(!Risk::PersistentOnly.needs_attention());
        assert!(!Risk::Clean.needs_attention());
    }

    /// 系统归属的两种判据：服务名、系统资源字符串引用。
    #[test]
    fn system_ownership_recognized_by_service_or_resource_name() {
        assert!(owned_filter(FLAG_PERSISTENT, true, None, Some("MpsSvc")).is_system_owned());
        assert!(owned_filter(FLAG_PERSISTENT, true, None, Some("IKEEXT")).is_system_owned());
        assert!(
            owned_filter(FLAG_PERSISTENT, true, Some("@bfe.dll,-1211"), None).is_system_owned()
        );
        // 服务名大小写不敏感：WFP 返回的并不保证统一大小写
        assert!(owned_filter(FLAG_PERSISTENT, true, None, Some("MPSSVC")).is_system_owned());
    }

    /// 判定不出来的一律算"非系统"：宁可把第三方底座当雷报一次，
    /// 也不能把真正的第三方底板当基线放过。
    #[test]
    fn unknown_ownership_is_treated_as_third_party() {
        assert!(!filter(FLAG_PERSISTENT, true).is_system_owned());
        assert!(!owned_filter(FLAG_PERSISTENT, true, Some("某杀软"), None).is_system_owned());
        assert!(!owned_filter(FLAG_PERSISTENT, true, None, Some("某厂商服务")).is_system_owned());
    }

    /// 本机实测场景：48 条持久/引导时间过滤器全是 Windows 自带的引导时间底板。
    /// 首版把它们全报成"可导致变砖"，属于假警报；现在应判为系统基线。
    #[test]
    fn all_system_owned_boottime_filters_are_baseline_not_bricking() {
        let snap = Snapshot {
            filters: vec![
                owned_filter(FLAG_BOOTTIME, true, Some("@bfe.dll,-1211"), Some("mpssvc")),
                owned_filter(
                    FLAG_PERSISTENT,
                    true,
                    Some("@bfe.dll,-1211"),
                    Some("mpssvc"),
                ),
            ],
            providers: Vec::new(),
        };
        assert_eq!(snap.bricking_candidates(), 2);
        assert_eq!(snap.thirdparty_bricking_candidates(), 0);
        assert_eq!(audit_backbone(&snap), Risk::SystemBaseline);
        assert!(!audit_backbone(&snap).needs_attention());
    }

    /// 只要混进一条第三方持久阻断，就必须升级为 Bricking。
    #[test]
    fn one_third_party_persistent_block_upgrades_to_bricking() {
        let snap = Snapshot {
            filters: vec![
                owned_filter(FLAG_BOOTTIME, true, Some("@bfe.dll,-1211"), Some("mpssvc")),
                owned_filter(FLAG_PERSISTENT, true, Some("某杀软底座"), None),
            ],
            providers: Vec::new(),
        };
        assert_eq!(snap.thirdparty_bricking_candidates(), 1);
        assert_eq!(audit_backbone(&snap), Risk::Bricking);
    }
}
