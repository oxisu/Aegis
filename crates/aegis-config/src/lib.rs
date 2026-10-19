//! Aegis 配置加载与 schema 版本校验（对应 design-spec.md §22）。
//!
//! # 边界
//! 只读文件、只做解析与校验：**不写配置、不改系统状态、不需要管理员权限**。
//! 因此可以在 CI 与普通权限下完整测试。
//!
//! # Fail-Closed：配置出错必须拒绝加载，绝不退回默认值
//! 这是本模块最重要的一条。配置里写着"哪些网卡可以出网"，如果解析失败就
//! 退回 `Default`，等于**在用户不知情的情况下用一套他没批准过的策略放行**。
//! 相比之下"拒绝加载 + 明确的报错"只是让用户改一行配置，代价小得多。
//! 所以这里没有任何 `unwrap_or_default()` 式的兜底路径。
//!
//! # schema 版本为什么要单独校验
//! 配置是对外契约。Aegis 升级后字段语义可能已变（例如某个默认值从
//! "放行"改成"绝缘"），此时读一份旧配置并按新语义解释，结果就是
//! **安全策略静默降级**——用户以为自己在严格模式，实际不是。
//! 因此必须先比对 `config_schema_version`，不兼容就直接拒。
//!
//! # 校验规则来自 `aegis_version::compat`
//! 与 IPC 版本握手共用同一套规则，避免"IPC 认为不兼容、配置却放行了"。
//! 特别注意本项目处于 0.x：**MINOR 不同即破坏性变更**。

use std::net::{Ipv4Addr, SocketAddr};

use aegis_core::guard::{collect, GuardFacts, ProxyMode};
use aegis_version::compat::{check_compat, ParseError, Verdict, VersionTriple};
use serde::Deserialize;

/// 本程序支持的配置 schema 版本（`MAJOR.MINOR`），取自 Cargo 版本前两段。
///
/// 刻意只取两段：schema 不随 PATCH 变化，用两段能避免"打个补丁就要求用户
/// 改配置"这种无谓打扰。
pub const SCHEMA_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION_MAJOR"),
    ".",
    env!("CARGO_PKG_VERSION_MINOR")
);

/// 配置加载失败。
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("读取配置文件失败：{path}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("TOML 解析失败：{message}")]
    Parse { message: String },
    #[error("缺少 [meta] 段：必须显式声明 config_schema_version，不允许猜")]
    MissingMeta,
    #[error("config_schema_version 无法解析：'{raw}'（应为 MAJOR.MINOR，如 0.1）")]
    SchemaMalformed { raw: String },
    #[error("配置 schema 版本不兼容：文件声明 {found}，本程序支持 {supported} —— {reason}")]
    SchemaRejected {
        found: String,
        supported: String,
        reason: String,
    },
    #[error("[[always_allow]] 第 {index} 条不合法：{reason}")]
    InvalidAlwaysAllow { index: usize, reason: String },
}

/// `[meta]` 段。
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Meta {
    /// 本文件遵循的 schema 版本。**必填**。
    pub config_schema_version: String,
    /// 生成 / 校验本文件时的 Aegis 完整版本号，仅用于追溯。
    #[serde(default)]
    pub aegis_version: String,
}

/// `[topology]` 段中与信任相关的部分。
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Topology {
    /// 已确认的拓扑指纹；空串表示首次开机，需人工分配角色。
    pub trusted_fingerprint: String,
    /// 上次用户确认的时间戳（RFC 3339）。
    pub last_confirmed_at: String,
}

/// `[proxy]` 段：谁是下游代理、它当前工作在哪种模式。
///
/// 两种模式的守卫判据**完全不同**（`docs/HOURGLASS.md` §4），
/// 所以模式必须是显式配置，**不能猜**——见 [`Config::guard_facts`]。
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Proxy {
    /// 工作模式：`tun` 或 `system_proxy`。**未配置时守卫不工作**
    /// （而不是挑一个默认值）。
    pub mode: Option<ProxyMode>,
    /// TUN 模式下代理虚拟网卡的 LUID。
    ///
    /// TOML 支持十六进制整数字面量，写 `0x6008008000000000` 更接近
    /// `netsh` / `Get-NetAdapter` 里看到的形式。
    pub tun_luid: Option<u64>,
    /// 代理**控制面**地址（形如 `127.0.0.1:9090`），守卫断言 A 的判据来源。
    ///
    /// ⚠ **不填 = 断言 A 判不了**（`None`，不是"可达"）。
    /// 早期这里没有可判的入口，只能一律按"可达"填 `true`——那是假事实：
    /// "代理进程已经死了"这条永远通过，守卫只剩 B/C 两条。
    /// 判不了就如实判不了（`GuardVerdict::Unknown`），**永不触发收紧**。
    ///
    /// 后续接上适配器 SPI 之后，断言 A 会改用 `Op::RulesEffective`
    /// 的三态结果（`RulesUnknown` 同样落到 `None`），本字段退化为无 SPI 时的兜底。
    pub control_addr: Option<SocketAddr>,
}

/// `[[always_allow]]` 一条**永久放行**条目。
///
/// # ⚠ 这是受控后门，不是普通放行规则
///
/// `docs/DOWNSTREAM-GUARD.md` §7.1：它**必然**破坏"只有走对网卡才放行"
/// 这条判据——校园网认证页只能从校园物理网卡访问，而那正是平时要砍的路。
/// 因此约束（由 [`validate_always_allow`] 与后续 GUI 共同保证）：
///
/// - 只能由**用户手工**添加，任何自动流程 / 适配器 SPI 都不许加；
/// - 作用域钉到最小：单个目的 IP + 明确列出的端口，不是"整个网段全端口"；
/// - 生成的规则**权重必须高于所有阻断**，否则会静默失效；
/// - 每次命中都要写审计——后门必须可追溯，否则变成暗门。
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlwaysAllow {
    /// 给人看的名字，会进审计与 GUI。
    pub name: String,
    /// 目的 IP（例如校园网认证网关）。**不是网段。**
    pub remote_ip: Ipv4Addr,
    /// 放行的端口。必须显式列出，空列表不合法。
    pub ports: Vec<u16>,
}

/// 完整配置。
#[derive(Debug, Clone)]
pub struct Config {
    pub meta: Meta,
    /// 角色判定策略。直接反序列化为 [`aegis_core::role::RolePolicy`]，
    /// 不另建 DTO——两个结构必然各自漂移。
    pub roles: aegis_core::role::RolePolicy,
    pub topology: Topology,
    /// 下游代理的工作模式与承载体（`docs/DOWNSTREAM-GUARD.md`）。
    pub proxy: Proxy,
    /// 永久放行名单（受控后门）。
    pub always_allow: Vec<AlwaysAllow>,
    /// 加载过程中产生的非致命提示（补丁版本不同、涉及预发布等）。
    pub warnings: Vec<String>,
}

impl Config {
    /// 守卫能不能工作；不能时返回缺什么。
    ///
    /// 与"加载失败"分开：**缺配置不等于配置错**。缺了只是守卫不工作
    /// （并且必须让用户知道），错的才拒绝加载。
    pub fn guard_gap(&self) -> Option<String> {
        match self.proxy.mode {
            None => Some(
                "未配置 proxy.mode：不知道代理工作在哪种模式，\
                          守卫无法选择断言"
                    .to_string(),
            ),
            Some(ProxyMode::Tun) if self.proxy.tun_luid.is_none() => Some(
                "已配置为 TUN 模式但缺少 proxy.tun_luid：\
                      无法验证默认出口是不是代理承载体"
                    .to_string(),
            ),
            Some(ProxyMode::SystemProxy) => Some(
                "系统代理模式的守卫断言需要适配器 SPI（读系统代理开关），\
                      尚未实现"
                    .to_string(),
            ),
            Some(ProxyMode::Tun) => None,
        }
    }

    /// 把配置 + 感知事实组装成守卫的事实集。
    ///
    /// **返回 `None` 而不是猜一个模式**：TUN 的判据是"默认出口是不是 TUN"，
    /// 把它用在系统代理模式上会**永远失败** → 守卫持续收紧 → **永久断网**。
    /// 猜错模式的后果比不守卫严重得多，所以这里宁可返回 `None`。
    ///
    /// 调用方（编排器）拿到 `None` 应当保持现状并提示用户，
    /// 而不是自行挑一个默认值。
    pub fn guard_facts(
        &self,
        proxy_reachable: Option<bool>,
        present_luids: &[u64],
        default_egress_luid: Option<u64>,
    ) -> Option<GuardFacts> {
        let mode = self.proxy.mode?;
        Some(collect(
            mode,
            proxy_reachable,
            self.proxy.tun_luid,
            present_luids,
            default_egress_luid,
        ))
    }

    /// 编排器真正会用的入口：**配置 + 一次拓扑快照 → 守卫事实集**。
    ///
    /// `TopologySnapshot` 来自 `aegis-sense::snapshot()`（只读，不需特权）。
    /// 有了这个入口，"采一次拓扑 → 判一次"就是一行代码，调用方不需要
    /// 知道 `default_egress_luid` 用 0 表示离线这种内部约定。
    pub fn guard_facts_from(
        &self,
        snap: &aegis_core::model::TopologySnapshot,
        proxy_reachable: Option<bool>,
    ) -> Option<GuardFacts> {
        let (present, egress) = aegis_core::guard::topology_inputs(snap);
        self.guard_facts(proxy_reachable, &present, egress)
    }
}

/// 校验永久放行名单。**Fail-Closed：不合法就拒绝加载，绝不静默丢弃条目。**
///
/// 静默丢弃的后果是"用户以为加了一条白名单，其实没生效"——
/// 而这条白名单存在的唯一理由就是让用户能打开认证页，失效等于把人锁在外面。
fn validate_always_allow(items: &[AlwaysAllow]) -> Result<(), ConfigError> {
    for (index, item) in items.iter().enumerate() {
        if item.name.trim().is_empty() {
            return Err(ConfigError::InvalidAlwaysAllow {
                index,
                reason: "name 不能为空（它要进审计，必须能追溯是谁开的）".to_string(),
            });
        }
        if item.ports.is_empty() {
            return Err(ConfigError::InvalidAlwaysAllow {
                index,
                reason: "ports 不能为空：请显式列出端口，\
                         空列表的语义是'全端口'，那是把后门开到最大"
                    .to_string(),
            });
        }
        if item.ports.contains(&0) {
            return Err(ConfigError::InvalidAlwaysAllow {
                index,
                reason: "ports 里不能出现 0（端口 0 不是合法的目的端口）".to_string(),
            });
        }
    }
    Ok(())
}

/// 反序列化用的原始结构。顶层**不** `deny_unknown_fields`：
/// 配置里还有大量本版本尚未实现的段（service / rescue / modes ...），
/// 顶层的宽容是为了兼容；但已实现的段内部一律严格。
#[derive(Debug, Deserialize)]
struct Raw {
    meta: Meta,
    #[serde(default)]
    roles: aegis_core::role::RolePolicy,
    #[serde(default)]
    topology: Topology,
    #[serde(default)]
    proxy: Proxy,
    #[serde(default)]
    always_allow: Vec<AlwaysAllow>,
}

/// 把 `MAJOR.MINOR` 补成 `MAJOR.MINOR.0` 以复用三段式版本比较。
fn parse_schema(s: &str) -> Result<VersionTriple, ParseError> {
    let t = s.trim();
    if t.is_empty() {
        return Err(ParseError::MissingSegment);
    }
    let padded = match t.split('.').count() {
        1 => format!("{t}.0.0"),
        2 => format!("{t}.0"),
        _ => t.to_string(),
    };
    VersionTriple::parse(&padded)
}

/// 校验一份声明的 schema 版本与本程序是否兼容。
///
/// 返回 [`Verdict`]：`Ok` / `Warn` 可继续，`Reject` 必须拒绝加载。
pub fn check_schema(found: &str) -> Result<Verdict, ConfigError> {
    let found_v = parse_schema(found).map_err(|_| ConfigError::SchemaMalformed {
        raw: found.to_string(),
    })?;
    let supported_v = parse_schema(SCHEMA_VERSION).expect("SCHEMA_VERSION 由 Cargo 保证格式合法");
    Ok(check_compat(found_v, supported_v))
}

/// 从字符串加载配置。
pub fn load_str(text: &str) -> Result<Config, ConfigError> {
    let raw: Raw = toml::from_str(text).map_err(|e| ConfigError::Parse {
        message: e.to_string(),
    })?;

    // 白名单要在**返回之前**校验：让它带着"看起来加成功了其实没生效"
    // 的状态进入运行期，是最难排查的一类故障。
    validate_always_allow(&raw.always_allow)?;

    // ⚠ 0 **不是**一个合法的 LUID（与 `TopologySnapshot::default_egress_luid`
    // 用 0 表示"无默认路由"是同一套约定）。样例配置里写 `tun_luid = 0`
    // 表示"还没填"，必须翻成 `None`：否则守卫会拿 0 去跟真实的默认出口比，
    // 永远不等 → 判定"规则未生效" → 持续收紧 → **永久断网**。
    let mut proxy = raw.proxy;
    if proxy.tun_luid == Some(0) {
        proxy.tun_luid = None;
    }

    let found = &raw.meta.config_schema_version;
    match check_schema(found)? {
        Verdict::Reject(reason) => Err(ConfigError::SchemaRejected {
            found: found.clone(),
            supported: SCHEMA_VERSION.to_string(),
            reason: reason.to_string(),
        }),
        other => {
            let mut warnings = Vec::new();
            if let Verdict::Warn(note) = other {
                warnings.push(format!("schema 版本提示：{note}"));
            }
            Ok(Config {
                meta: raw.meta,
                roles: raw.roles,
                topology: raw.topology,
                proxy,
                always_allow: raw.always_allow,
                warnings,
            })
        },
    }
}

/// 从文件加载配置。任何失败都向上传递，**不退回默认值**。
pub fn load_file(path: &std::path::Path) -> Result<Config, ConfigError> {
    let text = std::fs::read_to_string(path).map_err(|e| ConfigError::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    load_str(&text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::guard::GuardVerdict;
    use aegis_core::role::{Confidence, InterfaceRole};

    const OK: &str = r#"
[meta]
config_schema_version = "0.1"
"#;

    #[test]
    fn schema_version_matches_cargo_major_minor() {
        assert_eq!(SCHEMA_VERSION, "0.1");
        assert_eq!(check_schema("0.1").unwrap(), Verdict::Ok);
    }

    #[test]
    fn minimal_config_loads() {
        let c = load_str(OK).unwrap();
        assert_eq!(c.meta.config_schema_version, "0.1");
        assert!(c.warnings.is_empty());
    }

    /// 0.x 阶段 MINOR 不同即破坏性变更——照抄"主版本相同即兼容"会在这里翻车。
    #[test]
    fn unstable_minor_mismatch_is_rejected() {
        let text = r#"
[meta]
config_schema_version = "0.2"
"#;
        let err = load_str(text).unwrap_err();
        assert!(
            matches!(err, ConfigError::SchemaRejected { .. }),
            "0.2 schema 应被拒绝，实际：{err}"
        );
    }

    #[test]
    fn major_mismatch_is_rejected() {
        let text = r#"
[meta]
config_schema_version = "1.0"
"#;
        assert!(matches!(
            load_str(text).unwrap_err(),
            ConfigError::SchemaRejected { .. }
        ));
    }

    /// 拒绝加载而不是退回默认——退回默认等于用一套用户没批准过的策略放行。
    #[test]
    fn missing_meta_is_rejected_not_defaulted() {
        assert!(matches!(
            load_str("[roles]\nallow_multiple_free = false\n").unwrap_err(),
            ConfigError::Parse { .. }
        ));
        assert!(matches!(
            load_str("").unwrap_err(),
            ConfigError::Parse { .. }
        ));
    }

    #[test]
    fn malformed_schema_version_is_rejected() {
        for bad in ["", "  ", "abc", "0.x"] {
            assert!(
                matches!(
                    load_str(&format!("[meta]\nconfig_schema_version = \"{bad}\"\n")),
                    Err(ConfigError::SchemaMalformed { .. })
                ),
                "'{bad}' 应判为格式错误"
            );
        }
    }

    /// 安全配置里的拼写错误必须报错，而不是被静默忽略后退回默认值——
    /// 那样用户以为自己改了策略，实际生效的仍是旧的那套。
    #[test]
    fn typo_in_roles_section_is_rejected() {
        let text = r#"
[meta]
config_schema_version = "0.1"

[roles]
known_free_ssid = ["MMi"]
"#;
        let err = load_str(text).unwrap_err();
        assert!(
            matches!(err, ConfigError::Parse { .. }),
            "字段名拼错应报错，实际：{err}"
        );
    }

    #[test]
    fn invalid_fallback_role_is_rejected() {
        let text = r#"
[meta]
config_schema_version = "0.1"

[roles]
fallback_role = "FreeForAll"
"#;
        assert!(matches!(
            load_str(text).unwrap_err(),
            ConfigError::Parse { .. }
        ));
    }

    #[test]
    fn roles_section_deserializes_into_policy() {
        let text = r#"
[meta]
config_schema_version = "0.1"

[roles]
known_free_ssids   = ["MMi"]
known_campus_ssids = ["CQU-WLAN"]
campus_ssid_keywords = ["edu"]
free_ssid_keywords   = ["hotspot"]
campus_gateway_prefixes = ["10."]
fallback_role = "Isolated"
allow_multiple_free = false
"#;
        let c = load_str(text).unwrap();
        assert_eq!(c.roles.known_free_ssids, vec!["MMi".to_string()]);
        assert_eq!(c.roles.known_campus_ssids, vec!["CQU-WLAN".to_string()]);
        assert_eq!(c.roles.fallback_role, InterfaceRole::Isolated);
    }

    /// 端到端：配置里声明的手机热点名单，真的会让裁决放行。
    /// 这条把"配置文件 → 策略 → 裁决"整条链路钉死，避免任何一环被改坏。
    #[test]
    fn declared_hotspot_ssid_reaches_adjudication() {
        use aegis_core::model::{if_flags, if_type, InterfaceInfo, OperStatus};

        let nic = InterfaceInfo {
            luid: 1,
            index: 0,
            alias: "WLAN".into(),
            description: String::new(),
            mac: None,
            if_type: if_type::IEEE80211,
            flags: if_flags::HARDWARE,
            access_type: 2,
            tunnel_type: 0,
            oper_status: OperStatus::Up,
            ipv4: Vec::new(),
            gateway: vec!["192.168.40.220".parse().unwrap()],
            dhcp_server: None,
            ssid: Some("MMi".into()),
        };

        let text = r#"
[meta]
config_schema_version = "0.1"

[roles]
known_free_ssids = ["MMi"]
"#;
        let c = load_str(text).unwrap();
        let d = aegis_core::role::adjudicate(&nic, &c.roles);
        assert_eq!(d.role, InterfaceRole::FreeOutbound);
        assert_eq!(d.confidence, Confidence::Confirmed);
    }

    /// 仓库里的样例配置必须能被本程序加载——否则样例就是骗人的。
    #[test]
    fn shipped_example_config_loads() {
        let text = include_str!("../../../config/config.example.toml");
        let c = load_str(text).unwrap();
        assert_eq!(c.meta.config_schema_version, SCHEMA_VERSION);
        // 样例中 known_free_ssids 是注释掉的，故为空；但兜底必须仍是绝缘
        assert!(c.roles.known_free_ssids.is_empty());
        assert_eq!(c.roles.fallback_role, InterfaceRole::Isolated);
        assert!(c.topology.trusted_fingerprint.is_empty());

        // 样例里 `tun_luid = 0` 表示"还没填"，不能让守卫拿着 0 去比对
        assert_eq!(c.proxy.mode, Some(ProxyMode::Tun));
        assert_eq!(c.proxy.tun_luid, None, "0 必须被翻成未配置");
        assert!(c.always_allow.is_empty(), "样例不应自带任何后门条目");
    }

    #[test]
    fn missing_file_is_an_error_not_a_default() {
        let err = load_file(std::path::Path::new("no/such/config.toml")).unwrap_err();
        assert!(matches!(err, ConfigError::Io { .. }));
    }

    // ── [proxy] / [[always_allow]]（docs/DOWNSTREAM-GUARD.md）────────────

    fn with(body: &str) -> String {
        format!("[meta]\nconfig_schema_version = \"0.1\"\n{body}")
    }

    /// 没配 `[proxy]` 的老配置必须**照常能加载**（段是可选的），
    /// 但守卫要如实报告"缺模式"。拒绝加载旧配置是破坏性变更；
    /// 悄悄当成"已配好"才是真危险。
    #[test]
    fn a_config_without_a_proxy_section_still_loads_but_reports_the_gap() {
        let c = load_str(OK).unwrap();
        assert!(c.proxy.mode.is_none());
        assert!(c.proxy.tun_luid.is_none());
        let gap = c.guard_gap().expect("未配置模式时必须报告缺口");
        assert!(gap.contains("proxy.mode"));
    }

    #[test]
    fn tun_mode_without_a_luid_reports_the_gap_but_still_loads() {
        let c = load_str(&with("[proxy]\nmode = \"tun\"\n")).unwrap();
        assert_eq!(c.proxy.mode, Some(ProxyMode::Tun));
        assert!(c.guard_gap().unwrap().contains("proxy.tun_luid"));
    }

    /// TOML 支持十六进制字面量，LUID 用十六进制写更接近 `netsh` 里的形式。
    #[test]
    fn tun_luid_accepts_a_hex_literal() {
        let c = load_str(&with(
            "[proxy]\nmode = \"tun\"\ntun_luid = 0x6008008000000000\n",
        ))
        .unwrap();
        assert_eq!(c.proxy.tun_luid, Some(0x6008_0080_0000_0000));
        assert!(c.guard_gap().is_none(), "配齐了就不该有缺口");
    }

    #[test]
    fn control_addr_is_parsed_into_a_socket_addr() {
        let c = load_str(&with(
            "[proxy]\nmode = \"tun\"\ntun_luid = 7\ncontrol_addr = \"127.0.0.1:9090\"\n",
        ))
        .unwrap();
        assert_eq!(
            c.proxy.control_addr.map(|a| a.to_string()),
            Some("127.0.0.1:9090".to_string())
        );
    }

    /// ⚠ **写错的 control_addr 必须让配置加载失败**，不能静默变成"没配"。
    /// 静默成"没配"的后果是断言 A 悄悄退化成 Unknown、守卫从此不再收紧，
    /// 而日志上只看到"判不了"——没人会想到是自己打错了一个冒号。
    #[test]
    fn a_malformed_control_addr_is_a_load_error_not_a_silently_absent_one() {
        let e = load_str(&with(
            "[proxy]\nmode = \"tun\"\ntun_luid = 7\ncontrol_addr = \"127.0.0.1\"\n",
        ))
        .unwrap_err();
        assert!(
            e.to_string().contains("control_addr") || e.to_string().contains("proxy"),
            "错误里该点名字段：{e}"
        );
    }

    /// ⚠ **`tun_luid = 0` 表示"还没填"，必须翻成 `None`**，与
    /// `TopologySnapshot::default_egress_luid` 是同一套约定。
    /// 若当成 `Some(0)`，守卫会永远判定"默认出口不是 TUN" → 持续收紧
    /// → **永久断网**。样例配置里写的就是 0。
    #[test]
    fn a_zero_tun_luid_means_unconfigured_not_a_nic_called_zero() {
        let c = load_str(&with("[proxy]\nmode = \"tun\"\ntun_luid = 0\n")).unwrap();
        assert_eq!(c.proxy.tun_luid, None);
        assert!(c.guard_gap().unwrap().contains("proxy.tun_luid"));
    }

    /// ⚠ 系统代理模式下守卫**没有可用断言**（要 SPI 读系统代理开关）。
    /// 这里必须如实报告，不能假装能守卫。
    #[test]
    fn system_proxy_mode_admits_it_cannot_guard_yet() {
        let c = load_str(&with("[proxy]\nmode = \"system_proxy\"\n")).unwrap();
        assert!(c.guard_gap().unwrap().contains("适配器 SPI"));
    }

    /// **猜模式的后果比不守卫严重**：TUN 的判据用在系统代理模式上会永远
    /// 失败 → 守卫持续收紧 → 永久断网。所以未配模式时返回 `None`。
    #[test]
    fn guard_facts_refuses_to_guess_the_mode() {
        let c = load_str(OK).unwrap();
        assert!(c.guard_facts(Some(true), &[1], Some(1)).is_none());
    }

    /// 端到端：配置 → 事实 → 判决。配齐且一切吻合 → 生效。
    #[test]
    fn a_fully_configured_tun_proxy_yields_an_effective_verdict() {
        let c = load_str(&with("[proxy]\nmode = \"tun\"\ntun_luid = 7\n")).unwrap();
        let facts = c.guard_facts(Some(true), &[1, 7], Some(7)).unwrap();
        assert_eq!(aegis_core::guard::evaluate(facts), GuardVerdict::Effective);
    }

    /// 端到端：**默认出口不是 TUN** → 未生效（那条最值钱的静默失效）。
    #[test]
    fn a_default_egress_that_is_not_the_tun_is_caught_by_the_config() {
        let c = load_str(&with("[proxy]\nmode = \"tun\"\ntun_luid = 7\n")).unwrap();
        let facts = c.guard_facts(Some(true), &[1, 7], Some(1)).unwrap();
        match aegis_core::guard::evaluate(facts) {
            GuardVerdict::Ineffective { failed, .. } => {
                assert_eq!(failed, vec![aegis_core::guard::Assertion::EgressIsBearer])
            },
            other => panic!("期望 Ineffective，得到 {other:?}"),
        }
    }

    #[test]
    fn always_allow_deserializes_into_entries() {
        let c = load_str(&with(
            "[[always_allow]]\nname = \"校园网认证页\"\nremote_ip = \"10.0.0.1\"\nports = [80, 443]\n",
        ))
        .unwrap();
        assert_eq!(c.always_allow.len(), 1);
        assert_eq!(c.always_allow[0].name, "校园网认证页");
        assert_eq!(c.always_allow[0].remote_ip, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(c.always_allow[0].ports, vec![80, 443]);
    }

    /// ⚠ 空 ports 的语义会被理解成"全端口"，那是把后门开到最大 —— 必须拒。
    #[test]
    fn an_always_allow_without_ports_is_rejected() {
        let err = load_str(&with(
            "[[always_allow]]\nname = \"x\"\nremote_ip = \"10.0.0.1\"\nports = []\n",
        ))
        .unwrap_err();
        match err {
            ConfigError::InvalidAlwaysAllow { index, reason } => {
                assert_eq!(index, 0);
                assert!(reason.contains("全端口"));
            },
            other => panic!("期望 InvalidAlwaysAllow，得到 {other}"),
        }
    }

    #[test]
    fn an_always_allow_without_a_name_is_rejected() {
        let err = load_str(&with(
            "[[always_allow]]\nname = \"  \"\nremote_ip = \"10.0.0.1\"\nports = [80]\n",
        ))
        .unwrap_err();
        assert!(matches!(
            err,
            ConfigError::InvalidAlwaysAllow { index: 0, .. }
        ));
    }

    #[test]
    fn port_zero_in_always_allow_is_rejected() {
        let err = load_str(&with(
            "[[always_allow]]\nname = \"x\"\nremote_ip = \"10.0.0.1\"\nports = [0]\n",
        ))
        .unwrap_err();
        assert!(matches!(
            err,
            ConfigError::InvalidAlwaysAllow { index: 0, .. }
        ));
    }

    /// 后门条目里的拼写错误也必须报错（`deny_unknown_fields`），
    /// 否则用户以为自己钉死了目的 IP，实际那个字段压根没被读。
    #[test]
    fn a_typo_in_always_allow_is_rejected() {
        let err = load_str(&with(
            "[[always_allow]]\nname = \"x\"\nremote = \"10.0.0.1\"\nports = [80]\n",
        ))
        .unwrap_err();
        assert!(matches!(err, ConfigError::Parse { .. }));
    }

    // ── 拓扑 → 事实（编排器的真实入口）────────────────────────────────

    fn snap(egress: u64, luids: &[u64]) -> aegis_core::model::TopologySnapshot {
        use aegis_core::model::{
            if_flags, if_type, FingerprintScope, InterfaceInfo, OperStatus, TopologySnapshot,
        };
        TopologySnapshot {
            interfaces: luids
                .iter()
                .map(|l| InterfaceInfo {
                    luid: *l,
                    index: 0,
                    alias: String::new(),
                    description: String::new(),
                    mac: None,
                    if_type: if_type::ETHERNET_CSMACD,
                    flags: if_flags::HARDWARE,
                    access_type: 2,
                    tunnel_type: 0,
                    oper_status: OperStatus::Up,
                    ipv4: Vec::new(),
                    gateway: Vec::new(),
                    dhcp_server: None,
                    ssid: None,
                })
                .collect(),
            default_egress_luid: egress,
            fingerprint: String::new(),
            fingerprint_scope: FingerprintScope::Physical,
            fingerprint_participants: 0,
        }
    }

    /// 端到端：配置里写的 TUN LUID + 一次拓扑快照 → 判决。
    /// 这是"配置 → 感知 → 守卫"整条链路的钉子。
    #[test]
    fn config_plus_topology_yields_the_verdict() {
        use aegis_core::guard::{evaluate, Assertion};

        let c = load_str(&with("[proxy]\nmode = \"tun\"\ntun_luid = 7\n")).unwrap();

        // TUN 在，且默认出口就是它
        let ok = c.guard_facts_from(&snap(7, &[1, 7]), Some(true)).unwrap();
        assert_eq!(evaluate(ok), GuardVerdict::Effective);

        // TUN 还在，但默认出口跑到了别的卡上（那条最阴的静默失效）
        let drifted = c.guard_facts_from(&snap(1, &[1, 7]), Some(true)).unwrap();
        match evaluate(drifted) {
            GuardVerdict::Ineffective { failed, .. } => {
                assert_eq!(failed, vec![Assertion::EgressIsBearer])
            },
            other => panic!("期望 Ineffective，得到 {other:?}"),
        }
    }

    /// 整机离线（`default_egress_luid == 0`）不能被当成"出口是 LUID 0"。
    #[test]
    fn an_offline_topology_is_not_treated_as_a_valid_egress() {
        use aegis_core::guard::evaluate;

        let c = load_str(&with("[proxy]\nmode = \"tun\"\ntun_luid = 7\n")).unwrap();
        let f = c.guard_facts_from(&snap(0, &[1, 7]), Some(true)).unwrap();
        assert!(
            !evaluate(f).is_effective(),
            "没有默认路由时不该判为规则生效"
        );
    }
}
