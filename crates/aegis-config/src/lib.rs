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

/// 完整配置。
#[derive(Debug, Clone)]
pub struct Config {
    pub meta: Meta,
    /// 角色判定策略。直接反序列化为 [`aegis_core::role::RolePolicy`]，
    /// 不另建 DTO——两个结构必然各自漂移。
    pub roles: aegis_core::role::RolePolicy,
    pub topology: Topology,
    /// 加载过程中产生的非致命提示（补丁版本不同、涉及预发布等）。
    pub warnings: Vec<String>,
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
        use aegis_core::sense::model::{if_flags, if_type, InterfaceInfo, OperStatus};

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
    }

    #[test]
    fn missing_file_is_an_error_not_a_default() {
        let err = load_file(std::path::Path::new("no/such/config.toml")).unwrap_err();
        assert!(matches!(err, ConfigError::Io { .. }));
    }
}
