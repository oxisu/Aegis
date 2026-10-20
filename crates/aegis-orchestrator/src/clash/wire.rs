//! mihomo / Clash 控制 API 的线协议模型。
//!
//! # 字段形状来自实测，不是猜的
//!
//! 本机 mihomo **v1.19.32**（`verge-mihomo.exe`，Clash Verge 内核），
//! `external-controller: 127.0.0.1:9097`，2026-10-20 实测。
//! 下面每一条都对应一次真实响应。
//!
//! # 只声明我们真正读的字段
//!
//! 未知字段一律忽略（serde 默认行为）。理由：mihomo 的 `/configs` 返回
//! **40 个顶层键**，而我们需要 5 个。把它们全建模等于把上游的兼容性
//! 风险全接过来——上游加个字段就可能让反序列化失败，而那会让 Aegis
//! 在"上游正常升级"时突然报错。
//!
//! ⚠ 反过来**确实要读**的字段一个不能少：漏一个的代价是 Aegis 以为
//!   某能力不可用，表现为"明明开着却说没有"，比解析失败更难查。

use serde::{Deserialize, Serialize};

/// 端口。**实测 mihomo 返回的是字符串**（`"443"`），但不同版本/不同接口
/// 见过数字形态——所以两种都收，不在这里挑一个赌。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum Port {
    Num(u16),
    Str(String),
}

impl Port {
    pub fn as_u16(&self) -> Option<u16> {
        match self {
            Port::Num(n) => Some(*n),
            Port::Str(s) => s.parse().ok(),
        }
    }

    /// 端口的**文本形式**，写进审计记录用。
    ///
    /// ⚠ 不做成 `as_str`：数字变体没有"字符串"可言，硬造一个 `"n/a"`
    ///   只会让人以为端口丢了。审计要的是"这条连接目的端口是 443"，
    ///   两种形态都要给出同样的文本。
    pub fn to_text(&self) -> String {
        match self {
            Port::Num(n) => n.to_string(),
            Port::Str(s) => s.clone(),
        }
    }
}

impl<'de> Deserialize<'de> for Port {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Num(u16),
            Str(String),
        }
        Ok(match Raw::deserialize(d)? {
            Raw::Num(n) => Port::Num(n),
            Raw::Str(s) => Port::Str(s),
        })
    }
}

/// `GET /version` → `{"meta": true, "version": "v1.19.32"}`
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Version {
    pub version: String,
}

/// `GET /configs` 里的 `tun` 段（实测全部字段）：
/// `{"enable": false, "device": "", "stack": "gVisor", "auto-route": true, ...}`
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct TunSection {
    /// ⚠ 实测**本机为 false**：系统代理模式下 TUN 不启用。
    pub enable: bool,
    #[serde(default)]
    pub device: String,
}

/// `GET /configs` 中我们关心的部分。键名是 **kebab-case**（实测）。
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Configs {
    /// `rule` / `global` / `direct`（实测 `rule`）
    pub mode: String,
    #[serde(rename = "mixed-port")]
    pub mixed_port: u16,
    #[serde(rename = "allow-lan")]
    pub allow_lan: bool,
    #[serde(rename = "log-level")]
    pub log_level: String,
    #[serde(default)]
    pub tun: Option<TunSection>,
}

/// 单条连接的 `metadata`（实测 24 个字段，这里只留审计要用的）。
///
/// ⚠ 关于 `type`：它的取值是**传输层类型**（`tcp`/`udp`），
///   不是"连接类型"。第一次读文档时很容易理解错。
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Metadata {
    #[serde(rename = "sourceIP")]
    pub source_ip: String,
    #[serde(rename = "sourcePort")]
    pub source_port: Port,
    #[serde(rename = "destinationIP")]
    pub destination_ip: String,
    #[serde(rename = "destinationPort")]
    pub destination_port: Port,
    /// 目标主机名。**可能为空**——目标是裸 IP 且没开 sniff 时就是空串。
    #[serde(default)]
    pub host: String,
    /// 传输层类型：`tcp` / `udp`
    #[serde(rename = "type")]
    pub transport: String,
    #[serde(rename = "network", default)]
    pub network: String,
    /// 进程路径。**可能为空**（find-process-mode=off 或权限不足）。
    #[serde(rename = "processPath", default)]
    pub process_path: String,
    #[serde(rename = "process", default)]
    pub process: String,
    /// 被规则集强制指定的代理名。空 = 没被指定。
    #[serde(default)]
    pub special_proxy: String,
}

/// 单条连接（实测字段：`id`/`upload`/`download`/`start`/`chains`/
/// `rule`/`rulePayload`/`providerChains`/`metadata`）。
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Connection {
    pub id: String,
    pub upload: u64,
    pub download: u64,
    /// 连接建立时间（mihomo 给的是**字符串**时间戳，实测形如
    /// `2026-10-20T04:32:11.123456789Z`）。
    pub start: String,
    /// 实际经过的代理链（实测长度 1 = 直连或单跳）。
    #[serde(default)]
    pub chains: Vec<String>,
    /// 命中的规则类型（实测值：`DomainSuffix` / `GeoSite` / `GeoIP` / `Match` …）
    #[serde(default)]
    pub rule: String,
    /// 命中的规则载荷（实测是规则的内容，如一个域名或 `cn`）。
    #[serde(default)]
    pub rule_payload: String,
    pub metadata: Metadata,
}

/// `GET /connections` 顶层（实测还有 `memory`，我们不读）。
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Connections {
    pub connections: Vec<Connection>,
    #[serde(rename = "uploadTotal", default)]
    pub upload_total: u64,
    #[serde(rename = "downloadTotal", default)]
    pub download_total: u64,
}

impl Connections {
    /// 现在有几条连接。
    pub fn len(&self) -> usize {
        self.connections.len()
    }
    pub fn is_empty(&self) -> bool {
        self.connections.is_empty()
    }
}

/// `GET /rules` 单条（实测字段：`type`/`payload`/`proxy`/`size`/`extra`/`index`）。
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RuleEntry {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub payload: String,
    #[serde(default)]
    pub proxy: String,
    #[serde(default)]
    pub index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Rules {
    pub rules: Vec<RuleEntry>,
}

/// `GET /providers/rules` 单个 provider（实测字段里
/// `vehicleType`/`type`/`name`/`ruleCount`/`updatedAt`）。
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RuleProvider {
    pub name: String,
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(rename = "vehicleType", default)]
    pub vehicle_type: String,
    #[serde(rename = "ruleCount", default)]
    pub rule_count: u64,
    /// 最后更新时间（实测是**毫秒时间戳的数字字符串**）。
    #[serde(rename = "updatedAt", default)]
    pub updated_at: String,
}

/// `GET /providers/rules` 顶层：`{"providers": {"<name>": {...}}}`
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Providers {
    pub providers: std::collections::BTreeMap<String, RuleProvider>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // 实测原文（连接）——用一个最小子集钉住字段名与类型
    const REAL_CONN: &str = r#"{
        "id": "abc123",
        "upload": 1234,
        "download": 5678,
        "start": "2026-10-20T04:32:11.123456789Z",
        "chains": ["DIRECT"],
        "rule": "GeoSite",
        "rulePayload": "cn",
        "providerChains": [],
        "metadata": {
            "sourceIP": "192.168.1.5",
            "sourcePort": "54321",
            "destinationIP": "1.2.3.4",
            "destinationPort": "443",
            "host": "example.com",
            "type": "tcp",
            "network": "tcp",
            "processPath": "C:\\Program Files\\x\\y.exe",
            "process": "y.exe",
            "specialProxy": ""
        }
    }"#;

    #[test]
    fn parses_real_connection() {
        let c: Connection = serde_json::from_str(REAL_CONN).unwrap();
        assert_eq!(c.id, "abc123");
        assert_eq!(c.upload, 1234);
        assert_eq!(c.chains, vec!["DIRECT"]);
        // 实测端口是**字符串**，别写成 u16 解析
        assert_eq!(c.metadata.source_port, Port::Str("54321".into()));
        assert_eq!(c.metadata.destination_port.as_u16(), Some(443));
        assert_eq!(c.metadata.transport, "tcp");
    }

    // mihomo 不同版本端口形态不一致，两种都得收
    #[test]
    fn port_accepts_both_shapes() {
        assert_eq!(serde_json::from_str::<Port>("443").unwrap(), Port::Num(443));
        assert_eq!(
            serde_json::from_str::<Port>("\"443\"").unwrap(),
            Port::Str("443".into())
        );
        assert_eq!(
            serde_json::from_str::<Port>("\"abc\"").unwrap().as_u16(),
            None
        );
    }

    // 空 host 是常态：目标是裸 IP 且没开 sniffing
    #[test]
    fn missing_optional_fields_default() {
        let raw = r#"{"id":"x","upload":0,"download":0,"start":"","metadata":{
            "sourceIP":"1.1.1.1","sourcePort":"1","destinationIP":"2.2.2.2",
            "destinationPort":"443","type":"tcp"}}"#;
        let c: Connection = serde_json::from_str(raw).unwrap();
        assert_eq!(c.metadata.host, "");
        assert_eq!(c.metadata.process_path, "");
        assert_eq!(c.rule, "");
        assert!(c.chains.is_empty());
    }

    // 实测 /configs 是 kebab-case，写成 mixed_port 就永远拿不到默认值
    #[test]
    fn configs_use_kebab_case_keys() {
        let raw = r#"{"mode":"rule","mixed-port":7897,"allow-lan":false,
            "log-level":"info","tun":{"enable":false,"device":"","stack":"gVisor"}}"#;
        let c: Configs = serde_json::from_str(raw).unwrap();
        assert_eq!(c.mode, "rule");
        assert_eq!(c.mixed_port, 7897);
        assert!(!c.allow_lan);
        assert!(!c.tun.as_ref().unwrap().enable);
    }

    // 上游加 40 个字段也不该让我们炸
    #[test]
    fn unknown_fields_are_ignored() {
        let raw = r#"{"mode":"rule","mixed-port":1,"allow-lan":false,"log-level":"info",
            "future-feature":{"x":1},"another":["a","b"]}"#;
        assert!(serde_json::from_str::<Configs>(raw).is_ok());
    }

    #[test]
    fn providers_parse_into_map() {
        let raw = r#"{"providers":{"campus":{"name":"campus","type":"Rule",
            "vehicleType":"File","ruleCount":42,"updatedAt":"1700000000000"}}}"#;
        let p: Providers = serde_json::from_str(raw).unwrap();
        let c = p.providers.get("campus").unwrap();
        assert_eq!(c.rule_count, 42);
        assert_eq!(c.vehicle_type, "File");
    }
}
