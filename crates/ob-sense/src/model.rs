//! 感知层数据模型。
//!
//! 设计与 Windows API 类型解耦：这里只用标准库类型表达"网卡长什么样"，
//! 所有 `windows` crate 的 FFI 细节都被收敛在 `topology` / `wifi` / `route` 三个模块里。
//! 这样做的好处是模型可序列化、可测试、可跨 ★ 模块复用，且更换底层实现时不必改动上层。

use serde::Serialize;
use std::fmt;
use std::net::Ipv4Addr;

/// 网卡角色（对应 design-spec.md §20.5 角色模型）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum InterfaceRole {
    /// 校园网接入：锁物理 53 / 广播端口，非白名单物理阻断
    CampusStrict,
    /// 热点 / PCE / 独立外网：自由出海
    FreeOutbound,
    /// 仅用于多网卡聚合的次级网卡
    Aggregated,
    /// 未知 / 未配置 / 违规网卡：绝对 DROP
    Isolated,
}

impl fmt::Display for InterfaceRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::CampusStrict => "校园网严格",
            Self::FreeOutbound => "自由出海",
            Self::Aggregated => "带宽聚合",
            Self::Isolated => "彻底绝缘",
        };
        f.write_str(s)
    }
}

/// 网卡运营状态（对应 Windows `IF_OPER_STATUS`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum OperStatus {
    Up,
    Down,
    Testing,
    Unknown,
    Dormant,
    NotPresent,
    LowerLayerDown,
}

/// MAC 地址的稳定字符串表达：`AA-BB-CC-DD-EE-FF`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    pub fn to_hex(&self) -> String {
        self.0
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join("-")
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// 一张网卡的完整感知信息（一次快照）。
#[derive(Debug, Clone, Serialize)]
pub struct InterfaceInfo {
    /// NET_LUID，稳定标识的首选
    pub luid: u64,
    /// 接口表索引
    pub index: u32,
    /// 网卡别名（Windows 里常作为"连接名"）
    pub alias: String,
    /// 驱动描述
    pub description: String,
    pub mac: Option<MacAddress>,
    /// `IF_TYPE_*`，例如 IF_TYPE_ETHERNET_CSMACD=6, IEEE80211=71
    pub if_type: u32,
    pub oper_status: OperStatus,
    /// 本机 IPv4 地址列表
    pub ipv4: Vec<Ipv4Addr>,
    /// 默认网关列表
    pub gateway: Vec<Ipv4Addr>,
    /// DHCPv4 服务器地址
    pub dhcp_server: Option<Ipv4Addr>,
    /// 已关联的 SSID（仅无线网卡有）
    pub ssid: Option<String>,
}

impl InterfaceInfo {
    /// 是否为无线网卡（IF_TYPE_IEEE80211 = 71）。
    pub fn is_wireless(&self) -> bool {
        self.if_type == 71
    }

    /// 参与拓扑指纹计算的接口是否成立：必须处于 Up 状态。
    pub fn is_up(&self) -> bool {
        self.oper_status == OperStatus::Up
    }

    /// 运营状态的简短文本，便于日志/CLI 输出。
    pub fn oper_status_str(&self) -> &'static str {
        match self.oper_status {
            OperStatus::Up => "Up",
            OperStatus::Down => "Down",
            OperStatus::Testing => "Testing",
            OperStatus::Unknown => "Unknown",
            OperStatus::Dormant => "Dormant",
            OperStatus::NotPresent => "NotPresent",
            OperStatus::LowerLayerDown => "LowerLayerDown",
        }
    }

    /// 指纹身份：优先 LUID，回退 MAC（对齐 design-spec.md §22 配置约定）。
    pub fn identity(&self) -> String {
        if self.luid != 0 {
            format!("LUID:{}", self.luid)
        } else if let Some(mac) = &self.mac {
            format!("MAC:{}", mac.to_hex())
        } else {
            format!("ALIAS:{}", self.alias)
        }
    }
}

/// 一次完整的拓扑快照。
#[derive(Debug, Clone, Serialize)]
pub struct TopologySnapshot {
    pub interfaces: Vec<InterfaceInfo>,
    /// 默认出口网卡的 LUID（0 表示无默认路由）
    pub default_egress_luid: u64,
    /// SHA-256 拓扑指纹，格式与 §20.4 一致
    pub fingerprint: String,
}
