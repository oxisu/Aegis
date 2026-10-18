//! 网络拓扑事实的共享数据模型（**事实的类型**，不含任何采集能力）。
//!
//! # 这个 crate 为什么单独存在
//!
//! 分层铁律是「`aegis-sense` = 事实，`aegis-core` = 策略」。策略层只需要
//! **若干类型**（[`InterfaceInfo`] / [`InterfaceKind`] / [`if_flags`] …），
//! 不需要感知层的采集能力。但这些类型原先住在 `aegis-sense` 里，于是为了
//! 拿到 3 个类型，`aegis-core` 被迫依赖整个 `aegis-sense`，把 `windows`
//! crate 拖进了策略层的依赖图——实测让策略层的增量构建从 0.7s 涨到 22.5s。
//! 详见本 crate 的 `Cargo.toml` 注释。
//!
//! 下沉到这里之后：
//! - `aegis-sense` 产出这些类型（它是唯一真正需要 Win32 的层）
//! - `aegis-core` 消费这些类型，且**不再**依赖 Win32 —— 策略层终于真的
//!   可以脱离特权环境干跑，而不用先编译一遍 WFP 绑定
//!
//! # 为什么与 Windows API 类型解耦
//!
//! 这里只用标准库类型表达"网卡长什么样"（`u64` LUID、`u32` ifType、
//! `u8` 位域……），所有 `windows` crate 的 FFI 细节都收敛在 `aegis-sense`
//! 的 `topology` / `wifi` / `route` 三个模块里。这样模型可序列化、可测试，
//! 更换底层实现时不必改动上层。

use serde::Serialize;
use std::fmt;
use std::net::Ipv4Addr;

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

/// 网卡的**性质分类**。
///
/// 这个分类是拓扑指纹收敛的基础：WFP / QoS / 杀软等 NDIS 轻量过滤器
/// （LightWeight Filter）会为**每一张物理网卡**再派生出若干个伪接口，
/// 名字形如 `以太网 4-WFP Native MAC Layer LightWeight Filter-0000`。
/// 它们数量会随驱动装卸载变化，若计入指纹就会造成"物理环境没变、指纹却漂了"。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum InterfaceKind {
    /// 真实硬件网卡：以太网 / Wi-Fi / 移动宽带
    Physical,
    /// NDIS 过滤器派生出的伪接口（WFP / QoS / 第三方 LWF）
    Filter,
    /// 隧道接口：6to4 / Teredo / ISATAP / IP-HTTPS
    Tunnel,
    /// 回环
    Loopback,
    /// 其它虚拟网卡：Hyper-V 交换机、VPN TAP、WAN Miniport 等
    Virtual,
}

impl InterfaceKind {
    /// 是否参与拓扑指纹计算。过滤器伪接口一律排除。
    pub fn counts_for_fingerprint(&self) -> bool {
        !matches!(self, Self::Filter)
    }

    /// 是否为真实网卡（物理网卡才需要用户分配角色）。
    pub fn is_real(&self) -> bool {
        matches!(self, Self::Physical)
    }
}

impl fmt::Display for InterfaceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Physical => "物理",
            Self::Filter => "过滤器",
            Self::Tunnel => "隧道",
            Self::Loopback => "回环",
            Self::Virtual => "虚拟",
        };
        f.write_str(s)
    }
}

/// `MIB_IF_ROW2.InterfaceAndOperStatusFlags` 的位标志（netioapi.h）。
pub mod if_flags {
    /// 位 0：接口由硬件（真实网卡）承载
    pub const HARDWARE: u8 = 0x01;
    /// 位 1：接口是 NDIS 过滤器派生出的伪接口
    pub const FILTER: u8 = 0x02;
    /// 位 2：接口报告存在物理连接器（插了网线）
    pub const CONNECTOR_PRESENT: u8 = 0x04;
    /// 位 3：未通过 802.1X 认证
    pub const NOT_AUTHENTICATED: u8 = 0x08;
    /// 位 4：介质未连接
    pub const NOT_MEDIA_CONNECTED: u8 = 0x10;
    /// 位 5：接口被暂停
    pub const PAUSED: u8 = 0x20;
    /// 位 6：接口处于低功耗
    pub const LOW_POWER: u8 = 0x40;
    /// 位 7：端点接口
    pub const END_POINT: u8 = 0x80;
}

/// IANA `ifType` 常用取值（只列本项目判型需要的）。
pub mod if_type {
    pub const OTHER: u32 = 1;
    pub const ETHERNET_CSMACD: u32 = 6;
    pub const PPP: u32 = 23;
    pub const SOFTWARE_LOOPBACK: u32 = 24;
    pub const IEEE80211: u32 = 71;
    pub const TUNNEL: u32 = 131;
    /// 移动宽带（GSM）
    pub const WWANPP: u32 = 243;
    /// 移动宽带（CDMA）
    pub const WWANPP2: u32 = 244;
}

/// `NET_IF_ACCESS_TYPE`：1 = 回环，2 = 广播。
pub mod if_access {
    pub const LOOPBACK: u32 = 1;
    pub const BROADCAST: u32 = 2;
}

/// MAC 地址的稳定字符串表达：`AA-BB-CC-DD-EE-FF`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
    /// `MIB_IF_ROW2.InterfaceAndOperStatusFlags` 原始位域，
    /// 判定"物理网卡 vs 过滤器伪接口"的权威依据（见 [`if_flags`]）。
    pub flags: u8,
    /// `NET_IF_ACCESS_TYPE`；1 = 回环
    pub access_type: u32,
    /// `TUNNEL_TYPE`；0 = 非隧道
    pub tunnel_type: u32,
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
        self.if_type == if_type::IEEE80211
    }

    /// 是否由真实硬件承载（位 0 `NIIF_HARDWARE_INTERFACE`）。
    pub fn is_hardware(&self) -> bool {
        self.flags & if_flags::HARDWARE != 0
    }

    /// 是否为 NDIS 过滤器派生出的伪接口（位 1 `NIIF_FILTER_INTERFACE`）。
    pub fn is_filter(&self) -> bool {
        self.flags & if_flags::FILTER != 0
    }

    /// 是否报告插着网线（位 2 `NIIF_CONNECTOR_PRESENT`）。
    pub fn connector_present(&self) -> bool {
        self.flags & if_flags::CONNECTOR_PRESENT != 0
    }

    /// 是否为回环。
    pub fn is_loopback(&self) -> bool {
        self.if_type == if_type::SOFTWARE_LOOPBACK || self.access_type == if_access::LOOPBACK
    }

    /// 是否为隧道接口（6to4 / Teredo / ISATAP / IP-HTTPS）。
    pub fn is_tunnel(&self) -> bool {
        self.if_type == if_type::TUNNEL || self.tunnel_type != 0
    }

    /// 网卡性质分类。判定顺序刻意"先伪后真"：
    /// 过滤器伪接口同时也会带 `HARDWARE` 位（它挂在真实网卡之上），
    /// 因此必须先排除 Filter，否则 WFP 伪接口会被误判成物理网卡。
    pub fn kind(&self) -> InterfaceKind {
        if self.is_filter() {
            InterfaceKind::Filter
        } else if self.is_loopback() {
            InterfaceKind::Loopback
        } else if self.is_tunnel() {
            InterfaceKind::Tunnel
        } else if self.is_hardware() {
            InterfaceKind::Physical
        } else {
            InterfaceKind::Virtual
        }
    }

    /// 是否为真实物理网卡（只有这类网卡需要用户分配角色）。
    pub fn is_physical(&self) -> bool {
        self.kind() == InterfaceKind::Physical
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TopologySnapshot {
    pub interfaces: Vec<InterfaceInfo>,
    /// 默认出口网卡的 LUID（0 表示无默认路由）
    pub default_egress_luid: u64,
    /// SHA-256 拓扑指纹，格式与 §20.4 一致
    pub fingerprint: String,
    /// 本次指纹实际采用的参与集合；收敛后通常应为 [`FingerprintScope::Physical`]
    pub fingerprint_scope: FingerprintScope,
    /// 参与指纹计算的接口数量
    pub fingerprint_participants: usize,
}

impl TopologySnapshot {
    /// 参与指纹计算的接口（供上层复核/展示）。
    pub fn fingerprint_participants(&self) -> impl Iterator<Item = &InterfaceInfo> {
        let scope = self.fingerprint_scope;
        self.interfaces
            .iter()
            .filter(move |i| i.is_up() && scope.includes(i.kind()))
    }

    /// 全部真实物理网卡（无论 Up/Down）——上层分配角色时用它。
    pub fn physical_interfaces(&self) -> impl Iterator<Item = &InterfaceInfo> {
        self.interfaces.iter().filter(|i| i.is_physical())
    }
}

/// 拓扑指纹的**参与集合作用域**。
///
/// 首选 [`Physical`](Self::Physical)：只有真实硬件网卡参与，
/// 这样 WFP / QoS / 杀软这类 NDIS 过滤器伪接口的增减就不会引起指纹漂移。
/// 其余两档是降级兜底——宁可放宽范围，也绝不对空集算出指纹
/// （空集指纹会把"采集失败"伪装成"拓扑没变"）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum FingerprintScope {
    /// 仅真实物理网卡（首选）
    Physical,
    /// 放宽到所有非过滤器接口（物理 + 虚拟 + 隧道 + 回环）
    NonFilter,
    /// 兜底：所有 Up 接口
    AllUp,
}

impl FingerprintScope {
    /// 该作用域是否接受某类接口。
    pub fn includes(&self, kind: InterfaceKind) -> bool {
        match self {
            Self::Physical => kind == InterfaceKind::Physical,
            Self::NonFilter => kind.counts_for_fingerprint(),
            Self::AllUp => true,
        }
    }
}

impl fmt::Display for FingerprintScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Physical => "仅物理网卡",
            Self::NonFilter => "非过滤器接口",
            Self::AllUp => "全部 Up 接口（兜底）",
        };
        f.write_str(s)
    }
}
