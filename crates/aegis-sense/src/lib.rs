//! `aegis-sense` —— **Aegis（宙斯的神盾）** 的**感知层**
//! （对应 design-spec.md §3.1 感知层 / §20.4 拓扑指纹）。
//!
//! # 职责边界（硬约束，务必牢记）
//!
//! - ✅ 只读采集：网卡拓扑、SSID、网关、默认出口、拓扑指纹
//! - ❌ **绝不**注入任何 WFP / 防火墙规则（那是 `aegis-wfp` 的事）
//! - ❌ **绝不**启停任何进程或服务（含任何上层代理软件）
//! - ❌ **绝不**修改注册表、系统代理、路由表
//! - ❌ **绝不**要求管理员权限——感知层必须能在普通用户下安全干跑
//!
//! 把这几条作为硬约束，是为了让本 crate 成为 §20.6 五阶段自检流水线中
//! "阶段 2 系统拓扑采集" 的可信数据源，且在任何环境都能先跑起来验证。
//!
//! # 关于幽灵网卡
//! 长期插拔安卓 USB 有线共享（RNDIS）会让 Windows 每次生成新的 NET_LUID 并
//! 留下 `Present=False` 的设备残留，导致拓扑指纹在物理环境没变的情况下漂移，
//! 误触发"拓扑变更"告警。可用 `tools/clean-ghost-nics.ps1` 盘点与清理。

pub mod error;
pub mod fingerprint;
pub mod model;
pub mod route;
pub mod topology;
pub mod wifi;

pub use self::error::SenseError;
pub use self::fingerprint::{compute_fingerprint, hex};
pub use self::model::{InterfaceInfo, InterfaceRole, MacAddress, OperStatus, TopologySnapshot};
pub use self::route::default_egress;
pub use self::topology::snapshot;

// 把版本标识透出，调用方无需再单独依赖 aegis-version 就能拿到统一版本号
pub use aegis_version as version;

/// 本 crate 所属项目的完整版本号，例如 `0.1.0-alpha.1+g334165c`。
/// 日志与导出文件统一用这个函数取值，避免各处硬编码导致版本错配。
#[must_use]
pub fn aegis_version() -> String {
    version::full()
}
