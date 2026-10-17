//! `ob-sense` —— InterBoot 编排器的**感知层**（对应 design-spec.md §3.1 感知层 / §20.4 拓扑指纹）。
//!
//! # 职责边界（硬约束，务必牢记）
//!
//! - ✅ 只读采集：网卡拓扑、SSID、网关、默认出口、拓扑指纹
//! - ❌ **绝不**注入任何 WFP / 防火墙规则（那是 `ob-netfilter` 的事）
//! - ❌ **绝不**启停任何进程或服务（含任何上层代理软件）
//! - ❌ **绝不**修改注册表、系统代理、路由表
//! - ❌ **绝不**要求管理员权限——感知层必须能在普通用户下安全干跑
//!
//! 把这几条作为硬约束，是为了让本 crate 成为 §20.6 五阶段自检流水线中
//! "阶段 2 系统拓扑采集" 的可信数据源，且在任何环境都能先跑起来验证。

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
