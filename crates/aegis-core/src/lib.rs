//! `aegis-core` —— **Aegis（宙斯的神盾）** 的**编排核心**。
//!
//! 职责：把感知层给出的"拓扑事实"翻译成"该做什么"的决策——
//! 网卡角色裁决（§20.5）与编排器状态机（§26）。
//!
//! # 本 crate 的硬约束
//! 与感知层一脉相承，这里同样**只做纯逻辑计算**：
//!
//! - ✅ 读取拓扑快照，输出角色建议与状态迁移
//! - ❌ 不注入任何 WFP / 防火墙规则（那是 `aegis-wfp` 的事）
//! - ❌ 不启停任何进程或服务（含任何上层代理软件）
//! - ❌ 不修改注册表、系统代理、路由表
//! - ❌ 不需要管理员权限——所有逻辑都必须能在普通用户下单测与干跑
//!
//! 把策略层也保持"可只读干跑"，是为了能在校园网环境下安全地验证决策链路，
//! 而不必先拿到特权。**先能看懂它要做什么，再谈让它去做。**

pub mod guard;
pub mod role;
pub mod state;

// 数据模型随本 crate 一起透出：调用方拿到策略裁决所需的类型，
// 不必再单独依赖 aegis-model，也不会因此碰到 aegis-sense / windows。
pub use aegis_model as model;
pub use aegis_version as version;

pub use self::role::{
    adjudicate, adjudicate_all, Confidence, InterfaceRole, RoleDecision, RolePolicy, RoleTable,
};
pub use self::guard::{
    evaluate, Assertion, GuardAction, GuardFacts, GuardPolicy, GuardTracker, GuardVerdict,
    ProxyMode, DEFAULT_COOLDOWN_MS, DEFAULT_FAILURE_THRESHOLD, DEFAULT_FLAP_LIMIT_PER_HOUR,
    FLAP_WINDOW_MS,
};
pub use self::state::{awaits_user, insulation, Event, Insulation, State};
