//! `aegis-wfp` —— OS 级底座：Windows 筛选平台（WFP）的状态勘察。
//!
//! # 当前阶段：只读
//! 本 crate 现阶段**只做勘察**：打开引擎、枚举过滤器与 Provider、
//! 审计"清不掉的持久背板"。不添加、不修改、不删除任何 WFP 对象。
//!
//! 这不是保守，而是顺序问题：design-spec.md §28.2 记着一条能让整机变砖的
//! 地雷——装了一个清理不掉的持久 / Boot-Time 过滤器。这类东西不随进程退出
//! 消失，一旦写的是"全部 DROP"，服务崩了网照样不通，而用户此时已经没有
//! 任何界面可以把它删掉。所以**在下发任何规则之前，必须先看清机器上
//! 现在已经有什么**。这一步不需要任何权限，因此也必须最先做、最先测。
//!
//! # 为什么不依赖 aegis-core
//! 底座层（OS Level）不关心上层的角色策略：换一套策略不该牵动最靠近
//! 内核的这一层。规则下发时需要的只是"哪张网卡、哪个方向、放行还是阻断"。
//!
//! # 失败一律上报，不 panic
//! 守护进程 panic = 绝缘笼可能没装完 = fail-open 的那一瞬间。
//! 所有 Win32 / WFP 失败都带错误码向上传递（见 [`error::WfpError`]）。

pub mod error;
pub mod layers;
pub mod model;
pub mod plan;
pub mod session;

pub use error::WfpError;
pub use layers::{
    action_is_terminal, action_name, is_known, layer_name, layer_purpose, watched_layers,
};
pub use model::{
    audit_backbone, FilterFlags, FilterSummary, ProviderSummary, Risk, Snapshot, FLAG_BOOTTIME,
    FLAG_PERSISTENT,
};
pub use plan::{
    apply_order, cage_plan, is_safe, needs_confirmation, verify, Action, CagePolicy, Condition,
    FilterSpec, Finding, Layer, Severity, Tier, BROADCAST_V4, PORTS_BROADCAST_LEAK,
    PORT_DHCP_CLIENT, PORT_DHCP_SERVER, PORT_DNS, WEIGHT_MAX, W_BROADCAST_LOCK, W_DEFAULT_DENY,
    W_DHCP, W_DNS_LOCK, W_FLOW_DROP, W_LOOPBACK,
};
pub use session::{Session, SESSION_PREFIX};

use aegis_version as version;

/// 本 crate 所属项目的完整版本号。
pub fn full_version() -> String {
    version::full()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 版本号是运维排障时第一个要看的东西，串了会直接误导。
    /// 变异测试曾把它整个替换成空串/占位串而无人发现。
    #[test]
    fn full_version_is_the_project_version_not_a_placeholder() {
        let v = full_version();
        assert!(!v.is_empty(), "版本号不得为空");
        assert_ne!(v, "xyzzy", "版本号不得是占位串");
        assert_eq!(v, version::full(), "必须与 aegis-version 单一事实来源一致");
        // 形如 0.1.0-alpha.2+g<hash>
        assert!(v.starts_with("0."), "{v}");
        assert!(v.contains("alpha"), "{v}");
    }
}
