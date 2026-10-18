//! `aegis-fuse` —— 微秒级拓扑震荡熔断器（§20.3 / §28.3）。
//!
//! # 它要解决的问题
//!
//! Aegis 的零信任模型是"拓扑一变就先断网"。但 Windows 协议栈在插拔网线、
//! 连 Wi-Fi 时会给出**连续密集震荡**：
//!
//! ```text
//! Media Disconnect → Media Connect → Link-Local 分配 → DHCP ACK → 路由表多轮更新
//! ```
//!
//! 短时间内触发**数十次** `NotifyIpInterfaceChange` 回调。这带来两个方向相反
//! 的失败：
//!
//! - **太敏感**：每一次都弹窗确认 → 用户被淹没 → 无脑点确认 → 零信任失效
//!   （和 `aegis-sense` 收敛指纹时防的"假漂移"是同一类危害）
//! - **太迟钝**：把第一个事件也去抖掉 → 熔断晚了一个窗口 →
//!   而漏包恰恰发生在这几十毫秒里
//!
//! 结论是**先熔断、后分析**：第一个事件立刻切断（微秒级，无锁），
//! 重活（指纹重算、存量连接 RST、角色重灌）等去抖窗口过去后交给异步
//! Worker 做**一次**。
//!
//! # 当前阶段：纯逻辑
//! [`debounce::ShockDebouncer`] 是完整的状态机，不依赖 Win32、不读系统
//! 时钟（时间从外部注入），因此可以脱离 Windows 权限环境完整单测，
//! 包括时钟回拨这类边界。真正接 `NotifyIpInterfaceChange` 的 FFI 层
//! 会在它之后单独加。

pub mod debounce;

pub use debounce::{Reaction, ShockDebouncer, WINDOW_DEFAULT_MS, WINDOW_MAX_MS, WINDOW_MIN_MS};

use aegis_version as version;

/// 本 crate 所属项目的完整版本号。
pub fn full_version() -> String {
    version::full()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_version_is_the_project_version_not_a_placeholder() {
        let v = full_version();
        assert!(!v.is_empty());
        assert_ne!(v, "xyzzy");
        assert_eq!(v, version::full());
        assert!(v.starts_with("0."), "{v}");
    }
}
