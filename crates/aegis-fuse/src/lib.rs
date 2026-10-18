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
//! 结论是**先熔断、后分析**：第一个事件立刻切断，重活（指纹重算、存量连接
//! RST、角色重灌）等去抖窗口过去后交给异步 Worker 做**一次**。
//!
//! # 模块分层（务必保持）
//!
//! | 模块 | 依赖 Win32 | 职责 |
//! |---|---|---|
//! | [`debounce`] | 否 | 去抖与"先断后算"状态机 |
//! | [`notify`] | 否 | 变动分类与"该不该响应" |
//! | [`signal`] | 否 | 回调与消费者之间的无锁信号槽 |
//! | [`watch`] | **是** | `NotifyIpInterfaceChange` 的 FFI，**唯一的 unsafe** |
//!
//! 判断逻辑全部不碰 Win32，因此能脱离权限环境完整推演与单测；
//! `unsafe` 被压缩在 [`watch`] 一个文件里，且回调只做一次 `fetch_add`。

pub mod debounce;
pub mod error;
pub mod notify;
pub mod signal;
pub mod watch;

pub use debounce::{Reaction, ShockDebouncer, WINDOW_DEFAULT_MS, WINDOW_MAX_MS, WINDOW_MIN_MS};
pub use error::FuseError;
pub use notify::{should_react, ChangeKind};
pub use signal::ChangeSignal;
pub use watch::{now_ms, InterfaceWatcher, WatchFamily};

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

    /// 一条端到端的链路：回调侧记信号 → Worker 取走 → 去抖器立刻熔断
    /// → 窗口过后再叫醒 Worker 一次 → 确认后放行。
    ///
    /// 这是整个 crate 要表达的东西，钉在这里防止各模块各自演化后拼不起来。
    #[test]
    fn end_to_end_from_signal_to_release() {
        let signal = ChangeSignal::new();
        let mut fuse = ShockDebouncer::with_default_window();

        // 系统回调（真实实现里跑在系统线程池上）：连来三次
        signal.signal();
        signal.signal();
        signal.signal();
        assert_eq!(signal.pending(), 3);

        // Worker 取走并喂给去抖器
        let taken = signal.take();
        assert!(taken > 0);
        let first = fuse.on_change(now_ms());
        assert_eq!(first, Reaction::Trip, "第一个事件必须立刻熔断，不等去抖");
        assert!(fuse.is_insulated());

        // 窗口内继续震荡 → 合并
        for _ in 0..10 {
            signal.signal();
        }
        signal.take();
        let _ = fuse.on_change(now_ms() + 10);
        assert_eq!(fuse.coalesced_count(), 1, "后续震荡应被合并");

        // 窗口过去，叫醒 Worker 做重活（只一次）
        let t = now_ms() + 10;
        assert!(fuse.ready_to_recompute(t + 75));
        fuse.mark_recompute_signaled();
        assert!(!fuse.ready_to_recompute(t + 80));

        // 重算完毕、用户确认 → 放行
        fuse.release();
        assert!(!fuse.is_insulated());
    }
}
