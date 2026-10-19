//! `NotifyIpInterfaceChange` 的 FFI 层 —— **本 crate 唯一出现 `unsafe` 的模块**。
//!
//! # 分层：unsafe 只允许出现在这里
//!
//! 熔断的判断逻辑（去抖、先断后算、通知分类）全在 [`crate::debounce`] 与
//! [`crate::notify`]，是纯状态机。这里只负责"把系统回调搬进来"，并且
//! 严格遵守 §28.3 的**回调即弃**：
//!
//! ```text
//! 系统线程池回调 → ChangeKind::from_raw → should_react → signal.signal()
//!                                                          （一次 fetch_add）
//! ```
//!
//! 回调里**绝不**做这些事：分配内存、加锁、打日志、调 WFP、碰路由表。
//! 它跑在系统线程池上，堵住它的后果不是"慢一点"，而是网络栈死锁。
//!
//! # 为什么 `initialnotification` 传 false
//!
//! 传 true 的话，注册瞬间系统会把所有现存接口喂一遍，产生几十次回调。
//! 那不是"拓扑变了"，但它会触发熔断——结果就是**服务一启动就把网断了**，
//! 而日志上只写"检测到网口变动"，根本看不出为什么。
//! 所以宁可不要这份"初始快照"（开机时本来就要全量采一次拓扑）。
//!
//! # ⚠ 已知残留风险（接真实守护进程时必须处理）
//!
//! `CancelMibChangeNotify2` 返回后，理论上仍可能有极短窗口的回调在飞行中。
//! 当前实现用 `Arc` 持有信号槽，且 drop 顺序固定为"先取消、再释放"，
//! 把窗口压到最小，但没有完全消除。彻底的做法是回调里先把引用计数 +1
//! （需要一个全局注册表来存放这些 Arc），留到真正接 `aegisd` 时再做。

use std::ffi::c_void;
use std::sync::Arc;

use windows::Win32::Foundation::{BOOLEAN, HANDLE};
use windows::Win32::NetworkManagement::IpHelper::{
    CancelMibChangeNotify2, NotifyIpInterfaceChange, MIB_IPINTERFACE_ROW, MIB_NOTIFICATION_TYPE,
};
use windows::Win32::Networking::WinSock::{ADDRESS_FAMILY, AF_INET, AF_INET6, AF_UNSPEC};
use windows::Win32::System::SystemInformation::GetTickCount64;

use crate::debounce::{Reaction, ShockDebouncer};
use crate::error::FuseError;
use crate::notify::{should_react, ChangeKind};
use crate::signal::ChangeSignal;

/// 要监听的地址族。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WatchFamily {
    /// 两者都监听（默认）。Aegis 关心的是"任何一条默认路由的出现"，
    /// 只看 IPv4 会让 IPv6 隧道成为绕过绝缘笼的口子。
    #[default]
    Any,
    V4,
    V6,
}

impl WatchFamily {
    pub fn to_af(self) -> ADDRESS_FAMILY {
        match self {
            Self::Any => AF_UNSPEC,
            Self::V4 => AF_INET,
            Self::V6 => AF_INET6,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Any => "IPv4 + IPv6",
            Self::V4 => "仅 IPv4",
            Self::V6 => "仅 IPv6",
        }
    }
}

/// 单调毫秒时钟（给去抖状态机用）。
///
/// 用 `GetTickCount64` 而不是 `SystemTime`：后者会被 NTP 校正往回跳。
/// 去抖窗口对时钟回拨的处理见 [`crate::debounce::ShockDebouncer`]——
/// 回拨必须等价于"窗口已过"，否则 Worker 永远不被唤醒。
pub fn now_ms() -> u64 {
    unsafe { GetTickCount64() }
}

/// 系统回调。**回调即弃**：只做分类 → 判断 → 计数，其它一概不做。
unsafe extern "system" fn on_interface_change(
    callercontext: *const c_void,
    _row: *const MIB_IPINTERFACE_ROW,
    notificationtype: MIB_NOTIFICATION_TYPE,
) {
    if callercontext.is_null() {
        return;
    }
    let kind = ChangeKind::from_raw(notificationtype.0);
    if !should_react(kind) {
        return;
    }
    // 唯一的副作用：一次原子的 fetch_add。
    // 这里绝不能分配、加锁、打日志、碰 WFP。
    (*(callercontext as *const ChangeSignal)).signal();
}

/// 网口变动监听器（RAII：离开作用域自动取消注册）。
pub struct InterfaceWatcher {
    handle: Option<HANDLE>,
    family: WatchFamily,
    signal: Arc<ChangeSignal>,
}

impl InterfaceWatcher {
    /// 注册监听。**不需要管理员权限**，可以干跑验证。
    pub fn register(family: WatchFamily) -> Result<Self, FuseError> {
        let signal = Arc::new(ChangeSignal::new());
        // 指向 Arc 内部分配（不是结构体字段），因此后续移动 watcher 不影响它。
        let ctx = Arc::as_ptr(&signal) as *const c_void;

        let mut handle = HANDLE::default();
        let rc = unsafe {
            NotifyIpInterfaceChange(
                family.to_af(),
                Some(on_interface_change),
                Some(ctx),
                BOOLEAN(0), // 不要初始通知：那不是变动，响应它会开机即断网
                &mut handle,
            )
        };
        if rc.0 != 0 {
            return Err(FuseError::Register(rc.0));
        }
        Ok(Self {
            handle: Some(handle),
            family,
            signal,
        })
    }

    pub fn family(&self) -> WatchFamily {
        self.family
    }

    /// 信号槽（回调写入、Worker 取走）。
    pub fn signal(&self) -> &Arc<ChangeSignal> {
        &self.signal
    }

    /// 取走自上次调用以来累积的变动次数。
    pub fn take_change(&self) -> u64 {
        self.signal.take()
    }

    /// 把"取信号 → 喂给去抖器"这步固定下来，避免每个调用方各写一遍。
    ///
    /// 返回 `None` 表示这次轮询没有任何变动；
    /// 返回 `Some(Trip)` 表示**必须立刻拉绝缘**（去抖器保证第一个事件必 Trip）。
    pub fn drain_into(&self, debouncer: &mut ShockDebouncer) -> Option<Reaction> {
        let n = self.signal.take();
        if n == 0 {
            return None;
        }
        Some(debouncer.on_change(now_ms()))
    }

    /// 取消注册。幂等：重复调用安全。
    pub fn cancel(&mut self) -> Result<(), FuseError> {
        let Some(h) = self.handle.take() else {
            return Ok(());
        };
        let rc = unsafe { CancelMibChangeNotify2(h) };
        if rc.0 != 0 {
            return Err(FuseError::Cancel(rc.0));
        }
        Ok(())
    }
}

impl Drop for InterfaceWatcher {
    fn drop(&mut self) {
        // Drop 不能返回 Result，只能忽略。顺序很重要：先取消，再让 Arc 释放。
        let _ = self.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn family_maps_to_the_right_address_family() {
        assert_eq!(WatchFamily::Any.to_af(), AF_UNSPEC);
        assert_eq!(WatchFamily::V4.to_af(), AF_INET);
        assert_eq!(WatchFamily::V6.to_af(), AF_INET6);
    }

    /// 默认必须是 Any：只看 IPv4 会让 IPv6 隧道成为绕过绝缘笼的口子。
    #[test]
    fn default_family_watches_both() {
        assert_eq!(WatchFamily::default(), WatchFamily::Any);
        assert_eq!(WatchFamily::default().to_af(), AF_UNSPEC);
    }

    #[test]
    fn family_labels_are_readable() {
        assert_eq!(WatchFamily::Any.label(), "IPv4 + IPv6");
        assert_eq!(WatchFamily::V4.label(), "仅 IPv4");
        assert_eq!(WatchFamily::V6.label(), "仅 IPv6");
    }

    /// 时钟必须单调且不回退到起点之前——去抖依赖它判断窗口。
    #[test]
    fn now_ms_is_monotonic_across_calls() {
        let a = now_ms();
        let b = now_ms();
        assert!(b >= a, "{b} 应不小于 {a}");
        assert!(b > 0, "系统启动至今不应为 0 毫秒");
    }

    /// 注册→取消这条链路在本机（无需提权）就能跑通。
    /// 这是 FFI 层少数能自动化验证的部分，务必保留。
    #[test]
    fn register_and_cancel_works_without_elevation() {
        let mut w = InterfaceWatcher::register(WatchFamily::Any).expect("注册不需要管理员权限");
        assert_eq!(w.family(), WatchFamily::Any);
        assert_eq!(w.take_change(), 0, "刚注册且未变动时不应有计数");
        w.cancel().expect("取消应成功");
        // 幂等：重复取消不应报错
        w.cancel().expect("重复取消应安全");
    }

    /// 没有变动时 `drain_into` 必须返回 None ——
    /// 否则调用方会把"没动静"当成"要熔断"。
    #[test]
    fn drain_into_without_change_returns_none() {
        let w = InterfaceWatcher::register(WatchFamily::V4).expect("注册应成功");
        let mut d = ShockDebouncer::with_default_window();
        assert_eq!(w.drain_into(&mut d), None);
        assert!(!d.is_insulated(), "没有变动绝不能拉绝缘");
    }

    /// 有变动时 `drain_into` 必须触发 Trip（第一个事件不等去抖）。
    #[test]
    fn drain_into_with_change_trips_immediately() {
        let w = InterfaceWatcher::register(WatchFamily::V4).expect("注册应成功");
        let mut d = ShockDebouncer::with_default_window();
        w.signal().signal();
        w.signal().signal();
        assert_eq!(w.drain_into(&mut d), Some(Reaction::Trip));
        assert!(d.is_insulated(), "第一个事件必须立刻熔断");
    }
}
