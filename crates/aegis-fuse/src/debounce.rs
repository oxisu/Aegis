//! 拓扑震荡的去抖与"先熔断、后分析"（纯逻辑，不调用任何 Win32 API）。
//!
//! # 为什么这块逻辑必须单独抽出来并且能单测
//!
//! design-spec.md §28.3 记着一条叫"回调风暴"的地雷：插拔网线 / 连 Wi-Fi 时，
//! Windows 协议栈会产生**连续密集震荡**——`Media Disconnect → Media Connect
//! → Link-Local 分配 → DHCP ACK → 路由表多轮更新`，短时间内触发**数十次**
//! `NotifyIpInterfaceChange` 回调。
//!
//! 如果在回调里同步做高开销的事（WFP 规则重载 + `GetExtendedTcpTable`
//! 全量扫描），结果就是线程上下文拥堵、CPU 瞬间拉满、**网络栈死锁**。
//! 所以修正是"回调即弃 + 去抖 + 先断后算"：
//!
//! 1. **回调即弃**：回调里只置一个无锁 `AtomicBool`，不做任何复杂逻辑
//! 2. **先熔断**：**第一个**事件到来时立刻切到绝缘态——**不等去抖**，
//!    等了就等于给了 OS 一个用默认路由发包的窗口期
//! 3. **后分析**：指纹重算、存量连接 RST、角色重灌这些重活，等去抖窗口
//!    （50–100ms）过去之后交给异步 Worker 做**一次**
//!
//! 第 2 条是本模块最容易写错的地方：去抖写得太"聪明"，把第一个事件也
//! 给抖掉了，熔断就晚了一个窗口——而漏包恰恰发生在这几十毫秒里。
//! 所以这里的结构是"第一次必熔断，后续才合并"，而不是"攒够一批再处理"。
//!
//! # 为什么时钟是注入的
//!
//! 时间用 `u64` 毫秒从外部传入，函数不自己读时钟。这样整个状态机可以在
//! 普通单元测试里推演（包括时钟回拨这种边界），不需要真的等 75 毫秒，
//! 也不需要 mock 一个系统时钟。

/// 去抖窗口的建议下限（毫秒）。§20.3 指定 50–100ms。
pub const WINDOW_MIN_MS: u64 = 50;
/// 去抖窗口的建议上限（毫秒）。
pub const WINDOW_MAX_MS: u64 = 100;
/// 默认去抖窗口：取区间中点。
pub const WINDOW_DEFAULT_MS: u64 = 75;

/// 一次网口变动事件应当引发的动作。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reaction {
    /// **立刻熔断**：切换无锁绝缘标志，并开启去抖窗口。
    /// 这是"先断后算"里的"断"，绝不能延后。
    Trip,
    /// 窗口内的后续震荡：合并掉，不再触发任何动作。
    /// 不合并的话用户会被连续弹窗打断几十次。
    Coalesced,
}

/// 拓扑震荡熔断器（纯状态机）。
///
/// 真实实现里"是否已绝缘"是一个 `AtomicBool`（回调里无锁切换）；
/// 这里用普通 `bool` 表达同一件事，好让它能被单测推演。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShockDebouncer {
    window_ms: u64,
    insulated: bool,
    /// 去抖窗口的起点；`None` 表示当前没有在攒窗口
    window_start: Option<u64>,
    /// 本次窗口内被合并掉的事件数
    coalesced: u64,
    /// 是否已经向异步 Worker 发过重算信号。
    /// 不发这个标记的话，窗口过后的每一次 poll 都会叫醒 Worker 一次。
    recompute_signaled: bool,
}

impl ShockDebouncer {
    /// 新建，初始状态为**未绝缘**。
    pub fn new(window_ms: u64) -> Self {
        Self {
            window_ms,
            insulated: false,
            window_start: None,
            coalesced: 0,
            recompute_signaled: false,
        }
    }

    pub fn with_default_window() -> Self {
        Self::new(WINDOW_DEFAULT_MS)
    }

    pub fn window_ms(&self) -> u64 {
        self.window_ms
    }

    pub fn is_insulated(&self) -> bool {
        self.insulated
    }

    /// 本次窗口内被合并掉的事件数。
    pub fn coalesced_count(&self) -> u64 {
        self.coalesced
    }

    /// 收到一个网口变动事件。
    ///
    /// **第一个事件必定返回 [`Reaction::Trip`]**——熔断不能等去抖。
    pub fn on_change(&mut self, now_ms: u64) -> Reaction {
        if !self.insulated {
            // 先熔断：这一刻就切断，不等窗口攒满。
            self.insulated = true;
            self.window_start = Some(now_ms);
            self.coalesced = 0;
            self.recompute_signaled = false;
            return Reaction::Trip;
        }
        self.coalesced += 1;
        Reaction::Coalesced
    }

    /// 去抖窗口是否已过，且**还没有**叫醒过异步 Worker。
    ///
    /// 过了就该让 Worker 去重算指纹 / 强杀存量连接 / 重灌角色策略。
    /// 只报一次：否则 Worker 会被唤醒 N 次，等于没去抖。
    pub fn ready_to_recompute(&self, now_ms: u64) -> bool {
        if self.recompute_signaled {
            return false;
        }
        match self.window_start {
            None => false,
            Some(start) => elapsed(start, now_ms) >= self.window_ms,
        }
    }

    /// 标记"已经叫醒过 Worker 了"。由调用方在发出信号后调用。
    pub fn mark_recompute_signaled(&mut self) {
        self.recompute_signaled = true;
    }

    /// 异步 Worker 重算完毕、确认可以放行后调用：解除绝缘。
    pub fn release(&mut self) {
        self.insulated = false;
        self.window_start = None;
        self.coalesced = 0;
        self.recompute_signaled = false;
    }

    /// 无条件立刻拉起绝缘（例如收到 `PBT_APMSUSPEND` 合盖通知，§27.3）。
    pub fn trip(&mut self, now_ms: u64) {
        self.insulated = true;
        self.window_start = Some(now_ms);
        self.coalesced = 0;
        self.recompute_signaled = false;
    }
}

/// 计算时间差，**时钟回拨时返回 `u64::MAX`** 而不是下溢 panic。
///
/// 系统时钟会被 NTP 校正、会在休眠唤醒后跳变。如果直接 `now - start`，
/// `now < start` 时在 debug 下 panic、在 release 下静默绕回。
///
/// ⚠ 回拨**必须**等价于"窗口已过"，不能等价于"还没到"。写成
/// `saturating_sub`（回拨得到 0）看起来更"安全"，实际是个死局：
/// 窗口永远不满 → Worker 永远不被唤醒 → 用户一直断着网，
/// 而且没有任何报错。第一版就是这么写的，被单测抓出来。
/// 宁可早点重算，也不能让熔断卡死。
fn elapsed(start: u64, now: u64) -> u64 {
    if now >= start {
        now - start
    } else {
        u64::MAX
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **最重要的一条**：第一个事件必须立刻熔断，不能等去抖。
    /// 等了就等于给了 OS 一个用默认路由发包的窗口期——漏包恰恰发生在这里。
    #[test]
    fn first_event_trips_immediately() {
        let mut d = ShockDebouncer::with_default_window();
        assert!(!d.is_insulated());
        assert_eq!(d.on_change(1000), Reaction::Trip);
        assert!(d.is_insulated());
    }

    #[test]
    fn subsequent_events_are_coalesced_not_retripped() {
        let mut d = ShockDebouncer::with_default_window();
        assert_eq!(d.on_change(1000), Reaction::Trip);
        for i in 1..=30 {
            assert_eq!(
                d.on_change(1000 + i),
                Reaction::Coalesced,
                "窗口内的第 {i} 个事件应被合并"
            );
        }
        assert_eq!(d.coalesced_count(), 30);
    }

    /// 默认窗口必须落在 §20.3 规定的 50–100ms 区间内。
    /// 用 `const` 块断言：改错就在编译期炸，不用等测试跑。
    const _: () = {
        assert!(WINDOW_DEFAULT_MS >= WINDOW_MIN_MS);
        assert!(WINDOW_DEFAULT_MS <= WINDOW_MAX_MS);
        assert!(WINDOW_MIN_MS <= WINDOW_MAX_MS);
    };

    #[test]
    fn window_default_is_within_the_spec_range() {
        assert_eq!(WINDOW_MIN_MS, 50);
        assert_eq!(WINDOW_MAX_MS, 100);
        assert_eq!(ShockDebouncer::with_default_window().window_ms(), 75);
    }

    #[test]
    fn not_ready_to_recompute_before_the_window_elapses() {
        let mut d = ShockDebouncer::new(100);
        d.on_change(1000);
        assert!(!d.ready_to_recompute(1099), "窗口未满不该叫醒 Worker");
        assert!(d.ready_to_recompute(1100), "窗口满了就该叫醒");
    }

    /// 窗口**恰好**等于边界时算"已过"：去抖是上限，不是下限。
    #[test]
    fn window_boundary_is_inclusive() {
        let d = {
            let mut x = ShockDebouncer::new(50);
            x.on_change(0);
            x
        };
        assert!(!d.ready_to_recompute(49));
        assert!(d.ready_to_recompute(50));
        assert!(d.ready_to_recompute(51));
    }

    /// 只报一次：否则窗口过后的每一次 poll 都会叫醒 Worker，等于没去抖。
    #[test]
    fn recompute_is_signaled_only_once() {
        let mut d = ShockDebouncer::with_default_window();
        d.on_change(1000);
        assert!(d.ready_to_recompute(2000));
        d.mark_recompute_signaled();
        assert!(!d.ready_to_recompute(2001));
        assert!(!d.ready_to_recompute(9999));
    }

    #[test]
    fn no_window_means_never_ready_to_recompute() {
        let d = ShockDebouncer::with_default_window();
        assert!(!d.ready_to_recompute(u64::MAX));
    }

    #[test]
    fn release_clears_insulation_and_allows_the_next_trip() {
        let mut d = ShockDebouncer::with_default_window();
        d.on_change(1000);
        assert!(d.is_insulated());
        d.release();
        assert!(!d.is_insulated());
        assert_eq!(d.coalesced_count(), 0);
        // 解除后下一次变动必须重新熔断
        assert_eq!(d.on_change(2000), Reaction::Trip);
    }

    #[test]
    fn release_marks_recompute_as_unsignaled_again() {
        let mut d = ShockDebouncer::with_default_window();
        d.on_change(1000);
        d.mark_recompute_signaled();
        assert!(!d.ready_to_recompute(5000));
        d.release();
        d.on_change(6000);
        assert!(d.ready_to_recompute(6100), "新一轮窗口应重新可报");
    }

    /// 合盖通知：无条件立刻拉绝缘，不等任何去抖（§27.3）。
    #[test]
    fn explicit_trip_works_even_when_already_insulated() {
        let mut d = ShockDebouncer::with_default_window();
        d.on_change(1000);
        assert_eq!(d.on_change(1010), Reaction::Coalesced);
        assert_eq!(d.coalesced_count(), 1);

        // 已经绝缘了，但合盖通知要求无条件重新拉起并重置窗口
        d.trip(1500);
        assert!(d.is_insulated());
        assert_eq!(d.coalesced_count(), 0, "显式熔断应重置合并计数");
        assert!(!d.ready_to_recompute(1574));
        assert!(d.ready_to_recompute(1575), "显式熔断也开一个新的 75ms 窗口");
    }

    /// 时钟回拨不能 panic，也不能让熔断逻辑卡死。
    /// NTP 校正、休眠唤醒都会让时间跳变，这是真实会发生的。
    #[test]
    fn clock_rewind_does_not_panic_and_counts_as_elapsed() {
        let mut d = ShockDebouncer::with_default_window();
        d.on_change(5000);
        // 时钟往回跳了 4 秒
        assert!(
            d.ready_to_recompute(1000),
            "回拨应等价于窗口已过，而不是卡住"
        );
        assert_eq!(d.on_change(1001), Reaction::Coalesced);
        // 并且仍然处于绝缘态——回拨不能顺手把网放开了
        assert!(d.is_insulated());
    }

    /// 时钟跳到很远（比如休眠唤醒）也不能出问题。
    #[test]
    fn huge_clock_jump_is_handled() {
        let mut d = ShockDebouncer::with_default_window();
        d.on_change(1000);
        assert!(d.ready_to_recompute(u64::MAX));
        assert_eq!(d.on_change(u64::MAX), Reaction::Coalesced);
    }

    /// 回拨必须走"已过"这条分支而不是饱和到 0——饱和到 0 会让窗口永远
    /// 不满，Worker 永远不被唤醒，用户一直断网且不报错。
    #[test]
    fn elapsed_never_underflows() {
        assert_eq!(elapsed(100, 250), 150);
        assert_eq!(elapsed(100, 100), 0);
        assert_eq!(elapsed(100, 0), u64::MAX, "回拨应视为已过很久，不是下溢");
    }

    /// 一整轮真实场景：拔网线 → 密集震荡 → 窗口过去 → Worker 重算 → 放行。
    #[test]
    fn full_cycle_matches_the_design_narrative() {
        let mut d = ShockDebouncer::with_default_window();

        // 拔网线，协议栈开始密集震荡
        assert_eq!(d.on_change(1000), Reaction::Trip, "第一个事件立刻熔断");
        for i in 1..=25 {
            assert_eq!(d.on_change(1000 + i), Reaction::Coalesced);
        }
        assert_eq!(d.coalesced_count(), 25, "25 次震荡被合并成 1 次处理");

        // 窗口未满，Worker 不该被叫醒
        assert!(!d.ready_to_recompute(1050));

        // 窗口过去，叫醒 Worker 做重活
        assert!(d.ready_to_recompute(1075));
        d.mark_recompute_signaled();
        assert!(!d.ready_to_recompute(1080), "只叫醒一次");

        // Worker 重算完毕、用户确认后放行
        d.release();
        assert!(!d.is_insulated());

        // 之后又一次变动，重新走一遍
        assert_eq!(d.on_change(2000), Reaction::Trip);
    }
}
