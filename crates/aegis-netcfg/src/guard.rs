//! [`SnapshotGuard`]：把"任何非 WFP 网络改动"包进**可一键复原**的笼子。
//!
//! # 它保证什么（用户硬约束：别把配置改死，一切断网行为都要能一键复原）
//!
//! 1. **改前必有基线**：`arm()` 先采集一份快照；之后任何改动都由
//!    [`SnapshotGuard::apply_change`] 包起来，结构上不可能"先改后快照"。
//! 2. **一键复原**：[`SnapshotGuard::restore`] 把基线写回，幂等，可反复点。
//! 3. **变更失败自动回滚**：`apply_change` 里的改动闭包一旦报错，
//!    立刻把基线写回去——不会留下"改了一半"的断网状态。
//! 4. **退出/析构兜底**：进程正常退出（[`Drop`]）时若还处于"改过"状态，
//!    尽力还原一次。
//! 5. **崩溃（被强杀/断电）靠外部**：`Drop` 不会在 `taskkill`/蓝屏下执行，
//!    所以真正的兜底是 aegisd 把基线**落盘**（`mark_dirty` 前后由调用方负责），
//!    下次启动发现残留快照文件再还原。本 guard 只负责"进程内"的可逆性。
//!
//! ⚠ 守卫**只**在"改过"（`dirty`）时才写系统。没改过就 `restore` 是 no-op——
//! 绝不会因为"开了个守卫"就去碰一次注册表/路由。

use aegis_model::NetSnapshot;

use crate::backend::NetCfgBackend;
use crate::error::NetCfgError;

/// 非 WFP 网络设置的"改前快照 + 一键复原"守卫。
#[derive(Debug)]
pub struct SnapshotGuard<B: NetCfgBackend> {
    backend: B,
    /// 改前基线（`arm()` 时采集）。
    baseline: NetSnapshot,
    /// 是否已经改过（有待还原的改动）。
    dirty: bool,
}

impl<B: NetCfgBackend> SnapshotGuard<B> {
    /// 采集当前非 WFP 网络设置作为基线，进入"受保护"态。
    ///
    /// 采集失败不进入保护态：连"现在长什么样"都不知道，就没法还原。
    pub fn arm(backend: B) -> Result<Self, NetCfgError> {
        let baseline = backend.capture()?;
        Ok(Self {
            backend,
            baseline,
            dirty: false,
        })
    }

    /// 改前基线。
    pub fn baseline(&self) -> &NetSnapshot {
        &self.baseline
    }

    /// 是否已经改过（有待还原的改动）。未改过时 `restore` 是 no-op。
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// 手动把守卫标记为"改过"。
    ///
    /// ⚠ 调用方应在**落盘基线之后、真正改动系统之前**调用它——落盘是崩溃
    /// （无 `Drop`）时唯一的兜底，顺序反了会在"改了但没留基线"的窗口里
    /// 被强杀而无法复原。
    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    /// 把一次非 WFP 网络改动包起来：标记 dirty → 执行改动闭包。
    ///
    /// 改动闭包一旦报错，**立即**把基线写回去——绝不留"改了一半"的断网现场：
    /// - 回滚成功 → 视为干净（清 `dirty`）；
    /// - 回滚**也**失败 → 保持 `dirty`，交给 [`Drop`] 与落盘快照恢复兜底
    ///   （此时系统可能处于半改状态，绝不能谎报干净）。
    pub fn apply_change<F>(&mut self, mutate: F) -> Result<(), NetCfgError>
    where
        F: FnOnce() -> Result<(), NetCfgError>,
    {
        self.dirty = true;
        match mutate() {
            Ok(()) => Ok(()),
            Err(e) => {
                if self.restore_inner().is_ok() {
                    self.dirty = false;
                } else {
                    tracing::error!(
                        "变更失败且回滚基线也失败：系统可能残留非 WFP 改动（保持 dirty，靠 Drop/落盘快照兜底）"
                    );
                }
                Err(e)
            },
        }
    }

    /// **一键复原**：把基线写回系统。返回是否真的执行了写回。
    ///
    /// 幂等：未 `dirty` 时返回 `Ok(false)` 且**不碰系统**；已还原则再次
    /// 调用也是 no-op（`dirty` 已被清）。
    pub fn restore(&mut self) -> Result<bool, NetCfgError> {
        if !self.dirty {
            return Ok(false);
        }
        self.restore_inner()?;
        self.dirty = false;
        Ok(true)
    }

    fn restore_inner(&self) -> Result<(), NetCfgError> {
        self.backend.apply(&self.baseline)
    }
}

impl<B: NetCfgBackend> Drop for SnapshotGuard<B> {
    fn drop(&mut self) {
        // 退出兜底：仍 dirty 就尽力还原一次。失败只记日志——
        // 真正的兜底是落盘快照 + 下次启动恢复（Drop 不在强杀下执行）。
        if self.dirty {
            if let Err(e) = self.restore_inner() {
                tracing::error!(
                    error = %e,
                    "退出时还原非 WFP 网络设置失败；请检查残留，必要时用落盘快照恢复"
                );
            }
            self.dirty = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::RecordingBackend;
    use aegis_model::{RouteEntry, SystemProxy};
    use std::net::Ipv4Addr;

    fn snap(server: &str) -> NetSnapshot {
        NetSnapshot::new(
            1000,
            SystemProxy {
                enabled: !server.is_empty(),
                server: server.to_string(),
                ..SystemProxy::default()
            },
            vec![RouteEntry {
                destination: Ipv4Addr::UNSPECIFIED,
                prefix_len: 0,
                next_hop: Ipv4Addr::new(10, 0, 0, 1),
                interface_luid: 42,
                metric: 25,
            }],
        )
    }

    /// arm 必须先把基线采进来——"先改后快照"在类型上就不允许。
    #[test]
    fn arm_captures_baseline_and_starts_clean() {
        let backend = RecordingBackend::new(snap("http://base:1"));
        let g = SnapshotGuard::arm(&backend).unwrap();
        assert_eq!(g.baseline().proxy.server, "http://base:1");
        assert!(!g.is_dirty(), "刚 arm 应是干净态");
        assert!(backend.applied().is_empty(), "arm 阶段绝不该写系统");
    }

    /// 采集失败就不进入保护态——不知道现状就没法还原。
    #[test]
    fn arm_fails_when_capture_fails() {
        let backend = crate::backend::MockBackend::failing_capture();
        let r = SnapshotGuard::arm(&backend);
        assert!(matches!(r, Err(NetCfgError::ProxyRead(_))));
    }

    /// 没改过就 restore = no-op，**不碰系统**。开守卫本身不该改任何设置。
    #[test]
    fn restore_without_change_is_a_noop_that_touches_nothing() {
        let backend = RecordingBackend::new(snap("http://base:1"));
        let mut g = SnapshotGuard::arm(&backend).unwrap();
        let changed = g.restore().unwrap();
        assert!(!changed, "未改过不应报告'已还原'");
        assert!(backend.applied().is_empty(), "未改过绝不该写系统");
    }

    /// 改过 → 一键复原写回基线一次，并清 dirty；再次 restore 是 no-op（幂等）。
    #[test]
    fn restore_writes_baseline_once_then_is_idempotent() {
        let backend = RecordingBackend::new(snap("http://base:1"));
        let mut g = SnapshotGuard::arm(&backend).unwrap();
        g.mark_dirty();
        assert!(g.is_dirty());

        assert!(g.restore().unwrap(), "改过应执行还原");
        assert!(!g.is_dirty(), "还原后应清 dirty");
        assert_eq!(backend.applied().len(), 1, "应恰好写回一次");
        assert_eq!(backend.applied()[0].proxy.server, "http://base:1");

        assert!(!g.restore().unwrap(), "第二次应 no-op");
        assert_eq!(backend.applied().len(), 1, "幂等：不该再写");
    }

    /// apply_change 成功：闭包执行，守卫变 dirty。
    #[test]
    fn apply_change_runs_mutation_and_marks_dirty() {
        let backend = RecordingBackend::new(snap("http://base:1"));
        let mut g = SnapshotGuard::arm(&backend).unwrap();
        let mut ran = false;
        g.apply_change(|| {
            ran = true;
            Ok(())
        })
        .unwrap();
        assert!(ran, "变更闭包必须被执行");
        assert!(g.is_dirty());
    }

    /// apply_change 失败：**立即回滚**到基线，错误继续上抛。
    /// 这条是"别留改了一半的断网现场"的硬保证。
    #[test]
    fn apply_change_rolls_back_when_mutation_fails() {
        let backend = RecordingBackend::new(snap("http://base:1"));
        let mut g = SnapshotGuard::arm(&backend).unwrap();
        let e = g
            .apply_change(|| Err(NetCfgError::RoutesWrite("改到一半挂了".into())))
            .unwrap_err();
        assert!(matches!(e, NetCfgError::RoutesWrite(_)), "错误必须上抛");
        assert_eq!(backend.applied().len(), 1, "变更失败必须回滚写回基线一次");
        assert!(!g.is_dirty(), "回滚后应视为干净");
    }

    /// Drop 兜底：忘了显式 restore 就退出，只要还 dirty 就该还原一次。
    #[test]
    fn drop_restores_when_still_dirty() {
        let backend = RecordingBackend::new(snap("http://base:1"));
        {
            let mut g = SnapshotGuard::arm(&backend).unwrap();
            g.mark_dirty();
            // 不显式 restore，直接离开作用域触发 Drop
        }
        assert_eq!(
            backend.applied().len(),
            1,
            "Drop 应对仍 dirty 的守卫兜底还原一次"
        );
    }

    /// Drop 在未 dirty 时不该碰系统。
    #[test]
    fn drop_is_inert_when_clean() {
        let backend = RecordingBackend::new(snap("http://base:1"));
        {
            let _g = SnapshotGuard::arm(&backend).unwrap();
            // 只 arm，不改
        }
        assert!(backend.applied().is_empty(), "干净态 Drop 不该写系统");
    }

    /// 变更失败**且回滚也失败**：必须保持 dirty，绝不能谎报干净——
    /// 此时系统可能半改，交给 Drop / 落盘快照继续兜底。
    #[test]
    fn failed_rollback_keeps_dirty_and_never_claims_clean() {
        use std::cell::RefCell;
        let backend = RecordingBackend {
            captured: Some(snap("http://base:1")),
            applied: RefCell::new(Vec::new()),
            fail_apply: true,
        };
        let mut g = SnapshotGuard::arm(&backend).unwrap();
        let _ = g.apply_change(|| Err(NetCfgError::RoutesWrite("boom".into())));
        assert!(g.is_dirty(), "回滚也失败时必须保持 dirty，不能谎报干净");
    }
}
