//! `aegis-netcfg` —— **非 WFP 网络设置**的采集 / 还原执行层。
//!
//! 这是 B4（网络设置变更前的快照 + 退出还原）的**执行**一半，与
//! `aegis-sense`（只读事实层）对称：这里负责"改前基线采集"与"还原写回"。
//!
//! # 还原范围（design-spec §6 / §16 / §F6）
//! WFP 防火墙 / kill-switch 走**动态会话**，进程死亡时内核自动清空，
//! **不需要**快照。本 crate 只管两类**非 WFP** 项——它们在进程退出后
//! 不会消失，留半截就是真断网：
//! - **系统代理**（`HKCU\...\Internet Settings`）
//! - **路由表**（IPv4）
//!
//! # 用户硬约束如何被满足
//! "别把配置改死，一切断网行为都要能一键复原"由 [`SnapshotGuard`] 保证：
//! 改前快照、一键 [`SnapshotGuard::restore`]、变更失败自动回滚、退出兜底、
//! 且**只在改过时才碰系统**。见 [`guard`] 模块文档。
//!
//! # 分层
//! 依赖 `aegis-model`（快照类型，零 Win32）与 `aegis-version`（标识），
//! **不**依赖 `aegis-core` / `aegis-config` / `aegis-sense`——策略层与配置层
//! 保持零 Win32，可脱离特权环境干跑。

pub mod apply;
pub mod backend;
pub mod capture;
pub mod error;
pub mod guard;
pub mod persist;

pub use backend::{MockBackend, NetCfgBackend, RecordingBackend};
pub use capture::capture;
pub use error::NetCfgError;
pub use guard::SnapshotGuard;
pub use persist::{clear_baseline, load_baseline, save_baseline};

/// 真实 Windows 后端：读当前系统代理 + 路由表，写回一份快照。
///
/// `now_ms` 是采集时钟（由 aegisd 统一给定，便于把快照时间与审计对齐）。
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsBackend {
    pub now_ms: u64,
}

impl WindowsBackend {
    pub fn new(now_ms: u64) -> Self {
        Self { now_ms }
    }
}

impl NetCfgBackend for WindowsBackend {
    fn capture(&self) -> Result<aegis_model::NetSnapshot, NetCfgError> {
        capture::capture(self.now_ms)
    }

    fn apply(&self, snap: &aegis_model::NetSnapshot) -> Result<(), NetCfgError> {
        apply::apply(snap)
    }
}
