//! 本 crate 的统一错误类型。

use thiserror::Error;

/// 非 WFP 网络设置采集/还原失败。
#[derive(Debug, Error)]
pub enum NetCfgError {
    /// 系统代理注册表读取失败（含 HKCU / 用户 hive 上下文问题）。
    #[error("系统代理注册表读取失败：{0}")]
    ProxyRead(String),
    /// 系统代理注册表写入失败。
    #[error("系统代理注册表写入失败：{0}")]
    ProxyWrite(String),
    /// 路由表读取失败（`GetIpForwardTable2`）。
    #[error("路由表读取失败：{0}")]
    RoutesRead(String),
    /// 路由表写入失败。
    #[error("路由表写入失败：{0}")]
    RoutesWrite(String),
    /// 快照文件（崩溃恢复用）读写失败。
    #[error("快照文件读写失败：{0}")]
    SnapshotFile(String),
    /// 没有可还原的快照：守卫未 arm，或已还原过。
    #[error("没有可还原的快照（守卫未 arm 或已还原）")]
    NoSnapshot,
}

impl NetCfgError {
    /// 包装成 `ProxyRead`，方便 `?` 链上把不同来源的错误收敛成一类。
    pub fn proxy_read(msg: impl Into<String>) -> Self {
        Self::ProxyRead(msg.into())
    }
    pub fn proxy_write(msg: impl Into<String>) -> Self {
        Self::ProxyWrite(msg.into())
    }
    pub fn routes_read(msg: impl Into<String>) -> Self {
        Self::RoutesRead(msg.into())
    }
    pub fn routes_write(msg: impl Into<String>) -> Self {
        Self::RoutesWrite(msg.into())
    }
}
