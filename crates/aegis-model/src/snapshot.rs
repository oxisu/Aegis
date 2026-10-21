//! 网络设置快照：**非 WFP 项**的"改前基线"。
//!
//! B4 的范围由 design-spec.md 钉死（§6 / §16 / §F6）：WFP 防火墙 / kill-switch
//! 走**动态会话**（`FWPM_SESSION_FLAG_DYNAMIC`），进程死亡时内核自动瞬时清空
//! 全部规则，天然防断网残留，**不需要**快照回滚。真正需要"变更前快照 + 退出/
//! 崩溃还原"的，只有**系统代理注册表**与**路由表**这两类非 WFP 项——它们不是
//! WFP 规则，不会随进程退出而消失，一旦留下半截改动就是真断网。
//!
//! # 本模块只定义**纯数据**，不碰任何 Win32
//!
//! 真正的采集（读注册表 / `GetIpForwardTable2`）与写回，在 `aegis-netcfg`
//! ——那个 crate 才依赖 `windows`。把类型放在这里，是为了让策略层（`aegis-core`）
//! 与 IPC / 落盘 / 展示都能拿到快照结构，而不必把 `windows` 拖进自己的依赖图
//! （与 `InterfaceInfo` 下沉到 `aegis-model` 是同一条纪律）。

use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

/// Windows 系统代理设置（`HKCU\...\Internet Settings`）。
///
/// 只收录本项目可能改动、因而需要能还原的字段：
/// `ProxyEnable` / `ProxyServer` / `ProxyOverride` / `AutoConfigURL`。
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SystemProxy {
    /// `ProxyEnable`：是否启用系统代理。
    pub enabled: bool,
    /// `ProxyServer`：例如 `http=127.0.0.1:7890;https=127.0.0.1:7890`
    /// 或统一形式 `127.0.0.1:7890`。未启用时通常为空串。
    pub server: String,
    /// `ProxyOverride`：绕过代理的地址列表（分号分隔），例如 `<local>`。
    ///
    /// JSON 侧用 `override`（`override` 是 Rust 关键字，故字段名用 `override_`，
    /// 序列化时 rename 回来）。
    #[serde(default, rename = "override")]
    pub override_: String,
    /// `AutoConfigURL`：PAC 自动配置脚本地址，未设置时为 `None`。
    #[serde(default)]
    pub autoconfig_url: Option<String>,
}

impl SystemProxy {
    /// 是否为"干净"状态：未启用、无服务器、无 PAC。
    ///
    /// 还原时用来判断"是否真的需要写回"——若基线本就干净，
    /// 强行写一串空值既无意义又多一次注册表 I/O。
    pub fn is_clean(&self) -> bool {
        !self.enabled && self.server.is_empty() && self.autoconfig_url.is_none()
    }
}

/// 一条 IPv4 路由（来自 `GetIpForwardTable2`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteEntry {
    /// 目的网络。
    pub destination: Ipv4Addr,
    /// 前缀长度；0 = 默认路由（`0.0.0.0/0`）。
    pub prefix_len: u8,
    /// 下一跳网关。
    pub next_hop: Ipv4Addr,
    /// 出口接口的 NET_LUID。
    pub interface_luid: u64,
    /// 选路度量（**合成度量** = 接口度量 + 路由度量偏移）。
    ///
    /// ⚠ 采集侧必须存合成度量，不能只存 `MIB_IPFORWARD_ROW2.Metric`——
    /// 那只是"度量偏移"，自动度量下恒为 0，还原后选路会错（见
    /// `aegis-sense` 的度量陷阱说明）。
    pub metric: u32,
}

/// 一次完整的"非 WFP 网络设置"快照。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetSnapshot {
    /// 采集时刻（Unix 毫秒）。
    ///
    /// 崩溃恢复时用它判断一份残留快照是否过于陈旧——若采集时间远早于
    /// 进程崩溃时间，多半是上一轮遗留，绝不该拿来"还原"到一台网络已变的机器上。
    pub taken_at_ms: u64,
    /// 系统代理基线。
    pub proxy: SystemProxy,
    /// 路由表基线（IPv4 全量）。
    pub routes: Vec<RouteEntry>,
}

impl NetSnapshot {
    pub fn new(taken_at_ms: u64, proxy: SystemProxy, routes: Vec<RouteEntry>) -> Self {
        Self {
            taken_at_ms,
            proxy,
            routes,
        }
    }

    /// 是否含任何需要还原的内容。空快照（无路由、代理干净）不值得写回。
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty() && self.proxy.is_clean()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> NetSnapshot {
        NetSnapshot::new(
            1_769_000_000_000,
            SystemProxy {
                enabled: true,
                server: "http=127.0.0.1:7890;https=127.0.0.1:7890".to_string(),
                override_: "<local>".to_string(),
                autoconfig_url: None,
            },
            vec![
                RouteEntry {
                    destination: Ipv4Addr::new(0, 0, 0, 0),
                    prefix_len: 0,
                    next_hop: Ipv4Addr::new(192, 168, 1, 1),
                    interface_luid: 1_689_399_631_429_632,
                    metric: 25,
                },
                RouteEntry {
                    destination: Ipv4Addr::new(192, 168, 1, 0),
                    prefix_len: 24,
                    next_hop: Ipv4Addr::new(192, 168, 1, 1),
                    interface_luid: 1_689_399_631_429_632,
                    metric: 25,
                },
            ],
        )
    }

    /// 快照要能无损 JSON 往返：它是落盘崩溃恢复与过 IPC 展示的唯一载体，
    /// 字段丢一个，"还原"就会还原成一台错的网络。
    #[test]
    fn json_round_trip_preserves_every_field() {
        let snap = sample();
        let json = serde_json::to_string(&snap).expect("序列化不应失败");
        let back: NetSnapshot = serde_json::from_str(&json).expect("反序列化不应失败");
        assert_eq!(back, snap);
    }

    /// `override` 是 Rust 关键字，字段名用 `override_`；但 JSON 侧必须
    /// 还原成 `override`，否则写回 / 展示会对不上 Windows 的键名。
    #[test]
    fn override_key_serializes_as_windows_name() {
        let json = serde_json::to_string(&sample()).expect("序列化不应失败");
        assert!(
            json.contains("\"override\":"),
            "应为 override，实际：{json}"
        );
    }

    /// 默认系统代理必须判定为"干净"——这是"无需写回"的判据。
    #[test]
    fn default_proxy_is_clean_and_empty_snapshot() {
        let empty = NetSnapshot::new(0, SystemProxy::default(), Vec::new());
        assert!(empty.proxy.is_clean());
        assert!(empty.is_empty());
    }

    /// 只要有一项非干净/非空，就不算空快照，必须走还原。
    #[test]
    fn any_nonclean_item_makes_snapshot_nonempty() {
        let dirty_proxy = NetSnapshot::new(
            0,
            SystemProxy {
                enabled: true,
                ..SystemProxy::default()
            },
            Vec::new(),
        );
        assert!(!dirty_proxy.is_empty());

        let with_routes = NetSnapshot::new(0, SystemProxy::default(), sample().routes);
        assert!(!with_routes.is_empty());
    }
}
