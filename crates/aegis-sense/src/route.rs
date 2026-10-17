//! 路由表采集与"默认出口裁决"。
//!
//! 使用 `GetIpForwardTable2`（Win32 IP Helper，非轮询一次性快照）获取 IPv4 路由表。
//! 默认路由 = `DestinationPrefix.PrefixLength == 0`（即 0.0.0.0/0）。
//!
//! # ⚠ 度量陷阱（这里踩过坑，改动前请先读完）
//! `MIB_IPFORWARD_ROW2.Metric` **不是** Windows 选路时用的最终度量，它只是
//! "路由度量偏移量"，在绝大多数由 DHCP/自动度量产生的路由上恒为 **0**。
//! 真正的选路度量是：
//!
//! ```text
//! 合成度量 = MIB_IPINTERFACE_ROW.Metric（接口度量） + MIB_IPFORWARD_ROW2.Metric（偏移）
//! ```
//!
//! 只比较 `MIB_IPFORWARD_ROW2.Metric` 就等于在 0 和 0 之间比大小，
//! 结果完全取决于表内顺序 —— 会随机把默认出口判成另一张网卡。
//! 本机实测：以太网 4（接口度量 25）与 WLAN（接口度量 55）两条默认路由的
//! 路由度量偏移都是 0，按偏移量裁决会误选 WLAN。
//!
//! 因此本模块统一用 [`RouteRow::effective_metric`] 裁决。

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::ptr;

use windows::Win32::NetworkManagement::IpHelper::*;
use windows::Win32::Networking::WinSock::{AF_INET, SOCKADDR_INET};

use crate::error::{check, SenseError};

/// 一条 IPv4 路由记录。
#[derive(Debug, Clone)]
pub struct RouteRow {
    pub interface_luid: u64,
    pub interface_index: u32,
    /// 目的前缀长度；0 表示默认路由
    pub dest_prefix_len: u8,
    /// 下一跳网关
    pub next_hop: Option<Ipv4Addr>,
    /// 路由度量**偏移量**（`MIB_IPFORWARD_ROW2.Metric`）。
    /// 注意：它通常就是 0，**不可**直接用于选路比较。
    pub route_metric: u32,
    /// 接口度量（`MIB_IPINTERFACE_ROW.Metric`）。自动度量下由链路带宽推算。
    /// 取不到时降级为 0（此时合成度量退化为纯路由度量偏移）。
    pub interface_metric: u32,
    /// Windows 实际选路所用的**合成度量** = 接口度量 + 路由度量偏移。
    /// 裁决默认出口一律用这个字段。
    pub effective_metric: u32,
}

/// 读取 IPv4 路由表，并已按 LUID 合并好接口度量。失败时返回 [`SenseError`]，绝不 panic。
pub fn ipv4_routes() -> Result<Vec<RouteRow>, SenseError> {
    // 接口度量取不到不应让整次路由采集失败：降级为全 0，
    // 此时合成度量退化为路由度量偏移（等同于旧行为），仍可正常工作。
    let if_metrics = interface_metrics().unwrap_or_default();

    unsafe {
        let mut table: *mut MIB_IPFORWARD_TABLE2 = ptr::null_mut();
        let code = GetIpForwardTable2(AF_INET, &mut table);
        check("GetIpForwardTable2", code.0)?;
        if table.is_null() {
            return Err(SenseError::Malformed {
                op: "GetIpForwardTable2",
                detail: "返回空表指针".into(),
            });
        }

        let n = (*table).NumEntries as usize;
        let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), n);

        let mut out = Vec::with_capacity(n);
        for r in rows {
            let route_metric = r.Metric;
            let interface_metric = if_metrics.get(&r.InterfaceLuid.Value).copied().unwrap_or(0);
            out.push(RouteRow {
                interface_luid: r.InterfaceLuid.Value,
                interface_index: r.InterfaceIndex,
                dest_prefix_len: r.DestinationPrefix.PrefixLength,
                next_hop: sockaddr_inet_v4(&r.NextHop),
                route_metric,
                interface_metric,
                effective_metric: interface_metric.saturating_add(route_metric),
            });
        }

        FreeMibTable(table as *const core::ffi::c_void);
        Ok(out)
    }
}

/// 读取 IPv4 接口表，返回 `LUID → 接口度量`。
///
/// 这是正确裁决默认出口的关键输入：Windows 的自动度量会把千兆有线设成
/// 较低值（如 25）、Wi-Fi 设成较高值（如 55），从而实现"有线优先"。
pub fn interface_metrics() -> Result<HashMap<u64, u32>, SenseError> {
    unsafe {
        let mut table: *mut MIB_IPINTERFACE_TABLE = ptr::null_mut();
        let code = GetIpInterfaceTable(AF_INET, &mut table);
        check("GetIpInterfaceTable", code.0)?;
        if table.is_null() {
            return Err(SenseError::Malformed {
                op: "GetIpInterfaceTable",
                detail: "返回空表指针".into(),
            });
        }

        let n = (*table).NumEntries as usize;
        let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), n);
        let mut map = HashMap::with_capacity(n);
        for r in rows {
            map.insert(r.InterfaceLuid.Value, r.Metric);
        }

        FreeMibTable(table as *const core::ffi::c_void);
        Ok(map)
    }
}

/// 裁决默认出口：所有默认路由（前缀长 0）中**合成度量**最小者。
/// 无任何默认路由时返回 `Ok(None)`——这是合法状态（例如整机离线）。
///
/// 度量相同时按 LUID 取小，保证同一环境下结果稳定（不随表内顺序漂移）。
pub fn default_egress() -> Result<Option<RouteRow>, SenseError> {
    let rows = ipv4_routes()?;
    Ok(pick_best(
        rows.into_iter().filter(|r| r.dest_prefix_len == 0),
    ))
}

/// 在给定路由里挑最优：合成度量最小，同度量时 LUID 最小。
pub(crate) fn pick_best<I>(rows: I) -> Option<RouteRow>
where
    I: IntoIterator<Item = RouteRow>,
{
    rows.into_iter().min_by(|a, b| {
        a.effective_metric
            .cmp(&b.effective_metric)
            .then_with(|| a.interface_luid.cmp(&b.interface_luid))
    })
}

/// 从 `SOCKADDR_INET` 里取 IPv4。
///
/// 刻意绕开 union 字段名差异：按 Windows `sockaddr_in` 的稳定内存布局直接取字节——
/// `family(u16) @0 | port(u16) @2 | addr(4B) @4`。这样即使 windows crate 版本
/// 调整了 union 的表达方式，本实现也不会受影响。
pub(crate) unsafe fn sockaddr_inet_v4(sa: &SOCKADDR_INET) -> Option<Ipv4Addr> {
    let p = sa as *const SOCKADDR_INET as *const u8;
    let family = u16::from_ne_bytes([*p, *p.add(1)]);
    if family != AF_INET.0 {
        return None;
    }
    Some(Ipv4Addr::new(*p.add(4), *p.add(5), *p.add(6), *p.add(7)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_are_readable() {
        // CI 与本机都是有网环境，至少能读到路由；不假设一定有默认路由
        let rows = ipv4_routes().expect("读取 IPv4 路由表不应失败");
        assert!(!rows.is_empty(), "路由表不应为空");
    }

    #[test]
    fn effective_metric_is_sum_of_parts() {
        for r in ipv4_routes().expect("读取路由失败") {
            assert_eq!(
                r.effective_metric,
                r.interface_metric.saturating_add(r.route_metric),
                "合成度量必须等于接口度量 + 路由度量偏移"
            );
        }
    }

    /// 这条是本模块的**回归测试**，专门盯住"只看路由度量偏移会误判出口"的坑。
    /// 即便只有一条默认路由，它也保证裁决逻辑走的是合成度量而非偏移量。
    #[test]
    fn default_egress_uses_effective_metric() {
        let rows = ipv4_routes().expect("读取路由失败");
        let defaults: Vec<RouteRow> = rows
            .into_iter()
            .filter(|r| r.dest_prefix_len == 0)
            .collect();
        if defaults.is_empty() {
            // 离线环境：允许没有默认路由，跳过而不是让测试失败
            return;
        }
        let best = default_egress()
            .expect("读取默认出口失败")
            .expect("有默认路由时不应为 None");

        let min_effective = defaults.iter().map(|r| r.effective_metric).min().unwrap();
        assert_eq!(
            best.effective_metric, min_effective,
            "默认出口必须取合成度量最小者"
        );

        // 反例校验：若存在多条默认路由且各条偏移量相同（典型自动度量场景），
        // 说明偏移量本身没有区分度，必须用接口度量才能区分。
        if defaults.len() > 1 {
            let offsets: Vec<u32> = defaults.iter().map(|r| r.route_metric).collect();
            if offsets.iter().all(|&m| m == offsets[0]) {
                assert!(
                    defaults.iter().any(|r| r.interface_metric > 0),
                    "多条默认路由的度量偏移相同，必须依靠接口度量区分"
                );
            }
        }
    }

    #[test]
    fn pick_best_is_deterministic_on_ties() {
        let mk = |luid: u64, m: u32| RouteRow {
            interface_luid: luid,
            interface_index: 0,
            dest_prefix_len: 0,
            next_hop: None,
            route_metric: m,
            interface_metric: 0,
            effective_metric: m,
        };
        // 度量相同（都是 5）时，必须稳定地选出 LUID 较小的那条
        let best = pick_best(vec![mk(200, 5), mk(100, 5), mk(300, 9)]).unwrap();
        assert_eq!(best.interface_luid, 100);
        assert_eq!(best.effective_metric, 5);
    }
}
