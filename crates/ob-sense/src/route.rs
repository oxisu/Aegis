//! 路由表采集与"默认出口裁决"。
//!
//! 使用 `GetIpForwardTable2`（Win32 IP Helper，非轮询一次性快照）获取 IPv4 路由表。
//! 默认路由 = `DestinationPrefix.PrefixLength == 0`（即 0.0.0.0/0），
//! 多条默认路由并存时按 Metric 最小者裁决（Windows 真实的选路顺序）。

use std::net::Ipv4Addr;
use std::ptr;

use windows::Win32::NetworkManagement::IpHelper::*;
use windows::Win32::Networking::WinSock::{SOCKADDR_INET, AF_INET};

use crate::error::{SenseError, Win32Error};

/// 一条 IPv4 路由记录。
#[derive(Debug, Clone)]
pub struct RouteRow {
    pub interface_luid: u64,
    pub interface_index: u32,
    /// 目的前缀长度；0 表示默认路由
    pub dest_prefix_len: u8,
    /// 下一跳网关
    pub next_hop: Option<Ipv4Addr>,
    pub metric: u32,
}

/// 读取 IPv4 路由表。失败时返回 [`SenseError`]，绝不 panic。
pub fn ipv4_routes() -> Result<Vec<RouteRow>, SenseError> {
    unsafe {
        let mut table: *mut MIB_IPFORWARD_TABLE2 = ptr::null_mut();
        let code = GetIpForwardTable2(AF_INET, &mut table);
        if code.0 != 0 {
            return Err(SenseError::Os {
                op: "GetIpForwardTable2",
                code: Win32Error(code.0),
            });
        }
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
            out.push(RouteRow {
                interface_luid: r.InterfaceLuid.Value,
                interface_index: r.InterfaceIndex,
                dest_prefix_len: r.DestinationPrefix.PrefixLength,
                next_hop: sockaddr_inet_v4(&r.NextHop),
                metric: r.Metric,
            });
        }

        FreeMibTable(table as *const core::ffi::c_void);
        Ok(out)
    }
}

/// 裁决默认出口：所有默认路由（前缀长 0）中 Metric 最小者。
/// 无任何默认路由时返回 `Ok(None)`——这是合法状态（例如整机离线）。
pub fn default_egress() -> Result<Option<RouteRow>, SenseError> {
    let rows = ipv4_routes()?;
    let best = rows
        .into_iter()
        .filter(|r| r.dest_prefix_len == 0)
        .min_by_key(|r| r.metric);
    Ok(best)
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
    Some(Ipv4Addr::new(
        *p.add(4),
        *p.add(5),
        *p.add(6),
        *p.add(7),
    ))
}
