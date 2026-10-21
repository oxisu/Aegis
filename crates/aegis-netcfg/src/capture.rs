//! 采集当前非 WFP 网络设置作为"改前基线"。
//!
//! 两件事：
//! - **系统代理**：读 `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`
//!   的 `ProxyEnable` / `ProxyServer` / `ProxyOverride` / `AutoConfigURL`。
//! - **路由表**：`GetIpForwardTable2` 读 IPv4 全量，度量存**合成度量**
//!   （接口度量 + 路由度量偏移）——只存偏移会在还原后选路错（见下）。
//!
//! # ⚠ SYSTEM 上下文的 HKCU 陷阱（B4 已知限制，B7 解决）
//! aegisd 常以 `NT AUTHORITY\SYSTEM` 运行，此时读写的 `HKEY_CURRENT_USER`
//! 是 **SYSTEM 的** hive，**不是**登录用户的那份。而系统代理恰恰在
//! 用户 hive 里。所以：
//! - **路由**是机器全局的，SYSTEM 读/写都正确，B4 立即可用；
//! - **系统代理**要真正作用到登录用户，B7 必须加载对应用户的 hive
//!   （`RegLoadKey` + 离线 hive，或以用户上下文跑一个 helper）。
//!   B4 只把采集/写回的**函数**与**可逆笼子**立起来，此刻**不会**实际
//!   改任何用户的代理——因为 B4 没有任何触发点会调用写回（见 `guard`）。
//!
//! 度量陷阱复述（`aegis-sense/src/route.rs` 踩过）：`MIB_IPFORWARD_ROW2.Metric`
//! 只是"度量偏移"，自动度量下恒为 0；真正选路度量 = 接口度量 + 偏移。

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::ptr;

use windows::core::PCWSTR;
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::NetworkManagement::IpHelper::*;
use windows::Win32::Networking::WinSock::{AF_INET, SOCKADDR_INET};
use windows::Win32::System::Registry::{
    RegGetValueW, HKEY_CURRENT_USER, RRF_RT_REG_DWORD, RRF_RT_REG_SZ,
};

use aegis_model::{NetSnapshot, RouteEntry, SystemProxy};

use crate::error::NetCfgError;

const INTERNET_SETTINGS: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";

/// 采集一份完整快照。`now_ms` 由调用方给出（aegisd 统一时钟）。
pub fn capture(now_ms: u64) -> Result<NetSnapshot, NetCfgError> {
    let proxy = capture_proxy()?;
    let routes = capture_routes()?;
    Ok(NetSnapshot::new(now_ms, proxy, routes))
}

/// 读系统代理注册表。键不存在/值缺失时按"干净"处理（未启用、空串），
/// 因为"没有系统代理"本身就是合法的还原目标。
pub fn capture_proxy() -> Result<SystemProxy, NetCfgError> {
    let enabled = read_dword("ProxyEnable").unwrap_or(0) != 0;
    let server = read_string("ProxyServer").unwrap_or_default();
    let override_ = read_string("ProxyOverride").unwrap_or_default();
    let autoconfig_url = read_string("AutoConfigURL");

    Ok(SystemProxy {
        enabled,
        server,
        override_,
        autoconfig_url,
    })
}

/// 读 IPv4 路由表，度量存合成度量。
pub fn capture_routes() -> Result<Vec<RouteEntry>, NetCfgError> {
    let if_metrics = interface_metrics().unwrap_or_default();

    unsafe {
        let mut table: *mut MIB_IPFORWARD_TABLE2 = ptr::null_mut();
        let code = GetIpForwardTable2(AF_INET, &mut table);
        if code.0 != ERROR_SUCCESS.0 {
            return Err(NetCfgError::RoutesRead(format!(
                "GetIpForwardTable2 = {}",
                code.0
            )));
        }
        if table.is_null() {
            return Err(NetCfgError::RoutesRead("返回空表指针".into()));
        }

        let n = (*table).NumEntries as usize;
        let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), n);

        let mut out = Vec::with_capacity(n);
        for r in rows {
            let Some(next_hop) = sockaddr_inet_v4(&r.NextHop) else {
                continue;
            };
            let dest =
                sockaddr_inet_v4(&r.DestinationPrefix.Prefix).unwrap_or(Ipv4Addr::UNSPECIFIED);
            let interface_metric = if_metrics.get(&r.InterfaceLuid.Value).copied().unwrap_or(0);
            out.push(RouteEntry {
                destination: dest,
                prefix_len: r.DestinationPrefix.PrefixLength,
                next_hop,
                interface_luid: r.InterfaceLuid.Value,
                metric: interface_metric.saturating_add(r.Metric),
            });
        }

        FreeMibTable(table as *const core::ffi::c_void);
        Ok(out)
    }
}

/// 读取 IPv4 接口表，返回 `LUID → 接口度量`。
fn interface_metrics() -> Result<HashMap<u64, u32>, NetCfgError> {
    unsafe {
        let mut table: *mut MIB_IPINTERFACE_TABLE = ptr::null_mut();
        let code = GetIpInterfaceTable(AF_INET, &mut table);
        if code.0 != ERROR_SUCCESS.0 {
            return Err(NetCfgError::RoutesRead(format!(
                "GetIpInterfaceTable = {}",
                code.0
            )));
        }
        if table.is_null() {
            return Err(NetCfgError::RoutesRead("GetIpInterfaceTable 空表".into()));
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

/// 从 `SOCKADDR_INET` 里取 IPv4（与 `aegis-sense` 同款稳定内存布局法，
/// 不依赖 windows crate 的 union 表达方式）。
unsafe fn sockaddr_inet_v4(sa: &SOCKADDR_INET) -> Option<Ipv4Addr> {
    let p = sa as *const SOCKADDR_INET as *const u8;
    let family = u16::from_ne_bytes([*p, *p.add(1)]);
    if family != AF_INET.0 {
        return None;
    }
    Some(Ipv4Addr::new(*p.add(4), *p.add(5), *p.add(6), *p.add(7)))
}

/// 读一个 REG_DWORD 值；键/值不存在返回 `None`（不是错误）。
fn read_dword(value: &str) -> Option<u32> {
    let sub = to_wide(INTERNET_SETTINGS);
    let val = to_wide(value);
    let mut data: u32 = 0;
    let mut size = std::mem::size_of::<u32>() as u32;
    let status = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            PCWSTR(sub.as_ptr()),
            PCWSTR(val.as_ptr()),
            RRF_RT_REG_DWORD,
            None,
            Some(&mut data as *mut u32 as *mut core::ffi::c_void),
            Some(&mut size),
        )
    };
    if status.0 == ERROR_SUCCESS.0 {
        Some(data)
    } else {
        None
    }
}

/// 读一个 REG_SZ 值；键/值不存在返回 `None`。
fn read_string(value: &str) -> Option<String> {
    let sub = to_wide(INTERNET_SETTINGS);
    let val = to_wide(value);
    // 先探长度，再按需分配，避免固定缓冲区截断长 PAC URL。
    let mut size: u32 = 0;
    let probe = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            PCWSTR(sub.as_ptr()),
            PCWSTR(val.as_ptr()),
            RRF_RT_REG_SZ,
            None,
            None,
            Some(&mut size),
        )
    };
    if probe.0 != ERROR_SUCCESS.0 || size == 0 {
        return None;
    }
    let mut buf = vec![0u16; (size as usize).div_ceil(2)];
    let status = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            PCWSTR(sub.as_ptr()),
            PCWSTR(val.as_ptr()),
            RRF_RT_REG_SZ,
            None,
            Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
            Some(&mut size),
        )
    };
    if status.0 != ERROR_SUCCESS.0 {
        return None;
    }
    Some(from_wide(&buf))
}

/// UTF-16 空结尾宽串（含结尾 NUL）。
pub(crate) fn to_wide(s: &str) -> Vec<u16> {
    let mut v: Vec<u16> = s.encode_utf16().collect();
    v.push(0);
    v
}

/// 从含结尾 NUL 的宽串缓冲区还原 `String`（截到第一个 NUL）。
pub(crate) fn from_wide(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}
