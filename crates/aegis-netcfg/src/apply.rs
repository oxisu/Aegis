//! 把一份快照**写回**系统（一键还原）。
//!
//! 分两半：
//! - **系统代理**：精确写回 `ProxyEnable` / `ProxyServer` / `ProxyOverride`
//!   / `AutoConfigURL`。这是真断网残留的高危项，必须逐字段还原。
//! - **路由表**：**best-effort** 重建捕获到的路由（度量交给系统自动）。
//!
//! # ⚠ 路由还原是 best-effort（B4 已知限制，B7 精确化）
//! "把整张路由表还原"在 Windows 上不可行：内核自管路由删不掉、盲目重建
//! 全表会冲突。B4 的做法是把捕获到的路由**尽力重建**（已存在则忽略），
//! 只为"消失的路由"兜底；真正"精确拆掉 Aegis 加的那几条"是 B7 的活
//! （记录改动 diff 再定向回滚）。度量一律传 0（自动），规避度量陷阱。
//!
//! # 同 capture：SYSTEM 的 HKCU 陷阱
//! 代理写回同样受 HKCU 上下文影响。B4 不提供触发点，此函数仅在
//! guard 判定"改过"后由 aegisd 调用；真正的用户上下文解决见 B7。

use std::net::Ipv4Addr;

use windows::core::PCWSTR;
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, IP_ADDRESS_PREFIX, MIB_IPFORWARD_ROW2,
};
use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows::Win32::Networking::WinSock::{AF_INET, SOCKADDR_INET};
use windows::Win32::System::Registry::{
    RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegSetValueExW, HKEY, HKEY_CURRENT_USER,
    KEY_SET_VALUE, REG_DWORD, REG_SZ,
};

use aegis_model::{NetSnapshot, RouteEntry, SystemProxy};

use crate::capture::to_wide;
use crate::error::NetCfgError;

const INTERNET_SETTINGS: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";

/// 把一份完整快照写回系统。
pub fn apply(snap: &NetSnapshot) -> Result<(), NetCfgError> {
    apply_proxy(&snap.proxy)?;
    apply_routes(&snap.routes)?;
    Ok(())
}

/// 精确写回系统代理。逐字段，缺失即还原为空/关闭。
pub fn apply_proxy(p: &SystemProxy) -> Result<(), NetCfgError> {
    write_dword("ProxyEnable", u32::from(p.enabled))?;
    write_string("ProxyServer", &p.server)?;
    write_string("ProxyOverride", &p.override_)?;
    match &p.autoconfig_url {
        Some(url) => write_string("AutoConfigURL", url)?,
        // 基线本就没有 PAC：删掉该值，而不是写个空串（空串 != 不存在）。
        None => {
            let _ = delete_value("AutoConfigURL");
        },
    }
    Ok(())
}

/// best-effort 重建捕获到的路由（度量自动，已存在则忽略）。
pub fn apply_routes(routes: &[RouteEntry]) -> Result<(), NetCfgError> {
    let mut failures = 0usize;
    for r in routes {
        let code = unsafe {
            let mut row: MIB_IPFORWARD_ROW2 = std::mem::zeroed();
            row.InterfaceLuid = NET_LUID_LH {
                Value: r.interface_luid,
            };
            row.DestinationPrefix = IP_ADDRESS_PREFIX {
                PrefixLength: r.prefix_len,
                Prefix: sockaddr_inet_v4(r.destination),
            };
            row.NextHop = sockaddr_inet_v4(r.next_hop);
            row.Metric = 0; // 交给系统自动度量，规避"偏移恒 0"陷阱
            CreateIpForwardEntry2(&row)
        };
        if code.0 != ERROR_SUCCESS.0 {
            // 单条失败不让整次还原否决——其它路由仍应尽力恢复。
            failures += 1;
        }
    }
    if failures > 0 {
        tracing::warn!(
            failures,
            total = routes.len(),
            "部分路由重建失败（best-effort）"
        );
    } else {
        tracing::debug!(count = routes.len(), "路由基线已重建");
    }
    Ok(())
}

/// 打开 `Internet Settings` 键用于写入。失败即上层错误。
fn open_for_write() -> Result<HKEY, NetCfgError> {
    let sub = to_wide(INTERNET_SETTINGS);
    let mut hkey = HKEY::default();
    let code = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(sub.as_ptr()),
            0,
            KEY_SET_VALUE,
            &mut hkey,
        )
    };
    if code.0 != ERROR_SUCCESS.0 {
        return Err(NetCfgError::ProxyWrite(format!(
            "RegOpenKeyExW({INTERNET_SETTINGS}) = {}",
            code.0
        )));
    }
    Ok(hkey)
}

fn write_string(value: &str, s: &str) -> Result<(), NetCfgError> {
    let hkey = open_for_write()?;
    let val = to_wide(value);
    let wide = to_wide(s);
    let bytes = wide_bytes(&wide);
    let code = unsafe { RegSetValueExW(hkey, PCWSTR(val.as_ptr()), 0, REG_SZ, Some(&bytes)) };
    let _ = unsafe { RegCloseKey(hkey) };
    if code.0 != ERROR_SUCCESS.0 {
        return Err(NetCfgError::ProxyWrite(format!(
            "写 {value} 失败 = {}",
            code.0
        )));
    }
    Ok(())
}

fn write_dword(value: &str, d: u32) -> Result<(), NetCfgError> {
    let hkey = open_for_write()?;
    let val = to_wide(value);
    let code = unsafe {
        RegSetValueExW(
            hkey,
            PCWSTR(val.as_ptr()),
            0,
            REG_DWORD,
            Some(&d.to_ne_bytes()),
        )
    };
    let _ = unsafe { RegCloseKey(hkey) };
    if code.0 != ERROR_SUCCESS.0 {
        return Err(NetCfgError::ProxyWrite(format!(
            "写 {value} 失败 = {}",
            code.0
        )));
    }
    Ok(())
}

fn delete_value(value: &str) -> Result<(), NetCfgError> {
    let hkey = open_for_write()?;
    let val = to_wide(value);
    let code = unsafe { RegDeleteValueW(hkey, PCWSTR(val.as_ptr())) };
    let _ = unsafe { RegCloseKey(hkey) };
    if code.0 != ERROR_SUCCESS.0 {
        // "值不存在"也是可接受的（本就干净），不当硬错误。
        tracing::debug!(
            value,
            code = code.0,
            "删除 AutoConfigURL：不存在或失败，忽略"
        );
    }
    Ok(())
}

/// 宽串 Vec 转小端字节（`RegSetValueExW` 的 REG_SZ 需要含结尾 NUL 的字节流）。
fn wide_bytes(wide: &[u16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(wide.len() * 2);
    for w in wide {
        out.extend_from_slice(&w.to_ne_bytes());
    }
    out
}

/// 由一个 IPv4 地址构造 `SOCKADDR_INET`（与 capture 同款稳定内存布局法：
/// `family(u16)@0 | port(u16)@2 | addr(4B)@4`，不碰 union 字段表达）。
unsafe fn sockaddr_inet_v4(addr: Ipv4Addr) -> SOCKADDR_INET {
    let mut bytes = [0u8; std::mem::size_of::<SOCKADDR_INET>()];
    bytes[0..2].copy_from_slice(&AF_INET.0.to_ne_bytes());
    bytes[4..8].copy_from_slice(&addr.octets());
    std::ptr::read(bytes.as_ptr() as *const SOCKADDR_INET)
}
