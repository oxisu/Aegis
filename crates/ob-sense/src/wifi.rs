//! 无线网 SSID 采集（只读）。
//!
//! 通过 Windows WLAN AutoConfig API（`wlanapi.dll`）读取每张无线网卡**当前已关联**的 SSID。
//! 这是拓扑指纹里 `SSID/Profile` 分量的唯一可靠来源（对应 design-spec.md §20.4）。
//!
//! 设计取舍：本模块**完全尽力而为**。若 WLAN 服务未启动、或调用被策略拒绝，
//! 直接返回 `Err`，让上层降级为"SSID 未知"，而不是让它拖垮整个拓扑采集流程。

use std::ffi::c_void;
use std::ptr;

use windows::core::GUID;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::WiFi::*;

use crate::error::{SenseError, Win32Error};

/// 已关联的 (接口 GUID, SSID) 列表。
pub fn connected_ssids() -> Result<Vec<(GUID, String)>, SenseError> {
    unsafe {
        let mut negotiated: u32 = 0;
        let mut handle = HANDLE::default();

        // WLAN API 客户端版本 2（Win Vista+）
        let rc = WlanOpenHandle(2, None, &mut negotiated, &mut handle);
        if rc != 0 {
            return Err(SenseError::Os {
                op: "WlanOpenHandle",
                code: Win32Error(rc),
            });
        }

        // RAII 守卫：保证任何提前返回路径都不会泄漏 Wlan 句柄
        let _guard = WlanHandleGuard { handle };

        let mut list: *mut WLAN_INTERFACE_INFO_LIST = ptr::null_mut();
        let rc = WlanEnumInterfaces(handle, None, &mut list);
        if rc != 0 {
            return Err(SenseError::Os {
                op: "WlanEnumInterfaces",
                code: Win32Error(rc),
            });
        }
        if list.is_null() {
            return Err(SenseError::Malformed {
                op: "WlanEnumInterfaces",
                detail: "返回空接口列表指针".into(),
            });
        }
        let _list_guard = WlanMemGuard {
            ptr: list as *const c_void,
        };

        let n = (*list).dwNumberOfItems as usize;
        let infos = std::slice::from_raw_parts((*list).InterfaceInfo.as_ptr(), n);

        let mut out = Vec::new();
        for info in infos {
            if let Some(ssid) = query_ssid(handle, &info.InterfaceGuid) {
                out.push((info.InterfaceGuid, ssid));
            }
        }
        Ok(out)
    }
}

/// 查询单个接口当前连接属性中的 SSID；失败返回 None（降级，不中断整体采集）。
unsafe fn query_ssid(handle: HANDLE, guid: &GUID) -> Option<String> {
    let mut data_size: u32 = 0;
    let mut data: *mut c_void = ptr::null_mut();

    let rc = WlanQueryInterface(
        handle,
        guid,
        wlan_intf_opcode_current_connection,
        None,
        &mut data_size,
        &mut data,
        None,
    );
    if rc != 0 || data.is_null() {
        return None;
    }
    let _guard = WlanMemGuard {
        ptr: data as *const c_void,
    };

    let attr = &*(data as *const WLAN_CONNECTION_ATTRIBUTES);
    let ssid = &attr.wlanAssociationAttributes.dot11Ssid;
    let len = (ssid.uSSIDLength as usize).min(ssid.ucSSID.len());
    if len == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&ssid.ucSSID[..len]).to_string())
}

/// Wlan 句柄 RAII 守卫。
struct WlanHandleGuard {
    handle: HANDLE,
}
impl Drop for WlanHandleGuard {
    fn drop(&mut self) {
        unsafe {
            if !self.handle.is_invalid() {
                let _ = WlanCloseHandle(self.handle, None);
            }
        }
    }
}

/// `WlanFreeMemory` RAII 守卫。
struct WlanMemGuard {
    ptr: *const c_void,
}
impl Drop for WlanMemGuard {
    fn drop(&mut self) {
        unsafe {
            if !self.ptr.is_null() {
                WlanFreeMemory(self.ptr);
            }
        }
    }
}
