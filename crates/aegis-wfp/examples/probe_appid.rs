//! **只读探针**：确认 WFP 里"服务"到底怎么表达。
//!
//! ```text
//! cargo run -p aegis-wfp --example probe_appid
//! ```
//!
//! # 为什么要有这个探针
//!
//! `FwpmFilterAdd0` 返回 `0x80320027`（`FWP_E_TYPE_MISMATCH`）暴露了一件事：
//! 我们把"按服务放行"翻译成了 `ALE_APP_ID` + `UINT64(pid)`，而
//! `ALE_APP_ID` 的真实类型是**字节 blob**，不是整数。
//!
//! 那么"绑定到某个服务"到底该怎么表达？社区里有两种说法：
//!
//! 1. 传**服务短名**（如 `Dhcp`）给 `FwpmGetAppIdFromFileName0`；
//! 2. 传**服务宿主的可执行文件路径**（如 `svchost.exe`）。
//!
//! 这两种说法给出的 blob **不一样**，选错的下场是规则装得上、但永远不匹配，
//! 表现就是开机即断网。所以不猜——用引擎自己算出来的 blob 来回答。
//!
//! # 安全性
//!
//! 本探针**只查询，不添加、不修改、不删除任何 WFP 对象**。
//! 它会打开一个动态会话（需要提权），仅此而已。

use std::ptr;

use windows::core::PCWSTR;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform as wfp;

fn main() {
    println!("Aegis · WFP AppId 只读探针");
    println!("⚠ 本程序不添加/修改/删除任何 WFP 对象。");
    println!();

    let mut handle = windows::Win32::Foundation::HANDLE::default();
    let mut name: Vec<u16> = "aegis-probe"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut desc: Vec<u16> = "read-only".encode_utf16().chain(std::iter::once(0)).collect();
    let session = wfp::FWPM_SESSION0 {
        sessionKey: windows::core::GUID::zeroed(),
        displayData: wfp::FWPM_DISPLAY_DATA0 {
            name: windows::core::PWSTR(name.as_mut_ptr()),
            description: windows::core::PWSTR(desc.as_mut_ptr()),
        },
        flags: wfp::FWPM_SESSION_FLAG_DYNAMIC,
        ..Default::default()
    };
    let rc = unsafe {
        wfp::FwpmEngineOpen0(
            PCWSTR::null(),
            10, // RPC_C_AUTHN_WINNT
            None,
            Some(&session),
            &mut handle,
        )
    };
    if rc != 0 {
        println!("[FATAL] 打开 WFP 引擎失败：0x{rc:08X}（多半是没提权）");
        return;
    }
    println!("已打开动态会话（只读查询）。");
    println!();

    // ── 1. 服务短名 ──────────────────────────────────────────────────
    for svc in ["Dhcp", "Dnscache", "Schedule", "完全不存在的服务"] {
        probe(svc);
    }
    println!();

    // ── 2. 服务宿主的可执行文件路径 ──────────────────────────────────
    for path in [
        r"C:\Windows\system32\svchost.exe",
        r"C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p",
        r"C:\Windows\System32\dhcpcore.dll",
        r"C:\Windows\System32\notepad.exe",
    ] {
        probe(path);
    }

    unsafe {
        let _ = wfp::FwpmEngineClose0(handle);
    }
}

fn probe(what: &str) {
    let mut wide: Vec<u16> = what.encode_utf16().chain(std::iter::once(0)).collect();
    let mut blob: *mut wfp::FWP_BYTE_BLOB = ptr::null_mut();
    let rc = unsafe {
        wfp::FwpmGetAppIdFromFileName0(PCWSTR(wide.as_mut_ptr()), &mut blob)
    };
    if rc != 0 || blob.is_null() {
        println!("  {what:<60} → 失败 0x{rc:08X}");
        return;
    }
    let (size, data) = unsafe {
        let b = &*blob;
        (
            b.size,
            std::slice::from_raw_parts(b.data, b.size as usize),
        )
    };
    println!("  {:<60} → {size} 字节  {}", truncate(what, 60), preview(data));
    unsafe {
        wfp::FwpmFreeMemory0(&mut blob as *mut _ as *mut *mut core::ffi::c_void);
    }
}

/// 打印前若干字节。**刻意同时打印 UTF-16 文本与 hex**：
/// 只看 hex 看不出这是路径还是服务名，而"它到底是什么"正是本探针要回答的。
fn preview(data: &[u8]) -> String {
    let head: Vec<u16> = data
        .chunks_exact(2)
        .take(48)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let text = String::from_utf16_lossy(&head);
    let hex: String = data.iter().take(16).map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ");
    format!("{:?} | {hex}", text.trim_end_matches('\0'))
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let head: String = s.chars().take(max - 1).collect();
    format!("{head}…")
}
