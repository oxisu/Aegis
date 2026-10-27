//! HypoMux 监管（B7 · §9）。
//!
//! 仅负责 SCM 启停 `HypoMuxCore` 服务——Aegis 所管控的上游代理守护进程。
//! 本模块**不做**端口协调、不改它的配置、不与 Clash 做互斥仲裁（那些是
//! 后续阶段）。这里只有"要不要让这个服务跑起来"这件事。
//!
//! # ⚠ 授权边界（红线）
//!
//! 启动 / 停止上游代理会改变本机网络出口走向，属于**人拍板**的动作。
//! 本模块的函数**绝不**由 aegisd 启动 / 守护链路自动调用——它们只能由
//! 用户显式 `aegisctl hypomux start|stop|status`（且控制端已提权）经 IPC 危险
//! 命令闸门抵达。本项目约定：涉及上游代理启停的动作必须先取得用户明确同意。
//!
//! # 复用策略
//!
//! SCM 的 FFI 调用与服务宿主 `service.rs` 形态一致，但目标服务名不同
//! （`HypoMuxCore` vs `Aegis`），所以这里写一套**独立**的最小实现，而不是去
//! 改 `service.rs` 里那些已经测过的 `Aegis` 专属函数——改那边有回归风险。

use windows::core::PCWSTR;
use windows::Win32::Foundation::ERROR_SERVICE_DOES_NOT_EXIST;
use windows::Win32::System::Services::{
    CloseServiceHandle, ControlService, OpenSCManagerW, OpenServiceW, QueryServiceStatus,
    ENUM_SERVICE_TYPE, SC_HANDLE, SC_MANAGER_CONNECT, SERVICE_CONTROL_STOP, SERVICE_QUERY_STATUS,
    SERVICE_RUNNING, SERVICE_START, SERVICE_STATUS, SERVICE_STATUS_CURRENT_STATE, SERVICE_STOP,
    SERVICE_STOP_PENDING, SERVICE_WIN32_OWN_PROCESS,
};

use aegis_ipc::{DENY_PREFIX, OK_PREFIX};

/// HypoMux 上游代理在 SCM 里的服务名。
pub const HYPOMUX_SERVICE_NAME: &str = "HypoMuxCore";

/// 字符串转成以 NUL 结尾的 UTF-16（Win32 宽字符）。
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// 打开 SCM（只需连接权限；启动/停止的具体权限在打开服务时再申请）。
fn open_manager() -> Result<SC_HANDLE, String> {
    unsafe { OpenSCManagerW(None, None, SC_MANAGER_CONNECT) }
        .map_err(|e| format!("打开 SCM 失败（需要管理员权限）：{e}"))
}

/// 打开 `HypoMuxCore` 服务（带指定访问权限）。
///
/// 服务不存在时返回**人话**错误，而不是一串 Win32 错误码。
fn open_service(access: u32) -> Result<SC_HANDLE, String> {
    let scm = open_manager()?;
    let name = wide(HYPOMUX_SERVICE_NAME);
    let svc = unsafe { OpenServiceW(scm, PCWSTR(name.as_ptr()), access) };
    let _ = unsafe { CloseServiceHandle(scm) };
    svc.map_err(|e| {
        if e.code() == ERROR_SERVICE_DOES_NOT_EXIST.into() {
            format!("服务「{HYPOMUX_SERVICE_NAME}」未安装。")
        } else {
            format!("打开服务失败（需管理员权限）：{e}")
        }
    })
}

/// 以固定权限打开服务，执行一个动作，最后关句柄。
fn with_service_handle(
    access: u32,
    f: impl FnOnce(SC_HANDLE) -> Result<(), String>,
) -> Result<(), String> {
    let svc = open_service(access)?;
    let r = f(svc);
    let _ = unsafe { CloseServiceHandle(svc) };
    r
}

/// 启动 `HypoMuxCore` 服务（需管理员）。
///
/// ⚠ **红线动作**：只由 `aegisctl hypomux start` 触发，绝不自动调用。
pub fn start() -> String {
    match with_service_handle(SERVICE_START, |svc| unsafe {
        windows::Win32::System::Services::StartServiceW(svc, None)
            .map_err(|e| format!("启动 HypoMuxCore 失败：{e}"))
    }) {
        Ok(()) => format!("{OK_PREFIX}已向 SCM 请求启动 HypoMuxCore 服务。"),
        Err(e) => format!("{DENY_PREFIX}{e}"),
    }
}

/// 停止 `HypoMuxCore` 服务（需管理员）。
///
/// ⚠ 同上，红线动作。
pub fn stop() -> String {
    match with_service_handle(SERVICE_STOP, |svc| unsafe {
        let mut status = SERVICE_STATUS {
            dwServiceType: ENUM_SERVICE_TYPE(SERVICE_WIN32_OWN_PROCESS.0),
            dwCurrentState: SERVICE_STATUS_CURRENT_STATE(SERVICE_STOP_PENDING.0),
            dwControlsAccepted: 0,
            dwWin32ExitCode: 0,
            dwServiceSpecificExitCode: 0,
            dwCheckPoint: 0,
            dwWaitHint: 0,
        };
        ControlService(svc, SERVICE_CONTROL_STOP, &mut status)
            .map_err(|e| format!("停止 HypoMuxCore 失败：{e}"))
    }) {
        Ok(()) => format!("{OK_PREFIX}已向 HypoMuxCore 发出停止指令。"),
        Err(e) => format!("{DENY_PREFIX}{e}"),
    }
}

/// 查询 `HypoMuxCore` 服务状态（只读，普通用户也能查）。
///
/// 与 start/stop 不同，status 不要求提权——它只是 `SERVICE_QUERY_STATUS`，
/// 但 IPC 层仍把它判为危险命令（前缀 `hypomux `），所以控制端需以管理员
/// 运行才能走到这里；这是一致的保守策略，不放松。
pub fn status() -> String {
    let scm = match open_manager() {
        Ok(h) => h,
        Err(e) => return format!("{DENY_PREFIX}{e}"),
    };
    let name = wide(HYPOMUX_SERVICE_NAME);
    let svc = match unsafe { OpenServiceW(scm, PCWSTR(name.as_ptr()), SERVICE_QUERY_STATUS) } {
        Ok(h) => h,
        Err(e) if e.code() == ERROR_SERVICE_DOES_NOT_EXIST.into() => {
            let _ = unsafe { CloseServiceHandle(scm) };
            return format!("{DENY_PREFIX}服务「{HYPOMUX_SERVICE_NAME}」未安装。");
        },
        Err(e) => {
            let _ = unsafe { CloseServiceHandle(scm) };
            return format!("{DENY_PREFIX}打开服务失败：{e}");
        },
    };

    let mut st = SERVICE_STATUS {
        dwServiceType: ENUM_SERVICE_TYPE(0),
        dwCurrentState: SERVICE_STATUS_CURRENT_STATE(0),
        dwControlsAccepted: 0,
        dwWin32ExitCode: 0,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: 0,
    };
    let state = unsafe { QueryServiceStatus(svc, &mut st) }
        .map(|()| st.dwCurrentState)
        .ok();
    let _ = unsafe { CloseServiceHandle(svc) };
    let _ = unsafe { CloseServiceHandle(scm) };

    match state {
        Some(c) if c == SERVICE_RUNNING => format!("{OK_PREFIX}HypoMuxCore 正在运行。"),
        Some(_) => format!("{OK_PREFIX}HypoMuxCore 已安装，当前未运行。"),
        None => format!("{DENY_PREFIX}无法读取 HypoMuxCore 状态。"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_service_name_is_stable() {
        // 改名等于换了个服务，旧的要手动卸；这个常量必须稳定。
        assert_eq!(HYPOMUX_SERVICE_NAME, "HypoMuxCore");
    }

    /// 三个动作词都映射到危险命令；这里只验证它们被 [`risk_of`] 正确归类，
    /// 真正的 SCM 调用需要本机装有 HypoMuxCore 且管理员权限，不在此自动化。
    #[test]
    fn hypomux_subcommands_are_all_dangerous() {
        use aegis_ipc::peer::Risk;
        use aegis_ipc::risk_of;
        assert_eq!(risk_of("hypomux start"), Risk::Dangerous);
        assert_eq!(risk_of("hypomux stop"), Risk::Dangerous);
        assert_eq!(risk_of("hypomux status"), Risk::Dangerous);
    }
}
