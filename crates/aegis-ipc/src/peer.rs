//! **对端身份检查**：token 之外那道门（命令分级授权）。
//!
//! # 为什么光有 token 不够
//!
//! `TOKEN_FILE_SDDL` 里 Authenticated Users 有**读**权限，这是故意的——
//! GUI 不提权，它必须能读到 token。代价是本机任何已登录用户都能读到它。
//! 于是"持有 token"只能证明"你是本机的一个客户端"，证明不了"你有权指挥
//! 服务做特权操作"。
//!
//! 服务是 SYSTEM，而且即将持有"下发 / 拆除 WFP 规则"这类**装错就断网**
//! 的操作。如果"有 token 就能干所有事"，那么一个标准用户读走一个文件，
//! 就等于拿到了指挥特权进程的能力——这就是提权漏洞的形状。
//!
//! 所以命令要分级：
//!
//! | 风险 | 命令 | 要求 |
//! |---|---|---|
//! | [`Risk::ReadOnly`] | `status` / `ping` | 持有 token 即可 |
//! | [`Risk::Dangerous`] | `apply` / `rollback` / `confirm` | 持有 token **且**对端进程已提权 |
//!
//! # 为什么用"进程是否已提权"而不是"是不是管理员"
//!
//! UAC 之下，管理员登录后拿到的默认令牌是**已过滤**的：Administrators SID
//! 还在，但只用于拒绝项（`USE_FOR_DENY_ONLY`）。按 SID 判会说"是管理员"，
//! 而它其实什么都特权操作都做不了。判 `TokenIsElevated` 才是准确的。
//!
//! ⚠ **判不出来就当成没权限**（Fail-Closed）。取不到对端进程令牌时返回
//! `false`，因为此时唯一安全的假设就是"它不配"。

use std::mem::size_of;

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{
    GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
};
use windows::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows::Win32::System::Threading::{
    OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::pipe::PipeEnd;

/// 一个命令的风险等级。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Risk {
    /// 只读：查状态、心跳。持有 token 即可。
    ReadOnly,
    /// 危险：会改变本机网络状态（下发 / 拆除 WFP 规则）。
    /// 除 token 外还要求对端进程已提权。
    Dangerous,
}

impl Risk {
    /// 这个等级是否需要**额外**的对端提权检查。
    pub fn needs_elevation(self) -> bool {
        matches!(self, Self::Dangerous)
    }
}

/// 对端进程是否运行在**已提权**的令牌下。
///
/// 取不到（进程已退出、权限不足、API 失败）一律返回 `false`：
/// 此时唯一安全的假设是"它不配"。宁可让管理员多提一次权，
/// 也不能让一个查不清身份的对端去动 WFP 规则。
pub fn is_elevated(end: &PipeEnd) -> bool {
    let pid = match client_pid(end) {
        Some(p) => p,
        None => return false,
    };

    let process = match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
        Ok(h) => h,
        Err(_) => return false,
    };

    let mut token = HANDLE::default();
    let opened = unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) };
    unsafe {
        let _ = CloseHandle(process);
    }
    if opened.is_err() {
        return false;
    }

    let elevated = token_is_elevated(token);
    unsafe {
        let _ = CloseHandle(token);
    }
    elevated
}

fn client_pid(end: &PipeEnd) -> Option<u32> {
    let mut pid = 0u32;
    let ok = unsafe { GetNamedPipeClientProcessId(end.as_raw_handle(), &mut pid) };
    if ok.is_ok() && pid != 0 {
        Some(pid)
    } else {
        None
    }
}

fn token_is_elevated(token: HANDLE) -> bool {
    let mut elevation = TOKEN_ELEVATION::default();
    let mut len = 0u32;
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        )
    };
    ok.is_ok() && elevation.TokenIsElevated != 0
}

/// 判定一个命令能不能被这个对端执行。
///
/// 只读命令不查提权；危险命令必须 [`is_elevated`]。
pub fn allows(end: &PipeEnd, risk: Risk) -> bool {
    !risk.needs_elevation() || is_elevated(end)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn risk_levels_are_ordered_and_distinguishable() {
        assert!(!Risk::ReadOnly.needs_elevation());
        assert!(Risk::Dangerous.needs_elevation());
        assert!(Risk::Dangerous > Risk::ReadOnly);
    }

    /// Fail-Closed 的钉子：句柄无效时，`is_elevated` 必须返回 false，
    /// 绝不能因为"查不清"就放行。
    ///
    /// 这里用一个明显非法的句柄（`isize::MAX` 当指针）走完整条路径：
    /// 拿不到对端 PID → 直接 false。
    #[test]
    fn an_unusable_handle_is_never_treated_as_elevated() {
        let bogus = PipeEnd::from_raw_for_test(HANDLE(isize::MAX as *mut _));
        assert!(!is_elevated(&bogus));
    }

    /// 同理：`allows` 对危险命令不能因为查不清就放行。
    #[test]
    fn a_dangerous_command_from_an_unidentifiable_peer_is_denied() {
        let bogus = PipeEnd::from_raw_for_test(HANDLE(isize::MAX as *mut _));
        assert!(!allows(&bogus, Risk::Dangerous));
    }

    /// 只读命令不查提权——否则标准用户的 GUI 连查个状态都做不到，
    /// 而"查状态"根本不碰系统状态。
    #[test]
    fn read_only_commands_do_not_require_elevation() {
        let bogus = PipeEnd::from_raw_for_test(HANDLE(isize::MAX as *mut _));
        assert!(allows(&bogus, Risk::ReadOnly));
    }
}
