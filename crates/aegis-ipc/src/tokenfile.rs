//! token 文件的**带 DACL 落盘**（§23.1）。
//!
//! # 这个文件为什么必须单独存在
//!
//! 服务以 SYSTEM 运行，token 是"你是不是我的客户端"的唯一凭据。
//! 用 [`std::fs::write`] 落盘时会继承父目录的默认 DACL——典型情况下
//! `%PROGRAMDATA%` 下的文件**对 Authenticated Users 可读写**。后果有两层：
//!
//! 1. **可读** → 任何已登录用户拿到 token，就能冒充 GUI 给服务下命令。
//!    服务是 SYSTEM 且即将持有"下发/拆除 WFP 规则"这类特权操作，
//!    于是"读到一个文件"直接升级成"指挥特权进程"。
//! 2. **可写** → 任何用户都能把 token 换掉，GUI 立刻连不上，
//!    表现为"服务莫名其妙不认我"，排障时会一路查错方向。
//!
//! 所以落盘必须显式套上 [`crate::endpoint::TOKEN_FILE_SDDL`]。
//!
//! # ⚠ DACL 之外还有一层：命令分级授权
//!
//! `TOKEN_FILE_SDDL` 里 AU 有**读**权限——这是故意的：GUI 不提权，
//! 它必须能读到 token。也就是说**本机任何已登录用户都能读到 token**。
//! 光靠 DACL 挡不住"标准用户指挥 SYSTEM 服务"。
//!
//! 因此真正的边界在**命令级别**：
//!
//! - token 只证明"你是本机 Aegis 的客户端"；
//! - 危险命令（下发 / 回滚 / 改策略）另需对端是管理员或 SYSTEM，
//!   见 [`crate::peer`]。
//!
//! 把这两件事合成一道门（"有 token 就能干所有事"）就是提权漏洞。

use std::mem::size_of;
use std::path::Path;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL, INVALID_HANDLE_VALUE};
use windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, WriteFile, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_WRITE, FILE_SHARE_READ,
};

use crate::endpoint::TOKEN_FILE_SDDL;
use crate::token::IpcToken;

/// token 文件落盘失败。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TokenFileError {
    #[error("SDDL 转安全描述符失败：{0}")]
    BadSddl(String),
    #[error("创建 token 文件失败：{0}")]
    Create(String),
    #[error("写入 token 文件失败：{0}")]
    Write(String),
}

/// 把一个 token 落盘，**显式套用 `TOKEN_FILE_SDDL`**。
///
/// 刻意不提供"不设 DACL"的快捷方式：少一个参数就少一处"忘了设权限"
/// 的机会，而这种遗漏在测试里完全看不出来——功能一切正常，只是门没锁。
///
/// ⚠ 若目标已存在会被**覆盖**（`CREATE_ALWAYS`）。服务每次启动都换 token，
/// 旧 token 必须失效，否则"一次性"是假的。
pub fn write_protected(path: &Path, token: &IpcToken) -> Result<(), TokenFileError> {
    let wide_path = to_wide(&path.to_string_lossy());
    let mut sd = PSECURITY_DESCRIPTOR::default();
    let wide_sddl = to_wide(TOKEN_FILE_SDDL);

    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(wide_sddl.as_ptr()),
            1, // SDDL_REVISION_1
            &mut sd,
            None,
        )
        .map_err(|e| TokenFileError::BadSddl(e.to_string()))?
    };

    let attrs = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        // 不可继承：否则服务启动的子进程会拿到这个句柄
        bInheritHandle: windows::Win32::Foundation::BOOL(0),
    };

    let opened = unsafe {
        CreateFileW(
            PCWSTR(wide_path.as_ptr()),
            FILE_GENERIC_WRITE.0,
            // 共享读：GUI / aegisctl 要能同时读
            FILE_SHARE_READ,
            Some(&attrs),
            windows::Win32::Storage::FileSystem::CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    };

    // 内核已在创建时复制 DACL，此处可以安全释放
    unsafe {
        let _ = LocalFree(HLOCAL(sd.0 as *mut _));
    };

    let handle = match opened {
        Ok(h) => h,
        Err(e) => return Err(TokenFileError::Create(e.to_string())),
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(TokenFileError::Create(
            std::io::Error::last_os_error().to_string(),
        ));
    }

    let result = write_all(handle, token.to_hex().as_bytes());
    unsafe {
        let _ = CloseHandle(handle);
    }
    result
}

fn write_all(handle: HANDLE, bytes: &[u8]) -> Result<(), TokenFileError> {
    let mut written = 0u32;
    let ok = unsafe { WriteFile(handle, Some(bytes), Some(&mut written), None) };
    if ok.is_err() {
        return Err(TokenFileError::Write(
            std::io::Error::last_os_error().to_string(),
        ));
    }
    if written as usize != bytes.len() {
        return Err(TokenFileError::Write(format!(
            "只写了 {} / {} 字节",
            written,
            bytes.len()
        )));
    }
    Ok(())
}

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint::TOKEN_FILE_SDDL;

    /// SDDL 必须真的能被系统接受。写错一个 SID 缩写，
    /// `ConvertStringSecurityDescriptorToSecurityDescriptorW` 会失败——
    /// 而失败时机是**服务启动时**，不是编译时。
    #[test]
    fn the_sddl_is_accepted_by_the_system() {
        let wide = to_wide(TOKEN_FILE_SDDL);
        let mut sd = PSECURITY_DESCRIPTOR::default();
        let r = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide.as_ptr()),
                1,
                &mut sd,
                None,
            )
        };
        assert!(r.is_ok(), "SDDL 被系统拒绝：{TOKEN_FILE_SDDL}");
        unsafe {
            let _ = LocalFree(HLOCAL(sd.0 as *mut _));
        }
    }

    /// 端到端：真的写一个文件出来，内容必须能被读回来且能还原成 token。
    /// 这条同时覆盖了"DACL 路径下的 CreateFileW 能不能正常写"。
    #[test]
    fn writing_a_token_file_produces_readable_content() {
        let dir = std::env::temp_dir().join(format!("aegis-tok-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ipc.token");

        let t = IpcToken::generate().unwrap();
        write_protected(&path, &t).expect("带 DACL 写入应成功");

        let back = std::fs::read_to_string(&path).expect("应能读回");
        assert_eq!(back, t.to_hex());
        assert!(IpcToken::from_hex(back.trim()).is_some());
        assert!(t.verify_hex(back.trim()));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 覆盖语义：服务每次启动换 token，旧 token 必须失效。
    #[test]
    fn rewriting_replaces_the_old_token_completely() {
        let dir = std::env::temp_dir().join(format!("aegis-tok2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ipc.token");

        let first = IpcToken::generate().unwrap();
        write_protected(&path, &first).unwrap();
        let second = IpcToken::generate().unwrap();
        write_protected(&path, &second).unwrap();

        let got = std::fs::read_to_string(&path).unwrap();
        assert_eq!(got, second.to_hex());
        assert_ne!(got, first.to_hex(), "旧 token 必须被完全覆盖，不能残留");
        // 若实现用了 append 或没截断，长度会不对
        assert_eq!(got.len(), crate::TOKEN_HEX_LEN);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 父目录不存在时必须报错，不能静默成功——
    /// "写成功了"但文件不在，排查起来最费时间。
    #[test]
    fn a_missing_parent_directory_is_an_error() {
        let path = std::env::temp_dir()
            .join(format!("aegis-none-{}-{}", std::process::id(), line!()))
            .join("nope")
            .join("ipc.token");
        let t = IpcToken::generate().unwrap();
        assert!(write_protected(&path, &t).is_err());
    }
}
