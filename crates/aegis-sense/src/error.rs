//! 感知层统一错误类型。
//!
//! 约定：感知层始终保持**只读**，任何失败都必须向上传递而不是 panic，
//! 这样即使某一路探针失败，编排器仍能带着部分拓扑继续走自检流水线。

use std::fmt;

/// Win32 错误码包装，保留原始错误码便于排障与审计。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Win32Error(pub u32);

impl Win32Error {
    /// 是否为成功码（NO_ERROR / ERROR_SUCCESS）。
    pub fn is_ok(self) -> bool {
        self.0 == 0
    }
}

impl fmt::Display for Win32Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Win32 error 0x{:08X}", self.0)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SenseError {
    /// 底层 Win32 API 调用失败。
    #[error("{op} 调用失败: {code}")]
    Os { op: &'static str, code: Win32Error },

    /// API 返回的缓冲区结构异常（长度、指针为 null 等）。
    #[error("{op} 返回的数据结构异常: {detail}")]
    Malformed { op: &'static str, detail: String },

    /// 字符串转换失败（宽字符 → UTF-8）。
    #[error("字符串转码失败: {0}")]
    Encoding(String),
}

/// 把 Win32 返回码转成 `Result`（0 = 成功）。
///
/// 各 API 的返回类型在 windows-rs 中并不统一：有的返回 `WIN32_ERROR`，
/// 有的直接返回 `u32`。这里统一收敛到 `u32` 入口，调用方只需 `check("Op", code.0)`。
pub(crate) fn check(op: &'static str, raw: u32) -> Result<(), SenseError> {
    if raw == 0 {
        Ok(())
    } else {
        Err(SenseError::Os {
            op,
            code: Win32Error(raw),
        })
    }
}
