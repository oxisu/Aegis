//! 熔断层的错误。

use thiserror::Error;

/// 网口变动通知相关操作的失败。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum FuseError {
    /// 注册 `NotifyIpInterfaceChange` 失败。
    #[error("注册网口变动通知失败（错误码 0x{0:08X}）")]
    Register(u32),

    /// 取消通知失败。
    ///
    /// 这条不能只当噪音：取消失败意味着**通知句柄泄露**，系统线程池会继续
    /// 往一个已经失效的上下文回调 —— 那是 use-after-free，不是慢一点。
    #[error("取消网口变动通知失败（错误码 0x{0:08X}）：通知句柄可能泄露")]
    Cancel(u32),
}

impl FuseError {
    pub fn code(self) -> u32 {
        match self {
            Self::Register(c) | Self::Cancel(c) => c,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_is_exposed_for_every_variant() {
        assert_eq!(FuseError::Register(5).code(), 5);
        assert_eq!(FuseError::Cancel(0x8032_0009).code(), 0x8032_0009);
    }

    /// 取消失败的文案必须点明"句柄泄露"，否则容易被当成可以忽略的清理失败。
    #[test]
    fn cancel_failure_message_explains_the_consequence() {
        let s = FuseError::Cancel(87).to_string();
        assert!(s.contains("0x00000057"), "{s}");
        assert!(s.contains("泄露"), "{s}");
    }

    #[test]
    fn register_failure_message_carries_the_code() {
        let s = FuseError::Register(8).to_string();
        assert!(s.contains("0x00000008"), "{s}");
        assert!(s.contains("注册"), "{s}");
    }
}
