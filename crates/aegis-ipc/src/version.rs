//! IPC 握手载荷。
//!
//! # 兼容性判定不在本模块
//! "什么版本算兼容"由 [`aegis_version::compat`] 统一提供，IPC 帧格式与
//! 配置 schema 共用同一套规则。这里只定义 IPC 特有的**握手载荷编码**。
//!
//! # 为什么 IPC 要做版本握手
//! Aegis 的守护进程（`aegisd` SYSTEM 权限）与控制端（`aegisctl`/GUI，普通权限）
//! 是**两个独立编译的二进制**，升级时可能只替换了其中一个。
//! 若帧布局变了而两端版本不一致，轻则解析出乱码，重则把一条
//! "放行"命令解析成别的东西——**IPC 解析错误在安全底座上就是安全漏洞**。
//! 因此必须在握手阶段就把版本不兼容挡掉，而不是等到解析时才发现。
//!
//! # 0.x 阶段的特殊性
//! Aegis 当前处于 `0.x`，按 SemVer 约定 MINOR 递增即代表破坏性变更，
//! 所以 `0.1.x` 与 `0.2.x` 判为不兼容，尽管主版本号都是 0。
//! 详见 [`aegis_version::compat::check_compat`]。

pub use aegis_version::compat::{
    check_compat, Note, ParseError, RejectReason, Verdict, VersionTriple,
};

/// 握手载荷：把版本三段压成定长 16 字节，避免任何字符串解析歧义。
///
/// 之所以不让握手阶段传字符串版本号：字符串解析在不同实现间有太多
/// 自由度（前导空格、build metadata、大小写），而握手是**拒绝服务前的
/// 最后一道闸**，不应该有任何歧义空间。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakePayload {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    /// 位 0：预发布
    pub flags: u32,
}

impl HandshakePayload {
    pub const LEN: usize = 16;
    const FLAG_PRERELEASE: u32 = 0x1;

    pub fn from_triple(v: VersionTriple) -> Self {
        Self {
            major: v.major,
            minor: v.minor,
            patch: v.patch,
            flags: if v.prerelease {
                Self::FLAG_PRERELEASE
            } else {
                0
            },
        }
    }

    pub fn to_triple(self) -> VersionTriple {
        VersionTriple {
            major: self.major,
            minor: self.minor,
            patch: self.patch,
            prerelease: self.flags & Self::FLAG_PRERELEASE != 0,
        }
    }

    pub fn encode(self) -> [u8; Self::LEN] {
        let mut b = [0u8; Self::LEN];
        b[0..4].copy_from_slice(&self.major.to_be_bytes());
        b[4..8].copy_from_slice(&self.minor.to_be_bytes());
        b[8..12].copy_from_slice(&self.patch.to_be_bytes());
        b[12..16].copy_from_slice(&self.flags.to_be_bytes());
        b
    }

    /// 解码。**拒绝短于 [`Self::LEN`] 的输入**，而不是"有多少读多少"——
    /// 握手阶段对残缺数据的唯一正确处理是拒绝。
    pub fn decode(b: &[u8]) -> Result<Self, ParseError> {
        if b.len() < Self::LEN {
            return Err(ParseError::MissingSegment);
        }
        let u32_at = |i: usize| u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
        Ok(Self {
            major: u32_at(0),
            minor: u32_at(4),
            patch: u32_at(8),
            flags: u32_at(12),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_payload_roundtrip() {
        let t = VersionTriple::parse("0.1.0-alpha.1").unwrap();
        let p = HandshakePayload::from_triple(t);
        let bytes = p.encode();
        assert_eq!(bytes.len(), HandshakePayload::LEN);
        assert_eq!(HandshakePayload::decode(&bytes).unwrap().to_triple(), t);
    }

    #[test]
    fn prerelease_flag_survives_encoding() {
        let bytes =
            HandshakePayload::from_triple(VersionTriple::parse("1.2.3-rc.1").unwrap()).encode();
        assert_ne!(bytes[15], 0, "预发布位应落在 flags 末字节");
        assert!(
            HandshakePayload::decode(&bytes)
                .unwrap()
                .to_triple()
                .prerelease
        );

        let bytes = HandshakePayload::from_triple(VersionTriple::parse("1.2.3").unwrap()).encode();
        assert_eq!(bytes[15], 0);
        assert!(
            !HandshakePayload::decode(&bytes)
                .unwrap()
                .to_triple()
                .prerelease
        );
    }

    #[test]
    fn short_handshake_payload_is_rejected() {
        assert!(HandshakePayload::decode(&[0u8; 8]).is_err());
        assert!(HandshakePayload::decode(&[]).is_err());
    }
}
