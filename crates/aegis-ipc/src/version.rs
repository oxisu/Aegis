//! IPC 版本兼容性判定。
//!
//! # 为什么 IPC 要单独做版本握手
//! Aegis 的守护进程（`aegisd` SYSTEM 权限）与控制端（`aegisctl`/GUI，普通权限）
//! 是**两个独立编译的二进制**，升级时可能只替换了其中一个。
//! 若帧布局变了而两端版本不一致，轻则解析出乱码，重则把一条
//! "放行"命令解析成别的东西——**IPC 解析错误在安全底座上就是安全漏洞**。
//! 因此必须在握手阶段就把版本不兼容挡掉，而不是等到解析时才发现。
//!
//! # 0.x 阶段的特殊性（与 docs/VERSIONING.md 保持一致）
//! Aegis 当前处于 `0.x`，而按 SemVer 约定 **0.x 阶段 MINOR 递增即代表破坏性变更**。
//! 所以这里不能照搬常见的"主版本号相同即兼容"规则——
//! `0.1.x` 与 `0.2.x` 必须判定为**不兼容**，尽管它们主版本号都是 0。
//! 这一条如果不显式处理，就会在 0.x 阶段静默放行不兼容的两端，
//! 属于典型的"照抄通用规则而忽略自身约定"的坑。

use std::fmt;

/// 从 `Cargo.toml` 语义版本字符串解析出的三段式版本。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionTriple {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    /// 是否为预发布版本（含 `-alpha.N` / `-beta.N` / `-rc.N`）
    pub prerelease: bool,
}

impl VersionTriple {
    /// 解析 `MAJOR.MINOR.PATCH[-PRERELEASE]`。build metadata（`+g<hash>`）被忽略——
    /// 按 SemVer 它不参与版本比较，握手时也不应影响兼容性。
    pub fn parse(s: &str) -> Result<Self, ParseError> {
        // 先砍掉 build metadata
        let core = s.split('+').next().unwrap_or(s);
        let (nums, pre) = match core.split_once('-') {
            Some((n, p)) => (n, !p.is_empty()),
            None => (core, false),
        };

        let mut it = nums.split('.');
        let parse = |v: Option<&str>| -> Result<u32, ParseError> {
            v.ok_or(ParseError::MissingSegment)?
                .parse()
                .map_err(|_| ParseError::NotANumber)
        };
        let major = parse(it.next())?;
        let minor = parse(it.next())?;
        let patch = parse(it.next())?;
        if it.next().is_some() {
            return Err(ParseError::TooManySegments);
        }
        Ok(Self {
            major,
            minor,
            patch,
            prerelease: pre,
        })
    }

    /// 是否处于 0.x 阶段（此阶段 MINOR 承载破坏性变更）。
    pub fn is_unstable(&self) -> bool {
        self.major == 0
    }
}

impl fmt::Display for VersionTriple {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    #[error("版本号段数不足（应为 MAJOR.MINOR.PATCH）")]
    MissingSegment,
    #[error("版本号含有非数字段")]
    NotANumber,
    #[error("版本号段数过多（应为 MAJOR.MINOR.PATCH）")]
    TooManySegments,
}

/// 握手结论。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// 兼容，可以通信
    Ok,
    /// 兼容但需注意：补丁版本不同，或有一端是预发布
    Warn(Note),
    /// 不兼容，必须拒绝服务
    Reject(RejectReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Note {
    /// 补丁版本不同：按 SemVer 兼容，但值得记一条日志
    PatchDiffers,
    /// 至少一端是预发布版本：协议可能仍在变动
    Prerelease,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// 主版本号不同：架构级不兼容
    MajorMismatch,
    /// 0.x 阶段 MINOR 不同：按本项目约定即破坏性变更
    UnstableMinorMismatch,
    /// 稳定阶段（1.0+）客户端比服务端新：服务端需要升级
    ServerTooOld,
    /// 版本号格式无法解析
    Malformed,
}

impl fmt::Display for RejectReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::MajorMismatch => "主版本号不同，架构级不兼容",
            Self::UnstableMinorMismatch => "0.x 阶段 MINOR 不同，按约定即破坏性变更",
            Self::ServerTooOld => "客户端协议比服务端新，需升级服务端",
            Self::Malformed => "版本号格式无法解析",
        };
        f.write_str(s)
    }
}

/// 判定两端是否兼容。
///
/// 规则（严格贴合 docs/VERSIONING.md）：
/// 1. 主版本号必须相同，否则 `MajorMismatch`
/// 2. 0.x 阶段：MINOR 必须相同（MINOR 承载破坏性变更），否则 `UnstableMinorMismatch`
/// 3. 1.0+ 阶段：客户端 MINOR 不得大于服务端，否则 `ServerTooOld`
///    （服务端更旧 = 听不懂客户端的新命令）
/// 4. PATCH 不同只警告不拒绝
/// 5. 任一端为预发布版本时警告：协议仍可能变动
pub fn check_compat(client: VersionTriple, server: VersionTriple) -> Verdict {
    if client.major != server.major {
        return Verdict::Reject(RejectReason::MajorMismatch);
    }

    if client.is_unstable() || server.is_unstable() {
        // 0.x：MINOR 就是破坏性变更的载体
        if client.minor != server.minor {
            return Verdict::Reject(RejectReason::UnstableMinorMismatch);
        }
    } else if client.minor > server.minor {
        return Verdict::Reject(RejectReason::ServerTooOld);
    }

    if client.prerelease || server.prerelease {
        return Verdict::Warn(Note::Prerelease);
    }
    if client.patch != server.patch {
        return Verdict::Warn(Note::PatchDiffers);
    }
    Verdict::Ok
}

/// 握手载荷：把版本三段压成定长 16 字节，避免任何字符串解析歧义。
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

    fn v(s: &str) -> VersionTriple {
        VersionTriple::parse(s).unwrap()
    }

    #[test]
    fn parses_semver_with_prerelease_and_build() {
        let t = v("0.1.0-alpha.1+g05d624e");
        assert_eq!((t.major, t.minor, t.patch), (0, 1, 0));
        assert!(t.prerelease);

        let t = v("1.2.3");
        assert_eq!((t.major, t.minor, t.patch), (1, 2, 3));
        assert!(!t.prerelease);
    }

    #[test]
    fn build_metadata_is_ignored() {
        assert_eq!(
            v("1.2.3+gaaa"),
            v("1.2.3+gbbb"),
            "build metadata 不参与比较"
        );
    }

    #[test]
    fn malformed_versions_are_rejected() {
        assert!(VersionTriple::parse("1.2").is_err());
        assert!(VersionTriple::parse("1.2.3.4").is_err());
        assert!(VersionTriple::parse("1.x.3").is_err());
        assert!(VersionTriple::parse("").is_err());
    }

    #[test]
    fn major_mismatch_always_rejects() {
        assert_eq!(
            check_compat(v("1.0.0"), v("2.0.0")),
            Verdict::Reject(RejectReason::MajorMismatch)
        );
    }

    /// 本项目当前处于 0.x，这条规则是"照抄通用 SemVer 规则"最容易踩错的地方。
    #[test]
    fn unstable_minor_mismatch_rejects() {
        assert_eq!(
            check_compat(v("0.1.0"), v("0.2.0")),
            Verdict::Reject(RejectReason::UnstableMinorMismatch)
        );
        assert_eq!(
            check_compat(v("0.2.0"), v("0.1.0")),
            Verdict::Reject(RejectReason::UnstableMinorMismatch)
        );
    }

    #[test]
    fn stable_minor_only_rejects_when_client_is_newer() {
        assert_eq!(check_compat(v("1.2.0"), v("1.3.0")), Verdict::Ok);
        assert_eq!(
            check_compat(v("1.4.0"), v("1.3.0")),
            Verdict::Reject(RejectReason::ServerTooOld)
        );
    }

    #[test]
    fn patch_and_prerelease_are_only_warnings() {
        assert_eq!(
            check_compat(v("1.2.3"), v("1.2.9")),
            Verdict::Warn(Note::PatchDiffers)
        );
        assert_eq!(
            check_compat(v("0.1.0-alpha.1"), v("0.1.0")),
            Verdict::Warn(Note::Prerelease)
        );
    }

    #[test]
    fn handshake_payload_roundtrip() {
        let t = v("0.1.0-alpha.1");
        let p = HandshakePayload::from_triple(t);
        let bytes = p.encode();
        assert_eq!(bytes.len(), HandshakePayload::LEN);
        assert_eq!(HandshakePayload::decode(&bytes).unwrap().to_triple(), t);
    }

    #[test]
    fn short_handshake_payload_is_rejected() {
        assert!(HandshakePayload::decode(&[0u8; 8]).is_err());
    }
}
