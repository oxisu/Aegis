//! 对外契约的版本兼容性判定。
//!
//! # 为什么放在 `aegis-version` 而不是各自的 crate
//! Aegis 有两类对外契约需要版本判定：
//!
//! - **IPC 帧格式**（`aegis-ipc`）：`aegisd` 与 `aegisctl` 是两个独立编译、
//!   可能不同版本的二进制
//! - **配置 schema**（`aegis-config`）：用户手写的 `config.toml`
//!
//! 两者需要的是**同一套规则**。若各写一份，总有一天会出现
//! "IPC 认为 0.1 与 0.2 不兼容、配置加载却静默放行了"——
//! 而这种不一致在安全底座上就是静默降级。因此规则只有一处。
//!
//! # 0.x 阶段的特殊性（与 docs/VERSIONING.md 保持一致）
//! Aegis 当前处于 `0.x`，而按 SemVer 约定 **0.x 阶段 MINOR 递增即代表破坏性变更**。
//! 所以这里不能照搬常见的"主版本号相同即兼容"规则——
//! `0.1.x` 与 `0.2.x` 必须判定为**不兼容**，尽管它们主版本号都是 0。
//! 这一条如果不显式处理，就会在 0.x 阶段静默放行不兼容的两端，
//! 属于典型的"照抄通用规则而忽略自身约定"的坑。
//!
//! # 零依赖
//! 本模块刻意不使用 `thiserror`：`aegis-version` 是全工作区最底层的 crate，
//! 保持零依赖可避免任何依赖升级波及版本号这一单一事实来源。

use core::fmt;

/// 从语义版本字符串解析出的三段式版本。
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

        // 空串按"段数不足"处理而不是"非数字"：''.split('.') 会得到 [""]
        // 这一个空段，说它是数字错误会让人以为自己写了字母。
        if nums.is_empty() {
            return Err(ParseError::MissingSegment);
        }

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

/// 版本号解析失败。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// 段数不足（连 `MAJOR.MINOR.PATCH` 都不够）
    MissingSegment,
    /// 含有非数字段
    NotANumber,
    /// 段数过多
    TooManySegments,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::MissingSegment => "版本号段数不足（应为 MAJOR.MINOR.PATCH）",
            Self::NotANumber => "版本号含有非数字段",
            Self::TooManySegments => "版本号段数过多（应为 MAJOR.MINOR.PATCH）",
        };
        f.write_str(s)
    }
}

impl std::error::Error for ParseError {}

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

impl Verdict {
    /// 是否允许继续（含警告）。
    pub fn is_allowed(self) -> bool {
        !matches!(self, Self::Reject(_))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Note {
    /// 补丁版本不同：按 SemVer 兼容，但值得记一条日志
    PatchDiffers,
    /// 至少一端是预发布版本：协议可能仍在变动
    Prerelease,
}

impl fmt::Display for Note {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::PatchDiffers => "补丁版本不同",
            Self::Prerelease => "涉及预发布版本",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// 主版本号不同：架构级不兼容
    MajorMismatch,
    /// 0.x 阶段 MINOR 不同：按本项目约定即破坏性变更
    UnstableMinorMismatch,
    /// 稳定阶段（1.0+）对方比本方新：本方需要升级
    CounterpartyTooNew,
    /// 版本号格式无法解析
    Malformed,
}

impl fmt::Display for RejectReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::MajorMismatch => "主版本号不同，架构级不兼容",
            Self::UnstableMinorMismatch => "0.x 阶段 MINOR 不同，按约定即破坏性变更",
            Self::CounterpartyTooNew => "对方协议比本方新，需升级本方",
            Self::Malformed => "版本号格式无法解析",
        };
        f.write_str(s)
    }
}

/// 判定两份契约版本是否兼容。
///
/// 参数命名刻意用 `found` / `supported` 而非 `client` / `server`：
/// 同一套规则既要判 IPC 两端，也要判"用户配置里的 schema 版本"与
/// "本程序支持的 schema 版本"，用通用名字才不会在某处读起来别扭。
///
/// 规则（严格贴合 docs/VERSIONING.md）：
/// 1. 主版本号必须相同，否则 `MajorMismatch`
/// 2. 0.x 阶段：MINOR 必须相同（MINOR 承载破坏性变更），否则 `UnstableMinorMismatch`
/// 3. 1.0+ 阶段：`found` 的 MINOR 不得大于 `supported`，否则 `CounterpartyTooNew`
///    （对方更旧格式的新版本 = 本方听不懂）
/// 4. PATCH 不同只警告不拒绝
/// 5. 任一端为预发布版本时警告：协议仍可能变动
pub fn check_compat(found: VersionTriple, supported: VersionTriple) -> Verdict {
    if found.major != supported.major {
        return Verdict::Reject(RejectReason::MajorMismatch);
    }

    if found.is_unstable() || supported.is_unstable() {
        // 0.x：MINOR 就是破坏性变更的载体
        if found.minor != supported.minor {
            return Verdict::Reject(RejectReason::UnstableMinorMismatch);
        }
    } else if found.minor > supported.minor {
        return Verdict::Reject(RejectReason::CounterpartyTooNew);
    }

    if found.prerelease || supported.prerelease {
        return Verdict::Warn(Note::Prerelease);
    }
    if found.patch != supported.patch {
        return Verdict::Warn(Note::PatchDiffers);
    }
    Verdict::Ok
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
        assert_eq!(VersionTriple::parse("1.2"), Err(ParseError::MissingSegment));
        assert_eq!(
            VersionTriple::parse("1.2.3.4"),
            Err(ParseError::TooManySegments)
        );
        assert_eq!(VersionTriple::parse("1.x.3"), Err(ParseError::NotANumber));
        assert_eq!(VersionTriple::parse(""), Err(ParseError::MissingSegment));
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
    fn stable_minor_only_rejects_when_found_is_newer() {
        assert_eq!(check_compat(v("1.2.0"), v("1.3.0")), Verdict::Ok);
        assert_eq!(
            check_compat(v("1.4.0"), v("1.3.0")),
            Verdict::Reject(RejectReason::CounterpartyTooNew)
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
    fn is_allowed_tracks_verdict() {
        assert!(Verdict::Ok.is_allowed());
        assert!(Verdict::Warn(Note::Prerelease).is_allowed());
        assert!(!Verdict::Reject(RejectReason::Malformed).is_allowed());
    }

    #[test]
    fn reject_reason_display_is_human_readable() {
        for r in [
            RejectReason::MajorMismatch,
            RejectReason::UnstableMinorMismatch,
            RejectReason::CounterpartyTooNew,
            RejectReason::Malformed,
        ] {
            assert!(!r.to_string().is_empty());
        }
    }
}
