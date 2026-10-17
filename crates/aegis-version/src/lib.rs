//! `aegis-version` —— Aegis 版本标识的**单一事实来源**。
//!
//! 项目：**Aegis**（英文为主）/ **宙斯的神盾**（中文为辅）。
//! 版本规范见仓库根目录 `docs/VERSIONING.md`，与 `VERSION` 文件严格一致。
//!
//! # 为什么单独开一个 crate
//! 版本号是最底层的公共信息：从最靠近内核的 `aegis-wfp` 到最上层的
//! `aegisctl`，每一层都需要在日志、IPC 握手、审计记录里打上同一个版本号。
//! 如果各 crate 各自 `env!("CARGO_PKG_VERSION")`，一旦某个 crate 漏同步
//! workspace 版本就会出现"底座 0.1.0 / 控制端 0.1.1"这种错配——
//! 而 IPC 协议是按版本号做兼容性握手的，错配会直接导致守护进程拒绝服务。
//! 因此这里收敛成零依赖的单一 crate，全工作区强制引用。
//!
//! # 完整版本号的形态
//! ```text
//! 0.1.0-alpha.1+g334165c
//! │ │ │   │    │  └─ build metadata：Git 短哈希（构建期采集）
//! │ │ │   │    └──── 预发布序号
//! │ │ │   └───────── 预发布标签：alpha → beta → rc
//! │ │ └───────────── PATCH：缺陷修复
//! │ └─────────────── MINOR：0.x 阶段的破坏性变更
//! └───────────────── MAJOR：架构级破坏性变更
//! ```
//! Cargo 的 `version` 字段不接受 build metadata（`+` 之后的部分），
//! 所以 `Cargo.toml` 里只写到预发布标签，`+` 段由本 crate 在运行时追加。
//!
//! # 模块
//! - [`compat`]：对外契约（IPC 帧格式、配置 schema）的版本兼容性判定。
//!   放在这里而不是各自 crate，是为了让"什么算兼容"只有一处定义。
//!
//! # 零依赖
//! 本 crate 不依赖任何第三方 crate（含 `thiserror`）：
//! 它是最底层的事实来源，任何依赖升级都不应波及版本号。

pub mod compat;

/// 项目英文名（用于日志前缀、IPC 协议标识、服务名）。
pub const NAME: &str = "Aegis";

/// 项目中文名，仅用于人类可读的输出，不参与任何协议或标识。
pub const NAME_ZH: &str = "宙斯的神盾";

/// 语义化版本号（不含 build metadata），取自 `CARGO_PKG_VERSION`。
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// 预发布标签，例如 `alpha` / `beta` / `rc`；正式发布时为空串。
pub const PRERELEASE: &str = env!("CARGO_PKG_VERSION_PRE");

/// 构建期采集的 Git 短哈希；非 Git 工作副本下为 `unknown`。
pub const GIT_HASH: &str = env!("AEGIS_GIT_HASH");

/// 构建期采集的 Git 分支名；detached HEAD 下为 `detached`。
pub const GIT_BRANCH: &str = env!("AEGIS_GIT_BRANCH");

/// 构建配置：`debug` 或 `release`。
pub const BUILD_PROFILE: &str = if cfg!(debug_assertions) {
    "debug"
} else {
    "release"
};

/// 编译目标三元组，例如 `x86_64-pc-windows-gnu`。
///
/// 注意：Cargo 的 `TARGET` 只在构建脚本执行期间可见，crate 编译期拿不到，
/// 因此由 `build.rs` 采集后以 `AEGIS_TARGET_TRIPLE` 透传进来。
pub const TARGET_TRIPLE: &str = env!("AEGIS_TARGET_TRIPLE");

/// 拆分后的版本号三段（预发布标签不含在内）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl Version {
    /// 从 `CARGO_PKG_VERSION_*` 环境变量解析，恒定成功（由 Cargo 保证格式）。
    #[must_use]
    pub fn current() -> Self {
        Self {
            major: parse_env(env!("CARGO_PKG_VERSION_MAJOR")),
            minor: parse_env(env!("CARGO_PKG_VERSION_MINOR")),
            patch: parse_env(env!("CARGO_PKG_VERSION_PATCH")),
        }
    }

    /// 是否处于 0.x 阶段：此阶段 MINOR 递增即代表破坏性变更。
    #[must_use]
    pub fn is_unstable(&self) -> bool {
        self.major == 0
    }
}

impl core::fmt::Display for Version {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

fn parse_env(s: &str) -> u32 {
    s.parse().unwrap_or(0)
}

/// **完整版本号**：`MAJOR.MINOR.PATCH[-PRERELEASE][+g<hash>]`，例如
/// `0.1.0-alpha.1+g334165c`。这是对外编号与 CHANGELOG 归档用的形态。
#[must_use]
pub fn full() -> String {
    let mut s = String::from(VERSION);
    if GIT_HASH != "unknown" {
        s.push_str("+g");
        s.push_str(GIT_HASH);
    }
    s
}

/// 单行版本横幅，供 CLI `--version` 与守护进程启动日志使用。
///
/// 例：`Aegis 0.1.0-alpha.1+g334165c (宙斯的神盾) [debug/x86_64-pc-windows-gnu @ master]`
#[must_use]
pub fn banner() -> String {
    format!(
        "{name} {full} ({name_zh}) [{profile}/{triple} @ {branch}]",
        name = NAME,
        full = full(),
        name_zh = NAME_ZH,
        profile = BUILD_PROFILE,
        triple = TARGET_TRIPLE,
        branch = GIT_BRANCH,
    )
}

/// 多行版本横幅，供 `--version --verbose` 或启动自检输出。
#[must_use]
pub fn banner_long() -> String {
    let v = Version::current();
    // 必须显式列出所有命名参数：format 串来自 concat! 展开时，
    // 编译期无法隐式捕获作用域里的同名常量。
    format!(
        concat!(
            "{name} —— {name_zh}\n",
            "  版本      : {full}\n",
            "  语义版本  : {semver}{pre}\n",
            "  预发布    : {pre_label}\n",
            "  构建配置  : {profile}\n",
            "  目标平台  : {triple}\n",
            "  Git 分支  : {branch}\n",
            "  Git 提交  : {hash}\n",
            "  稳定性    : {stability}"
        ),
        name = NAME,
        name_zh = NAME_ZH,
        full = full(),
        semver = v,
        pre = if PRERELEASE.is_empty() {
            String::new()
        } else {
            format!("-{PRERELEASE}")
        },
        pre_label = if PRERELEASE.is_empty() {
            "正式发布"
        } else {
            PRERELEASE
        },
        profile = BUILD_PROFILE,
        triple = TARGET_TRIPLE,
        branch = GIT_BRANCH,
        hash = GIT_HASH,
        stability = if v.is_unstable() {
            "0.x 阶段，MINOR 递增即破坏性变更"
        } else {
            "稳定版"
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_parses_from_cargo_env() {
        let v = Version::current();
        // 当前 workspace 版本为 0.1.0-alpha.1
        assert_eq!(v.major, 0);
        assert!(v.is_unstable());
    }

    #[test]
    fn version_display_is_three_segments() {
        assert_eq!(Version::current().to_string(), "0.1.0");
    }

    #[test]
    fn full_version_carries_semver() {
        assert!(
            full().starts_with(VERSION),
            "完整版本号必须以语义版本开头: {}",
            full()
        );
        // Cargo 不允许 build metadata，故 VERSION 本身不得含 '+'
        assert!(!VERSION.contains('+'));
    }

    #[test]
    fn banner_contains_project_name() {
        let b = banner();
        assert!(b.starts_with("Aegis "), "横幅应以项目名开头: {b}");
        assert!(b.contains(NAME_ZH));
        assert!(b.contains(TARGET_TRIPLE));
    }

    #[test]
    fn prerelease_matches_workspace_version() {
        assert_eq!(PRERELEASE, "alpha.1");
    }
}
