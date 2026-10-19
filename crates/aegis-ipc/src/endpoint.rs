//! IPC 端点名与安全描述符（**纯字符串常量，不调用任何 Win32 API**）。
//!
//! # 为什么常量要单独放一个模块
//!
//! 管道名和 SDDL 是**安全边界的一部分**：写错一个 SID 缩写，要么把管道
//! 开给所有人，要么把标准用户挡在门外（GUI 不提权，挡住就是彻底不可用）。
//! 把它们集中在这里，好让"这两串到底是什么"成为一眼能审的东西，
//! 而不是散落在 FFI 调用里的字面量。

/// 命名管道名。
///
/// design-spec §23.1 原文写的是 `\\.\pipe\orchestrator`，那是项目改名
/// **Aegis** 之前的遗留。按 §31 的命名规范统一为 `aegis-` 前缀。
pub const PIPE_NAME: &str = r"\\.\pipe\aegis";

/// Win32 命名管道路径的前缀。
pub const PIPE_PREFIX: &str = r"\\.\pipe\";

/// 命令行里收到的管道名 → Win32 完整路径。**裸名也收。**
///
/// # 为什么必须有这个
///
/// 真机踩到的坑：`--pipe aegis-ob` 原样交给 `CreateNamedPipeW`，内核回
/// **os error 123「文件名、目录名或卷标语法不正确」**，而启动日志那句提示
/// 写的是"多半是已有实例占用"——**完全指错方向**，排查被带偏两次。
///
/// 更阴的是第二层：就算用户记得写完整路径 `\\.\pipe\aegis`，
/// **Git Bash 会吃掉一个反斜杠**（MSYS 路径转换），写出来是对的、
/// 传到进程里是错的。所以"让用户自己写对"这条路根本走不通，
/// 只能在程序里补。
///
/// 命名管道不存在"相对路径"这种语义，裸名只可能是想要 `\\.\pipe\<name>`，
/// 所以补前缀是安全的。
pub fn normalize_pipe_name(name: &str) -> String {
    if name.is_empty() {
        return PIPE_NAME.to_string();
    }
    // 逐段剥，而不是拿完整前缀去比对：Git Bash 会把 `\\.\pipe\aegis` 吃掉
    // 一个反斜杠变成 `\.\pipe\aegis`，而完整前缀比对认不出它，会当成裸名
    // 补出双重前缀 `\\.\pipe\\.\pipe\aegis`——比不补还糟。
    let t = name.trim_start_matches(['\\', '/']); // "\.\pipe\aegis" → ".\pipe\aegis"
    let t = t.strip_prefix('.').unwrap_or(t); // → "\pipe\aegis"
    let t = t.trim_start_matches(['\\', '/']); // → "pipe\aegis"
    let body = t
        .strip_prefix("pipe\\")
        .or_else(|| t.strip_prefix("pipe/"))
        .unwrap_or(t);
    // 一律归一到**唯一**的规范写法，而不是"认得出来就原样返回"：
    // 两种写法并存的话，对端拼出的名字可能和本机不一样。
    format!("{PIPE_PREFIX}{body}")
}

/// 管道的安全描述符（SDDL）。
///
/// ```text
/// D:(A;;GA;;;SY)         SYSTEM          完全控制 —— 服务自己
///   (A;;GA;;;BA)         内置管理员       完全控制 —— 排障
///   (A;;GRGW;;;AU)       Authenticated Users  读 + 写
/// ```
///
/// # 为什么必须显式写 DACL
///
/// 命名管道若传 `NULL` 安全属性，会继承创建者的默认 DACL。服务以 SYSTEM
/// 运行，其默认 DACL **不放行标准用户**，于是 GUI（不提权）根本连不上，
/// 而且失败表现只是"连接被拒绝"，看不出是 ACL 的锅。这就是 §16/§20
/// 修正 #5 说的那件事。
///
/// # 为什么只给 AU 读写而不是完全控制
///
/// 够用即可：`GRGW` 已经能连接、发送、接收。给 `GA` 意味着任何已登录用户
/// 都能改这个对象的 DACL。
///
/// ⚠ **ACL 只是第一道门，不是门闩。** `AU`（Authenticated Users）包含本机
/// 所有已认证用户，域环境下还包括域用户。真正的门闩是 [`crate::token`]
/// 里的一次性随机 token —— 别把 ACL 当成鉴权。
pub const PIPE_SDDL: &str = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)";

/// token 文件的安全描述符（SDDL）。
///
/// §23.1 原文给的是 `D:(A;;GR;;;AU)`——**只放行 AU 读**。这里额外补了
/// SYSTEM 与内置管理员的完全控制，原因是：文件是服务（SYSTEM）自己写的，
/// 若 DACL 里只有 AU:GR，创建者连写回和管理自己刚建的文件都会失败。
/// "最小权限"不能小到把自己也挡住。
pub const TOKEN_FILE_SDDL: &str = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;AU)";

/// 管道实例上限。GUI 只有一个，留几路给 `aegisctl` 与重连。
pub const MAX_INSTANCES: u32 = 4;

/// 单帧之后等待对端的默认超时（毫秒）。
pub const DEFAULT_TIMEOUT_MS: u32 = 3000;

// 常量上的约束：**编译期**断言，而不是运行时 assert!()。
// 它们两边都是常量，放进 `#[test]` 里既是恒真断言（clippy 会挑），
// 又要等 CI 跑起来才发现改坏了 —— 编译期立刻拦下才对。
const _: () = assert!(MAX_INSTANCES >= 2, "至少要有 GUI + 一次重连的余量");
const _: () = assert!(MAX_INSTANCES <= 255, "不能超过 PIPE_UNLIMITED_INSTANCES");
const _: () = assert!(DEFAULT_TIMEOUT_MS >= 100, "0 会被当成「默认 50ms」，太短");
const _: () = assert!(DEFAULT_TIMEOUT_MS <= 30_000, "再长就是让 GUI 假死");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_pipe_name_gets_the_win32_prefix() {
        assert_eq!(normalize_pipe_name("aegis-ob"), r"\\.\pipe\aegis-ob");
    }

    /// 一律归一到唯一写法：两种写法并存的话，对端拼出来的名字可能和本机不一样。
    #[test]
    fn every_spelling_lands_on_the_one_canonical_form() {
        assert_eq!(normalize_pipe_name(r"\\.\pipe\aegis"), r"\\.\pipe\aegis");
        assert_eq!(normalize_pipe_name("//./pipe/aegis"), r"\\.\pipe\aegis");
        assert_eq!(normalize_pipe_name(r"\.\pipe\aegis"), r"\\.\pipe\aegis");
    }

    #[test]
    fn an_empty_pipe_name_falls_back_to_the_default() {
        assert_eq!(normalize_pipe_name(""), PIPE_NAME);
    }

    /// Git Bash 吃掉一个反斜杠之后剩下 `\.\pipe\aegis`，这种**残缺**前缀
    /// 也得认出来补回去——这正是把容错放在程序里而不是靠用户写对的原因。
    #[test]
    fn a_half_eaten_prefix_is_repaired() {
        assert_eq!(normalize_pipe_name(r"\.\pipe\aegis"), r"\\.\pipe\aegis");
    }

    #[test]
    fn pipe_name_is_a_local_named_pipe_with_aegis_prefix() {
        assert!(PIPE_NAME.starts_with(r"\\.\pipe\"), "{PIPE_NAME}");
        assert!(PIPE_NAME.contains("aegis"), "{PIPE_NAME}");
        assert!(!PIPE_NAME.contains("orchestrator"), "项目已改名 Aegis");
    }

    /// 防 DACL 缺失：没有 `(A;;` 的 SDDL 会让管道继承 SYSTEM 默认 DACL，
    /// 标准用户连不上，且失败现象看不出是 ACL 的锅。
    #[test]
    fn pipe_sddl_grants_access_to_standard_users() {
        assert!(PIPE_SDDL.starts_with("D:"), "{PIPE_SDDL}");
        assert!(PIPE_SDDL.contains("(A;;GRGW;;;AU)"), "标准用户必须能读写：{PIPE_SDDL}");
        assert!(PIPE_SDDL.contains("(A;;GA;;;SY)"), "服务自己是 SYSTEM");
    }

    /// AU 只给读写，不给完全控制——否则任何已登录用户都能改这个对象的 DACL。
    #[test]
    fn pipe_sddl_does_not_give_authenticated_users_full_control() {
        assert!(
            !PIPE_SDDL.contains("(A;;GA;;;AU)"),
            "AU 不应有完全控制：{PIPE_SDDL}"
        );
    }

    /// token 文件本身不能被标准用户改写，否则门闩就形同虚设。
    #[test]
    fn token_file_sddl_is_read_only_for_standard_users() {
        assert!(TOKEN_FILE_SDDL.contains("(A;;GR;;;AU)"), "{TOKEN_FILE_SDDL}");
        assert!(
            !TOKEN_FILE_SDDL.contains("(A;;GRGW;;;AU)"),
            "token 文件不该让 AU 可写：{TOKEN_FILE_SDDL}"
        );
        assert!(
            TOKEN_FILE_SDDL.contains("(A;;GA;;;SY)"),
            "创建者必须能管理自己建的文件：{TOKEN_FILE_SDDL}"
        );
    }
}
