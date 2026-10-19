//! `aegisctl` —— Aegis 控制端的最小形态。
//!
//! ```text
//! cargo run -p aegisctl -- --token-file .aegis-run/ipc.token
//! ```
//!
//! # 它做的事
//!
//! ```text
//! 连管道 → 版本握手 → token 鉴权 → 发一个请求 → 收应答 → 按前缀判成败 → 打印
//! ```
//!
//! # 子命令
//!
//! | 命令 | 做什么 | 额外要求 |
//! |---|---|---|
//! | `status`（默认） | 查守护进程状态 | 无 |
//! | `ping` | 心跳 | 无 |
//! | `apply` | 下发绝缘笼，**装完只是待确认** | 控制端已提权 |
//! | `confirm` | 确认刚才那次下发 | 控制端已提权 |
//! | `rollback` | 立即拆除（含已确认的强拆） | 控制端已提权 |
//!
//! `apply` 之后必须在 10 秒内 `confirm`，否则守护进程自动撤销——
//! 这条倒计时的意义是：人装错了、手滑了、或者根本不在机器旁边的时候，
//! 不需要做任何事，网络自己会回来。
//!
//! # 两条纪律（由 `aegis_ipc::client` 的类型状态保证）
//!
//! 1. **握手必须在鉴权之前。** 版本谈不拢就别把 token 送过去——
//!    对面是老版本，它未必会用常量时间比对来验 token。
//! 2. **鉴权失败不要重试。** 一次失败就退出并说清为什么。
//!    自动重试会把"token 不对"变成一次慢速的拒绝服务，
//!    也更容易撞上服务端的防爆破策略。
//!
//! ⚠ 这两条现在**不在本文件里守**：它们收进了 `aegis_ipc::client::Session`
//! 的**类型状态**——没握手拿不到 `Handshook`，没鉴权拿不到 `Ready`，
//! 而 `request()` 只挂在 `Ready` 上，顺序写反是编译错误。
//! 本文件只负责把每一步**打印给人看**和把失败映射成退出码。

use std::path::PathBuf;
use std::process::ExitCode;

use aegis_ipc::client::{ClientError, Session};
use aegis_ipc::GuardView;
use aegis_ipc::{
    IpcToken, Status, Verdict, GUARD_EFFECTIVE, GUARD_INEFFECTIVE, GUARD_OFF, GUARD_UNKNOWN,
    REQ_APPLY, REQ_CONFIRM, REQ_PING, REQ_ROLLBACK, REQ_STATUS,
};
use aegis_version as version;

/// 子命令。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cmd {
    Status,
    Ping,
    /// 下发（危险）。
    Apply,
    /// 确认（危险）。
    Confirm,
    /// 拆除（危险）。
    Rollback,
}

impl Cmd {
    /// 对应的请求词。
    fn word(self) -> &'static str {
        match self {
            Self::Status => REQ_STATUS,
            Self::Ping => REQ_PING,
            Self::Apply => REQ_APPLY,
            Self::Confirm => REQ_CONFIRM,
            Self::Rollback => REQ_ROLLBACK,
        }
    }

    /// 这条命令会不会改变本机网络状态。
    fn dangerous(self) -> bool {
        matches!(self, Self::Apply | Self::Confirm | Self::Rollback)
    }
}

fn main() -> ExitCode {
    let args = Args::parse(std::env::args().skip(1));

    println!("Aegis · aegisctl —— {}", version::full());
    println!("管道：{}", args.pipe);
    if args.cmd.dangerous() {
        println!(
            "⚠ `{}` 会改变本机网络状态，服务端会额外检查本进程是否已提权。",
            args.cmd.word()
        );
    }
    println!();

    // ── 读 token ─────────────────────────────────────────────────────
    let hex = match std::fs::read_to_string(&args.token_file) {
        Ok(s) => s.trim().to_string(),
        Err(e) => {
            eprintln!("[FATAL] 读不到 token 文件：{e}");
            eprintln!("  路径：{}", args.token_file.display());
            eprintln!("  先启动 aegisd，它会把 token 写到这个文件。");
            return ExitCode::from(2);
        },
    };
    let token = match IpcToken::from_hex(&hex) {
        Some(t) => t,
        None => {
            eprintln!(
                "[FATAL] token 文件格式不对（应为 {} 个 hex 字符）",
                aegis_ipc::TOKEN_HEX_LEN
            );
            return ExitCode::from(2);
        },
    };
    println!("1. 已读取 token（{} 字节，不打印）", aegis_ipc::TOKEN_BYTES);

    // ── 连管道 ───────────────────────────────────────────────────────
    //
    // 从这里往下的整段流程（握手 → 鉴权 → 请求）走的是
    // `aegis_ipc::client::Session`。它用**类型状态**把顺序钉死：
    // 没握手拿不到 `Handshook`，没鉴权拿不到 `Ready`，而 `request()`
    // 只挂在 `Ready` 上。所以下面这段**不可能**写成"跳过握手直接鉴权"。
    let conn = match Session::connect(&args.pipe) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[FATAL] {e}");
            eprintln!("  aegisd 可能没启动，或用了不同的 --pipe。");
            return ExitCode::from(3);
        },
    };
    println!("2. 已连接");

    // ── 握手（在鉴权之前）────────────────────────────────────────────
    println!("3. → 版本握手（本端 {}）", aegis_ipc::local_version());
    let hs = match conn.handshake() {
        Ok(h) => h,
        Err(ClientError::Incompatible { peer, reason }) => {
            // 版本行照样打出来：人得先知道对面是谁，才知道该升级谁。
            println!("4. ← 服务端版本 {peer}：{:?}", Verdict::Reject(reason));
            eprintln!("[FATAL] 版本不兼容，到此为止：{reason}");
            eprintln!("  不会把 token 发给一个版本谈不拢的对端。");
            return ExitCode::from(4);
        },
        Err(e) => {
            eprintln!("[FATAL] {e}");
            return ExitCode::from(4);
        },
    };
    let peer = hs.handshake().peer();
    let verdict = hs.handshake().verdict();
    println!("4. ← 服务端版本 {peer}：{verdict:?}");

    // ── 鉴权 ─────────────────────────────────────────────────────────
    println!("5. → token 鉴权");
    let mut ready = match hs.authenticate(&token) {
        Ok(r) => {
            println!("6. ← 鉴权通过");
            r
        },
        Err(ClientError::AuthDenied(msg)) => {
            println!("6. ← 鉴权失败");
            eprintln!("[FATAL] 鉴权失败：{msg}");
            eprintln!("  不重试。自动重试会把「token 不对」变成一次慢速拒绝服务。");
            return ExitCode::from(5);
        },
        Err(ClientError::NoAuthReply(e)) => {
            // 服务端对鉴权失败是**立刻断开、不回任何响应**，
            // 所以收不到应答的第一嫌疑就是 token 不对。
            eprintln!("[FATAL] 没收到鉴权应答：{e}");
            eprintln!("  服务端对鉴权失败的处理是立刻断开且不回响应——");
            eprintln!("  收不到应答，第一嫌疑就是 token 不对。");
            return ExitCode::from(5);
        },
        Err(e) => {
            eprintln!("[FATAL] {e}");
            return ExitCode::from(4);
        },
    };

    // ── 发请求 ───────────────────────────────────────────────────────
    let word = args.cmd.word();
    println!("7. → 请求 {word}");

    // 成败按**前缀**判，不靠在正文里搜"失败"两个字。
    // 靠搜的下场是：服务端哪天把拒绝原因写成了"未执行"，
    // 这里就当成功，而人拿着绿色的结果以为规则已经装上。
    // 这条判定现在收在 `Session::request` 里：服务端明确拒绝会变成
    // `ClientError::Rejected`，不会和"链路故障"混在一起。
    let body = match ready.request(word) {
        Ok(b) => b,
        Err(ClientError::Rejected(reason)) => {
            eprintln!("[拒绝] {reason}");
            if args.cmd.dangerous() {
                eprintln!(
                    "  提示：`{}` 要求本终端**以管理员身份运行**。",
                    args.cmd.word()
                );
                eprintln!("  （token 只证明你是本机客户端，证明不了你有权改网络状态）");
            }
            return ExitCode::from(8);
        },
        Err(e) => {
            eprintln!("[FATAL] {e}");
            return ExitCode::from(4);
        },
    };

    match args.cmd {
        Cmd::Ping => {
            println!("8. ← {body}（链路活着）");
            return ExitCode::SUCCESS;
        },
        Cmd::Apply => {
            println!("8. ← {body}");
            println!();
            println!("⏳ 请在 10 秒内执行：aegisctl confirm --token-file <...>");
            println!("   超时未确认，规则会被**自动撤销**。");
            return ExitCode::SUCCESS;
        },
        Cmd::Confirm | Cmd::Rollback => {
            println!("8. ← {body}");
            return ExitCode::SUCCESS;
        },
        Cmd::Status => {},
    }

    let status = match Status::from_text(&body) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[FATAL] 状态文档解析失败：{e}");
            eprintln!("  原始应答：{body}");
            return ExitCode::from(6);
        },
    };

    println!();
    println!("── aegisd 状态 ───────────────────────────────────────────────");
    println!("  状态            : {}", status.state);
    println!("  绝缘等级        : {}", status.insulation);
    println!("  默认出口 LUID   : {}", status.egress_luid);
    println!("  拓扑指纹        : {}", status.fingerprint);
    println!("  物理网卡        : {} 张", status.physical_nics);
    println!("  待人工确认      : {} 张", status.pending_confirm);
    println!("  审计事件        : {} 条", status.audit_len);
    println!(
        "  绝缘笼规则      : {} 条（**干跑，未下发**）",
        status.wfp_rules
    );
    println!(
        "  不变量自检      : {}",
        if status.wfp_invariants_ok {
            "通过"
        } else {
            "**违反**"
        }
    );
    print_guard(&status.guard);

    // 可信指纹对不上 = 拓扑变了，按设计该重新打断用户确认。
    if let Some(trusted) = args.expect_fingerprint {
        if trusted != status.fingerprint {
            println!();
            println!("  ⚠ 拓扑指纹与期望不一致：");
            println!("      期望 {trusted}");
            println!("      实际 {}", status.fingerprint);
            println!("  按 §20.4，指纹漂移意味着网络拓扑变了，应重新人工确认。");
            return ExitCode::from(7);
        }
        println!("  指纹校验        : 与期望一致");
    }

    ExitCode::SUCCESS
}

struct Args {
    pipe: String,
    token_file: PathBuf,
    cmd: Cmd,
    expect_fingerprint: Option<String>,
}

impl Args {
    fn parse(argv: impl Iterator<Item = String>) -> Self {
        let mut pipe = aegis_ipc::PIPE_NAME.to_string();
        let mut token_file: Option<PathBuf> = None;
        let mut cmd = Cmd::Status;
        let mut expect_fingerprint = None;
        let mut args = argv;

        while let Some(a) = args.next() {
            match a.as_str() {
                // 与 aegisd 一样收裸名：Git Bash 会吃掉 `\.\pipeegis`
                // 里的一个反斜杠，靠"让用户写对"这条路根本走不通。
                "--pipe" => pipe = aegis_ipc::normalize_pipe_name(&args.next().unwrap_or(pipe)),
                "--token-file" => token_file = args.next().map(PathBuf::from),
                // `--ping` 是历史写法，等价于 `ping` 子命令
                "--ping" => cmd = Cmd::Ping,
                "--expect-fingerprint" => expect_fingerprint = args.next(),
                "--help" | "-h" => {
                    print_usage();
                    std::process::exit(0);
                },
                other => match Cmd::from_word(other) {
                    Some(c) => cmd = c,
                    None => eprintln!("[WARN] 忽略未知参数：{other}"),
                },
            }
        }

        Self {
            pipe,
            token_file: token_file.unwrap_or_else(|| PathBuf::from(".aegis-run/ipc.token")),
            cmd,
            expect_fingerprint,
        }
    }
}

impl Cmd {
    /// 从命令行位置参数解析。**认不出的返回 `None`**，由调用方当未知参数处理，
    /// 绝不默认成 `status`——"把打错的命令当查询执行"会让人以为自己下发成功了。
    fn from_word(w: &str) -> Option<Self> {
        match w {
            REQ_STATUS => Some(Self::Status),
            REQ_PING => Some(Self::Ping),
            REQ_APPLY => Some(Self::Apply),
            REQ_CONFIRM => Some(Self::Confirm),
            REQ_ROLLBACK => Some(Self::Rollback),
            _ => None,
        }
    }
}

/// 打印守卫状态。
///
/// # ⚠ 这块是**断网时给人看的第一屏**
///
/// 收紧 = 放行被撤 = 全都拒绝。用户这时候第一反应是"是不是 Aegis 坏了"，
/// 再往后就是卸载。所以这里必须回答三件事：断没断、为什么、要不要人管。
/// 只报一个"已收紧"是不够的——那是把人推向卸载。
fn print_guard(g: &GuardView) {
    println!();
    println!("── 守卫（下游规则生效性）──────────────────────────────────────");
    println!(
        "  放行            : {}",
        if g.tightened {
            "**已撤掉**（只剩拒绝底板 → 全都拒绝）"
        } else {
            "正常"
        }
    );
    println!("  最近结论        : {}", verdict_text(&g.verdict));
    if !g.reason.is_empty() {
        println!("  原因            : {}", g.reason);
    }
    if g.needs_human {
        println!();
        println!("  ⚠ **需要人工介入**：守卫已停止自动动作，等处理。");
        println!("    处理方式：修好下游代理 / 改对 proxy 配置，然后重启 aegisd");
        println!("    （『需要人工』一旦置上不会自动清除——自动清除等于又自动开关起来）");
    }
    if g.tightened && g.reason.is_empty() {
        println!("  ⚠ 已收紧但**没有给出原因**——这是 bug：断网不给理由会逼人卸载。");
    }
}

/// 结论取值翻译成人话。
///
/// ⚠ 认不出的取值**不能**显示成"正常"：那是把未知说成已知，
/// 而守卫的取值一旦新增（比如以后加 `degraded`），这里就该显式暴露出来。
fn verdict_text(v: &str) -> String {
    match v {
        GUARD_EFFECTIVE => "生效".to_string(),
        GUARD_INEFFECTIVE => "未生效".to_string(),
        GUARD_UNKNOWN => "判不了（不会收紧）".to_string(),
        GUARD_OFF => "未启用".to_string(),
        "" => "（守护进程未上报）".to_string(),
        other => format!("**未知取值** {other}"),
    }
}

fn print_usage() {
    println!("用法：aegisctl <命令> [选项]");
    println!();
    println!("命令（默认 status）：");
    println!("  status     查守护进程状态（只读）");
    println!("  ping       心跳（只读）");
    println!("  apply      下发绝缘笼（**危险**，装完只是待确认）");
    println!("  confirm    确认刚才那次下发（**危险**）");
    println!("  rollback   立即拆除，含已确认规则的强拆（**危险**）");
    println!();
    println!("选项：");
    println!(
        "  --pipe <name>                IPC 管道名（默认 {}）",
        aegis_ipc::PIPE_NAME
    );
    println!("  --token-file <path>          token 文件（默认 .aegis-run/ipc.token）");
    println!("  --ping                       等价于 `ping` 子命令（历史写法）");
    println!("  --expect-fingerprint <hex>   校验拓扑指纹，不一致则以 7 退出");
    println!();
    println!("危险命令要求本终端**以管理员身份运行**——token 只证明你是本机客户端，");
    println!("证明不了你有权改网络状态。");
    println!();
    println!("退出码：2 token 读不到 / 3 连不上 / 4 协议错误 / 5 鉴权失败");
    println!("        6 状态文档解析失败 / 7 指纹不一致 / 8 服务端拒绝");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(words: &[&str]) -> std::vec::IntoIter<String> {
        words
            .iter()
            .map(|s| (*s).to_string())
            .collect::<Vec<_>>()
            .into_iter()
    }

    #[test]
    fn defaults_point_at_the_daemon_pipe_and_the_default_token_path() {
        let a = Args::parse(std::iter::empty());
        assert_eq!(a.pipe, aegis_ipc::PIPE_NAME);
        assert_eq!(a.token_file, PathBuf::from(".aegis-run/ipc.token"));
        assert_eq!(a.cmd, Cmd::Status);
        assert!(!a.cmd.dangerous());
        assert!(a.expect_fingerprint.is_none());
    }

    #[test]
    fn options_are_parsed() {
        let a = Args::parse(argv(&[
            "--pipe",
            r"\\.\pipe\other",
            "--token-file",
            "t.txt",
            "--ping",
            "--expect-fingerprint",
            "ab12",
        ]));
        assert_eq!(a.pipe, r"\\.\pipe\other");
        assert_eq!(a.token_file, PathBuf::from("t.txt"));
        assert_eq!(a.cmd, Cmd::Ping);
        assert_eq!(a.expect_fingerprint.as_deref(), Some("ab12"));
    }

    /// 未知参数不能让控制端崩掉——它会被引进各种脚本里。
    #[test]
    fn unknown_args_are_ignored_not_fatal() {
        let a = Args::parse(argv(&["--nope", "--pipe"]));
        assert_eq!(a.pipe, aegis_ipc::PIPE_NAME);
        assert_eq!(a.cmd, Cmd::Status);
    }

    /// ⚠ 打错的命令**不能**默认成 `status`：那会让人以为自己下发成功了，
    /// 实际上只是查了个状态然后以 0 退出。
    #[test]
    fn a_misspelled_command_is_not_silently_downgraded_to_status() {
        assert_eq!(Cmd::from_word("aply"), None);
        assert_eq!(Cmd::from_word(""), None);
        assert_eq!(Cmd::from_word("--apply"), None);
    }

    #[test]
    fn every_subcommand_maps_to_its_request_word() {
        assert_eq!(Cmd::from_word("status"), Some(Cmd::Status));
        assert_eq!(Cmd::from_word("ping"), Some(Cmd::Ping));
        assert_eq!(Cmd::from_word("apply"), Some(Cmd::Apply));
        assert_eq!(Cmd::from_word("confirm"), Some(Cmd::Confirm));
        assert_eq!(Cmd::from_word("rollback"), Some(Cmd::Rollback));
    }

    /// 危险命令的标记必须和请求词表一致：漏标一个，控制端就不会打印
    /// 那条"要求管理员"的提示，人就会一头雾水地被拒。
    #[test]
    fn danger_marks_match_the_request_word_table() {
        assert!(Cmd::Apply.dangerous());
        assert!(Cmd::Confirm.dangerous());
        assert!(Cmd::Rollback.dangerous());
        assert!(!Cmd::Status.dangerous());
        assert!(!Cmd::Ping.dangerous());

        use aegis_ipc::risk_of;
        use aegis_ipc::Risk;
        for c in [Cmd::Apply, Cmd::Confirm, Cmd::Rollback] {
            assert_eq!(risk_of(c.word()), Risk::Dangerous);
        }
        for c in [Cmd::Status, Cmd::Ping] {
            assert_eq!(risk_of(c.word()), Risk::ReadOnly);
        }
    }

    #[test]
    fn a_positional_subcommand_is_picked_up() {
        let a = Args::parse(argv(&["apply"]));
        assert_eq!(a.cmd, Cmd::Apply);
        assert!(a.cmd.dangerous());
    }

    #[test]
    fn a_malformed_token_is_rejected() {
        assert!(IpcToken::from_hex("zz").is_none());
        assert!(IpcToken::from_hex("").is_none());
    }
}
