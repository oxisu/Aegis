//! `aegisctl` —— Aegis 控制端的最小形态。
//!
//! ```text
//! cargo run -p aegisctl -- --token-file .aegis-run/ipc.token
//! ```
//!
//! # 它做的事
//!
//! ```text
//! 连管道 → 版本握手 → token 鉴权 → 发 status 请求 → 收并校验状态文档 → 打印
//! ```
//!
//! # 两条纪律
//!
//! 1. **握手必须在鉴权之前。** 版本谈不拢就别把 token 送过去——
//!    对面是老版本，它未必会用常量时间比对来验 token。
//! 2. **鉴权失败不要重试。** 一次失败就退出并说清为什么。
//!    自动重试会把"token 不对"变成一次慢速的拒绝服务，
//!    也更容易撞上服务端的防爆破策略。

use std::path::PathBuf;
use std::process::ExitCode;

use aegis_ipc::{
    check_compat, encode_handshake, msg_type, IpcToken, PipeClient, Status, REQ_STATUS,
};
use aegis_version as version;

fn main() -> ExitCode {
    let args = Args::parse(std::env::args().skip(1));

    println!("Aegis · aegisctl —— {}", version::full());
    println!("管道：{}", args.pipe);
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
            eprintln!("[FATAL] token 文件格式不对（应为 {} 个 hex 字符）", aegis_ipc::TOKEN_HEX_LEN);
            return ExitCode::from(2);
        },
    };
    println!("1. 已读取 token（{} 字节，不打印）", aegis_ipc::TOKEN_BYTES);

    // ── 连管道 ───────────────────────────────────────────────────────
    let cli = match PipeClient::connect_named(&args.pipe) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[FATAL] 连不上管道：{e}");
            eprintln!("  aegisd 可能没启动，或用了不同的 --pipe。");
            return ExitCode::from(3);
        },
    };
    let end = cli.end();
    println!("2. 已连接");

    // ── 握手（在鉴权之前）────────────────────────────────────────────
    let hs = match encode_handshake(1) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[FATAL] 编码握手帧失败：{e}");
            return ExitCode::from(4);
        },
    };
    if let Err(e) = end.send_raw(&hs) {
        eprintln!("[FATAL] 发握手失败：{e}");
        return ExitCode::from(4);
    }
    println!("3. → 版本握手（本端 {}）", aegis_ipc::local_version());

    let mut reader = aegis_ipc::FrameReader::new();
    let reply = match end.recv(&mut reader) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[FATAL] 收握手应答失败：{e}");
            return ExitCode::from(4);
        },
    };
    let peer = match aegis_ipc::HandshakePayload::decode(&reply.payload) {
        Ok(p) => p.to_triple(),
        Err(e) => {
            eprintln!("[FATAL] 握手应答解析失败：{e}");
            return ExitCode::from(4);
        },
    };
    let verdict = check_compat(peer, aegis_ipc::local_version());
    println!("4. ← 服务端版本 {peer}：{verdict:?}");
    if let aegis_ipc::Verdict::Reject(reason) = verdict {
        eprintln!("[FATAL] 版本不兼容，到此为止：{reason}");
        eprintln!("  不会把 token 发给一个版本谈不拢的对端。");
        return ExitCode::from(4);
    }

    // ── 鉴权 ─────────────────────────────────────────────────────────
    if let Err(e) = end.send(msg_type::AUTH, 0, 2, token.to_hex().as_bytes()) {
        eprintln!("[FATAL] 发鉴权失败：{e}");
        return ExitCode::from(4);
    }
    println!("5. → token 鉴权");

    let auth = match end.recv(&mut reader) {
        Ok(f) => f,
        Err(e) => {
            // 服务端对鉴权失败是**立刻断开、不回任何响应**，
            // 所以收不到应答的第一嫌疑就是 token 不对。
            eprintln!("[FATAL] 没收到鉴权应答：{e}");
            eprintln!("  服务端对鉴权失败的处理是立刻断开且不回响应——");
            eprintln!("  收不到应答，第一嫌疑就是 token 不对。");
            return ExitCode::from(5);
        },
    };
    let ok = auth.payload == b"ok";
    println!(
        "6. ← 鉴权{}",
        if ok { "通过" } else { "失败" }
    );
    if !ok {
        eprintln!("[FATAL] 鉴权失败：{}", String::from_utf8_lossy(&auth.payload));
        eprintln!("  不重试。自动重试会把「token 不对」变成一次慢速拒绝服务。");
        return ExitCode::from(5);
    }

    // ── 状态查询 ─────────────────────────────────────────────────────
    if args.ping {
        if let Err(e) = end.send(msg_type::PING, 0, 3, &[]) {
            eprintln!("[FATAL] 发心跳失败：{e}");
            return ExitCode::from(4);
        }
        match end.recv(&mut reader) {
            Ok(f) if f.msg_type == msg_type::PONG => println!("7. ← PONG（链路活着）"),
            Ok(f) => println!("7. ← 意外的帧类型 {}", f.msg_type),
            Err(e) => {
                eprintln!("[FATAL] 收心跳应答失败：{e}");
                return ExitCode::from(4);
            },
        }
        return ExitCode::SUCCESS;
    }

    if let Err(e) = end.send(msg_type::REQUEST, 0, 3, REQ_STATUS.as_bytes()) {
        eprintln!("[FATAL] 发状态请求失败：{e}");
        return ExitCode::from(4);
    }
    println!("7. → 请求 status");

    let resp = match end.recv(&mut reader) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[FATAL] 收状态应答失败：{e}");
            return ExitCode::from(4);
        },
    };
    let text = String::from_utf8_lossy(&resp.payload).to_string();
    let status = match Status::from_text(&text) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[FATAL] 状态文档解析失败：{e}");
            eprintln!("  原始应答：{text}");
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
    println!("  绝缘笼规则      : {} 条（**干跑，未下发**）", status.wfp_rules);
    println!(
        "  不变量自检      : {}",
        if status.wfp_invariants_ok { "通过" } else { "**违反**" }
    );

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
    ping: bool,
    expect_fingerprint: Option<String>,
}

impl Args {
    fn parse(argv: impl Iterator<Item = String>) -> Self {
        let mut pipe = aegis_ipc::PIPE_NAME.to_string();
        let mut token_file: Option<PathBuf> = None;
        let mut ping = false;
        let mut expect_fingerprint = None;
        let mut args = argv;

        while let Some(a) = args.next() {
            match a.as_str() {
                "--pipe" => pipe = args.next().unwrap_or(pipe),
                "--token-file" => token_file = args.next().map(PathBuf::from),
                "--ping" => ping = true,
                "--expect-fingerprint" => expect_fingerprint = args.next(),
                "--help" | "-h" => {
                    print_usage();
                    std::process::exit(0);
                },
                other => eprintln!("[WARN] 忽略未知参数：{other}"),
            }
        }

        Self {
            pipe,
            token_file: token_file.unwrap_or_else(|| PathBuf::from(".aegis-run/ipc.token")),
            ping,
            expect_fingerprint,
        }
    }
}

fn print_usage() {
    println!("用法：aegisctl [选项]");
    println!();
    println!("  --pipe <name>                IPC 管道名（默认 {}）", aegis_ipc::PIPE_NAME);
    println!("  --token-file <path>          token 文件（默认 .aegis-run/ipc.token）");
    println!("  --ping                       只做心跳，不查状态");
    println!("  --expect-fingerprint <hex>   校验拓扑指纹，不一致则以 7 退出");
    println!();
    println!("退出码：2 token 读不到 / 3 连不上 / 4 协议错误 / 5 鉴权失败");
    println!("        6 状态文档解析失败 / 7 指纹不一致");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_point_at_the_daemon_pipe_and_the_default_token_path() {
        let a = Args::parse(std::iter::empty());
        assert_eq!(a.pipe, aegis_ipc::PIPE_NAME);
        assert_eq!(a.token_file, PathBuf::from(".aegis-run/ipc.token"));
        assert!(!a.ping);
        assert!(a.expect_fingerprint.is_none());
    }

    #[test]
    fn options_are_parsed() {
        let argv = [
            "--pipe",
            r"\\.\pipe\other",
            "--token-file",
            "t.txt",
            "--ping",
            "--expect-fingerprint",
            "ab12",
        ]
        .iter()
        .map(|s| (*s).to_string());
        let a = Args::parse(argv);
        assert_eq!(a.pipe, r"\\.\pipe\other");
        assert_eq!(a.token_file, PathBuf::from("t.txt"));
        assert!(a.ping);
        assert_eq!(a.expect_fingerprint.as_deref(), Some("ab12"));
    }

    /// 未知参数不能让控制端崩掉——它会被引进各种脚本里。
    #[test]
    fn unknown_args_are_ignored_not_fatal() {
        let argv = ["--nope", "--pipe"].iter().map(|s| (*s).to_string());
        let a = Args::parse(argv);
        assert_eq!(a.pipe, aegis_ipc::PIPE_NAME);
    }

    #[test]
    fn a_malformed_token_is_rejected() {
        assert!(IpcToken::from_hex("zz").is_none());
        assert!(IpcToken::from_hex("").is_none());
    }
}
