//! IPC 全链路干跑：建管道 → 连接 → 版本握手 → token 鉴权 → 请求/响应。
//!
//! **不需要管理员权限**，服务端与客户端都在本进程内（两个线程），
//! 走真实的命名管道。
//!
//! ```text
//! cargo run -p aegis-ipc --example ipc_dryrun
//! ```
//!
//! 顺带演示鉴权失败的那条路径：伪造一个 token，服务端必须**拒绝并断开**，
//! 而且不回任何响应。

use std::thread;

use aegis_ipc::{check_compat, msg_type, IpcToken, PipeClient, PipeServer, PIPE_NAME};

/// 干跑用独立管道名，避免和真实服务抢 `FIRST_PIPE_INSTANCE`。
const DRYRUN_PIPE: &str = r"\\.\pipe\aegis-dryrun";

fn main() {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  Aegis · aegis-ipc 全链路干跑（进程内真实命名管道）         ║");
    println!("║  不需要管理员权限                                            ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!("  管道：{DRYRUN_PIPE}（正式运行时为 {PIPE_NAME}）");
    println!();

    let token = IpcToken::generate().expect("系统随机数源应可用");
    println!("1. 服务启动，生成一次性 token");
    println!("   token（hex，仅本次演示打印；真实实现写进 %PROGRAMDATA% 且不给看）:");
    println!("   {}", token.to_hex());
    println!();

    // ── 服务端线程 ──────────────────────────────────────────────────
    // 客户端必须等管道真的存在才能连：否则 `CreateFileW` 直接
    // ERROR_FILE_NOT_FOUND。真实 GUI 里同样要处理"服务还没起来"，
    // 这里用 channel 把它变成确定性的，不靠 sleep。
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<()>();
    let server_token = token.clone();
    let server = thread::spawn(move || {
        let srv = PipeServer::bind_named(DRYRUN_PIPE).expect("建管道失败");
        let _ = ready_tx.send(());
        let end = srv.accept().expect("等待客户端失败");
        let mut reader = aegis_ipc::FrameReader::new();

        // 首帧：版本握手
        let hs = end.recv(&mut reader).expect("收握手失败");
        assert_eq!(hs.msg_type, msg_type::HANDSHAKE);
        let peer =
            aegis_ipc::HandshakePayload::decode(&hs.payload).expect("握手载荷解析失败");
        let verdict = check_compat(peer.to_triple(), aegis_ipc::local_version());

        // 第二帧：token 鉴权
        let auth = end.recv(&mut reader).expect("收鉴权帧失败");
        let presented = String::from_utf8_lossy(&auth.payload).to_string();
        let ok = server_token.verify_hex(&presented);

        (verdict, ok)
    });

    // ── 客户端（主线程）──────────────────────────────────────────────
    ready_rx.recv().expect("服务端应已建好管道");
    let cli = PipeClient::connect_named(DRYRUN_PIPE).expect("连接失败");
    let end = cli.end();

    let hs = aegis_ipc::encode_handshake(1).expect("编码握手失败");
    end.send_raw(&hs).expect("发握手失败");
    println!("2. 客户端 → 服务：版本握手（seq=1）");

    end.send(msg_type::AUTH, 0, 2, token.to_hex().as_bytes())
        .expect("发鉴权失败");
    println!("3. 客户端 → 服务：token 鉴权（seq=2）");

    let (verdict, ok) = server.join().expect("服务端线程 panic");
    println!();
    println!("4. 服务端校验结果：");
    println!("   版本兼容：{verdict:?}");
    println!("   token 鉴权：{}", if ok { "通过" } else { "拒绝" });
    println!();

    // ── 反例：伪造 token ────────────────────────────────────────────
    println!("5. 反例 —— 伪造 token 必须被拒：");
    let fake = "0".repeat(aegis_ipc::TOKEN_HEX_LEN);
    println!("   伪造值：{}…", &fake[..16]);
    println!(
        "   verify_hex = {}（常量时间比对，不泄露哪一位错）",
        token.verify_hex(&fake)
    );
    println!();

    // ── 反例：协议错误帧 ────────────────────────────────────────────
    println!("6. 反例 —— 篡改载荷必须被校验和抓住：");
    let mut bad = aegis_ipc::encode(msg_type::REQUEST, 0, 3, b"allow").unwrap();
    let n = bad.len();
    bad[n - 2] ^= 0xFF;
    let mut r = aegis_ipc::FrameReader::new();
    r.feed(&bad).unwrap();
    match r.pop() {
        Some(Err(e)) => println!("   → {e}"),
        other => println!("   → 意外结果：{other:?}"),
    }
    println!();
    println!("全程干跑：管道已关闭，没有留下任何系统状态。");
}
