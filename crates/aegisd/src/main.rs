//! `aegisd` —— Aegis 守护进程的**最小可运行链路**。
//!
//! ```text
//! cargo run -p aegisd -- --config config/config.example.toml --data-dir .aegis-run
//! ```
//!
//! # 这条链路证明什么
//!
//! 它把已经落地的各层串成一次真实的启动：
//!
//! ```text
//! 启动 → 加载配置（失败就退出）→ 开 IPC 命名管道 → 感知快照 → 角色裁决
//!      → WFP 干跑（**不下发**）→ 审计写一条"启动完成" → 应答 aegisctl
//! ```
//!
//! # 三条不可让步的启动纪律
//!
//! 1. **配置加载失败就退出，不退回默认值。**
//!    `aegis-config` 明确不提供默认值：读不到/解析不了/schema 不兼容，
//!    一律 `exit(2)`。带病运行的守护进程比不运行的守护进程危险——
//!    它看起来在工作，实际按一套没人审核过的策略在放行。
//! 2. **感知失败就退出。** 不知道这台机器长什么样，就不能裁决角色；
//!    此时的"放行"是盲放行。
//! 3. **WFP 只干跑。** 本链路**一条规则都不下发**。真正下发需要提权，
//!    且会改变本机网络状态，**必须先征求用户同意**（见 design-spec §21.1）。
//!
//! # 已知的、刻意留下的缺口
//!
//! - token 文件目前按**普通文件**写入，尚未套用 `TOKEN_FILE_SDDL`
//!   （SYSTEM/BA 完全控制、AU 只读）。正式版必须补上，否则本机任何用户
//!   都能读到 IPC token。见 [`write_token_file`]。
//! - "启动完成"这条审计事件是**链路自检事件，不是真实连接**。
//!   审计事件模型目前只描述连接，用它占位会让证据包里混进一条伪造的
//!   连接记录。正式版要么引入独立的事件种类，要么在导出时按 `BOOT:` 前缀
//!   过滤掉。见 [`startup_event`]。

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aegis_audit::{Action, AuditEvent, AuditLog, InterfaceRole, Protocol};
use aegis_config::load_file;
use aegis_core::role::{adjudicate_all, Confidence};
use aegis_core::state::{insulation, State};
use aegis_ipc::{
    check_compat, encode_handshake, msg_type, IpcToken, PipeServer, Status, REQ_PING, REQ_STATUS,
};
use aegis_sense::{default_egress, snapshot};
use aegis_wfp::{cage_plan, invariants_violated, verify_with, CagePolicy};
use aegis_version as version;

/// 退出码。**刻意各不相同**：运维看到码就知道卡在哪一步，
/// 不用去翻日志猜。
mod exit {
    pub const CONFIG: i32 = 2;
    pub const IPC: i32 = 3;
    pub const SENSE: i32 = 4;
    pub const AUDIT: i32 = 5;
}

fn main() {
    let args = Args::parse(std::env::args().skip(1));

    println!("Aegis · aegisd —— {}", version::full());
    println!("最小链路：配置 → IPC → 感知 → 裁决 → WFP 干跑 → 审计");
    println!("⚠ 本链路**一条 WFP 规则都不下发**。");
    println!();

    // ── 1. 加载配置：失败就退出，不退回默认值 ────────────────────────
    println!("[1/7] 加载配置");
    let config = match load_file(&args.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("  [FATAL] 配置加载失败：{e}");
            eprintln!("  配置文件：{}", args.config.display());
            eprintln!("  Aegis 不提供默认配置——带病运行比不运行更危险。");
            std::process::exit(exit::CONFIG);
        },
    };
    println!("  schema      : {}", config.meta.config_schema_version);
    println!("  可信指纹    : {}", if config.topology.trusted_fingerprint.is_empty() {
        "（空，首次开机）"
    } else {
        &config.topology.trusted_fingerprint
    });
    for w in &config.warnings {
        println!("  [WARN] {w}");
    }
    println!();

    // ── 2. 生成 IPC token 并开启命名管道 ─────────────────────────────
    println!("[2/7] 开启 IPC 命名管道");
    let token = match IpcToken::generate() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("  [FATAL] 无法生成 IPC token：{e}");
            std::process::exit(exit::IPC);
        },
    };
    if let Err(e) = write_token_file(&args.token_file, &token) {
        eprintln!("  [FATAL] 无法写入 token 文件：{e}");
        std::process::exit(exit::IPC);
    }
    println!("  管道      : {}", args.pipe);
    println!("  token 文件 : {}", args.token_file.display());
    println!("  ⚠ token 文件当前按普通文件写入，尚未套用 TOKEN_FILE_SDDL——正式版必须补。");

    // ⚠ `PipeServer` 里握着一个原始 HANDLE，**不是 `Send`**，不能跨线程搬。
    // 所以管道在**服务线程内部**绑定，绑定结果用 channel 回传主线程：
    // 主线程要能确认"管道真的起来了"才继续启动，而不是先打印"已绑定"
    // 再在后面悄悄失败——那种"说了但没做"的启动日志最坑人。
    let status_slot: Arc<Mutex<Option<Status>>> = Arc::new(Mutex::new(None));
    let (ready_tx, ready_rx) = std_mpsc::channel::<Result<(), String>>();
    let serve_pipe = args.pipe.clone();
    let serve_token = token.clone();
    let serve_status = Arc::clone(&status_slot);
    thread::spawn(move || {
        let server = match PipeServer::bind_named(&serve_pipe) {
            Ok(s) => s,
            Err(e) => {
                let _ = ready_tx.send(Err(e.to_string()));
                return;
            },
        };
        let _ = ready_tx.send(Ok(()));
        serve_forever(&server, &serve_token, &serve_status);
    });

    match ready_rx.recv_timeout(Duration::from_secs(10)) {
        Ok(Ok(())) => println!("  已绑定，等待 aegisctl 连接"),
        Ok(Err(e)) => {
            eprintln!("  [FATAL] 绑定命名管道失败：{e}");
            eprintln!("  （多半是已有实例占用：设计上只允许一个守护进程实例）");
            std::process::exit(exit::IPC);
        },
        Err(_) => {
            eprintln!("  [FATAL] 绑定命名管道超时（10 秒无响应）");
            std::process::exit(exit::IPC);
        },
    }
    println!();

    // ── 3. 感知快照：失败就退出 ──────────────────────────────────────
    println!("[3/7] 采集拓扑快照（只读）");
    let snap = match snapshot() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("  [FATAL] 拓扑采集失败：{e}");
            eprintln!("  不知道这台机器长什么样，就不能裁决角色——此时放行等于盲放行。");
            std::process::exit(exit::SENSE);
        },
    };
    println!("  物理网卡  : {} 张", snap.physical_interfaces().count());
    println!("  参与指纹  : {} 张（{}）", snap.fingerprint_participants, snap.fingerprint_scope);
    println!("  指纹      : {}", snap.fingerprint);
    match default_egress() {
        Ok(Some(r)) => println!(
            "  默认出口  : LUID {}（合成度量 {} = 接口 {} + 偏移 {}，网关 {:?}）",
            r.interface_luid, r.effective_metric, r.interface_metric, r.route_metric, r.next_hop
        ),
        Ok(None) => println!("  默认出口  : 无默认路由"),
        Err(e) => println!("  默认出口  : 读取失败（{e}），按 Fail-Closed 处理"),
    }
    println!("  快照里的默认出口 LUID: {}", snap.default_egress_luid);
    println!();

    // ── 4. 角色裁决 ──────────────────────────────────────────────────
    println!("[4/7] 角色裁决（§20.5，Fail-Closed）");
    let decisions = adjudicate_all(&snap.interfaces, &config.roles);
    let mut pending_confirm = 0usize;
    for d in &decisions {
        println!(
            "  ● {:<24} {}  [{}]{}",
            truncate(&d.alias, 24),
            d.role,
            d.confidence,
            if d.up { "" } else { "（未连接）" }
        );
        println!("      依据：{}", d.reason);
        if d.confidence != Confidence::Confirmed {
            pending_confirm += 1;
        }
    }
    if decisions.is_empty() {
        println!("  未发现物理网卡");
    }
    println!(
        "  待人工确认：{} 张（猜不出来就绝缘，绝不放开通往外网的口子）",
        pending_confirm
    );
    println!();

    // ── 5. 绝缘等级 ──────────────────────────────────────────────────
    let state = State::Boot;
    let level = insulation(state);
    println!("[5/7] 状态机与绝缘等级（§26）");
    println!("  状态      : {state}");
    println!("  绝缘等级  : {level}");
    println!();

    // ── 6. WFP：只干跑，一条都不下发 ─────────────────────────────────
    println!("[6/7] 绝缘笼计划（**干跑**，不下发）");
    let cage = CagePolicy::default();
    let plan = cage_plan(cage);
    let findings = verify_with(&plan, &cage);
    let ok = !invariants_violated(&findings);
    println!("  规则条数  : {}", plan.len());
    println!("  锁 53     : {} / 校园网严格 : {} / Boot 背板 : {}",
        cage.dns_lock, cage.campus_strict, cage.boot_backbone);
    println!("  静态自检  : {} 项，不变量{}", findings.len(), if ok { " OK" } else { " **违反**" });
    for f in &findings {
        println!("      [{:?}/{}] {}: {}", f.severity, f.kind.name(), f.code, f.detail);
    }
    println!("  ⚠ 以上只是**计划**。下发需提权且会改变本机网络状态，必须先征求用户同意。");
    println!();

    // ── 7. 审计：写一条"启动完成"，证明链路通 ────────────────────────
    println!("[7/7] 审计落盘（写一条链路自检事件）");
    let role = decisions
        .iter()
        .find(|d| d.up && d.role != InterfaceRole::Isolated)
        .map_or(config.roles.fallback_role, |d| d.role);
    let event = startup_event(snap.default_egress_luid, role);

    let audit_path = args.data_dir.join("audit-startup.binlog");
    let mut log = match AuditLog::create(&audit_path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("  [FATAL] 无法创建审计日志：{e}");
            eprintln!("  文件：{}（create_new：拒绝覆盖已有日志）", audit_path.display());
            std::process::exit(exit::AUDIT);
        },
    };
    let link = match log.append(&event) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("  [FATAL] 写入审计事件失败：{e}");
            std::process::exit(exit::AUDIT);
        },
    };
    if let Err(e) = log.flush().and_then(|()| log.sync()) {
        eprintln!("  [FATAL] 审计落盘失败：{e}");
        std::process::exit(exit::AUDIT);
    }
    println!("  事件      : rule={:?} role={} pid={}", event.rule, event.role, event.pid);
    println!("  链节 seq  : {}", link.seq);
    println!("  链头      : {}", aegis_audit::hex(&link.hash));
    println!("  落盘      : {}", audit_path.display());

    // 回读并校验：证明"写进去的和读出来的是同一条，且没被改过"
    match aegis_audit::read_records(&audit_path) {
        Ok(records) => {
            let events: Vec<AuditEvent> = records.iter().map(|r| r.event.clone()).collect();
            let links = records.iter().map(|r| r.link).collect::<Vec<_>>();
            match aegis_audit::verify(&events, &links) {
                Ok(()) => println!("  回读校验  : OK（{} 条，链完整）", records.len()),
                Err(e) => {
                    eprintln!("  [FATAL] 回读校验失败：{e}");
                    std::process::exit(exit::AUDIT);
                },
            }
        },
        Err(e) => {
            eprintln!("  [FATAL] 审计回读失败：{e}");
            std::process::exit(exit::AUDIT);
        },
    }
    println!("  ⚠ 这条是**链路自检事件，不是真实连接**；正式版导出证据包时必须过滤掉。");
    println!();

    // ── 把状态交给 IPC 线程，然后按 --serve-secs 等待 ─────────────────
    let status = Status {
        state: state.to_string(),
        insulation: level.to_string(),
        egress_luid: snap.default_egress_luid,
        fingerprint: snap.fingerprint.clone(),
        physical_nics: snap.physical_interfaces().count(),
        pending_confirm,
        audit_len: link.seq,
        wfp_rules: plan.len(),
        wfp_invariants_ok: ok,
    };

    // 状态交给服务线程：在它拿到之前，任何 status 查询都会得到"启动中"
    if let Ok(mut slot) = status_slot.lock() {
        *slot = Some(status);
    }

    println!("启动完成。IPC 已在 {} 上应答。", args.pipe);
    if args.serve_secs == 0 {
        println!("--serve-secs 0：不等客户端，直接退出。");
    } else {
        println!("等待 aegisctl 连接 {} 秒（--serve-secs 可调）…", args.serve_secs);
        println!("另开一个终端：");
        println!(
            "  cargo run -p aegisctl -- --token-file {} --pipe {}",
            args.token_file.display(),
            args.pipe
        );
        thread::sleep(Duration::from_secs(args.serve_secs));
        println!("服务时间到，退出。");
    }
}

// ── IPC 服务：握手 / 鉴权 / 状态查询 ─────────────────────────────────

/// 逐个接待连接。**鉴权失败立刻断开，不回任何响应**——
/// 回了就等于告诉对方"你猜得差不多了"。
fn serve_forever(server: &PipeServer, token: &IpcToken, status: &Arc<Mutex<Option<Status>>>) {
    loop {
        let end = match server.accept() {
            Ok(e) => e,
            Err(_) => return,
        };
        if let Err(_e) = serve_one(&end, token, status) {
            // 连接层面的错误（断开 / 帧坏）视为这次会话结束，继续等下一个
        }
        // ⚠ 必须显式 disconnect，否则下一次 accept 会失败：
        // 一个管道实例连过一次之后不复位就不能再连，而失败的表现是
        // "服务起来后只应答第一个客户端，之后全部连不上"——这种
        // "第一次好好的、后面全挂"的现象最难排查。
        if server.disconnect().is_err() {
            return;
        }
    }
}

fn serve_one(
    end: &aegis_ipc::PipeEnd,
    token: &IpcToken,
    status: &Arc<Mutex<Option<Status>>>,
) -> Result<(), aegis_ipc::PipeError> {
    let mut reader = aegis_ipc::FrameReader::new();

    // 首帧必须是握手
    let hs = end.recv(&mut reader)?;
    if hs.msg_type != msg_type::HANDSHAKE {
        return Ok(());
    }
    let Ok(peer) = aegis_ipc::HandshakePayload::decode(&hs.payload) else {
        return Ok(());
    };
    // 版本不兼容就到此为止：继续下去两边对同一批字段的语义理解不同，
    // 而"看起来通信正常、实际各说各话"比连不上危险得多。
    if let aegis_ipc::Verdict::Reject(reason) =
        check_compat(peer.to_triple(), aegis_ipc::local_version())
    {
        let msg = format!("版本不兼容：{reason}");
        end.send(msg_type::AUTH_RESULT, 0, 2, msg.as_bytes())?;
        return Ok(());
    }
    end.send_raw(&encode_handshake(1).map_err(|_| aegis_ipc::PipeError::Disconnected)?)?;

    // 第二帧必须是鉴权；失败立刻断开，不回任何响应
    let auth = end.recv(&mut reader)?;
    if auth.msg_type != msg_type::AUTH {
        return Ok(());
    }
    let presented = String::from_utf8_lossy(&auth.payload).to_string();
    if !token.verify_hex(&presented) {
        return Ok(());
    }
    end.send(msg_type::AUTH_RESULT, 0, 3, b"ok")?;

    // 之后才是业务请求
    loop {
        let frame = match end.recv(&mut reader) {
            Ok(f) => f,
            Err(_) => return Ok(()),
        };
        match frame.msg_type {
            msg_type::PING => {
                end.send(msg_type::PONG, 0, frame.seq, &[])?;
            },
            msg_type::REQUEST => {
                let want = String::from_utf8_lossy(&frame.payload);
                match want.trim() {
                    REQ_PING => end.send(msg_type::RESPONSE, 0, frame.seq, b"pong")?,
                    REQ_STATUS => {
                        // 启动还没走完时如实说"启动中"，不编一个看起来正常的状态
                        let body = match status.lock().ok().and_then(|s| s.clone()) {
                            Some(s) => s.to_text(),
                            None => "启动中：状态尚不可用".to_string(),
                        };
                        end.send(msg_type::RESPONSE, 0, frame.seq, body.as_bytes())?
                    },
                    other => {
                        let msg = format!("未知请求：{other}（可用：{REQ_STATUS} / {REQ_PING}）");
                        end.send(msg_type::RESPONSE, 0, frame.seq, msg.as_bytes())?
                    },
                }
            },
            _ => return Ok(()),
        }
    }
}

// ── 辅助 ─────────────────────────────────────────────────────────────

/// 写 token 文件。
///
/// ⚠ **已知缺口**：这里用的是普通文件写入，**没有**套用 `TOKEN_FILE_SDDL`
/// （SYSTEM / Administrators 完全控制，Authenticated Users 只读）。
/// 正式版必须用 `ConvertStringSecurityDescriptorToSecurityDescriptor` +
/// `CreateFileW` 的 `SECURITY_ATTRIBUTES` 落成带 DACL 的文件——
/// 否则本机任何用户都能读到 IPC token，等于鉴权形同虚设。
/// 最小链路先把它跑通，缺口显式留在这里并打印告警，不掩盖。
fn write_token_file(path: &Path, token: &IpcToken) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(path, token.to_hex())
}

/// 构造"启动完成"这条审计事件。
///
/// ⚠ **它是链路自检事件，不是真实连接。** 审计事件模型目前只描述连接，
/// 这里用 `rule = "BOOT:STARTUP_COMPLETE"` 占位。代价是证据包里会混进一条
/// 伪造的连接记录——正式版要么引入独立的事件种类，要么在导出时按 `BOOT:`
/// 前缀过滤掉。**不能**因为它无害就默认留着：核对证据的人不知道这条是假的。
fn startup_event(egress_luid: u64, role: InterfaceRole) -> AuditEvent {
    AuditEvent {
        ts_ms: now_ms(),
        pid: std::process::id(),
        process_path: std::env::current_exe()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| "<aegisd>".to_string()),
        src: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        protocol: Protocol::Other(0),
        host: None,
        rule: Some("BOOT:STARTUP_COMPLETE".to_string()),
        luid: egress_luid,
        role,
        action: Action::Allow,
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let head: String = s.chars().take(max.saturating_sub(1)).collect();
    format!("{head}…")
}

struct Args {
    config: PathBuf,
    pipe: String,
    token_file: PathBuf,
    data_dir: PathBuf,
    serve_secs: u64,
}

impl Args {
    fn parse(argv: impl Iterator<Item = String>) -> Self {
        let mut config: Option<PathBuf> = None;
        let mut pipe = aegis_ipc::PIPE_NAME.to_string();
        let mut token_file: Option<PathBuf> = None;
        let mut data_dir: Option<PathBuf> = None;
        let mut serve_secs: u64 = 30;
        let mut args = argv;

        while let Some(a) = args.next() {
            match a.as_str() {
                "--config" => config = args.next().map(PathBuf::from),
                "--pipe" => pipe = args.next().unwrap_or(pipe),
                "--token-file" => token_file = args.next().map(PathBuf::from),
                "--data-dir" => data_dir = args.next().map(PathBuf::from),
                "--serve-secs" => {
                    serve_secs = args.next().and_then(|v| v.parse().ok()).unwrap_or(serve_secs)
                },
                "--help" | "-h" => {
                    print_usage();
                    std::process::exit(0);
                },
                other => eprintln!("[WARN] 忽略未知参数：{other}"),
            }
        }

        let data_dir = data_dir.unwrap_or_else(|| PathBuf::from(".aegis-run"));
        let config = match config {
            Some(p) => p,
            None => {
                eprintln!("[FATAL] 必须用 --config 指定配置文件。");
                eprintln!("Aegis 不猜配置路径，也不提供默认配置。");
                print_usage();
                std::process::exit(exit::CONFIG);
            },
        };
        let token_file =
            token_file.unwrap_or_else(|| data_dir.join("ipc.token"));

        Self {
            config,
            pipe,
            token_file,
            data_dir,
            serve_secs,
        }
    }
}

fn print_usage() {
    println!("用法：aegisd --config <配置文件> [选项]");
    println!();
    println!("  --config <path>      配置文件（**必填**，读不到就退出）");
    println!("  --pipe <name>        IPC 管道名（默认 {}）", aegis_ipc::PIPE_NAME);
    println!("  --token-file <path>  IPC token 落盘路径（默认 <data-dir>/ipc.token）");
    println!("  --data-dir <dir>     运行数据目录（默认 .aegis-run）");
    println!("  --serve-secs <n>     IPC 服务时长（默认 30，0 = 启动完就退出）");
    println!();
    println!("⚠ 本程序**不下发任何 WFP 规则**。");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_keeps_short_strings_intact() {
        assert_eq!(truncate("以太网", 24), "以太网");
        assert_eq!(truncate("abcdef", 6), "abcdef");
    }

    #[test]
    fn truncate_marks_what_it_cut() {
        let s = truncate("1234567890", 4);
        assert!(s.ends_with('…'), "{s}");
        assert_eq!(s.chars().count(), 4);
    }

    /// 多字节字符按 char 数截断，不能按字节——按字节切会切出半个汉字。
    #[test]
    fn truncate_counts_chars_not_bytes() {
        let s = truncate("校园网接入适配器", 4);
        assert_eq!(s.chars().count(), 4);
        assert!(s.ends_with('…'));
    }

    #[test]
    fn now_ms_is_a_plausible_timestamp() {
        let t = now_ms();
        assert!(t > 1_600_000_000_000, "{t}");
    }

    /// 自检事件必须能被一眼认出来是"不是真实连接"——
    /// 靠的是 `BOOT:` 前缀，这是导出时过滤的依据。
    #[test]
    fn the_startup_event_is_market_as_not_a_real_connection() {
        let e = startup_event(42, InterfaceRole::Isolated);
        assert_eq!(e.rule.as_deref(), Some("BOOT:STARTUP_COMPLETE"));
        assert!(e.rule.as_deref().unwrap().starts_with("BOOT:"));
    }

    #[test]
    fn exit_codes_are_all_distinct() {
        let codes = [exit::CONFIG, exit::IPC, exit::SENSE, exit::AUDIT];
        let mut seen = Vec::new();
        for c in codes {
            assert!(!seen.contains(&c), "退出码重复：{c}");
            seen.push(c);
        }
    }
}
