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
//! 3. **启动路径上一条规则都不下发。** `apply` 是被动作：要由
//!    `aegisctl`（且该进程**已提权**）显式发起，装完还要在 10 秒内
//!    `confirm`，否则自动撤销（见 [`do_apply`] / [`watch`]）。
//!
//! # 下发为什么做成"两阶段 + 倒计时"
//!
//! 装错一条规则的后果不是报错，是**整机断网**。所以：
//!
//! - 需要**提权**（WFP 引擎本身要求），且对端进程必须已提权，
//!   光有 token 不够（token 文件对本机已登录用户可读）；
//! - 装完进入 [`Phase::Pending`]，10 秒内没有 `confirm` 就自动回滚；
//! - 会话是 `FWPM_SESSION_FLAG_DYNAMIC`：**进程一退出，规则全清**。
//!   这条比任何清理代码都可靠，因为崩溃路径上没有机会执行清理代码。
//!
//! # 已知的、刻意留下的缺口
//!
//! - "启动完成"这条审计事件是**链路自检事件，不是真实连接**。
//!   审计事件模型目前只描述连接，用它占位会让证据包里混进一条伪造的
//!   连接记录。正式版要么引入独立的事件种类，要么在导出时按 `BOOT:` 前缀
//!   过滤掉。见 [`startup_event`]。

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use std::fs::OpenOptions;
use std::io::Write as _;

use aegis_audit::{Action, AuditEvent, AuditLog, InterfaceRole, Protocol};
use aegis_config::{load_file, Config};
use aegis_core::guard::{evaluate, GuardAction, GuardPolicy, GuardTracker, GuardVerdict};
use aegis_core::role::{adjudicate_all, Confidence};
use aegis_core::state::{insulation, State};
use aegis_ipc::{
    check_compat, encode_handshake, msg_type, IpcToken, PipeServer, Status, DENY_PREFIX,
    OK_PREFIX, REQ_APPLY, REQ_CONFIRM, REQ_PING, REQ_ROLLBACK, REQ_STATUS,
};
use aegis_sense::{default_egress, snapshot};
use aegis_wfp::{
    apply, cage_plan, invariants_violated, preflight, rollback, verify_with, ApplyTicket,
    CagePolicy, FilterSpec, Phase, Session, CONFIRM_WINDOW_MS,
};
use aegis_version as version;

/// 退出码。**刻意各不相同**：运维看到码就知道卡在哪一步，
/// 不用去翻日志猜。
mod exit {
    pub const CONFIG: i32 = 2;
    pub const IPC: i32 = 3;
    pub const SENSE: i32 = 4;
    pub const AUDIT: i32 = 5;
}

/// 一次下发的票据。**纯数据**（`filter_ids` 只是 `Vec<u64>`），
/// 所以可以跨线程共享；真正不能跨线程的是 WFP 会话句柄，它**永远待在
/// 看门狗线程里**（见 [`watch`]）。
type TicketSlot = std::sync::Arc<std::sync::Mutex<Option<ApplyTicket>>>;

/// 守卫观测的默认周期（秒）。
///
/// 依据：泄漏窗口 ≈ `failure_threshold × 周期` = 3 × 3 = **9 秒**。
/// 更快会常驻占用（每次巡检要跑一遍 `GetIfTable2` + `GetAdaptersAddresses`），
/// 更慢则漏的时间太长。先跑起来再调。
const DEFAULT_GUARD_INTERVAL_SECS: u64 = 3;

/// ⚠ **断言 A 的占位值**：v1 还没接适配器 SPI，`proxy_reachable` 无法真判，
/// 暂时一律按"可达"处理。
///
/// 后果要说清楚：断言 A 永远不会失败，守卫只看 **B（TUN 在不在）** 与
/// **C（默认出口是不是它）**。也就是说**"代理进程死了"这一条目前抓不到**。
/// 接上 SPI 之后改用它返回的 `Op::Health` / `Op::RulesEffective` 的真实结果。
const PROXY_REACHABLE_PLACEHOLDER: bool = true;

fn main() {
    let args = Args::parse(std::env::args().skip(1));

    println!("Aegis · aegisd —— {}", version::full());
    println!("最小链路：配置 → IPC → 感知 → 裁决 → WFP 干跑 → 审计");
    println!("⚠ 启动过程中**不下发**任何 WFP 规则；");
    println!("  `aegisctl apply` 需提权 + 10 秒内 confirm，否则自动撤销。");
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

    // 绝缘笼计划在**开管道之前**就构造好：它是纯逻辑（不读网卡、不开引擎），
    // 而服务线程随时可能被 `apply` 叫到——到那时再临时构造，就得把配置
    // 也搬进线程里。先构造好，服务线程拿走一份拷贝即可。
    let cage = CagePolicy::default();
    let plan = cage_plan(cage);

    // ── 2. 生成 IPC token 并开启命名管道 ─────────────────────────────
    println!("[2/7] 开启 IPC 命名管道");
    let token = match IpcToken::generate() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("  [FATAL] 无法生成 IPC token：{e}");
            std::process::exit(exit::IPC);
        },
    };
    // 父目录要先建好：带 DACL 的 CreateFileW 不会顺手建目录。
    if let Some(parent) = args.token_file.parent() {
        if !parent.as_os_str().is_empty() && std::fs::create_dir_all(parent).is_err() {
            eprintln!("  [FATAL] 无法创建数据目录：{}", parent.display());
            std::process::exit(exit::IPC);
        }
    }
    if let Err(e) = aegis_ipc::write_protected(&args.token_file, &token) {
        eprintln!("  [FATAL] 无法写入 token 文件：{e}");
        std::process::exit(exit::IPC);
    }
    println!("  管道      : {}", args.pipe);
    println!("  token 文件 : {}（DACL: SY/BA 完全控制，AU 只读）", args.token_file.display());
    println!("  ⚠ AU 仍可读 token（GUI 不提权，必须能读）。危险命令另有提权检查。");

    // ⚠ `PipeServer` 里握着一个原始 HANDLE，**不是 `Send`**，不能跨线程搬。
    // 所以管道在**服务线程内部**绑定，绑定结果用 channel 回传主线程：
    // 主线程要能确认"管道真的起来了"才继续启动，而不是先打印"已绑定"
    // 再在后面悄悄失败——那种"说了但没做"的启动日志最坑人。
    let status_slot: Arc<Mutex<Option<Status>>> = Arc::new(Mutex::new(None));
    let ticket_slot: TicketSlot = Arc::new(Mutex::new(None));
    let (ready_tx, ready_rx) = std_mpsc::channel::<Result<(), String>>();
    let serve_pipe = args.pipe.clone();
    let serve_token = token.clone();
    let serve_status = Arc::clone(&status_slot);
    let serve_ticket = Arc::clone(&ticket_slot);
    let serve_plan = plan.clone();
    thread::spawn(move || {
        let server = match PipeServer::bind_named(&serve_pipe) {
            Ok(s) => s,
            Err(e) => {
                let _ = ready_tx.send(Err(e.to_string()));
                return;
            },
        };
        let _ = ready_tx.send(Ok(()));
        serve_forever(&server, &serve_token, &serve_status, &serve_plan, &serve_ticket);
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
    let findings = verify_with(&plan, &cage);
    let ok = !invariants_violated(&findings);
    println!("  规则条数  : {}", plan.len());
    println!("  锁 53     : {} / 校园网严格 : {} / Boot 背板 : {}",
        cage.dns_lock, cage.campus_strict, cage.boot_backbone);
    println!("  静态自检  : {} 项，不变量{}", findings.len(), if ok { " OK" } else { " **违反**" });
    for f in &findings {
        println!("      [{:?}/{}] {}: {}", f.severity, f.kind.name(), f.code, f.detail);
    }
    // ⚠ 逐条打印。让人在**下发之前**就能看清要装的是什么——
    // "装了 10 条规则"这种数字没有任何判断价值，
    // 而"第 3 条是无条件阻断"才是决定要不要按回车的依据。
    print_plan(&plan);
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
    // ⚠ **必须是 `open_or_create`，不能是 `create`。**
    // 用 `create` 的话，一次掉电 / 蓝屏留下的日志文件会让下一次启动因为
    // "文件已存在"而失败——一次断电就把服务**永久**打趴在地上，这正好是
    // 崩溃安全的反面。存在就续写（保住证据），不存在才新建。
    let (mut log, action) = match AuditLog::open_or_create(&audit_path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("  [FATAL] 无法打开审计日志：{e}");
            eprintln!("  文件：{}", audit_path.display());
            eprintln!("  ⚠ 日志读不懂 = 证据链已经不可信，此时不该带病启动。");
            eprintln!("  若确需丢弃证据：手动删除该文件后重启（删证据必须人来按下）。");
            std::process::exit(exit::AUDIT);
        },
    };
    println!("  打开方式  : {action}");
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

    // ── 守卫观测（步 1：**只判不动手**）─────────────────────────────
    //
    // 为什么先做这一步：`Tighten` 的代价是**整机断网**，所以在真的接上动作
    // 之前，必须先确认这套判据在真机上不会平白无故报 `Ineffective`。
    // 方案见 docs/GUARD-WIRING.md §5；步 2 才会把动作接上去。
    println!(
        "守卫：下游规则生效性观测{}",
        if args.guard_act {
            "（步 2：Tighten 已接线，会真的撤放行）"
        } else {
            "（步 1：只观测不动手）"
        }
    );
    match config.guard_gap() {
        Some(gap) => {
            println!("  ⚠ 未启用：{gap}");
            println!("  配置 proxy.mode 与 proxy.tun_luid 之后才会开始观测。");
        },
        None if args.guard_interval_secs == 0 => {
            println!("  已关闭（--guard-interval-secs 0）。");
        },
        None => {
            let log = args.data_dir.join("guard-observe.log");
            println!("  周期      : {} 秒", args.guard_interval_secs);
            println!("  断言      : B 承载体在 / C 默认出口指向承载体");
            println!("  ⚠ 断言 A（代理可达）尚未接 SPI，暂按可达处理");
            if args.guard_act {
                println!("  动作      : **已接线**（--guard-act）");
                println!("    Tighten → 撤掉放行（默认拒绝底板仍在 → 全都拒绝）");
                println!("    Relax   → **步 3 未接线**，只会记一行，不会自动重新下发");
            } else {
                println!("  动作      : 只观测（加 --guard-act 才会真的收紧）");
            }
            println!("  日志      : {}", log.display());
            spawn_guard_observer(
                config.clone(),
                Duration::from_secs(args.guard_interval_secs),
                log,
                Arc::clone(&ticket_slot),
                args.guard_act,
            );
        },
    }
    println!();

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
        if let Ok(g) = ticket_slot.lock() {
            if g.as_ref().is_some_and(|t| t.phase == Phase::Committed) {
                println!("⚠ 已确认的规则会随本进程退出而清空（动态会话）——这是兜底，不是 bug。");
            }
        }
    }
}

// ── 守卫观测（步 1：只判不动手）─────────────────────────────────────

/// 起一个观测线程。
///
/// `act = false`（默认）时**只观测**：不碰 WFP、不改票据、不做任何动作，
/// 只在日志里写"若已接线此刻会收紧"。这是步 1 的形态，也是默认形态——
/// **收紧的代价是整机断网，绝不能默认开。**
///
/// `act = true`（`--guard-act`）时走 [`observe_and_act`]，真撤放行。
///
/// 进程退出时线程随之消失——不需要 join，也不需要停止标志：
/// 守卫只在 aegisd 存活期间有意义，这正是动态会话的兜底性质。
fn spawn_guard_observer(
    cfg: Config,
    interval: Duration,
    log: PathBuf,
    ticket: TicketSlot,
    act: bool,
) {
    thread::spawn(move || {
        let policy = GuardPolicy::default();
        let mut tracker = GuardTracker::new();
        let mut ticks = 0u64;
        let mut streak = 0u32;
        loop {
            thread::sleep(interval);
            ticks += 1;
            let line = if act {
                observe_and_act(&cfg, &ticket, &mut tracker, &policy, ticks)
            } else {
                observe_once(&cfg, ticks, &mut streak, policy.failure_threshold)
            };
            println!("{line}");
            append_guard_line(&log, &line);
        }
    });
}

/// 步 2：判完**真的动手**。
///
/// ⚠ 与观测模式的 [`next_streak`] 是**两套状态**：观测模式故意不建模动作
/// （没真的收紧过，"已收紧"这个状态就是假的，后续的 Relax 也是假的），
/// 所以两者不能共用一个 tracker。
fn observe_and_act(
    cfg: &Config,
    ticket: &TicketSlot,
    tracker: &mut GuardTracker,
    policy: &GuardPolicy,
    tick: u64,
) -> String {
    let verdict = match collect_verdict(cfg, tick) {
        Ok(v) => v,
        Err(line) => return line,
    };
    let action = tracker.observe(&verdict, now_ms(), *policy);
    match action {
        GuardAction::Nothing => format!("[守卫 #{tick}] {}", verdict_brief(&verdict)),
        GuardAction::Tighten(_) => tighten_now(ticket, tick, &verdict),
        // 步 3 才接：重新 apply + 自动确认。这里**不能**谎称已经恢复。
        GuardAction::Relax(_) => format!(
            "[守卫 #{tick}] {} → 应放宽，但**步 3 未接线**：\
             不会自动重新下发放行（放行仍然撤着）",
            verdict_brief(&verdict)
        ),
        GuardAction::NeedsHuman { reason } => {
            format!("[守卫 #{tick}] ⚠ 交给人工：{reason}")
        },
    }
}

/// 收紧：**撤掉放行**，不是新增拒绝规则。
///
/// 默认拒绝底板本来就装在同一次下发里，把放行撤掉，剩下的就是"全都拒绝"。
/// 这条路的好处是它**不需要任何持久化**：放行本来就在动态会话里，
/// 进程一死连"误收紧"都跟着消失，不会把机器卡在断网态。
fn tighten_now(ticket: &TicketSlot, tick: u64, verdict: &GuardVerdict) -> String {
    let mut g = match ticket.lock() {
        Ok(g) => g,
        Err(_) => return format!("[守卫 #{tick}] ⚠ 该收紧，但票据锁损坏，不动作"),
    };
    let n = match g.as_mut() {
        // 从没下发过：压根没有放行可撤。此时**绝不能**临时去装一条拒绝规则——
        // 那等于让守卫凭空造出它没能力安全撤掉的东西。
        None => {
            return format!(
                "[守卫 #{tick}] ⚠ 该收紧，但当前**没有票据**（没下发过放行）→ 无放行可撤，不动作"
            )
        },
        Some(t) => match t.phase {
            // 已经撤过了：放行不在了，再删一次可能删到 id 复用后的别人的规则。
            Phase::RolledBack => {
                return format!("[守卫 #{tick}] ⚠ 该收紧，但票据已拆除过 → 放行已不在，不重复删")
            },
            Phase::Pending => {
                let n = t.filter_ids.len();
                t.request_abort();
                n
            },
            Phase::Committed => {
                let n = t.filter_ids.len();
                t.force_teardown();
                n
            },
        },
    };
    format!(
        "[守卫 #{tick}] ⚠ **已收紧**：撤销 {n} 条放行（{}）。\
         默认拒绝底板仍在 → 全都拒绝。看门狗 200 毫秒内执行。",
        verdict_brief(verdict)
    )
}

/// 一句话说清结论。
///
/// ⚠ 动作模式下日志里如果只写 `Nothing`，读的人分不清那是"生效"
/// 还是"判不了"——而这两件事的后果完全不同。
fn verdict_brief(v: &GuardVerdict) -> String {
    match v {
        GuardVerdict::Effective => "生效".to_string(),
        GuardVerdict::Unknown { reason } => format!("判不了（{reason}）"),
        GuardVerdict::Ineffective { reason, .. } => format!("未生效（{reason}）"),
    }
}

/// 连续失败计数规则。
///
/// ⚠ 必须与 [`aegis_core::guard::GuardTracker`] **逐条一致**，否则
/// "步 1 从没报过要收紧"就推不出"步 2 接上也不会收紧"——那这一步白跑了：
///
/// - `Effective` → 清零（中途好一次就不算连续）
/// - `Ineffective` → 累加
/// - `Unknown` → **不动**。判不了不等于好，也不等于坏；清零会漏掉真实的
///   连续失败，累加又会凭空制造失败。
fn next_streak(verdict: &GuardVerdict, streak: u32) -> u32 {
    match verdict {
        GuardVerdict::Effective => 0,
        GuardVerdict::Ineffective { .. } => streak.saturating_add(1),
        GuardVerdict::Unknown { .. } => streak,
    }
}

/// 把一次观测拼成一行日志。`streak` 是**更新后**的连续失败次数。
fn format_observation(tick: u64, verdict: &GuardVerdict, streak: u32, threshold: u32) -> String {
    match verdict {
        GuardVerdict::Effective => format!("[守卫 #{tick}] 生效"),
        GuardVerdict::Unknown { reason } => {
            format!("[守卫 #{tick}] 判不了（{reason}）→ 不动手")
        },
        GuardVerdict::Ineffective { reason, .. } => {
            // 超过阈值后不再显示 "5/3" 这种怪数字，只报连续次数与阈值
            let would = if streak >= threshold {
                " ⚠ **若已接线，此刻会收紧**（撤掉放行 → 全都拒绝）"
            } else {
                ""
            };
            format!(
                "[守卫 #{tick}] 未生效（{reason}）连续 {} 次（阈值 {}）{}",
                streak, threshold, would
            )
        },
    }
}

/// 采一次拓扑 → 构事实 → 判决。
///
/// 采不到就返回**已经拼好的日志行**，调用方直接返回即可：失败的原因必须
/// 原样进日志，不能笼统归成"生效"或"判不了"——
/// 采不到拓扑时**不能**当成"生效"（那等于放行）。
fn collect_verdict(cfg: &Config, tick: u64) -> Result<GuardVerdict, String> {
    let snap = snapshot()
        .map_err(|e| format!("[守卫 #{tick}] 拓扑采集失败：{e} → Unknown，不动手"))?;
    let facts = cfg
        .guard_facts_from(&snap, PROXY_REACHABLE_PLACEHOLDER)
        .ok_or_else(|| format!("[守卫 #{tick}] 配置缺 proxy.mode，无法构造事实，跳过"))?;
    Ok(evaluate(facts))
}

/// 观测一次，返回一行日志。
fn observe_once(cfg: &Config, tick: u64, streak: &mut u32, threshold: u32) -> String {
    let verdict = match collect_verdict(cfg, tick) {
        Ok(v) => v,
        Err(line) => return line,
    };
    *streak = next_streak(&verdict, *streak);
    format_observation(tick, &verdict, *streak, threshold)
}

/// 观测日志落盘。"跑一段时间确认无误报"这件事，光看终端是不行的——
/// 终端随会话一起没了。
fn append_guard_line(path: &PathBuf, line: &str) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(f, "{line}");
    }
}

// ── IPC 服务：握手 / 鉴权 / 状态查询 ─────────────────────────────────

/// 逐个接待连接。**鉴权失败立刻断开，不回任何响应**——
/// 回了就等于告诉对方"你猜得差不多了"。
fn serve_forever(
    server: &PipeServer,
    token: &IpcToken,
    status: &Arc<Mutex<Option<Status>>>,
    plan: &[FilterSpec],
    ticket: &TicketSlot,
) {
    loop {
        let end = match server.accept() {
            Ok(e) => e,
            Err(_) => return,
        };
        if let Err(_e) = serve_one(&end, token, status, plan, ticket) {
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
    plan: &[FilterSpec],
    ticket: &TicketSlot,
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
                let word = String::from_utf8_lossy(&frame.payload).trim().to_string();

                // ── 命令分级闸门 ──────────────────────────────────────
                // token 只证明"你是本机的客户端"。下发/确认/拆除还会改
                // 本机网络状态，所以**额外**要求对端进程已提权。
                // 不做这道闸，一个标准用户读走 token 文件就等于能指挥
                // SYSTEM 进程装/拆防火墙规则——那是提权漏洞的形状。
                let risk = aegis_ipc::risk_of(&word);
                if !aegis_ipc::allows(end, risk) {
                    let msg = format!(
                        "{}{}：这条命令会改变本机网络状态，\
                         要求控制端**以管理员身份运行**。",
                        DENY_PREFIX, word
                    );
                    end.send(msg_type::RESPONSE, 0, frame.seq, msg.as_bytes())?;
                    continue;
                }

                let body = if word == REQ_PING {
                    "pong".to_string()
                } else if word == REQ_STATUS {
                    // 启动还没走完时如实说"启动中"，不编一个看起来正常的状态
                    match status.lock().ok().and_then(|s| s.clone()) {
                        Some(s) => s.to_text(),
                        None => "启动中：状态尚不可用".to_string(),
                    }
                } else if word == REQ_APPLY {
                    do_apply(plan, ticket)
                } else if word == REQ_CONFIRM {
                    do_confirm(ticket)
                } else if word == REQ_ROLLBACK {
                    do_rollback(ticket)
                } else {
                    format!(
                        "未知请求：{word}（可用：{REQ_STATUS} / {REQ_PING} / {REQ_APPLY} / \
                         {REQ_CONFIRM} / {REQ_ROLLBACK}）"
                    )
                };
                end.send(msg_type::RESPONSE, 0, frame.seq, body.as_bytes())?
            },
            _ => return Ok(()),
        }
    }
}

// ── 计划的可读输出 ───────────────────────────────────────────────────

/// 把计划逐条打成一张表。
///
/// ⚠ **必须逐条打，不能只打条数。** "装了 10 条规则"这个数字没有任何
/// 判断价值——十条里可能有一条是无条件阻断，而那一条就决定了整机通不通。
/// 让人在下发之前看清每一行，是防呆的第一道。
fn print_plan(plan: &[FilterSpec]) {
    println!("  规则清单  ：");
    for (i, f) in plan.iter().enumerate() {
        let conds: Vec<String> = f.conditions.iter().map(ToString::to_string).collect();
        let cond = if conds.is_empty() {
            "**无条件**（匹配这一层的全部流量）".to_string()
        } else {
            conds.join(" 且 ")
        };
        println!(
            "    {:>2}. [{:<4} w{:<2}] {:<16} {:?}",
            i + 1,
            action_cn(f.action),
            f.weight,
            f.name,
            f.layer
        );
        println!("        条件：{}", cond);
    }
}

fn action_cn(a: aegis_wfp::Action) -> &'static str {
    match a {
        aegis_wfp::Action::Permit => "放行",
        aegis_wfp::Action::Block => "阻断",
    }
}

// ── 下发 / 确认 / 拆除（防呆）────────────────────────────────────────

/// 下发绝缘笼。**装完不算数**——开一个 [`CONFIRM_WINDOW_MS`] 的倒计时，
/// 窗口内没人 `confirm` 就自动撤掉。
///
/// # 为什么会话必须生在看门狗线程里
///
/// `Session` 里握着一个原始句柄，**不是 `Send`**，搬不进别的线程。
/// 于是顺序是：本线程发指令 → 新线程里开会话并装规则 → 新线程就地
/// 转成看门狗，会话**从头到尾都没离开过那个线程**。
/// 反过来（先装再想办法把会话交给一个守护线程）是搬不动的。
fn do_apply(plan: &[FilterSpec], slot: &TicketSlot) -> String {
    // 一次只允许一个待确认的下发：并发装会让回执与票据对不上，
    // 而"不知道哪批 id 是哪次装的"在回滚时就是删错规则。
    if let Ok(g) = slot.lock() {
        if g.as_ref().is_some_and(|t| t.phase == Phase::Pending) {
            return format!("{}已有一个待确认的下发，先 confirm 或 rollback。", DENY_PREFIX);
        }
    }

    // 自检在**碰引擎之前**跑完：装到一半才发现条件翻译不了，
    // 会留下半套规则，而半套规则就是断网。
    if let Err(e) = preflight(plan) {
        return format!("{}拒绝下发：{e}", DENY_PREFIX);
    }

    let (tx, rx) = std_mpsc::channel::<Result<usize, String>>();
    let watchdog_slot = Arc::clone(slot);
    let watchdog_plan = plan.to_vec();
    thread::spawn(move || {
        let now = now_ms();
        match apply(&watchdog_plan, now) {
            Ok((session, receipt)) => {
                let n = receipt.len();
                if let Ok(mut g) = watchdog_slot.lock() {
                    *g = Some(ApplyTicket::pending(
                        now,
                        CONFIRM_WINDOW_MS,
                        receipt.filter_ids,
                    ));
                }
                let _ = tx.send(Ok(n));
                watch(&session, &watchdog_slot);
            },
            Err(e) => {
                let _ = tx.send(Err(e.to_string()));
            },
        }
    });

    match rx.recv_timeout(Duration::from_secs(5)) {
        Ok(Ok(n)) => format!(
            "{}已下发 {n} 条规则。{CONFIRM_WINDOW_MS} 毫秒内不执行 \
             `aegisctl confirm` 将**自动撤销**。",
            OK_PREFIX
        ),
        Ok(Err(e)) => format!("{DENY_PREFIX}下发失败：{e}（多半是没提权：WFP 引擎要求管理员）"),
        Err(_) => format!(
            "{DENY_PREFIX}下发超时（5 秒无结果）。状态未知，按**未下发**处理——\
             装到一半的规则会随动态会话在进程退出时清空。"
        ),
    }
}

/// 看门狗：持有会话，直到票据说"该撤了"。
///
/// ⚠ **会话必须一直握着**。它一旦关闭（哪怕只是离开作用域），内核就把
/// 这次装的所有规则清掉——这正是动态会话的兜底性质，但也意味着
/// "提前 return" 等于静默撤防。所以确认之后也不能 return，得继续守着。
fn watch(session: &Session, slot: &TicketSlot) {
    loop {
        thread::sleep(Duration::from_millis(200));
        let now = now_ms();

        let due = match slot.lock() {
            Ok(g) => g.as_ref().is_some_and(|t| t.must_roll_back(now)),
            Err(_) => false,
        };
        if !due {
            continue;
        }

        // 只会读一次 id 快照：回滚认的是 id，不是"现在计划里有什么"
        let ids = match slot.lock() {
            Ok(g) => g.as_ref().map(|t| t.filter_ids.clone()).unwrap_or_default(),
            Err(_) => Vec::new(),
        };
        let removed = rollback(session, &ids).unwrap_or(0);
        if let Ok(mut g) = slot.lock() {
            if let Some(t) = g.as_mut() {
                t.mark_rolled_back(format!("已拆除 {removed} 条规则"));
            }
        }
        println!("  [IPC] 倒计时结束或收到拆除指令：已撤销 {removed} 条规则");
        return;
    }
}

fn do_confirm(slot: &TicketSlot) -> String {
    let now = now_ms();
    let mut g = match slot.lock() {
        Ok(g) => g,
        Err(_) => return format!("{DENY_PREFIX}票据锁损坏，无法确认"),
    };
    match g.as_mut() {
        None => format!("{DENY_PREFIX}当前没有待确认的下发"),
        Some(t) => match t.confirm(now) {
            Ok(()) => format!(
                "{}已确认，{} 条规则保留。会话是动态的：进程退出即全部清空。",
                OK_PREFIX,
                t.filter_ids.len()
            ),
            Err(e) => format!("{DENY_PREFIX}{e}"),
        },
    }
}

/// 立即拆除。
///
/// `Pending` 走普通拆除（等超时也行，这里不等）；
/// 已 `Committed` 的走**紧急强拆**——这是兜底手册里
/// "人在现场发现笼子装错了"的那条通道，它能撤掉已确认的规则。
fn do_rollback(slot: &TicketSlot) -> String {
    let mut g = match slot.lock() {
        Ok(g) => g,
        Err(_) => return format!("{DENY_PREFIX}票据锁损坏，无法拆除"),
    };
    match g.as_mut() {
        None => format!("{DENY_PREFIX}当前没有可拆除的下发"),
        Some(t) => {
            let n = t.filter_ids.len();
            match t.phase {
                Phase::Pending => {
                    t.request_abort();
                    format!("{OK_PREFIX}已标记拆除 {n} 条，看门狗 200 毫秒内执行")
                },
                Phase::Committed => {
                    t.force_teardown();
                    format!("{OK_PREFIX}已请求**紧急强拆** {n} 条已确认规则，看门狗 200 毫秒内执行")
                },
                Phase::RolledBack => format!("{DENY_PREFIX}这次下发已经拆除过了"),
            }
        },
    }
}

// ── 辅助 ─────────────────────────────────────────────────────────────

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
    /// 守卫观测周期（秒）。**0 = 关闭观测**。
    guard_interval_secs: u64,
    /// 守卫是否**真的动手**（步 2）。默认 false —— 只观测。
    guard_act: bool,
}

impl Args {
    fn parse(argv: impl Iterator<Item = String>) -> Self {
        let mut config: Option<PathBuf> = None;
        let mut pipe = aegis_ipc::PIPE_NAME.to_string();
        let mut token_file: Option<PathBuf> = None;
        let mut data_dir: Option<PathBuf> = None;
        let mut serve_secs: u64 = 30;
        let mut guard_interval_secs: u64 = DEFAULT_GUARD_INTERVAL_SECS;
        let mut guard_act = false;
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
                "--guard-interval-secs" => {
                    guard_interval_secs = args
                        .next()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(guard_interval_secs)
                },
                // 开关型参数，不带值：默认必须是"不动作"，
                // 收紧的代价是整机断网，不能让一次手滑的命令行把它打开。
                "--guard-act" => guard_act = true,
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
            pipe: normalize_pipe_name(&pipe),
            token_file,
            data_dir,
            serve_secs,
            guard_interval_secs,
            guard_act,
        }
    }
}

/// `--pipe` 的写法容错：裸名也收，补成 Win32 完整路径。
///
/// 真机踩到的坑：`--pipe aegis-ob` 会被原样交给 `CreateNamedPipeW`，
/// 内核回 **os error 123（文件名、目录名或卷标语法不正确）**，而启动日志
/// 那句提示写的是「多半是已有实例占用」——完全指错方向，排查方向被带偏。
/// 命名管道不存在"相对路径"这种语义，裸名只可能是想要 `\\.\pipe\<name>`，
/// 所以这里直接补前缀，别让人去猜。
fn normalize_pipe_name(name: &str) -> String {
    const PREFIX: &str = r"\\.\pipe\";
    if name.is_empty() {
        return aegis_ipc::PIPE_NAME.to_string();
    }
    // 已经带前缀就不动；`//./pipe/` 是同一种写法的正斜杠变体。
    if name.starts_with(PREFIX) || name.starts_with("//./pipe/") {
        name.to_string()
    } else {
        format!("{PREFIX}{name}")
    }
}

fn print_usage() {
    println!("用法：aegisd --config <配置文件> [选项]");
    println!();
    println!("  --config <path>      配置文件（**必填**，读不到就退出）");
    println!("  --pipe <name>        IPC 管道名（默认 {}，裸名会补成 \\\\.\\pipe\\<name>）", aegis_ipc::PIPE_NAME);
    println!("  --token-file <path>  IPC token 落盘路径（默认 <data-dir>/ipc.token）");
    println!("  --data-dir <dir>     运行数据目录（默认 .aegis-run）");
    println!("  --serve-secs <n>     IPC 服务时长（默认 30，0 = 启动完就退出）");
    println!(
        "  --guard-interval-secs <n>  守卫观测周期（默认 {}，0 = 关闭）",
        DEFAULT_GUARD_INTERVAL_SECS
    );
    println!(
        "  --guard-act              守卫**真的动手**（默认只观测，见下）"
    );
    println!();
    println!("守卫默认处于**只观测**形态：只判『下游规则生效吗』并记日志，");
    println!("不会收紧也不会放宽。加 --guard-act 之后 Tighten 才会真的撤掉放行");
    println!("（默认拒绝底板仍在 → 全都拒绝）；Relax 属步 3，仍未接线，");
    println!("所以**收紧后不会自动恢复**。日志落在 <data-dir>/guard-observe.log。");
    println!("启动过程不下发任何 WFP 规则。下发要由 `aegisctl apply` 发起，");
    println!("且该命令要求：持有 token + 控制端已提权 + 10 秒内 confirm。");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ineffective(reason: &str) -> GuardVerdict {
        GuardVerdict::Ineffective {
            failed: Vec::new(),
            reason: reason.to_string(),
        }
    }

    fn unknown(reason: &str) -> GuardVerdict {
        GuardVerdict::Unknown {
            reason: reason.to_string(),
        }
    }

    /// 步 1 的全部价值都押在这条上：计数规则必须和 `GuardTracker` 一致，
    /// 否则"观测期没报警"推不出"接上动作也不会误收紧"。
    #[test]
    fn the_streak_rule_matches_the_guard_tracker() {
        assert_eq!(next_streak(&GuardVerdict::Effective, 5), 0, "好一次就清零");
        assert_eq!(next_streak(&ineffective("x"), 2), 3, "失败累加");
        assert_eq!(
            next_streak(&unknown("y"), 2),
            2,
            "⚠ 判不了既不清零也不累加"
        );
    }

    #[test]
    fn the_streak_never_overflows() {
        assert_eq!(next_streak(&ineffective("x"), u32::MAX), u32::MAX);
    }

    /// "若已接线，此刻会收紧"这句话只在**达到阈值之后**出现——
    /// 它要是提前出现，观测结论就会被误读成"已经在收紧了"。
    #[test]
    fn the_would_tighten_note_appears_only_at_the_threshold() {
        let below = format_observation(1, &ineffective("r"), 2, 3);
        assert!(!below.contains("会收紧"), "{below}");

        let at = format_observation(1, &ineffective("r"), 3, 3);
        assert!(at.contains("会收紧"), "{at}");
        assert!(at.contains("连续 3 次（阈值 3）"), "{at}");
        assert!(!at.contains("3/3"), "'N/M' 的写法会被读成分数：{at}");
    }

    #[test]
    fn an_unknown_verdict_is_reported_without_any_action() {
        let s = format_observation(7, &unknown("读不到默认出口"), 0, 3);
        assert!(s.contains("判不了"), "{s}");
        assert!(s.contains("读不到默认出口"), "{s}");
        assert!(!s.contains("会收紧"), "{s}");
    }

    /// 裸管道名：不补前缀的话内核报 os error 123，而提示语指向"已有实例"，
    /// 排查方向会被彻底带偏。
    #[test]
    fn a_bare_pipe_name_gets_the_win32_prefix() {
        assert_eq!(normalize_pipe_name("aegis-ob"), r"\\.\pipe\aegis-ob");
    }

    #[test]
    fn an_already_prefixed_pipe_name_is_left_alone() {
        assert_eq!(normalize_pipe_name(r"\\.\pipe\aegis"), r"\\.\pipe\aegis");
        assert_eq!(normalize_pipe_name("//./pipe/aegis"), "//./pipe/aegis");
    }

    #[test]
    fn an_empty_pipe_name_falls_back_to_the_default() {
        assert_eq!(normalize_pipe_name(""), aegis_ipc::PIPE_NAME);
    }

    // ── 步 2：真的收紧 ──────────────────────────────────────────────

    /// 收紧 = **撤放行**，不是新增拒绝规则。所以没有票据时只能"不动作"——
    /// 凭空装一条拒绝规则，等于让守卫造出它没能力安全撤掉的东西。
    #[test]
    fn tightening_without_a_ticket_does_nothing_and_says_so() {
        let slot = empty_slot();
        let s = tighten_now(&slot, 1, &ineffective("x"));
        assert!(s.contains("没有票据"), "{s}");
        assert!(s.contains("不动作"), "{s}");
        assert!(slot.lock().unwrap().is_none(), "绝不能凭空造票据");
    }

    /// 已拆除过的票据**不能再删一次**：filter id 是会复用的，
    /// 第二次删的可能已经是别人的规则。
    #[test]
    fn tightening_an_already_rolled_back_ticket_does_not_delete_twice() {
        let slot = empty_slot();
        {
            let mut t = ApplyTicket::pending(now_ms(), CONFIRM_WINDOW_MS, vec![4]);
            t.mark_rolled_back("已拆除");
            *slot.lock().unwrap() = Some(t);
        }
        let s = tighten_now(&slot, 2, &ineffective("x"));
        assert!(s.contains("已拆除过"), "{s}");
        assert!(!slot.lock().unwrap().as_ref().unwrap().force_teardown);
    }

    #[test]
    fn tightening_a_committed_ticket_forces_a_teardown() {
        let slot = empty_slot();
        let mut t = ApplyTicket::pending(now_ms(), CONFIRM_WINDOW_MS, vec![4, 5, 6]);
        t.confirm(now_ms()).expect("窗口内确认应成功");
        *slot.lock().unwrap() = Some(t);

        let s = tighten_now(&slot, 3, &ineffective("r"));
        assert!(s.contains("已收紧"), "{s}");
        assert!(s.contains("撤销 3 条放行"), "{s}");
        assert!(slot.lock().unwrap().as_ref().unwrap().force_teardown);
    }

    /// 待确认期也要能撤：规则**已经装上了**，Pending 只表示还没点确认。
    /// 但这里走普通 abort，不用强拆——强拆是给"已确认"用的紧急通道。
    #[test]
    fn tightening_a_pending_ticket_requests_a_plain_abort() {
        let slot = empty_slot();
        *slot.lock().unwrap() =
            Some(ApplyTicket::pending(now_ms(), CONFIRM_WINDOW_MS, vec![9]));

        let s = tighten_now(&slot, 4, &ineffective("r"));
        assert!(s.contains("已收紧"), "{s}");
        let t = slot.lock().unwrap().clone().unwrap();
        assert!(t.abort_requested, "{t:?}");
        assert!(!t.force_teardown, "Pending 不需要动用强拆通道：{t:?}");
    }

    /// 收紧的代价是整机断网，所以**默认必须是关的**。
    #[test]
    fn guard_act_is_off_unless_asked_for() {
        let off = Args::parse(
            ["--config", "c.toml"]
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .into_iter(),
        );
        assert!(!off.guard_act, "默认只观测");

        let on = Args::parse(
            ["--config", "c.toml", "--guard-act"]
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .into_iter(),
        );
        assert!(on.guard_act);
    }

    /// 一句话结论必须区分"生效"与"判不了"——动作模式下只写 `Nothing`
    /// 会让人分不清这两件后果完全不同的事。
    #[test]
    fn the_verdict_brief_distinguishes_effective_from_unknown() {
        assert_eq!(verdict_brief(&GuardVerdict::Effective), "生效");
        assert!(verdict_brief(&unknown("读不到默认出口")).contains("判不了"));
        assert!(verdict_brief(&ineffective("r")).contains("未生效"));
    }

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

    fn empty_slot() -> TicketSlot {
        Arc::new(Mutex::new(None))
    }

    fn boot_plan() -> Vec<FilterSpec> {
        vec![FilterSpec {
            name: "boot",
            layer: aegis_wfp::Layer::AleAuthConnectV4,
            action: aegis_wfp::Action::Block,
            weight: 1,
            conditions: vec![],
            tier: aegis_wfp::Tier::Boot,
        }]
    }

    // ── 下发 / 确认 / 拆除 的决策逻辑（不碰引擎，可在普通权限下测）──

    #[test]
    fn exit_codes_are_all_distinct() {
        let codes = [exit::CONFIG, exit::IPC, exit::SENSE, exit::AUDIT];
        let mut seen = Vec::new();
        for c in codes {
            assert!(!seen.contains(&c), "退出码重复：{c}");
            seen.push(c);
        }
    }

    /// 没有票据时的确认/拆除必须是"拒绝"，不能是"成功"。
    /// 说"拆了 0 条"听起来像成功了，人就不去找真正的问题。
    #[test]
    fn confirm_and_rollback_without_a_ticket_are_denied() {
        assert!(do_confirm(&empty_slot()).starts_with(DENY_PREFIX));
        assert!(do_rollback(&empty_slot()).starts_with(DENY_PREFIX));
    }

    #[test]
    fn confirm_commits_a_pending_ticket() {
        let slot = empty_slot();
        *slot.lock().unwrap() = Some(ApplyTicket::pending(
            now_ms(),
            CONFIRM_WINDOW_MS,
            vec![1, 2],
        ));
        let out = do_confirm(&slot);
        assert!(out.starts_with(OK_PREFIX), "{out}");
        assert_eq!(slot.lock().unwrap().as_ref().unwrap().phase, Phase::Committed);
    }

    /// 晚了就确认不了——否则"超时自动回滚 → 再确认一次 → 又装回去"，
    /// 而这第二次没人兜底。
    #[test]
    fn confirming_a_stale_ticket_is_denied() {
        let slot = empty_slot();
        let past = now_ms() - CONFIRM_WINDOW_MS - 1;
        *slot.lock().unwrap() = Some(ApplyTicket::pending(past, 0, vec![7]));
        let out = do_confirm(&slot);
        assert!(out.starts_with(DENY_PREFIX), "{out}");
        assert_eq!(slot.lock().unwrap().as_ref().unwrap().phase, Phase::Pending);
    }

    #[test]
    fn rollback_of_a_pending_ticket_requests_an_abort() {
        let slot = empty_slot();
        *slot.lock().unwrap() =
            Some(ApplyTicket::pending(now_ms(), CONFIRM_WINDOW_MS, vec![3]));
        let out = do_rollback(&slot);
        assert!(out.starts_with(OK_PREFIX), "{out}");
        assert!(slot.lock().unwrap().as_ref().unwrap().must_roll_back(now_ms()));
    }

    /// 已确认的规则也得能拆——这是兜底手册的命脉。
    #[test]
    fn rollback_of_a_committed_ticket_forces_a_teardown() {
        let slot = empty_slot();
        let mut t = ApplyTicket::pending(now_ms(), CONFIRM_WINDOW_MS, vec![4]);
        t.confirm(now_ms()).unwrap();
        *slot.lock().unwrap() = Some(t);

        let out = do_rollback(&slot);
        assert!(out.starts_with(OK_PREFIX), "{out}");
        assert!(
            slot.lock().unwrap().as_ref().unwrap().must_roll_back(now_ms()),
            "已确认的也要能被强拆"
        );
    }

    /// 重复拆除必须是拒绝，不是"又删一遍"——第二次删可能删到别人的规则。
    #[test]
    fn rolling_back_twice_is_denied() {
        let slot = empty_slot();
        let mut t = ApplyTicket::pending(now_ms(), CONFIRM_WINDOW_MS, vec![5]);
        t.mark_rolled_back("已拆");
        *slot.lock().unwrap() = Some(t);
        assert!(do_rollback(&slot).starts_with(DENY_PREFIX));
    }

    /// Boot 层规则在**碰引擎之前**就被拒：装错了重启都清不掉。
    #[test]
    fn apply_refuses_boot_rules_before_touching_the_engine() {
        let out = do_apply(&boot_plan(), &empty_slot());
        assert!(out.starts_with(DENY_PREFIX), "{out}");
        assert!(out.contains("Boot"), "{out}");
    }

    /// 并发下发会让回执和票据对不上，而回滚时"不知道哪批 id 是哪次装的"
    /// 就是删错规则。
    #[test]
    fn a_second_apply_is_refused_while_one_is_pending() {
        let slot = empty_slot();
        *slot.lock().unwrap() =
            Some(ApplyTicket::pending(now_ms(), CONFIRM_WINDOW_MS, vec![9]));
        let out = do_apply(&boot_plan(), &slot);
        assert!(out.starts_with(DENY_PREFIX), "{out}");
        assert!(out.contains("待确认"), "{out}");
    }
}
