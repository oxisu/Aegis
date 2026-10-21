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
use std::net::TcpStream;

use aegis_audit::{Action, AuditEvent, AuditLog, InterfaceRole, Protocol};
use aegis_config::{load_file, Config};
// 第二审计源接线：把 mihomo 连接级元数据翻译成 `Action::Observed` 审计事件。
use aegis_core::guard::{evaluate, GuardAction, GuardPolicy, GuardTracker, GuardVerdict};
use aegis_core::role::{adjudicate_all, Confidence};
use aegis_core::state::{insulation, State};
use aegis_ipc::{
    check_compat, encode_handshake, msg_type, GuardView, IpcToken, PipeServer, Status, DENY_PREFIX,
    GUARD_EFFECTIVE, GUARD_INEFFECTIVE, GUARD_UNKNOWN, OK_PREFIX, REQ_APPLY, REQ_CONFIRM, REQ_PING,
    REQ_ROLLBACK, REQ_SNAPSHOT, REQ_STATUS,
};
use aegis_netcfg::{clear_baseline, load_baseline, NetCfgBackend, SnapshotGuard, WindowsBackend};
use aegis_orchestrator::clash::audit::connection_to_audit_event;
use aegis_orchestrator::clash::{ClashAdapter, ClashConfig};
use aegis_sense::{default_egress, snapshot};
use aegis_version as version;
use aegis_wfp::{
    apply, cage_plan, install, invariants_violated, preflight, rollback, verify_with,
    Action as WfpAction, ApplyTicket, CagePolicy, FilterSpec, Phase, Session, CONFIRM_WINDOW_MS,
    MAX_RESTORE_ATTEMPTS,
};
use std::collections::HashSet;

/// 退出码。**刻意各不相同**：运维看到码就知道卡在哪一步，
/// 不用去翻日志猜。
mod exit {
    pub const CONFIG: i32 = 2;
    pub const IPC: i32 = 3;
    pub const SENSE: i32 = 4;
    pub const AUDIT: i32 = 5;
    /// 服务管理类命令失败（§9 阶段 0）
    pub const SERVICE: i32 = 6;
}

mod service;

use service::ServiceCommand;

/// 一次下发的票据。**纯数据**（`filter_ids` 只是 `Vec<u64>`），
/// 所以可以跨线程共享；真正不能跨线程的是 WFP 会话句柄，它**永远待在
/// 看门狗线程里**（见 [`watch`]）。
type TicketSlot = std::sync::Arc<std::sync::Mutex<Option<ApplyTicket>>>;

/// 守卫对外可见的状态（进 IPC `Status`）。
///
/// 单独一个槽位，而不是塞进 `Status` 让守卫线程去改整个 `Status`：
/// 后者会让守卫线程去抢 IPC 线程正在持有的锁。
type GuardSlot = std::sync::Arc<std::sync::Mutex<GuardView>>;

/// 审计日志。**审计要能回答"谁在什么时候把网断掉的"**，所以守卫的每个
/// 动作都得落盘，不能只写在守护进程的日志里（那个会随会话一起没）。
type AuditSlot = std::sync::Arc<std::sync::Mutex<AuditLog>>;

/// B4 非 WFP 网络设置快照守卫（系统代理 + 路由表）。
///
/// `None` = 未 arm（采集基线失败）。此刻 `restore_protected=false` 会如实
/// 上报——没有基线的"还原保护"是假的，不能显示成正常。
///
/// ⚠ 放进 `Mutex` 只为跨线程共享（IPC 线程读基线 / rollback 还原 / 退出还原）；
/// WFP 票据同理是纯数据可共享，真正碰系统的动作都在持锁的瞬间同步完成。
type NetCfgSlot = std::sync::Arc<std::sync::Mutex<Option<SnapshotGuard<WindowsBackend>>>>;

/// 基线快照落盘路径（崩溃恢复用）。放在 data-dir 里，随运行数据一起走。
fn baseline_path(data_dir: &std::path::Path) -> std::path::PathBuf {
    data_dir.join("net-baseline.json")
}

/// 守卫观测的默认周期（秒）。
///
/// 依据：泄漏窗口 ≈ `failure_threshold × 周期` = 3 × 3 = **9 秒**。
/// 更快会常驻占用（每次巡检要跑一遍 `GetIfTable2` + `GetAdaptersAddresses`），
/// 更慢则漏的时间太长。先跑起来再调。
const DEFAULT_GUARD_INTERVAL_SECS: u64 = 3;

/// 断言 A 的探测超时。
///
/// ⚠ **必须带超时**：守卫线程每 3 秒跑一次，一个不设超时的 `connect` 在
/// 目标把包丢掉（而不是拒绝）时能挂几十秒，守卫就卡死在那儿——
/// 而它卡死的代价正好是"失效期间没人看着"。
const CONTROL_PROBE_TIMEOUT: Duration = Duration::from_millis(800);

/// 第二审计源（mihomo 连接表）的轮询周期（秒）。
///
/// 比守卫慢：它只是富化，不参与任何裁决/收紧，漏几秒毫无代价；
/// 太快则每轮都把当前连接重描一遍（去重后只在连接首次出现时落盘，
/// 但仍徒增控制口压力）。5 秒是"够新、又不烦"的折中。
const CLASH_AUDIT_INTERVAL_SECS: u64 = 5;

fn main() {
    let raw: Vec<String> = std::env::args().skip(1).collect();

    // 服务管理子命令（install / uninstall / start / stop / status）**先**分发。
    // 放在参数解析之前是有意的：这些子命令各自独立，让它们先走一遍
    // 守护进程那套解析只会拿到一屏"忽略未知参数"的噪音。
    match ServiceCommand::parse(&raw) {
        Ok(Some(sub)) => {
            let label = sub.label();
            match run_service_command(sub) {
                Ok(msg) => {
                    println!("{msg}");
                    std::process::exit(0);
                },
                Err(e) => {
                    eprintln!("[FATAL] `aegisd {label}` 失败：{e}");
                    std::process::exit(exit::SERVICE);
                },
            }
        },
        Ok(None) => {}, // 不是子命令，走守护进程
        Err(e) => {
            // 是子命令但参数不全
            eprintln!("[FATAL] {e}");
            print_usage();
            std::process::exit(exit::SERVICE);
        },
    }

    let args = Args::parse(raw.into_iter());

    // ── 服务模式：SCM 外壳 + 与控制台**同一份**守护链路 ──────────────
    if args.service {
        run_as_service(args);
    }

    serve(args)
}

/// 以服务形态运行：SCM 调度在主线程，守护链路在旁路线程。
///
/// 两者不能反：SCM 的 dispatcher 必须待在主线程（它要在服务主线程上下文里
/// 阻塞并回调状态机），而链路逻辑没有理由非得占用那个线程。
fn run_as_service(args: Args) -> ! {
    service::enter_service_mode();
    let inner = args.clone();
    std::thread::spawn(move || serve(inner));

    service::scm_dispatch();

    // dispatch 正常返回 = SCM 已经要停这个服务了。
    // ⚠ 直接结束进程是**刻意**的：WFP 规则全在动态会话里，进程一死内核
    //    立即清空。主动去 force_teardown() 反而多出一段"进程还活着但规则
    //    已经撤了"的窗口期。
    println!("收到服务停止信号，退出（WFP 动态会话随进程清空）。");
    std::process::exit(0);
}

/// 守护逻辑主体（控制台与服务两种运行形态共用**唯一一份**实现）。
///
/// 返回 `!` 是刻意的：链路的所有终止路径都自己 `exit`，调用方无需处理
/// 返回值，也就不会写出"以为它会返回"的死代码。
fn serve(args: Args) -> ! {
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
    println!(
        "  可信指纹    : {}",
        if config.topology.trusted_fingerprint.is_empty() {
            "（空，首次开机）"
        } else {
            &config.topology.trusted_fingerprint
        }
    );
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
    println!(
        "  token 文件 : {}（DACL: SY/BA 完全控制，AU 只读）",
        args.token_file.display()
    );
    println!("  ⚠ AU 仍可读 token（GUI 不提权，必须能读）。危险命令另有提权检查。");

    // ⚠ `PipeServer` 里握着一个原始 HANDLE，**不是 `Send`**，不能跨线程搬。
    // 所以管道在**服务线程内部**绑定，绑定结果用 channel 回传主线程：
    // 主线程要能确认"管道真的起来了"才继续启动，而不是先打印"已绑定"
    // 再在后面悄悄失败——那种"说了但没做"的启动日志最坑人。
    let status_slot: Arc<Mutex<Option<Status>>> = Arc::new(Mutex::new(None));
    let ticket_slot: TicketSlot = Arc::new(Mutex::new(None));
    // 守卫状态单独一个槽位：`aegisctl status` 要能看到"为什么断网"。
    let guard_slot: GuardSlot = Arc::new(Mutex::new(GuardView::default()));
    // B4：非 WFP 网络设置快照守卫。先置 None，启动后段（审计就绪）再 arm。
    let netcfg_slot: NetCfgSlot = Arc::new(Mutex::new(None));
    let (ready_tx, ready_rx) = std_mpsc::channel::<Result<(), String>>();
    let serve_pipe = args.pipe.clone();
    let serve_token = token.clone();
    let serve_status = Arc::clone(&status_slot);
    let serve_ticket = Arc::clone(&ticket_slot);
    let serve_guard = Arc::clone(&guard_slot);
    let serve_netcfg = Arc::clone(&netcfg_slot);
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
        serve_forever(
            &server,
            &serve_token,
            &serve_status,
            &serve_guard,
            &serve_plan,
            &serve_ticket,
            &serve_netcfg,
        );
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
    println!(
        "  参与指纹  : {} 张（{}）",
        snap.fingerprint_participants, snap.fingerprint_scope
    );
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
    println!(
        "  锁 53     : {} / 校园网严格 : {} / Boot 背板 : {}",
        cage.dns_lock, cage.campus_strict, cage.boot_backbone
    );
    println!(
        "  静态自检  : {} 项，不变量{}",
        findings.len(),
        if ok { " OK" } else { " **违反**" }
    );
    for f in &findings {
        println!(
            "      [{:?}/{}] {}: {}",
            f.severity,
            f.kind.name(),
            f.code,
            f.detail
        );
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
    println!(
        "  事件      : rule={:?} role={} pid={}",
        event.rule, event.role, event.pid
    );
    println!("  链节 seq  : {}", link.seq);
    println!("  链头      : {}", aegis_audit::hex(&link.hash));
    println!("  落盘      : {}", audit_path.display());
    // 交给共享槽位：守卫线程也要往里写（收紧/恢复/转人工都得留证据）。
    let audit: AuditSlot = Arc::new(Mutex::new(log));

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

    // ── B4：非 WFP 网络设置快照守卫（系统代理 + 路由表）──────────────
    //
    // 两件事，顺序刻意：
    //  1. **崩溃恢复优先**：若 data-dir 里有残留基线文件，说明上一轮改了
    //     非 WFP 项却被强杀（Drop 没跑）——先按它还原，再清文件。
    //  2. **arm 采集基线**：只读，绝不在此刻改任何系统设置。采集失败
    //     不致命（B4 无触发点会真改），只让 restore_protected=false 如实上报。
    let netcfg_protected = arm_netcfg_guard(&args.data_dir, &netcfg_slot);
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
        guard: GuardView::default(),
        restore_protected: netcfg_protected,
        restore_pending: false,
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
            *guard_slot.lock().unwrap() = GuardView::off(gap);
        },
        None if args.guard_interval_secs == 0 => {
            println!("  已关闭（--guard-interval-secs 0）。");
            *guard_slot.lock().unwrap() = GuardView::off("已关闭（--guard-interval-secs 0）");
        },
        None => {
            let log = args.data_dir.join("guard-observe.log");
            println!("  周期      : {} 秒", args.guard_interval_secs);
            match config.proxy.control_addr {
                Some(a) => println!(
                    "  断言      : A 代理可达（探测 {a}，超时 800ms）/ \
                                     B 承载体在 / C 默认出口=承载体"
                ),
                None => println!(
                    "  断言      : B 承载体在 / C 默认出口=承载体\n\
                     \x20                 ⚠ 断言 A **判不了**：未配置 proxy.control_addr\n\
                     \x20                   （判不了 = Unknown，永不收紧，不会假装可达）"
                ),
            }
            if args.guard_act {
                println!("  动作      : **已接线**（--guard-act）");
                println!("    Tighten → 撤掉放行（拒绝底板保留 → 全都拒绝）");
                println!("    Relax   → 把放行装回原会话（自动恢复，不再走 10s 确认）");
            } else {
                println!("  动作      : 只观测（加 --guard-act 才会真的收紧）");
            }
            println!("  日志      : {}", log.display());
            spawn_guard_observer(
                config.clone(),
                Duration::from_secs(args.guard_interval_secs),
                log,
                Arc::clone(&ticket_slot),
                Arc::clone(&guard_slot),
                Arc::clone(&audit),
                args.guard_act,
            );
        },
    }

    // ── 第二审计源：mihomo 连接级元数据（只读富化）────────────────────
    //
    // 这**不**改变任何流量、不碰 WFP、不收紧。它只是周期性地把"当前经过代理的
    // 连接"作为 `Action::Observed` 写进审计链，补上 WFP 第一审计源拿不到的
    // host / 进程路径 / 命中规则。拉不到（控制口连不上）就跳过本轮——
    // 第二审计源缺失**绝不**影响基本审计（第一源仍在）。
    if let Some(clash_cfg) = &config.proxy.clash {
        println!(
            "Clash 审计富化：每 {} 秒拉取连接（只读，{}）",
            CLASH_AUDIT_INTERVAL_SECS, clash_cfg.control_addr
        );
        spawn_clash_audit_enricher(
            clash_cfg,
            Arc::clone(&audit),
            Duration::from_secs(CLASH_AUDIT_INTERVAL_SECS),
        );
    } else {
        println!("Clash 审计富化：未配置 [proxy.clash]，跳过。");
    }
    println!();

    println!("启动完成。IPC 已在 {} 上应答。", args.pipe);
    if service::is_service_mode() {
        // ⚠ 服务模式下**忽略** --serve-secs：它的生命周期归 SCM。
        //   照抄控制台那个 30 秒默认值的话，开机 30 秒后服务自己就没了——
        //   现象是"服务看起来在、但连接不上"，排错方向会跑到 IPC 上去。
        println!("服务模式：等待 SCM 停止信号（--serve-secs 被忽略，这是刻意的）。");
        service::wait_or_stop(args.serve_secs);
        println!("收到停止信号，退出。");
        if let Ok(g) = ticket_slot.lock() {
            if g.as_ref().is_some_and(|t| t.phase == Phase::Committed) {
                println!("⚠ 已确认的规则会随本进程退出而清空（动态会话）——这是兜底，不是 bug。");
            }
        }
    } else if args.serve_secs == 0 {
        println!("--serve-secs 0：不等客户端，直接退出。");
    } else {
        println!(
            "等待 aegisctl 连接 {} 秒（--serve-secs 可调）…",
            args.serve_secs
        );
        println!("另开一个终端：");
        println!(
            "  cargo run -p aegisctl -- --token-file {} --pipe {}",
            args.token_file.display(),
            args.pipe
        );
        service::wait_or_stop(args.serve_secs);
        println!("服务时间到，退出。");
        if let Ok(g) = ticket_slot.lock() {
            if g.as_ref().is_some_and(|t| t.phase == Phase::Committed) {
                println!("⚠ 已确认的规则会随本进程退出而清空（动态会话）——这是兜底，不是 bug。");
            }
        }
    }

    // 走到这里说明等待结束（控制台模式到点 / 服务模式收到停止信号）。
    // 显式 exit 而不是让它自然返回：`serve()` 的返回类型是 `!`，
    // 而"自然返回"在服务模式下意味着**悄悄退出服务**，SCM 会当成异常终止
    // 在事件日志里留一条 ERROR。安静地按正常路径退出才对。
    //
    // ⚠ `process::exit` **不跑析构函数**——SnapshotGuard 的 Drop 兜底不会触发。
    // 所以正常退出前必须显式还原一次非 WFP 改动（B4 无触发点，通常是 no-op；
    // 但一旦将来接了真改动，这条就是"一键复原"在干净退出时的落点）。
    restore_netcfg_on_exit(&netcfg_slot);
    std::process::exit(0);
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
    view: GuardSlot,
    audit: AuditSlot,
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
                observe_and_act(&cfg, &ticket, &mut tracker, &policy, ticks, &view, &audit)
            } else {
                let l = observe_once(&cfg, ticks, &mut streak, policy.failure_threshold);
                // 观测模式也要更新状态：`aegisctl status` 里得能看到
                // "守卫在看着，结论是什么"，否则和没启用分辨不出来。
                publish(&view, &ticket, &audit, None, &l, None);
                l
            };
            println!("{line}");
            append_guard_line(&log, &line);
        }
    });
}

/// 第二审计源的富化线程：**只读**地把 mihomo 当前连接写进审计链。
///
/// 设计要点（见 design-spec §2A / §12 F3）：
/// - 只观测、不裁决：每条连接记成 `Action::Observed` + `InterfaceRole::Unknown`，
///   绝不冒充 WFP 的裁决证据（那是第一审计源的事）。
/// - **去重**：同一连接只在首次出现时落盘一次，避免每轮把同一批连接重描一遍
///   把日志撑爆。内存上界 = 当前活跃连接数。
/// - 控制口连不上 / 解析失败**只记日志不崩**：第二审计源缺失不影响基本审计，
///   也不收紧（收紧是 WFP 第一源的事）。
/// - 进程退出线程随之消失，无需 join / 停止标志（同守卫线程）。
fn spawn_clash_audit_enricher(cfg: &aegis_config::Clash, audit: AuditSlot, interval: Duration) {
    let cfg = cfg.clone();
    thread::spawn(move || {
        // 适配器无状态（只持配置 + 能力声明），跨轮复用即可，不必每轮重建。
        let adapter = build_clash_adapter(&cfg);
        // 已记录过的连接 id：只保留"当前仍活跃"的，腾出已关闭连接的占位，
        // 并允许其将来重连时重新记录。内存上界 = 当前活跃连接数。
        let mut seen: HashSet<String> = HashSet::new();
        let mut ticks = 0u64;
        loop {
            thread::sleep(interval);
            ticks += 1;
            let conns = match adapter.connections() {
                Ok(c) => c,
                Err(e) => {
                    // 判不了，不是故障。跳过本轮，不收紧、不崩。
                    println!("[clash-audit #{ticks}] 读取连接失败（跳过本轮）：{e}");
                    // 控制口失联时 seen 失去参照，清空以免占位常驻且恢复后不被重记。
                    seen.clear();
                    continue;
                },
            };
            let total = conns.connections.len();
            let mut logged = 0usize;
            {
                let Ok(mut log) = audit.lock() else {
                    // 锁被毒化：跳过本轮，下一轮再试。
                    println!("[clash-audit #{ticks}] 审计锁不可用，跳过本轮");
                    seen.clear();
                    continue;
                };
                for conn in &conns.connections {
                    if seen.contains(&conn.id) {
                        continue;
                    }
                    let event = connection_to_audit_event(conn, now_ms());
                    if log.append(&event).is_ok() {
                        seen.insert(conn.id.clone());
                        logged += 1;
                    } else {
                        println!(
                            "[clash-audit #{ticks}] 写入审计事件失败：连接 {} 跳过",
                            conn.id
                        );
                    }
                }
                let _ = log.flush();
            }
            // 仅保留仍活跃的连接 id（见上方字段注释）。
            seen = conns.connections.iter().map(|c| c.id.clone()).collect();
            if logged > 0 {
                println!("[clash-audit #{ticks}] +{logged} 条观测连接（活跃 {total} 条）");
            }
        }
    });
}

/// 把 `[proxy.clash]` 配置翻译成适配器配置（secret 优先走环境变量）。
///
/// 与 `clash_assertion_a` 同构：同一个配置段、同一套 secret 解析规则，
/// 避免两处各写一遍而漂移。
fn build_clash_adapter(clash: &aegis_config::Clash) -> ClashAdapter {
    let secret = clash
        .secret_env
        .as_ref()
        .and_then(|k| std::env::var(k).ok())
        .unwrap_or_else(|| clash.secret.clone());
    ClashAdapter::new(ClashConfig {
        addr: clash.control_addr.clone(),
        secret,
        tun_candidates: Vec::new(),
        expected_providers: clash.expected_providers.clone(),
    })
}

/// 把这一拍的结论写进对外状态，必要时落一条审计。
///
/// ⚠ **只在状态翻转时写审计**，不是每拍都写：守卫每 3 秒跑一次，
/// 一条"生效"写一次的话一天就是近 3 万条噪音，真正值钱的
/// "什么时候断的网"会被淹掉。
fn publish(
    view: &GuardSlot,
    ticket: &TicketSlot,
    audit: &AuditSlot,
    verdict: Option<&GuardVerdict>,
    line: &str,
    event: Option<GuardEvent>,
) {
    let Ok(mut v) = view.lock() else { return };

    // 收紧与否认**票据上的实际状态**，不看"打算收紧"——
    // 看门狗执行前那 200 毫秒里两者是不一样的，而那正是最容易被问的时刻。
    v.tightened = ticket
        .lock()
        .ok()
        .and_then(|g| g.as_ref().map(|t| t.permits_suspended))
        .unwrap_or(false);

    match verdict {
        Some(vd) => {
            v.verdict = match vd {
                GuardVerdict::Effective => GUARD_EFFECTIVE.to_string(),
                GuardVerdict::Ineffective { .. } => GUARD_INEFFECTIVE.to_string(),
                GuardVerdict::Unknown { .. } => GUARD_UNKNOWN.to_string(),
            };
            v.reason = vd.reason();
        },
        // 拓扑都没采到：那也是"判不了"，不能挂着上一次的结论装作还在看着
        None => {
            v.verdict = GUARD_UNKNOWN.to_string();
            v.reason = strip_tick(line);
        },
    }

    // ⚠ 一旦置上就**不再自动清除**：清除等于"又自动开关起来"，
    // 而把它交给人的前提正是"别再自己动了"。
    if let Some(GuardEvent::NeedsHuman { reason }) = &event {
        v.needs_human = true;
        v.reason = strip_tick(reason);
    }
    drop(v);

    if let Some(e) = event {
        append_guard_audit(audit, e);
    }
}

/// 去掉日志行里的 `[守卫 #N] ` 前缀。状态里不需要拍号，
/// 留着反而让人以为是"第几次断网"。
fn strip_tick(line: &str) -> String {
    line.split_once(']')
        .map_or_else(|| line.to_string(), |(_, rest)| rest.trim().to_string())
}

/// 守卫的**状态翻转**。落审计的只有这几种，每拍的"生效"不落。
#[derive(Debug, Clone, PartialEq, Eq)]
enum GuardEvent {
    /// 撤掉放行 → 全都拒绝。⚠ 这是会断网的动作，必须有据可查。
    Tightened { reason: String },
    /// 放行装回去了（自动恢复）。
    Relaxed { reason: String },
    /// 停止自动动作，等人工。
    NeedsHuman { reason: String },
}

impl GuardEvent {
    /// 审计里的规则名。
    ///
    /// ⚠ 沿用 `BOOT:` 的前缀约定：**这些是控制面事件，不是真实连接**。
    /// 导出证据包时必须按 `GUARD:` 前缀过滤掉——核对证据的人不知道
    /// 一条 `src=127.0.0.1:0` 的"连接"其实是守卫在收紧。
    fn rule(&self) -> &'static str {
        match self {
            Self::Tightened { .. } => "GUARD:TIGHTEN",
            Self::Relaxed { .. } => "GUARD:RELAX",
            Self::NeedsHuman { .. } => "GUARD:NEEDS_HUMAN",
        }
    }

    fn reason(&self) -> &str {
        match self {
            Self::Tightened { reason } | Self::Relaxed { reason } | Self::NeedsHuman { reason } => {
                reason
            },
        }
    }
}

/// 往审计链里追加一条守卫事件。
///
/// 失败**只打印不退出**：审计写不进去确实严重，但此时守卫已经把网收紧了，
/// 让进程退出会让动态会话清空 → 规则全没 → 从"全都拒绝"变成"全不设防"，
/// 那比丢一条审计记录糟得多。
fn append_guard_audit(audit: &AuditSlot, event: GuardEvent) {
    let Ok(mut log) = audit.lock() else {
        return;
    };
    let e = AuditEvent {
        ts_ms: now_ms(),
        pid: std::process::id(),
        process_path: std::env::current_exe()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| "<aegisd>".to_string()),
        src: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        protocol: Protocol::Other(0),
        host: None,
        rule: Some(format!("{}:{}", event.rule(), event.reason())),
        luid: 0,
        role: InterfaceRole::Isolated,
        action: match event {
            GuardEvent::Tightened { .. } | GuardEvent::NeedsHuman { .. } => Action::FirewallBlock,
            GuardEvent::Relaxed { .. } => Action::Allow,
        },
    };
    match log
        .append(&e)
        .and_then(|_| log.flush())
        .and_then(|()| log.sync())
    {
        Ok(()) => println!("  [审计] 已记录 {}", event.rule()),
        Err(err) => eprintln!("  [审计] ⚠ 写入失败（守卫动作已执行）：{err}"),
    }
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
    view: &GuardSlot,
    audit: &AuditSlot,
) -> String {
    let verdict = match collect_verdict(cfg, tick) {
        Ok(v) => v,
        Err(line) => {
            // 采不到拓扑也是"判不了"，同样要对外可见——
            // 否则 `status` 里会一直挂着上一次的结论。
            publish(view, ticket, audit, None, &line, None);
            return line;
        },
    };
    let action = tracker.observe(&verdict, now_ms(), *policy);

    // ⚠ 是否真的动了手，看**票据上的标记**，不去解析日志文本——
    // 解析文本的话，改一个字的文案就会让审计漏记一条断网。
    let (line, event) = match action {
        GuardAction::Nothing => (format!("[守卫 #{tick}] {}", verdict_brief(&verdict)), None),

        GuardAction::Tighten(_) => {
            let l = suspend_permits(ticket, tick, &verdict);
            let acted = flag_of(ticket, |t| t.suspend_requested);
            let ev = acted.then(|| GuardEvent::Tightened {
                reason: verdict.reason(),
            });
            (l, ev)
        },

        GuardAction::Relax(_) => {
            let l = restore_permits(ticket, tick, &verdict);
            let acted = flag_of(ticket, |t| t.restore_requested);
            let ev = acted.then(|| GuardEvent::Relaxed {
                reason: verdict.reason(),
            });
            (l, ev)
        },

        GuardAction::NeedsHuman { reason } => {
            let l = format!("[守卫 #{tick}] ⚠ 交给人工：{reason}");
            (l, Some(GuardEvent::NeedsHuman { reason }))
        },
    };

    // 已经判"该放宽"、但放行还没真的装回去 → 按**守卫周期**重试（3 秒），
    // 不是看门狗的 200 毫秒。装不回去通常是环境变了，狂试没用，
    // 但要试够几次再转人工。
    let retried = retry_restore(ticket, tick);
    // 重试到上限而放弃，和 tracker 主动说 NeedsHuman 是**同一类事**：
    // 都表示"不再自动动作了"，都得进状态 + 审计，否则用户只看到网断了。
    let gave_up = retried.as_deref().is_some_and(|r| r.contains("需人工"));

    let event = match event {
        Some(e) => Some(e),
        None if gave_up => Some(GuardEvent::NeedsHuman {
            reason: retried.clone().unwrap_or_default(),
        }),
        None => None,
    };

    let line = match retried {
        Some(retry) => format!("{line}\n{retry}"),
        None => line,
    };
    publish(view, ticket, audit, Some(&verdict), &line, event);
    line
}

/// 读票据上的一个标记。**读不到一律当 false**——宁可漏一条审计，
/// 也不能凭"大概动了手"去记一条没发生的断网。
fn flag_of(ticket: &TicketSlot, f: impl Fn(&ApplyTicket) -> bool) -> bool {
    ticket
        .lock()
        .ok()
        .and_then(|g| g.as_ref().map(f))
        .unwrap_or(false)
}

/// 收紧：**撤掉放行，留下拒绝底板**。
///
/// ⚠ 不是"整个绝缘笼一起拆"。默认拒绝底板也在同一次下发里，
/// 一起删掉的话机器就**完全不设防**——那不是"全都拒绝"，是"全都放行"，
/// 兜底反了个向。这个坑踩过一次（早期实现直接 `force_teardown`）。
fn suspend_permits(ticket: &TicketSlot, tick: u64, verdict: &GuardVerdict) -> String {
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
        Some(t) => {
            if t.permits_suspended {
                return format!("[守卫 #{tick}] 已在收紧态，不重复撤放行");
            }
            match t.phase {
                // 已拆除过：整批规则都不在了（连拒绝底板也没了），
                // 此时"撤放行"无从谈起，只能重新下发——那是步 3 之后的事。
                Phase::RolledBack => {
                    return format!(
                        "[守卫 #{tick}] ⚠ 该收紧，但票据已拆除过 → 规则已全部不在，\
                         需要重新下发（不是撤放行能解决的）"
                    )
                },
                _ if t.permit_ids.is_empty() => {
                    return format!(
                        "[守卫 #{tick}] ⚠ 该收紧，但票据里没有放行 id → \
                         不能为了收紧去动拒绝底板，不动作"
                    )
                },
                _ => {
                    let n = t.permit_ids.len();
                    t.request_suspend_permits();
                    n
                },
            }
        },
    };
    format!(
        "[守卫 #{tick}] ⚠ **已收紧**：撤掉 {n} 条放行（{}）。\
         拒绝底板保留 → 全都拒绝。看门狗 200 毫秒内执行。",
        verdict_brief(verdict)
    )
}

/// 放宽：把放行**装回去**（步 3）。
///
/// 走的是"往原会话里追加"，不是重新下发：没有"旧的拆了、新的没装上"这个
/// 空窗，也不需要重新走 10 秒确认倒计时——**自动恢复不是新装**。
/// ⚠ 但审计必须能看出这是自动恢复，所以 `note` 里写清楚。
fn restore_permits(ticket: &TicketSlot, tick: u64, verdict: &GuardVerdict) -> String {
    let mut g = match ticket.lock() {
        Ok(g) => g,
        Err(_) => return format!("[守卫 #{tick}] ⚠ 该放宽，但票据锁损坏，不动作"),
    };
    match g.as_mut() {
        None => format!("[守卫 #{tick}] ⚠ 该放宽，但没有票据 → 需人工下发"),
        Some(t) => {
            if !t.permits_suspended {
                return format!(
                    "[守卫 #{tick}] {} → 放行本来就在，无需恢复",
                    verdict_brief(verdict)
                );
            }
            t.request_restore_permits();
            format!(
                "[守卫 #{tick}] **已放宽**：正在把放行装回去（{}）。\
                 看门狗 200 毫秒内执行。",
                verdict_brief(verdict)
            )
        },
    }
}

/// 放行还没装回去时的重试。到上限就**停手并转人工**，不再刷屏。
fn retry_restore(ticket: &TicketSlot, tick: u64) -> Option<String> {
    let mut g = ticket.lock().ok()?;
    let t = g.as_mut()?;
    if !t.permits_suspended || t.restore_requested {
        return None;
    }
    if t.restore_failures >= MAX_RESTORE_ATTEMPTS {
        return Some(format!(
            "[守卫 #{tick}] ⚠ 放行仍未装回：已失败 {} 次（上限 {}），\
             停止自动重试，**需人工**。当前仍处收紧态。",
            t.restore_failures, MAX_RESTORE_ATTEMPTS
        ));
    }
    let attempt = t.restore_failures + 1;
    t.request_restore_permits();
    Some(format!(
        "[守卫 #{tick}] 放行仍未装回 → 第 {attempt} 次尝试恢复（上限 {}）",
        MAX_RESTORE_ATTEMPTS
    ))
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
    let snap =
        snapshot().map_err(|e| format!("[守卫 #{tick}] 拓扑采集失败：{e} → Unknown，不动手"))?;
    let facts = cfg
        .guard_facts_from(&snap, assertion_a(cfg))
        .ok_or_else(|| format!("[守卫 #{tick}] 配置缺 proxy.mode，无法构造事实，跳过"))?;
    Ok(evaluate(facts))
}

/// **断言 A**：代理控制面可连吗。
///
/// 返回 `None` 表示**判不了**，它和"不可达"是两回事：
/// 没配 `proxy.control_addr` 时不该收紧（收紧 = 断网），只能判不了。
///
/// 后续接上适配器 SPI 之后，这里换成 `Op::RulesEffective` 的三态结果：
/// `RulesEffective → Some(true)`、`RulesIneffective → Some(false)`、
/// `RulesUnknown → None`。本函数退化为"没有适配器时的兜底判据"。
fn assertion_a(cfg: &Config) -> Option<bool> {
    // 优先问适配器：它能回答"规则**生效**没有"，而不只是"端口通不通"。
    // 接线前这里是纯 TCP 探测——那只能证明进程活着，而这恰恰是
    // 「进程好好的、规则集是空的」这类静默失效抓不到的情形。
    if let Some(clash) = &cfg.proxy.clash {
        return clash_assertion_a(clash);
    }
    // 没配适配器 → 退回 TCP 探测（老行为，且它只能回答这么多）
    let addr = cfg.proxy.control_addr?;
    Some(TcpStream::connect_timeout(&addr, CONTROL_PROBE_TIMEOUT).is_ok())
}

/// 用 mihomo 适配器回答断言 A（`Op::RulesEffective` 的三态）。
///
/// ⚠ 三态必须映射成三态，**不能压成两态**：
/// · `RulesEffective`   → `Some(true)`
/// · `RulesIneffective` → `Some(false)` —— 守卫据此收紧
/// · `RulesUnknown` / 调用失败 → `None` —— 守卫**永不收紧**
///
/// 把最后两格合并的后果是"控制口连不上"被当成"规则没生效"→ 收网，
/// 而实际原因只是 Aegis 自己问不到；收紧的代价是整机断网。
/// 这条在 `aegis-orchestrator::clash::tests` 里有专门的用例钉住。
fn clash_assertion_a(clash: &aegis_config::Clash) -> Option<bool> {
    use aegis_orchestrator::clash::{ClashAdapter, ClashConfig};
    use aegis_orchestrator::{invoke_checked, Op, Outcome};

    // secret 优先从环境变量读：配置文件可能被外发，环境变量不会跟着走
    let secret = clash
        .secret_env
        .as_ref()
        .and_then(|k| std::env::var(k).ok())
        .unwrap_or_else(|| clash.secret.clone());

    let adapter = ClashAdapter::new(ClashConfig {
        addr: clash.control_addr.clone(),
        secret,
        tun_candidates: Vec::new(),
        expected_providers: clash.expected_providers.clone(),
    });

    match invoke_checked(&adapter, Op::RulesEffective) {
        Ok(Outcome::RulesEffective) => Some(true),
        Ok(Outcome::RulesIneffective { .. }) => Some(false),
        Ok(Outcome::RulesUnknown { .. }) => None,
        // 其余 Outcome 与"规则是否生效"无关。`invoke_checked` 已经保证
        // 能力对得上，走到这里说明契约被绕过——**判不了**，不是"生效"。
        // ⚠ 这个分支必须留在：以后给 Capability 加新能力时，
        //   编译器会在这里提醒，而不是让新能力悄悄落到"生效"上。
        Ok(other) => {
            eprintln!("[WARN] 断言 A 收到了非规则类结果：{other:?}（按判不了处理）");
            None
        },
        Err(_) => None,
    }
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
    guard: &GuardSlot,
    plan: &[FilterSpec],
    ticket: &TicketSlot,
    netcfg: &NetCfgSlot,
) {
    loop {
        let end = match server.accept() {
            Ok(e) => e,
            Err(_) => return,
        };
        if let Err(_e) = serve_one(&end, token, status, guard, plan, ticket, netcfg) {
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
    guard: &GuardSlot,
    plan: &[FilterSpec],
    ticket: &TicketSlot,
    netcfg: &NetCfgSlot,
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
                        // 守卫状态是**活的**，不能直接用启动时那份快照——
                        // 快照会永远显示"没在干活"，而用户恰恰是在断了网
                        // 之后才来查的。还原保护状态同理（B4，读快照守卫）。
                        Some(mut s) => {
                            if let Ok(g) = guard.lock() {
                                s.guard = g.clone();
                            }
                            if let Ok(nc) = netcfg.lock() {
                                (s.restore_protected, s.restore_pending) = match nc.as_ref() {
                                    Some(g) => (true, g.is_dirty()),
                                    None => (false, false),
                                };
                            }
                            s.to_text()
                        },
                        None => "启动中：状态尚不可用".to_string(),
                    }
                } else if word == REQ_SNAPSHOT {
                    // B4：把非 WFP 改前基线展示出来（只读，绝不改系统）。
                    snapshot_text(netcfg)
                } else if word == REQ_APPLY {
                    do_apply(plan, ticket)
                } else if word == REQ_CONFIRM {
                    do_confirm(ticket)
                } else if word == REQ_ROLLBACK {
                    do_rollback(ticket, netcfg)
                } else {
                    format!(
                        "未知请求：{word}（可用：{REQ_STATUS} / {REQ_PING} / {REQ_SNAPSHOT} / \
                         {REQ_APPLY} / {REQ_CONFIRM} / {REQ_ROLLBACK}）"
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
            return format!(
                "{}已有一个待确认的下发，先 confirm 或 rollback。",
                DENY_PREFIX
            );
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
                        receipt.permit_ids,
                    ));
                }
                let _ = tx.send(Ok(n));
                watch(&session, &watchdog_slot, &watchdog_plan);
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
fn watch(session: &Session, slot: &TicketSlot, plan: &[FilterSpec]) {
    loop {
        thread::sleep(Duration::from_millis(200));
        let now = now_ms();

        // 一次读清"现在该干什么"，再关掉锁去动手：
        // 握着锁去调用 WFP 会让守卫线程（每 3 秒一次）被卡在这里。
        let cmd = match slot.lock() {
            Ok(g) => match g.as_ref() {
                None => WatchCmd::Wait,
                Some(t) => {
                    if t.force_teardown {
                        WatchCmd::Teardown
                    } else if t.restore_requested {
                        WatchCmd::Restore
                    } else if t.suspend_requested {
                        WatchCmd::Suspend
                    } else if t.must_roll_back(now) {
                        WatchCmd::Teardown
                    } else {
                        WatchCmd::Wait
                    }
                },
            },
            Err(_) => WatchCmd::Wait,
        };

        match cmd {
            WatchCmd::Wait => {},

            WatchCmd::Teardown => {
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
            },

            // 守卫收紧：**只撤放行**。拒绝底板留在原处 → 剩下的就是全都拒绝。
            WatchCmd::Suspend => {
                let ids = match slot.lock() {
                    Ok(g) => g.as_ref().map(|t| t.permit_ids.clone()).unwrap_or_default(),
                    Err(_) => Vec::new(),
                };
                let removed = rollback(session, &ids).unwrap_or(0);
                if let Ok(mut g) = slot.lock() {
                    if let Some(t) = g.as_mut() {
                        t.suspend_requested = false;
                        t.permits_suspended = true;
                        // id 已经不存在了，必须清空：留着会在恢复/回滚时
                        // 删到 id 复用之后属于别人的规则。
                        t.permit_ids.clear();
                        t.note = format!("守卫收紧：撤掉 {removed} 条放行，拒绝底板保留");
                    }
                }
                println!("  [守卫] 已撤掉 {removed} 条放行（拒绝底板保留 → 全都拒绝）");
            },

            // 守卫自动恢复：往**同一个会话**里把放行装回去。
            // 不走重新下发，于是没有"旧的拆了、新的没装上"的空窗，
            // 也不需要再走一次 10 秒确认——自动恢复不是新装。
            WatchCmd::Restore => {
                let permits: Vec<FilterSpec> = plan
                    .iter()
                    .filter(|s| s.action == WfpAction::Permit)
                    .cloned()
                    .collect();
                match install(session, &permits) {
                    Ok(ids) => {
                        let n = ids.len();
                        if let Ok(mut g) = slot.lock() {
                            if let Some(t) = g.as_mut() {
                                t.restore_requested = false;
                                t.permits_suspended = false;
                                t.restore_failures = 0;
                                t.permit_ids = ids.clone();
                                // 也要进 filter_ids：整批拆除时必须连它们一起删。
                                t.filter_ids.extend(ids);
                                t.note = format!("守卫自动恢复：装回 {n} 条放行");
                            }
                        }
                        println!("  [守卫] 已装回 {n} 条放行（自动恢复）");
                    },
                    Err(e) => {
                        let mut gave_up = false;
                        let mut tries = 0;
                        if let Ok(mut g) = slot.lock() {
                            if let Some(t) = g.as_mut() {
                                t.restore_failures = t.restore_failures.saturating_add(1);
                                tries = t.restore_failures;
                                if tries >= MAX_RESTORE_ATTEMPTS {
                                    // 停手：再试也是同样的错，刷屏只会盖住真正的原因。
                                    t.restore_requested = false;
                                    gave_up = true;
                                }
                                t.note = if gave_up {
                                    format!("守卫恢复失败 {tries} 次，停止自动重试，需人工：{e}")
                                } else {
                                    format!("守卫恢复失败（第 {tries} 次）：{e}")
                                };
                            }
                        }
                        if gave_up {
                            println!("  [守卫] ⚠ 恢复放行失败 {tries} 次，停止重试，需人工：{e}");
                        } else {
                            println!("  [守卫] 恢复放行失败（第 {tries} 次）：{e}");
                        }
                    },
                }
            },
        }
    }
}

/// 看门狗这一轮该干什么。
enum WatchCmd {
    Wait,
    /// 整批拆除（超时 / 主动 abort / 人工强拆）。
    Teardown,
    /// 只撤放行（守卫收紧）。
    Suspend,
    /// 把放行装回去（守卫自动恢复）。
    Restore,
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
fn do_rollback(slot: &TicketSlot, netcfg: &NetCfgSlot) -> String {
    // 一键复原 = 拆 WFP（若有票据）+ 还原非 WFP 项（若改过）。二者**独立**：
    // 没有 WFP 票据也该还原非 WFP 改动，反之亦然。
    let (wfp_msg, wfp_did) = rollback_wfp(slot);
    let (nc_msg, nc_state) = restore_netcfg(netcfg);

    let any_failed = matches!(nc_state, NcRestore::Failed);
    let any_did = wfp_did || matches!(nc_state, NcRestore::Restored);
    let head = if any_failed {
        // 有残留没还原干净：必须让用户知道"没完全成功"，而不是报个 ok 了事。
        format!("{DENY_PREFIX}一键复原未完全成功（有非 WFP 残留，需人工留意）")
    } else if any_did {
        format!("{OK_PREFIX}一键复原")
    } else {
        format!("{DENY_PREFIX}无可复原项")
    };
    format!("{head}\n  {wfp_msg}\n  {nc_msg}")
}

/// 非 WFP 还原的结果分类。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NcRestore {
    /// 无事可做（未 arm，或未改过）。
    Idle,
    /// 真的还原了。
    Restored,
    /// 尝试还原但失败（有残留）。
    Failed,
}

/// 拆 WFP 下发票据。返回 `(无前缀描述, 是否真的触发了拆除)`。
fn rollback_wfp(slot: &TicketSlot) -> (String, bool) {
    let mut g = match slot.lock() {
        Ok(g) => g,
        Err(_) => return ("票据锁损坏，无法拆除".to_string(), false),
    };
    match g.as_mut() {
        None => ("WFP：当前没有待拆除的下发".to_string(), false),
        Some(t) => {
            let n = t.filter_ids.len();
            match t.phase {
                Phase::Pending => {
                    t.request_abort();
                    (
                        format!("WFP：已标记拆除 {n} 条，看门狗 200 毫秒内执行"),
                        true,
                    )
                },
                Phase::Committed => {
                    t.force_teardown();
                    (
                        format!("WFP：已请求**紧急强拆** {n} 条已确认规则，看门狗 200 毫秒内执行"),
                        true,
                    )
                },
                Phase::RolledBack => ("WFP：这次下发已经拆除过了".to_string(), false),
            }
        },
    }
}

/// 还原非 WFP 网络设置（系统代理 + 路由）到改前基线。返回 `(无前缀描述, 结果)`。
///
/// 只有"改过"（dirty）才写系统；否则是 `Idle`，绝不碰注册表/路由。
fn restore_netcfg(netcfg: &NetCfgSlot) -> (String, NcRestore) {
    let mut guard = match netcfg.lock() {
        Ok(g) => g,
        Err(_) => return ("非 WFP：锁损坏，无法还原".to_string(), NcRestore::Failed),
    };
    match guard.as_mut() {
        None => (
            "非 WFP：还原保护未就绪（启动时未采到基线）".to_string(),
            NcRestore::Idle,
        ),
        Some(g) => {
            if !g.is_dirty() {
                ("非 WFP：无待还原改动".to_string(), NcRestore::Idle)
            } else {
                match g.restore() {
                    Ok(true) => (
                        "非 WFP：已还原系统代理/路由到改前基线".to_string(),
                        NcRestore::Restored,
                    ),
                    Ok(false) => ("非 WFP：无待还原改动".to_string(), NcRestore::Idle),
                    Err(e) => (
                        format!("非 WFP：还原失败（{e}），可能有残留"),
                        NcRestore::Failed,
                    ),
                }
            }
        },
    }
}

// ── B4：非 WFP 快照守卫装配 / 展示 / 退出还原 ─────────────────────────

/// 启动装配：**先崩溃恢复，再 arm 采集基线**。返回基线是否就绪。
///
/// 顺序刻意——残留基线意味着上一轮改了非 WFP 项却被强杀（`Drop` 没跑），
/// 必须先按它还原再清文件，否则新采的基线会把"残留的坏状态"当成了原状。
fn arm_netcfg_guard(data_dir: &std::path::Path, netcfg: &NetCfgSlot) -> bool {
    let path = baseline_path(data_dir);

    // 1. 崩溃恢复。B4 自身不产生该文件（无触发点会真改）；只有将来接了
    //    非 WFP 改动、或被强杀时才会留下。有就还，没有是本该有的常态。
    match load_baseline(&path) {
        Ok(Some(stale)) => {
            println!("  ⚠ 发现残留非 WFP 基线快照（上一轮疑似被强杀，Drop 未跑）：按基线还原…");
            match WindowsBackend::new(now_ms()).apply(&stale) {
                Ok(()) => {
                    let _ = clear_baseline(&path);
                    println!("  ✓ 已按残留基线还原系统代理/路由，并清除快照文件。");
                },
                Err(e) => {
                    // 还原失败：**保留**快照文件，下次启动再试；绝不谎报成功。
                    eprintln!("  [WARN] 按残留基线还原失败：{e}");
                    eprintln!(
                        "     已保留 {} 以便下次重启重试；可手动 aegisctl rollback。",
                        path.display()
                    );
                },
            }
        },
        Ok(None) => {},
        Err(e) => eprintln!("  [WARN] 读取残留基线快照失败：{e}（忽略，继续 arm）"),
    }

    // 2. arm 采集基线（**只读**，绝不在此刻改任何系统设置）。
    match SnapshotGuard::arm(WindowsBackend::new(now_ms())) {
        Ok(guard) => {
            let b = guard.baseline();
            let server = if b.proxy.server.is_empty() {
                "（空）"
            } else {
                b.proxy.server.as_str()
            };
            println!(
                "  非 WFP 基线：系统代理 enabled={} server={} · 路由 {} 条",
                b.proxy.enabled,
                server,
                b.routes.len()
            );
            println!("  还原保护  ：在位（改前快照 + 退出/崩溃还原 + 一键 rollback）");
            if let Ok(mut slot) = netcfg.lock() {
                *slot = Some(guard);
            }
            true
        },
        Err(e) => {
            eprintln!("  [WARN] 采集非 WFP 基线失败：{e}");
            eprintln!("     还原保护**未就绪**——此时不应进行任何非 WFP 网络改动。");
            false
        },
    }
}

/// 把非 WFP 改前基线渲染成**只读**文本（供 `aegisctl snapshot` 展示）。
fn snapshot_text(netcfg: &NetCfgSlot) -> String {
    let guard = match netcfg.lock() {
        Ok(g) => g,
        Err(_) => return format!("{DENY_PREFIX}快照锁损坏"),
    };
    match guard.as_ref() {
        None => {
            format!("{DENY_PREFIX}还原保护未就绪（启动时未采到基线）——不掌握网络原状，不应改动。")
        },
        Some(g) => {
            let b = g.baseline();
            let or_empty = |s: &str| {
                if s.is_empty() {
                    "（空）".to_string()
                } else {
                    s.to_string()
                }
            };
            let pac = b
                .proxy
                .autoconfig_url
                .clone()
                .unwrap_or_else(|| "（无）".into());
            format!(
                "{OK_PREFIX}非 WFP 改前基线（taken_at_ms={}）\n  \
                 系统代理 enabled  : {}\n  \
                 系统代理 server   : {}\n  \
                 系统代理 override : {}\n  \
                 PAC AutoConfigURL : {}\n  \
                 路由条数          : {}\n  \
                 待还原(dirty)     : {}",
                b.taken_at_ms,
                b.proxy.enabled,
                or_empty(&b.proxy.server),
                or_empty(&b.proxy.override_),
                pac,
                b.routes.len(),
                g.is_dirty(),
            )
        },
    }
}

/// 正常退出前显式还原非 WFP 改动——`process::exit` **不跑 `Drop`**，
/// 守卫的析构兜底不会触发，必须在这里补一刀。B4 无触发点，通常是 no-op。
fn restore_netcfg_on_exit(netcfg: &NetCfgSlot) {
    let mut guard = match netcfg.lock() {
        Ok(g) => g,
        Err(_) => return,
    };
    if let Some(g) = guard.as_mut() {
        if g.is_dirty() {
            match g.restore() {
                Ok(true) => println!("退出前已还原非 WFP 网络设置（系统代理/路由）到改前基线。"),
                Ok(false) => {},
                Err(e) => eprintln!(
                    "[WARN] 退出前还原非 WFP 设置失败：{e}（可手动 aegisctl rollback 重试）"
                ),
            }
        }
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

#[derive(Clone)]
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
    /// 以 Windows 服务形态运行（由 SCM 调度）。
    ///
    /// ⚠ 只有 SCM 拉起的进程才该带这个：它在主线程阻塞于
    ///   `StartServiceCtrlDispatcherW`。手工带它跑会让 SCM 判定"服务没启动"
    ///   并在事件日志里报错——但链路本身照跑，所以现象是"能用，事件日志有红字"。
    service: bool,
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
        let mut service = false;
        let mut args = argv;

        while let Some(a) = args.next() {
            match a.as_str() {
                "--config" => config = args.next().map(PathBuf::from),
                "--pipe" => pipe = args.next().unwrap_or(pipe),
                "--token-file" => token_file = args.next().map(PathBuf::from),
                "--data-dir" => data_dir = args.next().map(PathBuf::from),
                "--serve-secs" => {
                    serve_secs = args
                        .next()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(serve_secs)
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
                "--service" => service = true,
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
        let token_file = token_file.unwrap_or_else(|| data_dir.join("ipc.token"));

        Self {
            config,
            pipe: aegis_ipc::normalize_pipe_name(&pipe),
            token_file,
            data_dir,
            serve_secs,
            guard_interval_secs,
            guard_act,
            service,
        }
    }
}

/// 执行服务管理子命令，返回要打印给用户的文本。
///
/// ⚠ 这些命令**会改这台机器的状态**（注册/删除服务 = 改开机行为）。
///   代码只提供能力，执行与否由人决定——项目约定：涉及系统状态变更的
///   动作必须先取得用户明确同意。
fn run_service_command(sub: ServiceCommand) -> Result<String, String> {
    match sub {
        ServiceCommand::Status => Ok(if service::is_installed() {
            format!(
                "服务「{}」已安装（SCMgr 名：{}）。",
                service::SERVICE_DISPLAY_NAME,
                service::SERVICE_NAME
            )
        } else {
            format!("服务「{}」未安装。", service::SERVICE_NAME)
        }),
        ServiceCommand::Install { opts, start_now } => {
            if service::is_installed() {
                return Err("服务已安装。要重装请先 `aegisd uninstall`。".into());
            }
            let spec = service::install(&opts)?;
            let mut msg = format!(
                "已注册服务。\n  显示名  ：{}\n  启动方式：{}\n  binPath  ：{}",
                spec.display_name,
                spec.start_type.label(),
                spec.bin_path
            );
            if start_now {
                service::start()?;
                msg.push_str("\n已启动。");
            } else {
                msg.push_str("\n未启动（加 --start 可立即启动，或 `aegisd start`）。");
            }
            Ok(msg)
        },
        ServiceCommand::Uninstall => service::uninstall().map(|_| "服务已卸载。".to_string()),
        ServiceCommand::Start => service::start().map(|_| "服务已启动。".to_string()),
        ServiceCommand::Stop => service::stop().map(|_| "已向服务发出停止指令。".to_string()),
    }
}

fn print_usage() {
    println!("用法：aegisd --config <配置文件> [选项]");
    println!();
    println!("  --config <path>      配置文件（**必填**，读不到就退出）");
    println!(
        "  --pipe <name>        IPC 管道名（默认 {}，裸名会补成 \\\\.\\pipe\\<name>）",
        aegis_ipc::PIPE_NAME
    );
    println!("  --token-file <path>  IPC token 落盘路径（默认 <data-dir>/ipc.token）");
    println!("  --data-dir <dir>     运行数据目录（默认 .aegis-run）");
    println!("  --serve-secs <n>     IPC 服务时长（默认 30，0 = 启动完就退出）");
    println!(
        "  --guard-interval-secs <n>  守卫观测周期（默认 {}，0 = 关闭）",
        DEFAULT_GUARD_INTERVAL_SECS
    );
    println!("  --guard-act              守卫**真的动手**（默认只观测，见下）");
    println!("  --service                以服务形态运行（由 SCM 拉起时才用）");
    println!();
    println!("服务管理子命令（**需要管理员权限**，会改这台机器的开机行为）：");
    println!("  aegisd install --config <配置文件> [--data-dir <dir>] [--start] [--start-type auto|demand]");
    println!("  aegisd uninstall | start | stop | status");
    println!("  ⚠ 注册后开机自动以 SYSTEM 运行。先 `aegisd status` 查是否已装。");
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
        assert_eq!(next_streak(&unknown("y"), 2), 2, "⚠ 判不了既不清零也不累加");
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
    ///
    /// ⚠ 完整的行为测试在 `aegis-ipc::endpoint` 里（含 Git Bash 吃掉一个
    /// 反斜杠那种残缺前缀）。这里只钉住"aegisd 确实接上了这个归一化"。
    #[test]
    fn the_daemon_normalizes_whatever_pipe_name_it_is_given() {
        let a = Args::parse(args_of(&["--config", "c.toml", "--pipe", "aegis-ob"]));
        assert_eq!(a.pipe, aegis_ipc::normalize_pipe_name("aegis-ob"));

        let b = Args::parse(args_of(&["--config", "c.toml"]));
        assert_eq!(b.pipe, aegis_ipc::PIPE_NAME);
    }

    fn args_of(items: &[&str]) -> std::vec::IntoIter<String> {
        items
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .into_iter()
    }

    // ── 步 2/3：收紧与恢复 ───────────────────────────────────────────

    /// 收紧 = **撤放行**，不是新增拒绝规则。所以没有票据时只能"不动作"——
    /// 凭空装一条拒绝规则，等于让守卫造出它没能力安全撤掉的东西。
    #[test]
    fn tightening_without_a_ticket_does_nothing_and_says_so() {
        let slot = empty_slot();
        let s = suspend_permits(&slot, 1, &ineffective("x"));
        assert!(s.contains("没有票据"), "{s}");
        assert!(s.contains("不动作"), "{s}");
        assert!(slot.lock().unwrap().is_none(), "绝不能凭空造票据");
    }

    /// ⚠ 这条钉的是"收紧 ≠ 拆笼子"：**绝不能**碰 `force_teardown`。
    /// 强拆会把默认拒绝底板一起删掉，那不是"全都拒绝"，是"全都放行"——
    /// 兜底反了个向，而且从日志上看不出来。
    #[test]
    fn tightening_a_committed_ticket_only_suspends_the_permits() {
        let slot = empty_slot();
        let mut t = ApplyTicket::pending(now_ms(), CONFIRM_WINDOW_MS, vec![4, 5, 6], vec![4, 5]);
        t.confirm(now_ms()).expect("窗口内确认应成功");
        *slot.lock().unwrap() = Some(t);

        let s = suspend_permits(&slot, 3, &ineffective("r"));
        assert!(s.contains("已收紧"), "{s}");
        assert!(s.contains("撤掉 2 条放行"), "{s}");

        let t = slot.lock().unwrap().clone().unwrap();
        assert!(t.suspend_requested, "{t:?}");
        assert!(!t.force_teardown, "⚠ 绝不能整批强拆：{t:?}");
        assert!(!t.abort_requested, "收紧不是 abort：{t:?}");
        assert_eq!(t.filter_ids.len(), 3, "整批 id 一个都不能少：{t:?}");
    }

    /// 收紧过一次就不重复撤。重复删的后果是删到 id 复用后的别人的规则。
    #[test]
    fn tightening_twice_does_not_delete_twice() {
        let slot = empty_slot();
        *slot.lock().unwrap() = Some(ApplyTicket::pending(
            now_ms(),
            CONFIRM_WINDOW_MS,
            vec![4, 5],
            vec![4],
        ));
        assert!(suspend_permits(&slot, 1, &ineffective("x")).contains("已收紧"));

        // 模拟看门狗执行完：清空 permit_ids 并置 suspended
        {
            let mut g = slot.lock().unwrap();
            let t = g.as_mut().unwrap();
            t.suspend_requested = false;
            t.permits_suspended = true;
            t.permit_ids.clear();
        }
        let s = suspend_permits(&slot, 2, &ineffective("x"));
        assert!(s.contains("已在收紧态"), "{s}");
        assert!(!slot.lock().unwrap().as_ref().unwrap().suspend_requested);
    }

    /// ⚠ 票据里没有放行 id 时**必须拒绝动手**。
    /// 放行 id 为空还想"收紧"，下一步只可能去动拒绝底板——那是把防护拆了。
    #[test]
    fn tightening_refuses_when_the_ticket_has_no_permit_ids() {
        let slot = empty_slot();
        *slot.lock().unwrap() = Some(ApplyTicket::pending(
            now_ms(),
            CONFIRM_WINDOW_MS,
            vec![7],
            vec![],
        ));
        let s = suspend_permits(&slot, 1, &ineffective("x"));
        assert!(s.contains("没有放行 id"), "{s}");
        assert!(!slot.lock().unwrap().as_ref().unwrap().suspend_requested);
    }

    /// 已经整批拆除过（人工强拆 / 超时）的票据：规则全没了，
    /// "撤放行"无从谈起，只能重新下发。必须说清楚，不能假装收紧了。
    #[test]
    fn tightening_an_already_rolled_back_ticket_says_it_needs_a_reapply() {
        let slot = empty_slot();
        {
            let mut t = ApplyTicket::pending(now_ms(), CONFIRM_WINDOW_MS, vec![4], vec![4]);
            t.mark_rolled_back("已拆除");
            *slot.lock().unwrap() = Some(t);
        }
        let s = suspend_permits(&slot, 2, &ineffective("x"));
        assert!(s.contains("已拆除过"), "{s}");
        assert!(s.contains("重新下发"), "{s}");
    }

    // ── 步 3：自动恢复 ────────────────────────────────────────────────

    #[test]
    fn restoring_asks_the_watchdog_to_put_the_permits_back() {
        let slot = empty_slot();
        {
            let mut t = ApplyTicket::pending(now_ms(), CONFIRM_WINDOW_MS, vec![4, 5], vec![4]);
            t.confirm(now_ms()).unwrap();
            t.permits_suspended = true;
            t.permit_ids.clear();
            *slot.lock().unwrap() = Some(t);
        }
        let s = restore_permits(&slot, 1, &GuardVerdict::Effective);
        assert!(s.contains("已放宽"), "{s}");
        let t = slot.lock().unwrap().clone().unwrap();
        assert!(t.restore_requested, "{t:?}");
        assert!(!t.suspend_requested, "{t:?}");
    }

    /// 放行本来就在时不能没事找事去重装一遍。
    #[test]
    fn restoring_when_the_permits_are_already_there_is_a_no_op() {
        let slot = empty_slot();
        *slot.lock().unwrap() = Some(ApplyTicket::pending(
            now_ms(),
            CONFIRM_WINDOW_MS,
            vec![4, 5],
            vec![4],
        ));
        let s = restore_permits(&slot, 1, &GuardVerdict::Effective);
        assert!(s.contains("无需恢复"), "{s}");
        assert!(!slot.lock().unwrap().as_ref().unwrap().restore_requested);
    }

    /// 重试有上限：到上限就停手并转人工，不能无限刷屏，
    /// 更不能一直卡在断网态还一声不吭。
    #[test]
    fn restore_retries_are_capped_and_then_handed_to_a_human() {
        let slot = empty_slot();
        {
            let mut t = ApplyTicket::pending(now_ms(), CONFIRM_WINDOW_MS, vec![4, 5], vec![4]);
            t.confirm(now_ms()).unwrap();
            t.permits_suspended = true;
            t.permit_ids.clear();
            *slot.lock().unwrap() = Some(t);
        }
        // 前 MAX 次：每次都再请求一次恢复
        for i in 0..MAX_RESTORE_ATTEMPTS {
            let s = retry_restore(&slot, i as u64).expect("应继续重试");
            assert!(s.contains("尝试恢复"), "{s}");
            let mut g = slot.lock().unwrap();
            let t = g.as_mut().unwrap();
            assert!(t.restore_requested);
            t.restore_requested = false;
            t.restore_failures += 1; // 模拟看门狗上报失败
        }
        let s = retry_restore(&slot, 99).expect("超限也要说一句话");
        assert!(s.contains("需人工"), "{s}");
        assert!(!slot.lock().unwrap().as_ref().unwrap().restore_requested);
    }

    /// 没挂起（放行在）时不该有任何重试动作。
    #[test]
    fn restore_retry_stays_silent_when_the_permits_are_installed() {
        let slot = empty_slot();
        *slot.lock().unwrap() = Some(ApplyTicket::pending(
            now_ms(),
            CONFIRM_WINDOW_MS,
            vec![4],
            vec![4],
        ));
        assert!(retry_restore(&slot, 1).is_none());
    }

    // ── 步 4：进 IPC 状态 + 审计 ──────────────────────────────────────

    /// ⚠ 收紧 = 断网。`aegisctl status` 必须能回答"为什么断"，
    /// 否则用户第一反应就是卸掉 Aegis——那才是真正的防护归零。
    #[test]
    fn a_tightened_guard_is_visible_in_the_published_view() {
        let ticket = empty_slot();
        *ticket.lock().unwrap() = Some({
            let mut t =
                ApplyTicket::pending(now_ms(), CONFIRM_WINDOW_MS, vec![4, 5, 6], vec![4, 5]);
            t.confirm(now_ms()).unwrap();
            t
        });
        let view: GuardSlot = Arc::new(Mutex::new(GuardView::default()));
        let audit = temp_audit();

        suspend_permits(&ticket, 1, &ineffective("2 项未通过 [承载体存在]"));
        publish(&view, &ticket, &audit, None, "（未用）", None);

        let v = view.lock().unwrap().clone();
        // 收紧态取自票据上的**实际**状态：这里看门狗还没跑，所以仍是 false。
        // 真正置上要看 `permits_suspended`。
        assert!(!v.tightened, "还没执行就不该显示已收紧：{v:?}");
        assert_eq!(v.verdict, GUARD_UNKNOWN, "没给 verdict 就是判不了：{v:?}");
        assert!(!v.reason.is_empty(), "原因不能是空的：{v:?}");
    }

    #[test]
    fn the_published_view_reflects_the_tickets_actual_suspension() {
        let ticket = empty_slot();
        *ticket.lock().unwrap() = Some({
            let mut t = ApplyTicket::pending(now_ms(), CONFIRM_WINDOW_MS, vec![4], vec![4]);
            t.confirm(now_ms()).unwrap();
            t.permits_suspended = true; // 看门狗已执行
            t
        });
        let view: GuardSlot = Arc::new(Mutex::new(GuardView::default()));
        publish(&view, &ticket, &temp_audit(), None, "x", None);
        assert!(view.lock().unwrap().tightened);
    }

    /// ⚠ `needs_human` 必须**粘住**：自动清除等于"又自动开关起来"，
    /// 而把它交给人的前提正是"别再自己动了"。
    #[test]
    fn needs_human_is_sticky_even_after_the_next_effective_tick() {
        let ticket = empty_slot();
        let view: GuardSlot = Arc::new(Mutex::new(GuardView::default()));
        let audit = temp_audit();

        publish(
            &view,
            &ticket,
            &audit,
            None,
            "x",
            Some(GuardEvent::NeedsHuman {
                reason: "一小时内已自动收紧 3 次".to_string(),
            }),
        );
        assert!(view.lock().unwrap().needs_human);

        // 之后再来一拍"生效"，不该把标记洗掉
        publish(
            &view,
            &ticket,
            &audit,
            Some(&GuardVerdict::Effective),
            "[守卫 #2] 生效",
            None,
        );
        let v = view.lock().unwrap().clone();
        assert!(v.needs_human, "⚠ 被自动清除了：{v:?}");
        assert_eq!(v.verdict, GUARD_EFFECTIVE);
    }

    /// 审计**只在翻转时写**，不是每拍都写：守卫每 3 秒一拍，
    /// 一条"生效"写一次的话，真正值钱的"什么时候断的网"会被淹掉。
    #[test]
    fn only_transitions_are_audited() {
        let ticket = empty_slot();
        let view: GuardSlot = Arc::new(Mutex::new(GuardView::default()));
        let (audit, path) = temp_audit_with_path();

        let before = audit.lock().unwrap().len();
        publish(
            &view,
            &ticket,
            &audit,
            Some(&GuardVerdict::Effective),
            "生效",
            None,
        );
        assert_eq!(audit.lock().unwrap().len(), before, "常态不该写审计");

        publish(
            &view,
            &ticket,
            &audit,
            Some(&ineffective("r")),
            "x",
            Some(GuardEvent::Tightened {
                reason: "下游规则未生效".to_string(),
            }),
        );
        assert_eq!(audit.lock().unwrap().len(), before + 1, "收紧必须留下证据");

        // 证据要真的读得回来，且链是完整的
        let records = aegis_audit::read_records(&path).unwrap();
        let events: Vec<_> = records.iter().map(|r| r.event.clone()).collect();
        let links: Vec<_> = records.iter().map(|r| r.link).collect();
        aegis_audit::verify(&events, &links).expect("链必须完整");
        let last = events.last().unwrap();
        assert!(
            last.rule
                .as_deref()
                .is_some_and(|r| r.starts_with("GUARD:TIGHTEN")),
            "守卫事件要带 GUARD: 前缀，导出证据包时才过滤得掉：{last:?}"
        );
    }

    /// 守卫事件**不是真实连接**，必须带 `GUARD:` 前缀以便过滤。
    /// 核对证据的人看到一条 `src=127.0.0.1:0` 的"连接"，不可能知道
    /// 那其实是守卫在收紧。
    #[test]
    fn every_guard_event_carries_a_filterable_prefix() {
        for e in [
            GuardEvent::Tightened { reason: "r".into() },
            GuardEvent::Relaxed { reason: "r".into() },
            GuardEvent::NeedsHuman { reason: "r".into() },
        ] {
            assert!(e.rule().starts_with("GUARD:"), "{e:?}");
            assert!(!e.rule().contains(char::is_whitespace), "{e:?}");
        }
        assert_ne!(
            GuardEvent::Tightened { reason: "r".into() }.rule(),
            GuardEvent::Relaxed { reason: "r".into() }.rule()
        );
    }

    /// 日志行带 `[守卫 #N] ` 前缀，进状态时要去掉——
    /// 状态里留着拍号会让人以为是"第几次断网"。
    #[test]
    fn strip_tick_removes_only_the_prefix() {
        assert_eq!(strip_tick("[守卫 #7] 生效"), "生效");
        assert_eq!(strip_tick("没有前缀"), "没有前缀");
    }

    fn temp_audit() -> AuditSlot {
        temp_audit_with_path().0
    }

    /// ⚠ 路径必须**每次都不同**：测试并行跑，同一毫秒里生成同一个文件名的话，
    /// 几个测试会拿到同一个审计文件的多个句柄，互相覆盖记录——
    /// 表现是"单跑全过、一起跑偶发失败"，最难排查的那一种。
    fn temp_audit_with_path() -> (AuditSlot, std::path::PathBuf) {
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "aegis-guard-test-{}-{}-{n}",
            std::process::id(),
            now_ms()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("audit.binlog");
        let (log, _) = AuditLog::open_or_create(&p).unwrap();
        (Arc::new(Mutex::new(log)), p)
    }

    // ── 步 5：断言 A ──────────────────────────────────────────────────

    /// ⚠ 没配 `control_addr` 时必须是 `None`（判不了），不是 `Some(true)`。
    /// 早期版本一律按"可达"填，等于让"代理进程已经死了"这条永远通过。
    #[test]
    fn assertion_a_is_unknown_without_a_control_addr() {
        let cfg = aegis_config::load_str(EXAMPLE_CONFIG).unwrap();
        assert!(
            cfg.proxy.control_addr.is_none(),
            "样例配置不该自带 control_addr"
        );
        assert_eq!(assertion_a(&cfg), None);
    }

    /// 连一个几乎肯定没人监听的本机高端口 → 不可达（且要**快**，
    /// 不能挂住守卫线程）。
    #[test]
    fn assertion_a_reports_unreachable_for_a_dead_local_port() {
        let mut cfg = aegis_config::load_str(EXAMPLE_CONFIG).unwrap();
        cfg.proxy.control_addr = Some("127.0.0.1:1".parse().unwrap());
        let t0 = std::time::Instant::now();
        assert_eq!(assertion_a(&cfg), Some(false));
        assert!(
            t0.elapsed() < Duration::from_secs(2),
            "探测必须带超时，实测 {:?}",
            t0.elapsed()
        );
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

    /// 未 arm 的非 WFP 快照守卫（测试默认态：无基线、无待还原）。
    fn empty_netcfg() -> NetCfgSlot {
        Arc::new(Mutex::new(None))
    }

    /// 直接用仓库里的样例配置，免得在测试里维护第二份 schema
    /// （两份必然漂移，而漂移的表现是"测试过了、真机加载失败"）。
    const EXAMPLE_CONFIG: &str = include_str!("../../../config/config.example.toml");

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
        assert!(do_rollback(&empty_slot(), &empty_netcfg()).starts_with(DENY_PREFIX));
    }

    #[test]
    fn confirm_commits_a_pending_ticket() {
        let slot = empty_slot();
        *slot.lock().unwrap() = Some(ApplyTicket::pending(
            now_ms(),
            CONFIRM_WINDOW_MS,
            vec![1, 2],
            vec![1],
        ));
        let out = do_confirm(&slot);
        assert!(out.starts_with(OK_PREFIX), "{out}");
        assert_eq!(
            slot.lock().unwrap().as_ref().unwrap().phase,
            Phase::Committed
        );
    }

    /// 晚了就确认不了——否则"超时自动回滚 → 再确认一次 → 又装回去"，
    /// 而这第二次没人兜底。
    #[test]
    fn confirming_a_stale_ticket_is_denied() {
        let slot = empty_slot();
        let past = now_ms() - CONFIRM_WINDOW_MS - 1;
        *slot.lock().unwrap() = Some(ApplyTicket::pending(past, 0, vec![7], vec![7]));
        let out = do_confirm(&slot);
        assert!(out.starts_with(DENY_PREFIX), "{out}");
        assert_eq!(slot.lock().unwrap().as_ref().unwrap().phase, Phase::Pending);
    }

    #[test]
    fn rollback_of_a_pending_ticket_requests_an_abort() {
        let slot = empty_slot();
        *slot.lock().unwrap() = Some(ApplyTicket::pending(
            now_ms(),
            CONFIRM_WINDOW_MS,
            vec![3],
            vec![3],
        ));
        let out = do_rollback(&slot, &empty_netcfg());
        assert!(out.starts_with(OK_PREFIX), "{out}");
        assert!(slot
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .must_roll_back(now_ms()));
    }

    /// 已确认的规则也得能拆——这是兜底手册的命脉。
    #[test]
    fn rollback_of_a_committed_ticket_forces_a_teardown() {
        let slot = empty_slot();
        let mut t = ApplyTicket::pending(now_ms(), CONFIRM_WINDOW_MS, vec![4], vec![4]);
        t.confirm(now_ms()).unwrap();
        *slot.lock().unwrap() = Some(t);

        let out = do_rollback(&slot, &empty_netcfg());
        assert!(out.starts_with(OK_PREFIX), "{out}");
        assert!(
            slot.lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .must_roll_back(now_ms()),
            "已确认的也要能被强拆"
        );
    }

    /// 重复拆除必须是拒绝，不是"又删一遍"——第二次删可能删到别人的规则。
    #[test]
    fn rolling_back_twice_is_denied() {
        let slot = empty_slot();
        let mut t = ApplyTicket::pending(now_ms(), CONFIRM_WINDOW_MS, vec![5], vec![5]);
        t.mark_rolled_back("已拆");
        *slot.lock().unwrap() = Some(t);
        assert!(do_rollback(&slot, &empty_netcfg()).starts_with(DENY_PREFIX));
    }

    /// 未 arm 时，快照查询必须诚实说"未就绪"，不能假装有基线。
    #[test]
    fn snapshot_text_reports_unarmed_honestly() {
        let out = snapshot_text(&empty_netcfg());
        assert!(out.starts_with(DENY_PREFIX), "{out}");
        assert!(out.contains("未就绪"), "{out}");
    }

    /// 未 arm 时还原 = Idle（无事可做），且**不碰系统**。
    #[test]
    fn restore_netcfg_is_idle_when_unarmed() {
        let (msg, state) = restore_netcfg(&empty_netcfg());
        assert_eq!(state, NcRestore::Idle);
        assert!(msg.contains("未就绪"), "{msg}");
    }

    /// arm 成功且干净时：无待还原、快照展示 ok 且 dirty=false。
    ///
    /// ⚠ 只走**只读**路径（采集真实基线；未 dirty 所以绝不写系统）。
    /// 采集在本机应成功；即便失败也只是 protected=false，不断言它。
    #[test]
    fn armed_clean_guard_reports_no_pending_restore() {
        let dir = std::env::temp_dir().join(format!("aegisd-netcfg-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let slot: NetCfgSlot = Arc::new(Mutex::new(None));
        let protected = arm_netcfg_guard(&dir, &slot);
        if protected {
            let (msg, state) = restore_netcfg(&slot);
            assert_eq!(state, NcRestore::Idle, "干净守卫不该有待还原");
            assert!(msg.contains("无待还原"), "{msg}");
            let snap = snapshot_text(&slot);
            assert!(snap.starts_with(OK_PREFIX), "{snap}");
            assert!(snap.contains("待还原(dirty)     : false"), "{snap}");
        }
        let _ = std::fs::remove_dir_all(&dir);
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
        *slot.lock().unwrap() = Some(ApplyTicket::pending(
            now_ms(),
            CONFIRM_WINDOW_MS,
            vec![9],
            vec![9],
        ));
        let out = do_apply(&boot_plan(), &slot);
        assert!(out.starts_with(DENY_PREFIX), "{out}");
        assert!(out.contains("待确认"), "{out}");
    }
}
