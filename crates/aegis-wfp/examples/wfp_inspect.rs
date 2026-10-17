//! WFP 只读勘察（dry run）。
//!
//! 打开一个**动态**会话，枚举本机现有的过滤器与 Provider，
//! 找出"进程死了也不会消失"的那些，并给出持久背板风险评级。
//!
//! **全程只读**：不添加 / 不修改 / 不删除任何 WFP 对象，不改动系统状态。
//!
//! ```text
//! cargo run -p aegis-wfp --example wfp_inspect
//! ```

use aegis_wfp::{audit_backbone, layer_purpose, watched_layers, Risk, Session, SESSION_PREFIX};

fn main() {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  Aegis · aegis-wfp WFP 只读勘察                              ║");
    println!("║  只读：不添加 / 不修改 / 不删除任何 WFP 对象                 ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!("  {}", aegis_wfp::full_version());
    println!();

    let session = match Session::open(&format!("{SESSION_PREFIX}inspect")) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[FATAL] {e}");
            eprintln!();
            eprintln!("只读勘察无法继续。本次未对系统做任何修改。");
            std::process::exit(1);
        },
    };

    let snap = match session.snapshot() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[FATAL] {e}");
            std::process::exit(1);
        },
    };

    println!("── 1. 引擎现状 ───────────────────────────────────────────────");
    println!("  Provider 数量 : {}", snap.providers.len());
    println!("  过滤器数量   : {}", snap.filters.len());
    println!();

    println!("── 1b. Provider 清单 ─────────────────────────────────────────");
    for p in &snap.providers {
        println!(
            "  {:<40} 服务={:<20} 持久={}",
            truncate(&p.name, 40),
            if p.service.is_empty() {
                "（无）"
            } else {
                &p.service
            },
            if p.persistent() { "是" } else { "否" }
        );
    }
    println!();

    println!("── 2. Aegis 关注的层上已有多少过滤器 ─────────────────────────");
    for (guid, name) in watched_layers() {
        let n = snap.filters.iter().filter(|f| f.layer == name).count();
        if n > 0 {
            let blocking = snap
                .filters
                .iter()
                .filter(|f| f.layer == name && f.terminal)
                .count();
            println!("  {name:<28} {n:>5} 条（其中终止型 {blocking} 条）");
            if let Some(p) = layer_purpose(&guid) {
                println!("  {:<28}   └ {p}", "");
            }
        }
    }
    println!();

    println!("── 3. 持久背板审计（§28.2 变砖地雷）──────────────────────────");
    println!("  判定标准：persistent 或 boottime 标志 = 进程退出 / 重启后仍然存在；");
    println!("            若其动作还会终止数据包，则服务崩溃后网络将不可恢复。");
    println!();

    let surviving: Vec<_> = snap.surviving_filters().collect();
    let risk = audit_backbone(&snap);
    println!("  风险评级 : {}", risk.label());
    println!(
        "  持久/开机生效的过滤器 : {} 条（其中会阻断的 {} 条）",
        surviving.len(),
        snap.bricking_candidates()
    );
    println!(
        "    其中系统自带        : {} 条",
        snap.bricking_candidates() - snap.thirdparty_bricking_candidates()
    );
    println!(
        "    其中第三方/未知归属 : {} 条  ← 只有这些才是雷",
        snap.thirdparty_bricking_candidates()
    );
    println!(
        "  持久 Provider         : {} 个",
        snap.persistent_providers().count()
    );
    println!();

    if surviving.is_empty() {
        println!("  本机没有发现持久 / Boot-Time 过滤器。");
    } else {
        // 只列前若干条，避免几千行刷屏；排序优先级：
        // 第三方阻断 > 系统自带阻断 > 其余持久项
        let mut shown = surviving.clone();
        shown.sort_by_key(|f| {
            (
                std::cmp::Reverse(f.terminal && !f.is_system_owned()),
                std::cmp::Reverse(f.terminal),
                f.id,
            )
        });
        println!("  ── 明细（第三方阻断优先，最多显示 20 条）──");
        for f in shown.iter().take(20) {
            let mark = if f.flags.persistent() { "P" } else { "-" };
            let boot = if f.flags.boottime() { "B" } else { "-" };
            let owner = f
                .provider
                .clone()
                .unwrap_or_else(|| "（未知归属）".to_string());
            let origin = if f.is_system_owned() {
                "系统"
            } else {
                "第三方"
            };
            println!(
                "  [{mark}{boot}][{origin}] #{} {:<9} {:<26} {}",
                f.id,
                f.action,
                truncate(&owner, 26),
                if f.name.is_empty() {
                    "（未命名）".to_string()
                } else {
                    truncate(&f.name, 28)
                }
            );
            println!("        层: {}", f.layer);
        }
        if shown.len() > 20 {
            println!("  …… 另有 {} 条未列出", shown.len() - 20);
        }
        println!();
        println!("  图例：[P-]=持久  [-B]=Boot-Time  [PB]=两者兼有");
    }
    println!();

    match risk {
        Risk::Bricking => {
            println!("  ⚠ 存在第三方 / 未知归属的持久阻断过滤器。Aegis 在下发自己的规则前");
            println!("    必须先确认这些对象的用途——它们不随进程退出消失，误删或叠加上去");
            println!("    都可能让本机在重启后无法恢复联网。");
        },
        Risk::SystemBaseline => {
            println!("  ✓ 持久 / 引导时间过滤器全部由 Windows 自带组件安装（引导时间底板，");
            println!("    BFE 启动后自行撤销），属系统正常行为，不是雷。");
            println!("    Aegis 可以放心使用动态会话（崩溃自动清空）。");
        },
        Risk::PersistentOnly => {
            println!("  ✓ 有持久对象但没有一条会阻断，属于杀软 / 防火墙的正常驻留。");
        },
        Risk::Clean => {
            println!("  ✓ 无持久背板，Aegis 可以放心使用动态会话（崩溃自动清空）。");
        },
    }
    println!();

    println!("✅ 勘察完成。全程只读，本机 WFP 状态未被修改。");
}

/// 按字符数截断（中文按一个字符算，够用即可）。
fn truncate(s: &str, max: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= max {
        return s.to_string();
    }
    let mut out: String = chars[..max.saturating_sub(1)].iter().collect();
    out.push('…');
    out
}
