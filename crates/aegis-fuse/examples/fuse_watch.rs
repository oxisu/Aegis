//! 网口变动熔断的**只读干跑**。
//!
//! 注册 `NotifyIpInterfaceChange`，把每一次变动喂给去抖状态机，
//! 打印"如果这是真实系统，此刻会发生什么"。
//!
//! **本示例不修改任何系统状态**，只观察；也不需要管理员权限。
//! 想看它动起来，就在这期间插拔一下网线 / 关开一下 Wi-Fi。
//!
//! ```text
//! cargo run -p aegis-fuse --example fuse_watch            # 默认监听 30 秒
//! cargo run -p aegis-fuse --example fuse_watch -- 60      # 监听 60 秒
//! cargo run -p aegis-fuse --example fuse_watch -- 30 --v4 # 只看 IPv4
//! ```

use std::thread::sleep;
use std::time::Duration;

use aegis_fuse::{
    full_version, now_ms, ChangeKind, InterfaceWatcher, Reaction, ShockDebouncer, WatchFamily,
};

/// 轮询间隔。去抖窗口是 50–100ms，取 10ms 能看清"第一个事件立刻熔断"
/// 与"后续被合并"这两件事分别发生在哪一刻。
const POLL_INTERVAL_MS: u64 = 10;

fn main() {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  Aegis · aegis-fuse 网口变动熔断干跑                        ║");
    println!("║  只观察不改系统状态 · 不需要管理员权限                      ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!("  {}", full_version());
    println!();

    let mut seconds: u64 = 30;
    let mut family = WatchFamily::Any;
    for a in std::env::args().skip(1) {
        match a.as_str() {
            "--v4" => family = WatchFamily::V4,
            "--v6" => family = WatchFamily::V6,
            other => match other.parse::<u64>() {
                Ok(n) => seconds = n,
                Err(_) => eprintln!("[WARN] 忽略未知参数：{other}（可用：<秒数> / --v4 / --v6）"),
            },
        }
    }

    println!("监听地址族：{}   时长：{seconds} 秒", family.label());
    println!(
        "去抖窗口：{} ms",
        ShockDebouncer::with_default_window().window_ms()
    );
    println!();

    let watcher = match InterfaceWatcher::register(family) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("[FATAL] 注册网口变动通知失败：{e}");
            std::process::exit(1);
        },
    };
    println!("已注册。现在插拔网线 / 关开 Wi-Fi 就能看到反应。");
    println!("──────────────────────────────────────────────────────────────");

    let mut fuse = ShockDebouncer::with_default_window();
    let start = now_ms();
    let deadline = start + seconds * 1000;

    while now_ms() < deadline {
        // 真实实现里这一步叫"先熔断"：立刻切绝缘标志，不等去抖。
        if let Some(reaction) = watcher.drain_into(&mut fuse) {
            let t = now_ms() - start;
            match reaction {
                Reaction::Trip => {
                    println!("[{t:>6} ms] ⚡ Trip    —— 立刻拉起绝缘（不等去抖）");
                    println!("                        真实实现：此刻切换 WFP 绝缘笼，");
                    println!("                        重活交给 Worker，不在回调里做");
                },
                Reaction::Coalesced => {
                    println!(
                        "[{t:>6} ms]   Coalesced —— 窗口内震荡，已合并（累计 {} 次）",
                        fuse.coalesced_count()
                    );
                },
            }
        }

        // 去抖窗口过去后，叫醒 Worker 做**一次**重活
        if fuse.ready_to_recompute(now_ms()) {
            fuse.mark_recompute_signaled();
            println!(
                "[{:>6} ms] → 窗口已过，叫醒 Worker 一次（重算指纹 / RST 存量连接 / 重灌角色）",
                now_ms() - start
            );
            // 干跑：这里直接放行。真实实现要等 Worker 重算完 + 用户确认
            fuse.release();
            println!("                        （干跑：自动放行，真实实现要等确认）");
        }

        sleep(Duration::from_millis(POLL_INTERVAL_MS));
    }

    println!("──────────────────────────────────────────────────────────────");
    println!("累计观测变动：{} 次", watcher.signal().total());
    println!(
        "末次绝缘状态：{}",
        if fuse.is_insulated() {
            "已绝缘"
        } else {
            "已放行"
        }
    );
    println!();
    println!("全程只读：没有下发任何 WFP 规则，没有修改任何系统状态。");
    println!();

    // 顺带把通知分类表打出来：真实排障时"这次变动是什么类型"是关键信息
    println!("通知分类（回调里只做这一步判断 + 一次计数）：");
    for k in [
        ChangeKind::Parameter,
        ChangeKind::Add,
        ChangeKind::Delete,
        ChangeKind::Initial,
    ] {
        println!(
            "  {:<20} 响应={}  结构变化={}",
            k.label(),
            if aegis_fuse::should_react(k) {
                "是"
            } else {
                "否"
            },
            if k.is_structural() { "是" } else { "否" }
        );
    }
}
