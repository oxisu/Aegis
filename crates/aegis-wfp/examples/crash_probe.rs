//! **崩溃安全的真机自证**（需要提权，只拦一个目标，等外部来杀）。
//!
//! ```text
//! cargo run -p aegis-wfp --example crash_probe
//! ```
//!
//! # 它要回答的问题
//!
//! "主机在绝缘笼装着的时候**非正常终止**（断电 / 蓝屏 / 被强杀），
//!  重启之后会不会留下一个清不掉的笼子？"
//!
//! 正常退出不算数——正常退出有清理代码。真正要验的是**清理代码没机会跑**
//! 的那条路径。所以本探针装完规则之后就**一直挂着不动**，等外部用
//! `taskkill /F` 把它打死：
//!
//! ```text
//! 装之前：443 通
//! 装之后：443 断        ← 规则确实生效了（否则后面的"消失"毫无意义）
//! taskkill /F 之后：443 通  ← 进程没了，内核把规则清了
//! ```
//!
//! 全程**一行清理代码都不执行**。如果最后 443 恢复，说明兜底在内核侧，
//! 不在我们的代码里——这正是"崩溃路径上没有机会执行清理代码"要的保证。
//!
//! # 为什么只用一个 IP 而不是整副绝缘笼
//!
//! 整副笼子的 blast radius 是"整机断网"；一旦这次验证不成立，
//! 就要靠重启才能恢复。用一个 IP 的 443，最坏情况只是"百度暂时打不开"，
//! 而它验证的是**同一件事**：动态会话里的对象随进程消亡。
//!
//! # 使用方式
//!
//! 由 `tools/crash-drill.sh` 驱动：它负责起本进程、等 `BLOCKED` 标记、
//! 强杀、再测连通性。本进程自己**永不退出**（除非被杀）。

use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use aegis_wfp::{apply, Action, Condition, FilterSpec, Layer, Tier};

/// 被拦的目标：只拦它的 443。
const TARGET_HOST: &str = "www.baidu.com";
const BLOCKED_PORT: u16 = 443;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

fn main() {
    println!("Aegis · 崩溃安全自证（装一条规则，然后等被强杀）");
    println!("pid = {}", std::process::id());
    println!();

    let ip = match resolve_v4(TARGET_HOST) {
        Some(ip) => ip,
        None => {
            println!("[FATAL] 解析不出 {TARGET_HOST} 的 IPv4 地址。");
            return;
        },
    };
    println!("目标      ：{TARGET_HOST} → {ip}:{BLOCKED_PORT}");

    println!("装之前    ：{}", word(reachable(ip)));
    if !reachable(ip) {
        println!("[FATAL] 基线就不通，对照失去意义。");
        return;
    }

    let plan = vec![FilterSpec {
        name: "崩溃探针·目标443",
        layer: Layer::AleAuthConnectV4,
        action: Action::Block,
        weight: aegis_wfp::WEIGHT_MAX,
        conditions: vec![
            Condition::RemoteAddrV4(ip),
            Condition::RemotePort(BLOCKED_PORT),
        ],
        tier: Tier::Runtime,
    }];

    let (_session, receipt) = match apply(&plan, 0) {
        Ok(r) => r,
        Err(e) => {
            println!("[FATAL] 装不上：{e}");
            if let Some(h) = e.hint() {
                println!("   {h}");
            }
            return;
        },
    };
    println!(
        "已装      ：{} 条，filterId={:?}",
        receipt.len(),
        receipt.filter_ids
    );
    println!("装之后    ：{}", word(reachable(ip)));
    if reachable(ip) {
        println!("[FATAL] 装了却没拦住 —— 后面的崩溃测试没有意义。");
        return;
    }

    // ── 关键标记 ──────────────────────────────────────────────────────
    // 驱动脚本等这一行才去杀进程。必须 flush：stdout 走管道时是块缓冲，
    // 不 flush 的话脚本可能永远等不到这一行，然后去杀一个还没装好规则的进程。
    println!("BLOCKED pid={}", std::process::id());
    let _ = std::io::stdout().flush();

    // 从此刻起**什么都不做**。没有 rollback，没有 drop，没有 Drop impl。
    // 等外部强杀。
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

fn resolve_v4(host: &str) -> Option<Ipv4Addr> {
    (host, 443u16)
        .to_socket_addrs()
        .ok()?
        .find_map(|a| match a {
            SocketAddr::V4(v) => Some(*v.ip()),
            SocketAddr::V6(_) => None,
        })
}

fn reachable(ip: Ipv4Addr) -> bool {
    TcpStream::connect_timeout(&SocketAddr::new(ip.into(), BLOCKED_PORT), CONNECT_TIMEOUT).is_ok()
}

fn word(ok: bool) -> &'static str {
    if ok {
        "通"
    } else {
        "断"
    }
}
