//! **"屏蔽整个主域名"到底做不做得到** —— 真机实证（需要提权）。
//!
//! ```text
//! cargo run -p aegis-wfp --example domain_probe -- arm
//! cargo run -p aegis-wfp --example domain_probe -- check   ← **另一个进程**
//! cargo run -p aegis-wfp --example domain_probe -- purge   ← 测完必须跑
//! ```
//!
//! # 结论先行：WFP 里**没有**"域名"这个字段
//!
//! 把 `windows` crate 里 **全部** `FWPM_CONDITION_*` 常量列出来（约 130 个），
//! 跟域名沾边的只有这四个：
//!
//! ```text
//! ALE_EFFECTIVE_NAME   ← 名字最像，但实测装得上拦不住（见 examples/name_probe）
//! PEER_NAME            ← IPsec 对端名，不是网站域名
//! IMAGE_NAME           ← 本地进程映像路径
//! RPC_SERVER_NAME      ← RPC 用的，不是网站域名
//! ```
//!
//! 也就是说：**"按域名拦"在 WFP 这个层里根本不存在这个原语**。
//! 上一个实验拦住的 `www.baidu.com:443`，实质是"拦住它此刻解析出来的那个 IP"。
//!
//! # 那"整个主域名"还能怎么拦
//!
//! 只剩一条路：**把主域 + 子域此刻解析出来的全部 IP 都拦掉**（IP 快照）。
//! 本探针就是这么做的。它的局限必须写清楚：
//!
//! - `*.baidu.com` 是**无限集**，这里只能枚举常见的几个子域；
//! - 同一个子域有多条 A 记录，且会**随解析轮换**（TTL 一过就变）；
//! - 于是这是一张**快照**：装的时候准，之后可能漏。
//!
//! 真正能覆盖"整个主域名"的层是 **DNS**（在解析环节按后缀判），
//! 那属于沙漏的上层漏斗，见 `docs/HOURGLASS.md`。
//!
//! # ⚠ 装上去就不归本进程管
//!
//! 用的是持久化过滤器（`FWPM_FILTER_FLAG_PERSISTENT`）：进程退出、重启都在。
//! **测完必须跑 `purge`**，否则要手动清。

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use aegis_wfp::{rollback, Action, Condition, FilterSpec, Layer, Session, Tier};
use windows::core::GUID;

/// 要封的"整个主域名"：主域 + 常见子域。
///
/// ⚠ 这是**枚举**，不是规则。`*.baidu.com` 在数学上是无限集，
/// 这里只能挑几个常见的——这本身就是"WFP 做不了域名"的证据之一。
const HOSTS: &[&str] = &[
    "baidu.com",
    "www.baidu.com",
    "pan.baidu.com",
    "tieba.baidu.com",
    "map.baidu.com",
    "image.baidu.com",
];

/// 只用来**测连通性**，不作为过滤条件——IP 快照一律整 IP 全断。
const TEST_PORT: u16 = 443;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

const FILTER_NAME: &str = "域名集探针";
const PROVIDER_NAME: &str = "Aegis 域名集探针";
/// 与 `persist_probe` 不同的 key：两个实验互不干扰，各自 purge 自己的。
const PROVIDER_KEY: GUID =
    GUID::from_u128(0x0a15_6754_0c0f_4a1e_9d3b_0002_ae15_0002);

fn main() {
    let mut args = std::env::args().skip(1);
    let cmd = args.next().unwrap_or_default();
    match cmd.as_str() {
        "arm" => arm(),
        "check" => check(),
        "purge" => purge(),
        _ => {
            println!("用法：domain_probe <arm|check|purge>");
            println!();
            println!("  目的：验证「屏蔽整个主域名」在 WFP 层能做到哪一步");
            println!("  结论：做**不到**按域名拦，只能拦住域名此刻解析出的 IP 集合（快照）");
            println!();
            println!("  arm    解析 {} 个域名 → 逐个 IP 装持久化阻断", HOSTS.len());
            println!("  check  **另起一个进程**逐域名测连通性");
            println!("  purge  全部删掉并复核为 0 —— 测完必须跑");
        },
    }
}

fn arm() {
    println!("[arm] 把「整个主域名」翻译成 IP 集合，然后整 IP 全断");

    // ── 第一幕：把域名翻译成 IP ──────────────────────────────────────
    // 这一步本身就是"WFP 不懂域名"的证明：真正干活的其实是 DNS。
    let mut ips: BTreeSet<Ipv4Addr> = BTreeSet::new();
    println!();
    println!("  第一幕：域名 → IP（这一步是 DNS 干的，不是 WFP）");
    for h in HOSTS {
        let got = resolve_all_v4(h);
        if got.is_empty() {
            println!("    {h:<18} 解析失败（跳过）");
            continue;
        }
        println!("    {h:<18} → {:?}", got);
        ips.extend(got);
    }
    println!();
    println!("  去重后共 {} 个 IP 要拦", ips.len());
    if ips.is_empty() {
        println!("  [FATAL] 一个 IP 都没解析出来，不装");
        return;
    }

    // ── 第二幕：装 ───────────────────────────────────────────────────
    let session = match Session::open_persistent("aegis-domain-arm") {
        Ok(s) => s,
        Err(e) => {
            println!("  ❌ 打不开非动态会话：{e}");
            return;
        },
    };
    println!("  ✅ 非动态会话已开（flags=0）");

    match session.add_provider(PROVIDER_KEY, PROVIDER_NAME, None, true) {
        Ok(()) => println!("  ✅ 已注册持久化 Provider"),
        Err(e) => println!("  ⚠ Provider 注册失败：{e}"),
    }

    // 幂等：先把上一次同名的清掉，否则重复 arm 会越堆越多
    if let Ok(old) = session.filters_named(FILTER_NAME) {
        if !old.is_empty() {
            let ids: Vec<u64> = old.iter().map(|f| f.id).collect();
            let n = rollback(&session, &ids).unwrap_or(0);
            println!("  已清掉上一次的 {n} 条（arm 幂等）");
        }
    }

    let mut installed = 0usize;
    for ip in &ips {
        let spec = FilterSpec {
            name: FILTER_NAME,
            layer: Layer::AleAuthConnectV4,
            action: Action::Block,
            weight: aegis_wfp::WEIGHT_MAX,
            // ⚠ 刻意**不**加端口条件：这是"整个域名访问不了"，不是"只封 443"。
            // 代价是这个 IP 上的**所有**流量都断（见模块头的局限说明）。
            conditions: vec![Condition::RemoteAddrV4(*ip)],
            tier: Tier::Runtime,
        };
        match aegis_wfp::add_persistent(&session, &spec, Some(PROVIDER_KEY)) {
            Ok(_) => installed += 1,
            Err(e) => println!("    ❌ {ip} 装不上：{e}"),
        }
    }
    println!("  ✅ 已装 {installed} / {} 条持久化阻断", ips.len());
    println!();
    println!("  ⚠ 从现在起它们**不归本进程管**：本进程退出它们还在。");
    println!("     下一步请在**另一个进程**里跑 `check`，测完一定跑 `purge`。");
}

fn check() {
    println!("[check] 另一个进程里逐域名测连通性");
    let session = match Session::open("aegis-domain-check") {
        Ok(s) => s,
        Err(e) => {
            println!("  ❌ 打不开会话：{e}");
            return;
        },
    };
    let installed: BTreeSet<u64> = match session.filters_named(FILTER_NAME) {
        Ok(f) => {
            println!(
                "  名字含「{FILTER_NAME}」的过滤器 = {} 条（跨重启={}）",
                f.len(),
                if f.iter().all(|x| x.flags.survives_reboot()) {
                    "是"
                } else {
                    "否"
                }
            );
            f.iter().map(|x| x.id).collect()
        },
        Err(e) => {
            println!("  ❌ 枚举失败：{e}");
            return;
        },
    };
    println!();

    println!("  逐域名实测（连 {TEST_PORT} 端口）：");
    for h in HOSTS {
        let got = resolve_all_v4(h);
        if got.is_empty() {
            println!("    {h:<18} 解析失败");
            continue;
        }
        let up: usize = got.iter().filter(|ip| reachable(**ip)).count();
        let verdict = if up == 0 {
            "断"
        } else if up == got.len() {
            "通"
        } else {
            "部分通"
        };
        println!("    {h:<18} {} 个 IP，能连上 {} 个 → {}", got.len(), up, verdict);
    }

    println!();
    println!("  ⚠ 怎么读这张表");
    println!("  · 「断」= 该域名此刻解析出的 IP 全部在被拦集合里；");
    println!("  · 「通」= 它换了一批 IP，而装规则时没有那批 —— **这就是快照的漏点**；");
    println!("  · 「部分通」= 一半命中一半没命中，最典型的快照漂移。");
    println!();
    println!("  另一个进程里能看到这 {0} 条规则，且它们不是这个进程装的",
             installed.len());
    println!("  → 这证明的是「跨进程存活」，不是「按域名匹配」。");
}

fn purge() {
    println!("[purge] 删掉全部「{FILTER_NAME}」并复核");
    let session = match Session::open_persistent("aegis-domain-purge") {
        Ok(s) => s,
        Err(e) => {
            println!("  ❌ 打不开非动态会话：{e}");
            return;
        },
    };
    let ids: Vec<u64> = match session.filters_named(FILTER_NAME) {
        Ok(f) => f.iter().map(|x| x.id).collect(),
        Err(e) => {
            println!("  ❌ 枚举失败：{e}");
            return;
        },
    };
    println!("  找到 {} 条", ids.len());
    let removed = rollback(&session, &ids).unwrap_or(0);
    println!("  已删 {removed} / {} 条", ids.len());
    match session.delete_provider(PROVIDER_KEY) {
        Ok(()) => println!("  ✅ Provider 已删"),
        Err(e) => println!("  ⚠ Provider 删除失败：{e}"),
    }

    // 删完必须复核：崩溃时"找到 0 条"是假象（进程挂了 grep 不到）
    match session.filters_named(FILTER_NAME) {
        Ok(left) => {
            println!("  复核：还剩 {} 条（期望：0）", left.len());
            if left.is_empty() {
                println!("  ✅ 清干净了。");
            } else {
                println!("  ❌ 没清干净，剩下 id={:?}", left.iter().map(|f| f.id).collect::<Vec<_>>());
            }
        },
        Err(e) => println!("  ❌ 复核枚举失败：{e}"),
    }
}

/// 解析出**全部** A 记录。只取一条的话，"部分通"会被误判成"断"。
fn resolve_all_v4(host: &str) -> Vec<Ipv4Addr> {
    let mut out: Vec<Ipv4Addr> = (host, TEST_PORT)
        .to_socket_addrs()
        .ok()
        .map(|it| {
            it.filter_map(|a| match a {
                SocketAddr::V4(v) => Some(*v.ip()),
                SocketAddr::V6(_) => None,
            })
            .collect()
        })
        .unwrap_or_default();
    out.sort_unstable();
    out.dedup();
    out
}

fn reachable(ip: Ipv4Addr) -> bool {
    TcpStream::connect_timeout(&SocketAddr::new(ip.into(), TEST_PORT), CONNECT_TIMEOUT).is_ok()
}
