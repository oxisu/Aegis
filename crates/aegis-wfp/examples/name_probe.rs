//! **"按域名拦"到底能不能做到**（需要提权，只碰一个网站）。
//!
//! ```text
//! cargo run -p aegis-wfp --example name_probe
//! ```
//!
//! # 两幕
//!
//! ## 第一幕：把域名解析成一批 IP，逐个拦（这是真能用的做法）
//!
//! WFP 在 ALE 层的过滤条件**没有"域名"这一项**——它工作在 IP 层，
//! 域名早在应用发起连接之前就被 DNS 解析掉了。所以"按域名拦"在底座这一层
//! 只能翻译成"把这个域名当前解析到的每一个 IP 都拦掉"。
//!
//! 后果是三条，第一条最要命：
//!
//! 1. **解析结果会变**。CDN 与轮询 DNS 下一次可能给出完全不同的 IP，
//!    这批规则就 silently 失效了——不报错，只是不再拦住。
//!    这就是为什么"按域名拦"天然属于 **App Level**（那里能每次都走一遍
//!    域名判断），而不属于 OS Level 的底座。
//! 2. **共享 IP 会误伤**。同一个 IP 上往往挂着几十个名字。
//! 3. **IPv6 不覆盖**。V4 层的规则管不到 AAAA 记录。
//!
//! ## 第二幕：试 `FWPM_CONDITION_ALE_EFFECTIVE_NAME`
//!
//! 这个字段确实出现在 `ALE_AUTH_CONNECT_V4` 的字段表里（blob 类型），
//! 名字听起来像"远端主机名"。但**"内核接受了这条规则"不等于
//! "它按你想的那样匹配"**——所以装上之后照样做连通性实测。
//!
//! # 安全性
//!
//! 全程只碰一个网站的 443 端口，每条规则装上去几秒内就按 id 拆掉。

use std::net::{Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aegis_wfp::{apply, rollback, Action, Condition, FilterSpec, Layer, Tier};

const TARGET: &str = "www.baidu.com";
/// 对照组：另一个域名，**不该**被波及。
const CONTROL: &str = "www.qq.com";
const PORT: u16 = 443;
const TIMEOUT: Duration = Duration::from_secs(3);

fn main() {
    println!("Aegis · \"按域名拦\"可行性探针");
    println!("目标 {TARGET}（要被拦），对照 {CONTROL}（不该被波及）");
    println!();

    act_one();
    println!();
    println!("{}", "─".repeat(68));
    println!();
    act_two();
}

// ── 第一幕：解析成一批 IP 逐个拦 ─────────────────────────────────────

fn act_one() {
    println!("【第一幕】把域名解析成一批 IP，逐个拦（真能用的做法）");

    let targets = match resolve_all_v4(TARGET) {
        v if v.is_empty() => {
            println!("  解析不出 {TARGET} 的 A 记录，跳过。");
            return;
        },
        v => v,
    };
    let control = resolve_all_v4(CONTROL);
    println!("  {TARGET} → {} 个 IP：{:?}", targets.len(), targets);
    println!("  {CONTROL} → {} 个 IP：{:?}", control.len(), control);
    println!();

    println!(
        "  基线：{TARGET}:{PORT} {}",
        word(reachable_host(TARGET, PORT))
    );
    println!(
        "       {CONTROL}:{PORT} {}",
        word(reachable_host(CONTROL, PORT))
    );
    println!();

    let plan: Vec<FilterSpec> = targets
        .iter()
        .map(|&ip| FilterSpec {
            name: "按域名拦·某IP",
            layer: Layer::AleAuthConnectV4,
            action: Action::Block,
            weight: aegis_wfp::WEIGHT_MAX,
            conditions: vec![Condition::RemoteAddrV4(ip), Condition::RemotePort(PORT)],
            tier: Tier::Runtime,
        })
        .collect();

    let (session, receipt) = match apply(&plan, now_ms()) {
        Ok(r) => r,
        Err(e) => {
            println!("  ❌ 装不上：{e}");
            return;
        },
    };
    println!("  已装 {} 条（每个 IP 一条）", receipt.len());

    let t_after = reachable_host(TARGET, PORT);
    let c_after = control.first().is_some_and(|ip| reachable(*ip, PORT));
    println!();
    println!("  装之后：{TARGET}:{PORT} {}（应断）", word(t_after));
    println!("         {CONTROL}:{PORT} {}（应仍通）", word(c_after));
    println!();

    let removed = rollback(&session, &receipt.filter_ids).unwrap_or(0);
    println!("  拆除 {removed} 条");
    let t_final = reachable_host(TARGET, PORT);
    println!("  拆之后：{TARGET}:{PORT} {}（应恢复）", word(t_final));
    println!();

    let ok = !t_after && c_after && t_final && removed == receipt.len();
    println!(
        "  {} 第一幕：按 IP 集合拦{}",
        if ok { "✅" } else { "❌" },
        if ok {
            "可行"
        } else {
            "不对，看上面打叉的项"
        }
    );
    if ok {
        println!();
        println!("  ⚠ 但这是**代换**，不是真的按域名拦：");
        println!("    · CDN / 轮询 DNS 下次给出别的 IP 就 silently 失效（不报错）");
        println!("    · 这些 IP 上如果有别的名字，会一起被拦（误伤）");
        println!("    · V4 层的规则管不到 AAAA 记录");
        println!("  结论：按域名判归属 **App Level**（那儿每次都能走一遍域名判断），");
        println!("        底座只负责把「该拦哪些 IP」执行到底。");
    }
}

// ── 第二幕：试 ALE_EFFECTIVE_NAME ────────────────────────────────────

fn act_two() {
    println!("【第二幕】试 FWPM_CONDITION_ALE_EFFECTIVE_NAME（实验性）");
    println!("  它确实在这一层的字段表里，但**装得上 ≠ 按你想的那样匹配**。");
    println!();

    let ip = match resolve_all_v4(TARGET).into_iter().next() {
        Some(i) => i,
        None => {
            println!("  解析不出 IP，跳过。");
            return;
        },
    };
    println!(
        "  基线：{TARGET}({ip}):{PORT} {}",
        word(reachable(ip, PORT))
    );

    let spec = FilterSpec {
        name: "按名字拦·探针",
        layer: Layer::AleAuthConnectV4,
        action: Action::Block,
        weight: aegis_wfp::WEIGHT_MAX,
        conditions: vec![Condition::RemoteName(TARGET), Condition::RemotePort(PORT)],
        tier: Tier::Runtime,
    };

    // 必须**装住不拆**再测：probe_add_then_remove 是秒拆的，
    // 那样只能证明"内核接受"，证明不了"它按名字匹配"。
    let (session, receipt) = match apply(&[spec], now_ms()) {
        Ok(r) => r,
        Err(e) => {
            println!("  ❌ 内核不接受：{e}");
            println!();
            println!("     结论：这条路不通。按域名拦只能走第一幕的 IP 集合代换，");
            println!("     或者交给 App Level 的 DNS 层处理。");
            return;
        },
    };
    println!(
        "  ✅ 内核接受了（id={:?}）—— 但这只说明参数合法",
        receipt.filter_ids
    );

    let after_ip = reachable(ip, PORT);
    let after_name = reachable_host(TARGET, PORT);
    println!();
    println!("  装之后（**装住不拆**地测）：");
    println!("    直连 {ip}:{PORT}      {}", word(after_ip));
    println!("    按名字 {TARGET}:{PORT}  {}", word(after_name));
    println!();

    let removed = rollback(&session, &receipt.filter_ids).unwrap_or(0);
    println!("  拆除 {removed} 条");

    if after_ip || after_name {
        println!();
        println!("  ❌ **拦不住**：规则装上了，但目标仍然可达。");
        println!("     这就是「装得上 ≠ 拦得住」的又一个例子——内核接受了这条规则，");
        println!("     只说明参数合法，不说明它按你想的那样匹配。");
        println!();
        println!("     结论：ALE_EFFECTIVE_NAME **不是**可以用来按域名拦的字段");
        println!("     （至少不是把主机名塞进 blob 这么个用法）。");
        println!("     按域名拦只能：① 第一幕的 IP 集合代换；② 交给 App Level 的 DNS 层。");
    } else {
        println!();
        println!("  ✅ 拦住了 —— ALE_EFFECTIVE_NAME 可以按名字拦！");
        println!("     ⚠ 别急着高兴：还要验证它**不会**拦到别的名字（精确性），");
        println!("       以及 DNS 变了之后还灵不灵。这两条没验之前别进生产。");
    }
}

// ── 辅助 ─────────────────────────────────────────────────────────────

fn resolve_all_v4(host: &str) -> Vec<Ipv4Addr> {
    let mut out = Vec::new();
    if let Ok(addrs) = (host, PORT).to_socket_addrs() {
        for a in addrs {
            if let SocketAddr::V4(v) = a {
                let ip = *v.ip();
                if !out.contains(&ip) {
                    out.push(ip);
                }
            }
        }
    }
    out
}

fn reachable_host(host: &str, port: u16) -> bool {
    match resolve_all_v4(host).into_iter().next() {
        Some(ip) => reachable(ip, port),
        None => false,
    }
}

fn reachable(ip: Ipv4Addr, port: u16) -> bool {
    TcpStream::connect_timeout(&SocketAddr::new(ip.into(), port), TIMEOUT).is_ok()
}

fn word(ok: bool) -> &'static str {
    if ok {
        "通"
    } else {
        "断"
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
