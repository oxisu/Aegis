//! **阻断规则的真机自证**（需要提权，只拦一个具体目标）。
//!
//! ```text
//! cargo run -p aegis-wfp --example block_probe
//! ```
//!
//! # 为什么是"拦百度"而不是"拦一切"
//!
//! 要验证阻断规则真的生效，必须有一个**可观测**的目标。
//! 拦一个编出来的 IP（比如 `203.0.113.5`）毫无意义——它本来就不通，
//! 拦不拦都一样，测不出任何东西。
//!
//! 而整副绝缘笼一装上去就是"整机断网"，那是用**事故**在做验证。
//!
//! 于是取中间：解析 `www.baidu.com` 拿到它的真实 IP，装一条
//! **只拦"这个 IP 的 443 端口"**的规则，然后自己做前后对照：
//!
//! ```text
//! 装之前：443 通、80 通
//! 装之后：443 断、80 通   ← 断得精确（说明条件翻译对了，不是"拦了一切"）
//! 拆之后：443 通、80 通   ← 拆得干净（说明回滚认得回自己装的规则）
//! ```
//!
//! ⚠ **80 必须仍然通**。如果 80 也断了，说明这条规则拦的范围比声明的大——
//! 那就是"装成另一个意思"，比装不上更危险。
//!
//! # 为什么"通不通"用 TCP 握手判定
//!
//! 不用 ping：WFP 的 ALE 层**不管 ICMP**，ping 在装了阻断规则之后照样通，
//! 会给出一个假的"没生效"结论。判 TCP 握手才是 ALE 层真正的作用点。
//!
//! # 安全性
//!
//! 全程只拦一个网站的 443 端口，持续几秒，结束前一定按 id 拆除。
//! 进程退出时动态会话也会兜底清空。

use std::net::{Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aegis_wfp::{apply, rollback, Action, Condition, FilterSpec, Layer, Tier};

/// 用来做对照的目标。443 被拦、80 不拦。
const TARGET_HOST: &str = "www.baidu.com";
const BLOCKED_PORT: u16 = 443;
const CONTROL_PORT: u16 = 80;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

fn main() {
    println!("Aegis · 阻断规则真机自证（只拦 {TARGET_HOST} 的 {BLOCKED_PORT} 端口）");
    println!("⚠ 用 TCP 握手判通断，不用 ping —— WFP 的 ALE 层不管 ICMP，");
    println!("  用 ping 会得到假的\"没生效\"结论。");
    println!();

    // ── 1. 解析目标 ──────────────────────────────────────────────────
    let ip = match resolve_v4(TARGET_HOST) {
        Some(ip) => ip,
        None => {
            println!("[FATAL] 解析不出 {TARGET_HOST} 的 IPv4 地址。");
            println!("  本探针需要一个真实可达的目标来做对照；本机当前可能就没有网。");
            return;
        },
    };
    println!("目标      ：{TARGET_HOST} → {ip}");
    println!();

    // ── 2. 装之前的基线 ──────────────────────────────────────────────
    println!("[1/4] 装之前的基线");
    let before_blocked = reachable(ip, BLOCKED_PORT);
    let before_control = reachable(ip, CONTROL_PORT);
    println!("  {BLOCKED_PORT:<5}（将被拦）：{}", word(before_blocked));
    println!("  {CONTROL_PORT:<5}（对照组）：{}", word(before_control));
    if !before_blocked || !before_control {
        println!();
        println!("  ⚠ 基线就不通，对照失去意义。先确认这台机器能访问 {TARGET_HOST}。");
        return;
    }
    println!();

    // ── 3. 装一条阻断规则 ────────────────────────────────────────────
    println!("[2/4] 装一条阻断规则");
    let plan = vec![FilterSpec {
        name: "测试阻断·目标443",
        layer: Layer::AleAuthConnectV4,
        action: Action::Block,
        // 用最高权重：确保压过同层里其它过滤器的放行
        weight: aegis_wfp::WEIGHT_MAX,
        conditions: vec![
            Condition::RemoteAddrV4(ip),
            Condition::RemotePort(BLOCKED_PORT),
        ],
        tier: Tier::Runtime,
    }];

    let now = now_ms();
    let (session, receipt) = match apply(&plan, now) {
        Ok(r) => r,
        Err(e) => {
            println!("  ❌ 装不上：{e}");
            if let Some(h) = e.hint() {
                println!("     {h}");
            }
            println!();
            // 装不上时自动定位是哪条条件不被这层接受。
            // 一条条试，而不是让人去猜——`FWP_E_CONDITION_NOT_FOUND`
            // 只会说"有条件不被支持"，不说哪一条。
            bisect(ip);
            return;
        },
    };
    println!(
        "  已装 {} 条，filterId={:?}",
        receipt.len(),
        receipt.filter_ids
    );
    println!();

    // ⚠ 装得上 ≠ 拦得住。`FWPM_CONDITION_IP_REMOTE_ADDRESS` 的值是 UINT32，
    // 字节序写反的话内核照样接受（它只看到一个数字），但规则永远不匹配——
    // 表现就是"装了，也没报错，就是没生效"。所以必须实测。
    println!("[2.5/4] 装得上不等于拦得住：实测字节序");
    if reachable(ip, BLOCKED_PORT) {
        println!("  ⚠ 规则已装但 443 仍通 —— 地址大概率字节序反了。");
        drop(session); // 先撤掉错的（动态会话随之清空）
        let swapped = Ipv4Addr::from(u32::from(ip).swap_bytes());
        println!("  换用另一种字节序重试：{ip} → {swapped}");
        let plan2 = vec![FilterSpec {
            name: "测试阻断·目标443",
            layer: Layer::AleAuthConnectV4,
            action: Action::Block,
            weight: aegis_wfp::WEIGHT_MAX,
            conditions: vec![
                Condition::RemoteAddrV4(swapped),
                Condition::RemotePort(BLOCKED_PORT),
            ],
            tier: Tier::Runtime,
        }];
        match apply(&plan2, now_ms()) {
            Ok((s2, _r2)) => {
                if reachable(ip, BLOCKED_PORT) {
                    println!("  ❌ 两种字节序都拦不住 —— 条件翻译还有别的问题。");
                    drop(s2);
                    return;
                }
                println!("  ✅ 拦住了。映射里应该用 **swap_bytes** 后的值。");
                println!("  ⚠ 请把 apply.rs 里的 RemoteAddrV4 改成用 swap_bytes。");
                drop(s2);
                return;
            },
            Err(e) => {
                println!("  ❌ 重试也装不上：{e}");
                return;
            },
        }
    }
    println!("  ✅ 443 已断 —— 当前字节序是对的。");
    println!();

    // ⚠ session 必须一直活着：动态会话一关，内核就把这条规则清掉，
    //    后面的"装之后"测量就测了个寂寞。
    println!("[3/4] 装之后的对照");
    let after_blocked = reachable(ip, BLOCKED_PORT);
    let after_control = reachable(ip, CONTROL_PORT);
    println!("  {BLOCKED_PORT:<5}（应被拦）：{}", word(after_blocked));
    println!("  {CONTROL_PORT:<5}（应仍通）：{}", word(after_control));
    println!();

    // ── 4. 拆掉并复核 ────────────────────────────────────────────────
    println!("[4/4] 按 id 拆除并复核");
    let removed = rollback(&session, &receipt.filter_ids).unwrap_or(0);
    println!("  已删除 {removed} 条（应为 {}）", receipt.len());
    let final_blocked = reachable(ip, BLOCKED_PORT);
    let final_control = reachable(ip, CONTROL_PORT);
    println!("  {BLOCKED_PORT:<5}：{}", word(final_blocked));
    println!("  {CONTROL_PORT:<5}：{}", word(final_control));
    println!();

    // ── 判定 ─────────────────────────────────────────────────────────
    let checks: &[(&str, bool)] = &[
        ("装之前 443 通（基线）", before_blocked),
        ("装之后 443 断（规则生效）", !after_blocked),
        ("装之后 80 仍通（拦得精确，不是拦了一切）", after_control),
        ("拆除条数正确", removed == receipt.len()),
        ("拆之后 443 恢复（回滚干净）", final_blocked),
        ("拆之后 80 仍通", final_control),
    ];
    let mut all_ok = true;
    for (name, ok) in checks {
        println!("  {} {}", if *ok { "✅" } else { "❌" }, name);
        all_ok &= *ok;
    }
    println!();
    if all_ok {
        println!("✅ 阻断规则生效、拦得精确、拆得干净 —— 下发通路可以信任。");
    } else {
        println!("❌ 有一项没过。别下发整副绝缘笼，先查上面打叉的那一项。");
        println!("  尤其是\"装之后 80 仍通\"：它不过意味着拦的范围比声明的大，");
        println!("  那比装不上更危险。");
    }
}

/// 逐条试，定位哪条条件不被这一层接受。
///
/// 内核只回 `FWP_E_CONDITION_NOT_FOUND`（有条件不被支持），不说哪一条；
/// 而"猜"的代价是往生产计划里塞一个自以为对的字段。
fn bisect(ip: Ipv4Addr) {
    println!("逐条定位（装一条立刻拆掉，各持续几毫秒）：");
    let cases: &[(&str, Vec<Condition>)] = &[
        ("只有远端端口", vec![Condition::RemotePort(BLOCKED_PORT)]),
        ("只有远端地址", vec![Condition::RemoteAddrV4(ip)]),
        (
            "地址 + 端口",
            vec![
                Condition::RemoteAddrV4(ip),
                Condition::RemotePort(BLOCKED_PORT),
            ],
        ),
        ("只有本地端口", vec![Condition::LocalPort(BLOCKED_PORT)]),
    ];
    for (name, conds) in cases {
        let spec = FilterSpec {
            name: "定位探针",
            layer: Layer::AleAuthConnectV4,
            action: Action::Block,
            weight: aegis_wfp::WEIGHT_MAX,
            conditions: conds.clone(),
            tier: Tier::Runtime,
        };
        match aegis_wfp::probe_add_then_remove(&spec) {
            Ok(r) => println!("  ✅ {name:<14} 可装（id={}）", r.filter_id),
            Err(e) => println!("  ❌ {name:<14} {e}"),
        }
    }
    println!();
    dump_layer_fields();
}

/// 直接问引擎：这一层到底支持哪些条件字段。
///
/// 不看文档、不猜——"层支持什么字段"会随版本/SKU/已装驱动变化，
/// 而装不上时内核只说"有条件不支持"，不说哪一条。
fn dump_layer_fields() {
    let session = match aegis_wfp::Session::open("aegis-layer-fields") {
        Ok(s) => s,
        Err(e) => {
            println!("  （打不开会话，无法枚举层字段：{e}）");
            return;
        },
    };
    let key = Layer::AleAuthConnectV4.guid();
    let fields = match session.fields(key) {
        Ok(f) => f,
        Err(e) => {
            println!("  （枚举层字段失败：{e}）");
            return;
        },
    };
    println!("ALE_AUTH_CONNECT_V4 支持的字段共 {} 个：", fields.len());

    // 我们用到的几个字段，逐个点名说在不在
    let want: &[(&str, windows::core::GUID)] = &[
        (
            "IP_REMOTE_ADDRESS_V4",
            windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_CONDITION_IP_REMOTE_ADDRESS_V4,
        ),
        (
            "IP_REMOTE_PORT",
            windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_CONDITION_IP_REMOTE_PORT,
        ),
        (
            "IP_LOCAL_PORT",
            windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_CONDITION_IP_LOCAL_PORT,
        ),
        (
            "ALE_APP_ID",
            windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_CONDITION_ALE_APP_ID,
        ),
        (
            "FLAGS",
            windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_CONDITION_FLAGS,
        ),
    ];
    for (name, k) in want {
        let hit = fields.iter().find(|f| f.is(k));
        match hit {
            Some(f) => println!("  ✅ {name:<22} 在（要求类型 {:?}）", f.data_type),
            None => println!("  ❌ {name:<22} **不在这一层的字段表里**"),
        }
    }
    println!();
    println!("  这一层全部字段的 GUID：");
    for f in &fields {
        println!("    {:?}  {:?}", f.key, f.data_type);
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

/// 这个 IP 的端口能不能完成 TCP 握手。
fn reachable(ip: Ipv4Addr, port: u16) -> bool {
    TcpStream::connect_timeout(&SocketAddr::new(ip.into(), port), CONNECT_TIMEOUT).is_ok()
}

fn word(reachable_: bool) -> &'static str {
    if reachable_ {
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
