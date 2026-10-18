//! **"按出口网卡砍流量"能不能真的生效**（需要提权，含阴性对照）。
//!
//! ```text
//! cargo run -p aegis-wfp --example iface_probe
//! ```
//!
//! # 这是沙漏模型第二层漏斗的判决实验
//!
//! `examples/egress_probe` 已经问出 `ALE_AUTH_CONNECT_V4` **有**
//! `IP_LOCAL_INTERFACE`（UINT64 = `NET_LUID`）这个字段。但：
//!
//! > **字段在 ≠ 分类时它带着正确的值。**
//!
//! ALE 是"连接授权"层，发生在路由选择**之前还是之后**决定了这个值有没有意义。
//! 如果它在分类时是 0 / 未设置，那么"按网卡砍"这条规则就是一条**永不匹配的
//! 死规则**——装上不报错，看起来在防，其实什么都没防。那比不装更危险，
//! 因为人会以为自己已经防住了。
//!
//! # 三组实验，缺一不可
//!
//! | 组 | 层 | 出口网卡条件值 | 期望 | 它在证明什么 |
//! |---|---|---|---|---|
//! | A | ALE_AUTH_CONNECT_V4 | **真实默认出口 LUID** | 断 | 值是对的，规则真的匹配 |
//! | B | ALE_AUTH_CONNECT_V4 | **假的 LUID** | **通** | 阴性对照：证明 A 不是"匹配了一切" |
//! | C | OUTBOUND_TRANSPORT_V4 | 真实默认出口 LUID | 断 | 兜底层：ALE 拿不到值时还有没有退路 |
//!
//! ⚠ B 是整套实验的命门。没有它，A 的"断"可能只是"这条规则拦了一切"
//! ——而"拦了一切"恰恰是我们要避免的假象（它看起来通过了，其实是拦错了范围）。
//!
//! # 安全性
//!
//! 全程只拦 `www.baidu.com` 的 443，每组装了立刻拆。最坏情况只是百度暂时打不开。

use std::net::{Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use aegis_wfp::{apply, rollback, Action, Condition, FilterSpec, Layer, Tier};

const TARGET_HOST: &str = "www.baidu.com";
const BLOCKED_PORT: u16 = 443;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

fn main() {
    println!("Aegis · 出口网卡过滤判决实验（含阴性对照）");
    println!();

    let ip = match resolve_v4(TARGET_HOST) {
        Some(ip) => ip,
        None => {
            println!("[FATAL] 解析不出 {TARGET_HOST} 的 IPv4 地址。");
            return;
        },
    };

    // 默认出口网卡的 LUID —— 沙漏第二层要钉的就是它
    let luid = match aegis_sense::default_egress() {
        Ok(Some(r)) => r.interface_luid,
        Ok(None) => {
            println!("[FATAL] 本机没有默认路由，做不了这个实验。");
            return;
        },
        Err(e) => {
            println!("[FATAL] 读不到默认出口：{e}");
            return;
        },
    };
    println!("目标        : {TARGET_HOST} → {ip}:{BLOCKED_PORT}");
    println!("默认出口 LUID: {luid:#x}");
    println!();

    if !reachable(ip) {
        println!("[FATAL] 基线就不通，对照失去意义。");
        return;
    }
    println!("基线        : 通");
    println!();

    // ── A：真实 LUID，ALE 层 ───────────────────────────────────────────
    let a = run(
        "A  ALE 层 + 真实默认出口 LUID",
        Layer::AleAuthConnectV4,
        luid,
        ip,
        "断 —— 值是对的，规则真的匹配了这一跳",
    );
    println!();

    // ── B：假 LUID，ALE 层（**阴性对照**）──────────────────────────────
    let bogus = luid ^ 0x0000_0000_DEAD_0000;
    let b = run(
        "B  ALE 层 + 假 LUID（阴性对照）",
        Layer::AleAuthConnectV4,
        bogus,
        ip,
        "通 —— 否则 A 的'断'只是'匹配了一切'",
    );
    println!();

    // ── C：真实 LUID，传输层（ALE 拿不到值时的退路）─────────────────────
    let c = run(
        "C  OUTBOUND_TRANSPORT 层 + 真实 LUID（退路）",
        Layer::OutboundTransportV4,
        luid,
        ip,
        "断 —— 说明传输层也能钉住出口网卡",
    );
    println!();

    // ── 收尾复核 ───────────────────────────────────────────────────────
    let restored = reachable(ip);
    println!("收尾后      : {}   （期望：通 —— 规则都拆干净了）", w(restored));
    println!();

    println!("─── 结论 ───");
    if a.blocked && !b.blocked {
        println!("✅ **沙漏第二层成立**：ALE 层能拿到出口网卡 LUID，且规则只匹配这一张卡。");
        println!("   A 断（真 LUID 匹配）+ B 通（假 LUID 不匹配）= 不是\"拦了一切\"。");
    } else if a.blocked && b.blocked {
        println!("❌ A、B 都断 —— 这条规则**匹配了一切**，不是按网卡过滤。");
        println!("   不能用于沙漏第二层：它会把走对网卡的流量一起砍掉。");
    } else if !a.blocked {
        println!("❌ A 没断 —— ALE 分类时 `IP_LOCAL_INTERFACE` **带着空值**，");
        println!("   按网卡过滤在 ALE 层不成立。看 C 组：");
        if c.blocked {
            println!("   → C 成立，退路有效：沙漏第二层要挂在 **OUTBOUND_TRANSPORT** 层。");
        } else {
            println!("   → C 也不成立。单靠 WFP 做不到\"按出口网卡砍\"，");
            println!("     第二层必须换成按**进程**放行（那只在系统代理模式下成立，");
            println!("     TUN 模式要另想办法）。");
        }
    }
    if !restored {
        println!();
        println!("⚠ 收尾后仍不通：有规则没拆干净。结束本进程即可（动态会话会清空）。");
    }
}

/// 装一条"出口网卡 = luid 且 目的 = ip:443 → 阻断"，测一次，立刻拆。
struct OneRun {
    blocked: bool,
}

fn run(title: &str, layer: Layer, luid: u64, ip: Ipv4Addr, expect: &str) -> OneRun {
    println!("── {title} ──");
    let spec = FilterSpec {
        name: "出口网卡探针",
        layer,
        action: Action::Block,
        weight: aegis_wfp::WEIGHT_MAX,
        conditions: vec![
            Condition::EgressInterfaceLuid(luid),
            Condition::RemoteAddrV4(ip),
            Condition::RemotePort(BLOCKED_PORT),
        ],
        tier: Tier::Runtime,
    };

    let (session, receipt) = match apply(&[spec], 0) {
        Ok(r) => r,
        Err(e) => {
            println!("  ❌ 装不上：{e}");
            if let Some(h) = e.hint() {
                println!("     {h}");
            }
            return OneRun { blocked: false };
        },
    };
    println!("  已装 {} 条（filterId={:?}）", receipt.len(), receipt.filter_ids);

    // ⚠ `w()` 收的是"能不能通"，不是"有没有被拦"。传错一个布尔量，
    // 整张表就是反的——而反过来的表会让人得出完全相反的结论。
    let ok = reachable(ip);
    let blocked = !ok;
    println!("  实测      : {}   （期望：{expect}）", w(ok));

    let removed = rollback(&session, &receipt.filter_ids).unwrap_or(0);
    if removed != receipt.len() {
        println!("  ⚠ 拆了 {removed} / {} 条", receipt.len());
    }
    drop(session);
    std::thread::sleep(Duration::from_millis(300));

    OneRun { blocked }
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

fn w(ok: bool) -> &'static str {
    if ok { "通" } else { "断" }
}
