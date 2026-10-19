//! **持久化规则验证实验**（需要提权）。
//!
//! ```text
//! cargo run -p aegis-wfp --example persist_probe -- arm
//! cargo run -p aegis-wfp --example persist_probe -- check   ← **另一个进程**
//! cargo run -p aegis-wfp --example persist_probe -- purge
//! ```
//!
//! # 它要回答的三件事（`docs/PERSISTENT-CAGE.md` §8 第 1/3/7 项）
//!
//! 1. 本机到底让不让装持久化规则？
//! 2. **进程退出之后它是不是真的还在？**（这是"死了也不放开"的全部意义）
//! 3. 能不能可靠地**再删掉**？（删不掉 = 变砖）
//!
//! # 安全性（每一条都是刻意的）
//!
//! - 只拦 `www.baidu.com:443`，最坏情况只是百度暂时打不开；
//! - `arm` 和 `check` 必须是**两个进程**——"跨进程存活"只能用两个进程证明，
//!   同一个进程里装完再看，什么都证明不了；
//! - `purge` 的实现顺序是**先删 filter 再删 Provider**，绝不依赖级联删除
//!   （微软文档说"必须先删引用者才能删被引用者"，与第三方注释矛盾，
//!   这条实验正好也实测了这件事）。
//!
//! ⚠ **装上去之后它就不归这个进程管了。** 任何一步失败都要靠 `purge` 收尾；
//! `purge` 也失败的话，只有重启能清掉。所以驱动脚本必须在任何退出路径上
//! 都再跑一次 `purge`。

use std::net::{Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use aegis_wfp::{rollback, Action, Condition, FilterSpec, Layer, Session, Tier};
use windows::core::GUID;

const TARGET_HOST: &str = "www.baidu.com";
const BLOCKED_PORT: u16 = 443;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// 过滤器名字。`purge` 靠它找到"我们装的"。
const FILTER_NAME: &str = "持久化探针";
/// Provider 显示名。
const PROVIDER_NAME: &str = "Aegis 持久化探针";
/// 固定 Provider GUID：arm / check / purge 三个进程必须认同一个 key。
const PROVIDER_KEY: GUID = GUID::from_u128(0x0a15_6754_0c0f_4a1e_9d3b_0001_ae15_0001);

fn main() {
    let mut args = std::env::args().skip(1);
    let cmd = args.next().unwrap_or_default();
    match cmd.as_str() {
        "arm" => arm(),
        "check" => check(),
        "purge" => purge(),
        _ => {
            println!("用法：persist_probe <arm|check|purge>");
            println!();
            println!("  arm    装一条**持久化**阻断规则（只拦 {TARGET_HOST}:443）");
            println!("  check  **另起一个进程**看它还在不在；顺便测连通性");
            println!("  purge  先删 filter 再删 Provider，然后复核为 0");
        },
    }
}

fn arm() {
    println!("[arm] 装一条持久化阻断规则");

    let session = match Session::open_persistent("aegis-persist-arm") {
        Ok(s) => s,
        Err(e) => {
            println!("  ❌ 打不开非动态会话：{e}");
            if let Some(h) = e.hint() {
                println!("     {h}");
            }
            return;
        },
    };
    println!("  ✅ 非动态会话已开（flags=0，不是 DYNAMIC）");

    match session.add_provider(PROVIDER_KEY, PROVIDER_NAME, None, true) {
        Ok(()) => println!("  ✅ 已注册持久化 Provider（key={PROVIDER_KEY:?}）"),
        Err(e) => println!("  ⚠ Provider 注册失败：{e}（继续试着装 filter）"),
    }

    let ip = match resolve_v4(TARGET_HOST) {
        Some(ip) => ip,
        None => {
            println!("  [FATAL] 解析不出 {TARGET_HOST}");
            return;
        },
    };

    let spec = FilterSpec {
        name: FILTER_NAME,
        layer: Layer::AleAuthConnectV4,
        action: Action::Block,
        weight: aegis_wfp::WEIGHT_MAX,
        conditions: vec![
            Condition::RemoteAddrV4(ip),
            Condition::RemotePort(BLOCKED_PORT),
        ],
        tier: Tier::Runtime,
    };

    match aegis_wfp::add_persistent(&session, &spec, Some(PROVIDER_KEY)) {
        Ok(id) => {
            println!("  ✅ 已装持久化过滤器 id={id}");
            println!();
            println!("  ⚠ 从现在起它**不归本进程管**：本进程退出它还在。");
            println!("     下一步请在**另一个进程**里跑 `check`，");
            println!("     确认完之后一定要跑 `purge`。");
        },
        Err(e) => {
            println!("  ❌ 装不上：{e}");
            if let Some(h) = e.hint() {
                println!("     {h}");
            }
            println!();
            println!("  常见原因：会话是动态的（动态会话**结构上禁止**持久化），");
            println!("  或者 `FWPM_FILTER_FLAG_PERSISTENT` 与某些条件组合不被接受。");
        },
    }
}

fn check() {
    println!("[check] 另一个进程里看持久化规则还在不在");
    let ip = match resolve_v4(TARGET_HOST) {
        Some(ip) => ip,
        None => {
            println!("  [FATAL] 解析不出 {TARGET_HOST}");
            return;
        },
    };
    println!(
        "  {TARGET_HOST}:{BLOCKED_PORT} = {}   （期望：断 —— 规则还在）",
        w(reachable(ip))
    );

    // 用**动态会话**来查：说明"看得到"不依赖于之前那个非动态会话还活着
    let session = match Session::open("aegis-persist-check") {
        Ok(s) => s,
        Err(e) => {
            println!("  ❌ 打不开会话：{e}");
            return;
        },
    };
    match session.filters_named(FILTER_NAME) {
        Ok(found) => {
            println!("  名字含「{FILTER_NAME}」的过滤器 = {} 条", found.len());
            for f in &found {
                println!(
                    "    id={:<8} 层={:<22} 动作={:<4} 跨重启={} Provider={:?}",
                    f.id,
                    f.layer,
                    f.action,
                    if f.flags.survives_reboot() {
                        "是"
                    } else {
                        "否"
                    },
                    f.provider
                );
            }
        },
        Err(e) => println!("  ❌ 枚举失败：{e}"),
    }
}

fn purge() {
    println!("[purge] 先删 filter，再删 Provider，然后复核");
    let session = match Session::open_persistent("aegis-persist-purge") {
        Ok(s) => s,
        Err(e) => {
            println!("  ❌ 打不开非动态会话：{e}");
            return;
        },
    };

    let ids: Vec<u64> = match session.filters_named(FILTER_NAME) {
        Ok(found) => found.iter().map(|f| f.id).collect(),
        Err(e) => {
            println!("  ❌ 枚举失败：{e}");
            return;
        },
    };
    println!("  找到 {} 条", ids.len());

    // ── 级联语义实测 ────────────────────────────────────────────────
    // 微软文档："必须先删除引用它的所有对象，才能删除该对象"（不级联）。
    // 第三方代码注释却声称"删 Provider 会级联删掉它的过滤器"。两者矛盾，
    // 而逃生舱不能押在任何一条没实测的说法上。所以这里先试一次。
    if !ids.is_empty() {
        match session.delete_provider(PROVIDER_KEY) {
            Ok(()) => println!("  ⚠ filter 还在时删 Provider **成功了** → 说明它会级联"),
            Err(e) => {
                println!("  ✅ filter 还在时删 Provider 被拒（{e}）→ **不级联**，与微软文档一致")
            },
        }
    }

    let removed = rollback(&session, &ids).unwrap_or(0);
    println!("  已删 filter {removed} / {} 条", ids.len());

    match session.delete_provider(PROVIDER_KEY) {
        Ok(()) => println!("  ✅ Provider 已删"),
        Err(e) => println!("  ⚠ Provider 删除失败：{e}"),
    }

    // ── 删完必须复核 ────────────────────────────────────────────────
    // "删了 N 条"不等于"删干净了"。复核才是结论。
    match session.filters_named(FILTER_NAME) {
        Ok(left) => {
            println!("  复核：还剩 {} 条（期望：0）", left.len());
            if let Some(ip) = resolve_v4(TARGET_HOST) {
                println!(
                    "  {TARGET_HOST}:{BLOCKED_PORT} = {}   （期望：通）",
                    w(reachable(ip))
                );
            }
            if left.is_empty() {
                println!("  ✅ 清干净了。");
            } else {
                println!(
                    "  ❌ **没清干净** —— 剩下的 id={:?}",
                    left.iter().map(|f| f.id).collect::<Vec<_>>()
                );
                println!(
                    "     这 { } 条已经不受任何进程控制，只能重启或手动删。",
                    left.len()
                );
            }
        },
        Err(e) => println!("  ❌ 复核枚举失败：{e}"),
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

/// ⚠ 参数是"能不能通"，不是"有没有被拦"。传反整张表就是反的
/// （第一版 iface_probe 就栽在这里）。
fn w(ok: bool) -> &'static str {
    if ok {
        "通"
    } else {
        "断"
    }
}
