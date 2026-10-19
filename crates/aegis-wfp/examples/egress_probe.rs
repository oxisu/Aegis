//! **"能不能按出口网卡过滤"的真机自证**（需要提权，只读枚举 + 对照）。
//!
//! ```text
//! cargo run -p aegis-wfp --example egress_probe
//! ```
//!
//! # 它要回答的问题
//!
//! 沙漏模型的第二层漏斗（Aegis 那一层）有一条核心断言：
//!
//! > "我不管你是哪个软件，只要你的数据包试图从**物理校园网卡**直接出去
//! >  （而不是从代理的 TUN 出去），就截掉。"
//!
//! 这条断言成立的前提是：**WFP 的分类层能看到"这一跳要从哪张网卡出去"**。
//! 这件事不能靠背文档——"层支持哪些字段"会随版本 / SKU / 已装驱动变化。
//! 所以直接问引擎。
//!
//! # 为什么必须在 ALE 层看到出口网卡
//!
//! 代理软件跑在用户态，**TUN 模式下**应用的 socket 仍然连的是真实远端 IP，
//! 系统只是按路由把它送进 TUN。于是：
//!
//! - 按**进程**放行（只放行代理进程）会把应用自己的 socket 一起拦掉，
//!   TUN 模式直接废掉；
//! - 按**出口网卡**放行（只放行走 TUN 的）才是 TUN 模式的正确原语。
//!
//! 反过来，**系统代理模式**（SOCKS/HTTP）下应用连的是 127.0.0.1，
//! 此时按进程放行代理进程才是对的。
//!
//! 两种模式要的原语不同，所以先搞清楚：ALE 层到底给不给网卡字段。
//!
//! # 只读，不改任何东西
//!
//! 全程 `FwpmLayerGetByKey0` 枚举字段，一个过滤器都不装。

use aegis_wfp::{Layer, Session};
use windows::core::GUID;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform as wfp;

/// 所有跟"网卡 / 下一跳"沾边的条件字段，逐个问引擎在不在这一层。
const WANT: &[(&str, GUID)] = &[
    ("IP_LOCAL_INTERFACE", wfp::FWPM_CONDITION_IP_LOCAL_INTERFACE),
    ("INTERFACE_INDEX", wfp::FWPM_CONDITION_INTERFACE_INDEX),
    (
        "SUB_INTERFACE_INDEX",
        wfp::FWPM_CONDITION_SUB_INTERFACE_INDEX,
    ),
    ("INTERFACE_TYPE", wfp::FWPM_CONDITION_INTERFACE_TYPE),
    (
        "IP_NEXTHOP_INTERFACE",
        wfp::FWPM_CONDITION_IP_NEXTHOP_INTERFACE,
    ),
    (
        "IP_FORWARD_INTERFACE",
        wfp::FWPM_CONDITION_IP_FORWARD_INTERFACE,
    ),
    (
        "IP_ARRIVAL_INTERFACE",
        wfp::FWPM_CONDITION_IP_ARRIVAL_INTERFACE,
    ),
    (
        "IP_PHYSICAL_NEXTHOP_INTERFACE",
        wfp::FWPM_CONDITION_IP_PHYSICAL_NEXTHOP_INTERFACE,
    ),
    (
        "NEXTHOP_INTERFACE_INDEX",
        wfp::FWPM_CONDITION_NEXTHOP_INTERFACE_INDEX,
    ),
    (
        "NEXTHOP_SUB_INTERFACE_INDEX",
        wfp::FWPM_CONDITION_NEXTHOP_SUB_INTERFACE_INDEX,
    ),
    (
        "SOURCE_INTERFACE_INDEX",
        wfp::FWPM_CONDITION_SOURCE_INTERFACE_INDEX,
    ),
    (
        "DESTINATION_INTERFACE_INDEX",
        wfp::FWPM_CONDITION_DESTINATION_INTERFACE_INDEX,
    ),
    (
        "ARRIVAL_INTERFACE_INDEX",
        wfp::FWPM_CONDITION_ARRIVAL_INTERFACE_INDEX,
    ),
    (
        "LOCAL_INTERFACE_PROFILE_ID",
        wfp::FWPM_CONDITION_LOCAL_INTERFACE_PROFILE_ID,
    ),
    ("TUNNEL_TYPE", wfp::FWPM_CONDITION_TUNNEL_TYPE),
];

/// 作为对照：这几个是我们**已经验证过能用**的字段。
const CONTROL: &[(&str, GUID)] = &[
    ("IP_REMOTE_ADDRESS", wfp::FWPM_CONDITION_IP_REMOTE_ADDRESS),
    ("IP_REMOTE_PORT", wfp::FWPM_CONDITION_IP_REMOTE_PORT),
    ("IP_LOCAL_PORT", wfp::FWPM_CONDITION_IP_LOCAL_PORT),
    ("ALE_APP_ID", wfp::FWPM_CONDITION_ALE_APP_ID),
    ("FLAGS", wfp::FWPM_CONDITION_FLAGS),
];

const LAYERS: &[(Layer, &str)] = &[
    (
        Layer::AleAuthConnectV4,
        "出站连接授权（沙漏第二层的主战场）",
    ),
    (Layer::AleAuthConnectV6, "出站连接授权 IPv6"),
    (Layer::OutboundTransportV4, "包离开真实网卡前的最后一道"),
    (Layer::AleAuthRecvAcceptV4, "入站连接授权"),
];

fn main() {
    println!("Aegis · 出口网卡条件字段自证（只读，不装任何过滤器）");
    println!();

    let session = match Session::open("aegis-egress-probe") {
        Ok(s) => s,
        Err(e) => {
            println!("[FATAL] 打不开会话：{e}");
            if let Some(h) = e.hint() {
                println!("   {h}");
            }
            return;
        },
    };

    for (layer, role) in LAYERS {
        println!("── {} ──", layer.name());
        println!("   用途：{role}");
        let fields = match session.fields(layer.guid()) {
            Ok(f) => f,
            Err(e) => {
                println!("   （枚举失败：{e}）");
                println!();
                continue;
            },
        };
        println!("   字段总数：{}", fields.len());

        println!("   网卡/下一跳相关：");
        let mut any = false;
        for (name, key) in WANT {
            if let Some(f) = fields.iter().find(|x| x.is(key)) {
                println!("     ✅ {name:<32} 在（值类型 {:?}）", f.data_type);
                any = true;
            }
        }
        if !any {
            println!("     ❌ **一个都没有** —— 这一层无法按出口网卡过滤");
        }

        print!("   对照组（已验证可用）：");
        for (name, key) in CONTROL {
            print!(
                " {}{}",
                name,
                if fields.iter().any(|x| x.is(key)) {
                    "✅"
                } else {
                    "❌"
                }
            );
        }
        println!();
        println!();
    }

    println!("─── 怎么读这张表 ───");
    println!("· `ALE_AUTH_CONNECT_V4` 里有 IP_LOCAL_INTERFACE / INTERFACE_INDEX");
    println!("  → 沙漏第二层（按出口网卡砍）**在原理上成立**，可以往下做行为验证。");
    println!("· 一个都没有 → 单靠 WFP 做不到「按网卡砍」，第二层必须换成");
    println!("  **按进程**（放行代理进程，其余全断），那只在系统代理模式下成立，");
    println!("  TUN 模式就得另想办法。");
    println!();
    println!("⚠ 字段在 ≠ 分类时它带着正确的值。值对不对要另做行为实验：");
    println!("  装一条 IP_LOCAL_INTERFACE=<校园网卡> 的阻断，看流量是否真的断。");
}
