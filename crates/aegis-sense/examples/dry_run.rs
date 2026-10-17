//! 感知层干跑自检（read-only dry run）。
//!
//! 这是 §21 待编码项里"Rust 最小骨架"的第一刀：
//! **只读**地把本机网络拓扑、默认出口和拓扑指纹采一遍并打印出来。
//!
//! 安全性：本示例不写注册表、不改网络设置、不启停任何进程、不注入任何防火墙规则。
//! 因此它可以在接入校园网的机器上放心运行（这也是先做它的原因）。
//!
//! 运行：
//! ```text
//! cargo run -p aegis-sense --example dry_run
//! ```

use std::time::Instant;

use aegis_sense::model::OperStatus;
use aegis_sense::route;
use aegis_sense::snapshot;
use aegis_sense::version;

fn main() {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  Aegis · aegis-sense 感知层干跑自检（Dry Run）              ║");
    println!("║  纯只读：不修改任何网络设置 / 不启停任何进程                 ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    // 每次采集都打上完整版本号，便于事后把结果回溯到具体版本与提交
    println!("  {}", version::banner());
    println!();

    let started = Instant::now();
    let snap = match snapshot() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[FATAL] 拓扑采集失败: {}", e);
            std::process::exit(1);
        },
    };
    let elapsed = started.elapsed();

    println!("── 本机网络接口拓扑 ────────────────────────────────────────────");
    println!("共 {} 张网卡：", snap.interfaces.len());
    println!();

    for iface in &snap.interfaces {
        let up = matches!(iface.oper_status, OperStatus::Up);
        let flag = if up { "●" } else { "○" };
        let kind = if iface.is_wireless() {
            "无线"
        } else {
            "有线/其它"
        };

        println!(
            "{} {} [{}] {}",
            flag,
            iface.alias,
            kind,
            iface.oper_status_str()
        );
        println!("    identity : {}", iface.identity());
        println!(
            "    MAC      : {}",
            iface
                .mac
                .as_ref()
                .map(|m| m.to_hex())
                .unwrap_or_else(|| "<无>".into())
        );
        println!("    LUID     : {}", iface.luid);
        if !iface.ipv4.is_empty() {
            let ips: Vec<String> = iface.ipv4.iter().map(|i| i.to_string()).collect();
            println!("    IPv4     : {}", ips.join(", "));
        }
        if !iface.gateway.is_empty() {
            let gws: Vec<String> = iface.gateway.iter().map(|i| i.to_string()).collect();
            println!("    网关     : {}", gws.join(", "));
        }
        if let Some(dhcp) = iface.dhcp_server {
            println!("    DHCP     : {}", dhcp);
        }
        if let Some(ssid) = &iface.ssid {
            println!("    SSID     : {}", ssid);
        }
        println!();
    }

    println!("── 默认出口裁决 ────────────────────────────────────────────────");
    // 先把所有默认路由的度量摊开，让裁决依据可被人工核对。
    // 这里刻意同时打印三个度量：
    //   接口度量（自动度量下按带宽推算，有线通常远低于 Wi-Fi）
    //   路由度量偏移（自动度量下几乎恒为 0，单独看它没有区分度）
    //   合成度量 = 前两者之和 ← Windows 真正用来选路的值
    match route::ipv4_routes() {
        Ok(rows) => {
            let defaults: Vec<_> = rows.iter().filter(|r| r.dest_prefix_len == 0).collect();
            if defaults.is_empty() {
                println!("（无 IPv4 默认路由）");
            } else {
                println!(
                    "  {:<28} {:>10} {:>10} {:>10}",
                    "接口", "接口度量", "路由偏移", "合成度量"
                );
                for r in &defaults {
                    let alias = snap
                        .interfaces
                        .iter()
                        .find(|i| i.luid == r.interface_luid)
                        .map(|i| i.alias.as_str())
                        .unwrap_or("<未知>");
                    let mark = if r.interface_luid == snap.default_egress_luid {
                        "← 选中"
                    } else {
                        ""
                    };
                    println!(
                        "  {:<28} {:>10} {:>10} {:>10}  {}",
                        crate_truncate(alias, 28),
                        r.interface_metric,
                        r.route_metric,
                        r.effective_metric,
                        mark
                    );
                }
            }
        },
        Err(e) => println!("（读取路由表失败: {}）", e),
    }
    println!();

    // 注意：这里读的是 snapshot 里裁决过的结果（优先"默认路由 ∧ 接口 Up"，
    // 且按合成度量而非路由度量偏移比较），而不是只看路由表的裸结果。
    if snap.default_egress_luid == 0 {
        println!("⚠ 未发现可用于出网的 IPv4 默认路由（整机离线？）—— 这是合法状态");
    } else {
        let luid = snap.default_egress_luid;
        let egress = snap.interfaces.iter().find(|i| i.luid == luid);
        let alias = egress.map(|i| i.alias.as_str()).unwrap_or("<未知接口>");
        println!("默认出口 : {}  [{}]", alias, luid);
        match egress.and_then(|i| i.gateway.first()) {
            Some(gw) => println!("  网关     : {}", gw),
            None => println!("  网关     : <直连 / 无网关>"),
        }
    }
    println!();

    println!("── 拓扑指纹（§20.4）───────────────────────────────────────────");
    println!("SHA-256 : {}", snap.fingerprint);
    println!(
        "（仅 {} 张 Up 接口参与计算；插拔网口/换 Wi-Fi 会改变此值 = 判定拓扑漂移）",
        snap.interfaces.iter().filter(|i| i.is_up()).count()
    );
    println!();
    println!("采集耗时: {:?}", elapsed);
    println!();
    println!("✅ 干跑完成。全程只读，本机网络状态未被修改。");
    println!("   Aegis {}", version::full());
}

/// 按**显示宽度**截断（中文按 2 列宽算），避免格式化对齐被打乱。
fn crate_truncate(s: &str, width: usize) -> String {
    let mut used = 0usize;
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        let w = if ch.is_ascii() { 1 } else { 2 };
        if used + w > width {
            break;
        }
        used += w;
        out.push(ch);
    }
    // 补足到目标宽度，让后续列右对齐
    out.push_str(&" ".repeat(width.saturating_sub(used)));
    out
}
