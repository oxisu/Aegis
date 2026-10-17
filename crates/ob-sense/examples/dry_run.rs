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
//! cargo run -p ob-sense --example dry_run
//! ```

use std::time::Instant;

use ob_sense::model::OperStatus;
use ob_sense::{default_egress, snapshot};

fn main() {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  InterBoot · ob-sense 感知层干跑自检（Dry Run）              ║");
    println!("║  纯只读：不修改任何网络设置 / 不启停任何进程                 ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    let started = Instant::now();
    let snap = match snapshot() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[FATAL] 拓扑采集失败: {}", e);
            std::process::exit(1);
        }
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

        println!("{} {} [{}] {}", flag, iface.alias, kind, iface.oper_status_str());
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
    match default_egress() {
        Ok(Some(route)) => {
            println!("默认路由存在，出口 LUID = {}", route.interface_luid);
            println!(
                "  下一跳网关 : {}",
                route
                    .next_hop
                    .map(|i| i.to_string())
                    .unwrap_or_else(|| "<直连/无网关>".into())
            );
            println!("  Metric     : {}", route.metric);
        }
        Ok(None) => println!("⚠ 未发现 IPv4 默认路由（整机离线？）—— 这是合法状态"),
        Err(e) => eprintln!("[WARN] 路由采集失败: {}", e),
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
}
