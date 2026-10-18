//! 绝缘笼规则计划 —— **只读干跑**。
//!
//! 打印"如果现在下发，会装哪些规则、按什么顺序命中、会不会把自己锁死"，
//! **一条都不会真的装下去**。不需要管理员权限。
//!
//! ```bash
//! cargo run -p aegis-wfp --example wfp_plan
//! cargo run -p aegis-wfp --example wfp_plan -- --campus-strict
//! cargo run -p aegis-wfp --example wfp_plan -- --boot-backbone   # 会要求确认
//! ```

use aegis_wfp::plan::{
    apply_order, cage_plan, invariants_violated, is_safe, needs_confirmation, verify_with,
    CagePolicy,
};

fn parse_args() -> CagePolicy {
    let mut p = CagePolicy::default();
    let mut i = 1;
    let args: Vec<String> = std::env::args().collect();
    while i < args.len() {
        match args[i].as_str() {
            "--campus-strict" => p.campus_strict = true,
            "--boot-backbone" => p.boot_backbone = true,
            "--no-dns-lock" => p.dns_lock = false,
            "--help" | "-h" => {
                println!(
                    "用法: wfp_plan [--campus-strict] [--boot-backbone] [--no-dns-lock]\n\
                     注: 本命令只做干跑，不下发任何 WFP 规则。"
                );
                std::process::exit(0);
            },
            other => {
                eprintln!("未知参数: {other}（用 --help 查看用法）");
                std::process::exit(2);
            },
        }
        i += 1;
    }
    p
}

fn main() {
    let policy = parse_args();
    let plan = apply_order(&cage_plan(policy));

    println!("Aegis 绝缘笼规则计划（干跑 · 未下发）");
    println!("{}", "─".repeat(78));
    println!(
        "53 封锁={}  校园严格={}  Boot 背板={}",
        onoff(policy.dns_lock),
        onoff(policy.campus_strict),
        onoff(policy.boot_backbone)
    );
    println!();

    let mut current_layer = None;
    for f in &plan {
        if current_layer != Some(f.layer) {
            current_layer = Some(f.layer);
            println!("── {} ──", f.layer.name());
        }
        let conds = if f.conditions.is_empty() {
            "(无条件 · 兜底)".to_string()
        } else {
            f.conditions
                .iter()
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
                .join(" 且 ")
        };
        println!(
            "  [{:>2}] {:<8} {:<26} {:<14} {}",
            f.weight,
            f.action.name(),
            f.name,
            f.tier.name(),
            conds
        );
    }

    println!();
    println!("── 静态自检（第一层：安全不变量 + 策略兑现）──");
    let findings = verify_with(&plan, &policy);
    if findings.is_empty() {
        println!("无问题。");
    } else {
        for f in &findings {
            let tag = match f.severity {
                aegis_wfp::plan::Severity::Error => "错误",
                aegis_wfp::plan::Severity::Warn => "注意",
            };
            // 归属层（§20.10）：不变量 vs 写法问题，处置完全不同
            println!("  [{tag}/{}] {}: {}", f.kind.name(), f.code, f.detail);
        }
    }

    println!();
    if invariants_violated(&findings) {
        println!("结论: **不可下发** —— 安全不变量被违反。");
        println!("      这是第一层（宪法）的问题，不是「没写好」；");
        println!("      任何用户定制都不得覆盖，必须回头改策略。");
        std::process::exit(1);
    }
    if !is_safe(&plan) {
        println!("结论: **不可下发** —— 存在会静默失效的写法问题（第二层）。");
        std::process::exit(1);
    }
    if needs_confirmation(&plan) {
        println!("结论: 可下发，但需人工确认（含引导时间持久规则，装错即变砖）。");
    } else {
        println!("结论: 可下发，无需额外确认。");
    }
    println!("（本次运行未下发任何规则。）");
}

fn onoff(b: bool) -> &'static str {
    if b {
        "开"
    } else {
        "关"
    }
}
