//! **真实下发通路探针**（需要提权，但结构上无害）。
//!
//! ```text
//! cargo run -p aegis-wfp --example apply_probe
//! ```
//!
//! # 它做什么
//!
//! 把默认绝缘笼计划里**所有放行类（Permit）规则**逐条"装上去再按 id 拆掉"，
//! 打印每一条的结果。
//!
//! # 为什么这样是安全的
//!
//! 放行类规则只会**扩大**放行面，不会收窄；而这里装的每一条都是
//! "回环放行"和"DHCP 放行"——在默认策略下本来就是放行的，装上去等于
//! 什么都没变。**它一条阻断规则都不装。**
//!
//! # 为什么必须先有它
//!
//! 从"干跑"走向"真实下发"是唯一一个"写错了一跑就断网"的阶段。
//! 而 WFP 没有 dry-run 接口，`FwpmFilterAdd0` 要么成功要么报错。
//! 所以在拿整副绝缘笼冒险之前，先验证：
//!
//! ```text
//! 会话能开 → 条件翻译得对 → 内核接受 → 按 id 能删回去
//! ```
//!
//! 这套机械动作对**每一条放行规则**都成立。曾经就是靠它发现
//! `ServicePid` 被翻译成了 `ALE_APP_ID` + `UINT64(pid)`，
//! 内核回 `0x80320027`（`FWP_E_TYPE_MISMATCH`）——那种错在干跑里
//! 永远看不出来。
//!
//! ⚠ 它**不验证**阻断规则。阻断规则必须靠人工在可控窗口里确认
//! （见 `aegisctl apply` 的 10 秒倒计时），因为"装上去网断了"正是
//! 它本该造成的效果。

use aegis_wfp::{
    cage_plan, probe_add_then_remove, Action, CagePolicy, FilterSpec, ProbeResult, WfpError,
};

fn main() {
    let plan = cage_plan(CagePolicy::default());

    println!("Aegis · WFP 下发通路探针");
    println!("⚠ 只装**放行类**规则（装上去等于什么都没变），一条阻断规则都不装。");
    println!(
        "  计划共 {} 条，其中放行 {} 条、阻断 {} 条。",
        plan.len(),
        plan.iter().filter(|f| f.action == Action::Permit).count(),
        plan.iter().filter(|f| f.action == Action::Block).count()
    );
    println!();

    let mut ok = 0usize;
    let mut failed = 0usize;

    for spec in &plan {
        if spec.action != Action::Permit {
            println!(
                "  ── 跳过（阻断）：{} —— 它需要人工在 10 秒窗口内确认",
                spec.name
            );
            continue;
        }
        match probe(spec) {
            Ok(r) => {
                ok += 1;
                println!(
                    "  ✅ {:>16}  filterId={:<8} 删除 {}",
                    spec.name, r.filter_id, r.removed
                );
            },
            Err(e) => {
                failed += 1;
                println!("  ❌ {:>16}  {}", spec.name, e);
                if let Some(h) = e.hint() {
                    println!("        {h}");
                }
            },
        }
    }

    println!();
    println!("放行规则探针：成功 {ok} 条，失败 {failed} 条。");
    if failed > 0 {
        println!("⚠ 有放行规则装不上——**别下发整副笼子**。");
        println!("  放行规则装不上的后果是 DHCP/回环被默认拒绝挡掉，即开机即断网。");
    } else {
        println!("放行通路全部验证通过。阻断规则仍需人工确认后再下发。");
    }
}

fn probe(spec: &FilterSpec) -> Result<ProbeResult, WfpError> {
    let r = probe_add_then_remove(spec)?;
    // 删不掉等于回滚失效，比装不上更危险：它会留下一条没人认领的规则
    if r.removed != 1 {
        eprintln!("  ⚠ 删除条数 {} != 1：按 id 删除这一步有问题", r.removed);
    }
    Ok(r)
}
