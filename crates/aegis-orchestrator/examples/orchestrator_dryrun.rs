//! 适配器 SPI 干跑：声明 → 矩阵 → 声明自检 → 契约测试 → 三种真实故障。
//!
//! **不需要管理员权限**，不启进程、不改路由表、不碰任何系统状态。
//!
//! ```text
//! cargo run -p aegis-orchestrator --example orchestrator_dryrun
//! ```
//!
//! 这个例子刻意演示三类"看起来适配了其实在漏"的情况：
//!   1. 适配器撒谎：声明了 `Reload` 却回 `Unsupported`
//!   2. 适配器答非所问：问 DNS 却回 `Healthy`
//!   3. 适配器诚实但能力不够：契约全绿，却有 Fail-Closed 缺口
//!
//! 第 3 类最阴——它不会让任何一条契约变红。

use aegis_orchestrator::{
    audit_declaration, check, fragment_text, invoke_checked, matrix, Adapter, AdapterError,
    Capability, ContractReport, DeclarationCheck, Op, Outcome, ReferenceAdapter, Scenario,
    UNPERMITTED_TUN,
};

fn main() {
    println!(
        "Aegis 适配器 SPI 干跑 —— {}",
        aegis_orchestrator::full_version()
    );
    println!("全程不碰系统：不启进程、不改路由表、不提权。\n");

    let scenario = Scenario::sample();
    let adapter = ReferenceAdapter::new("sing-box(参考模型)", scenario.clone());

    // ── 1. 能力矩阵 ────────────────────────────────────────────────────
    println!("1. 能力矩阵（§2A.4 ②：缺失怎么办，写死在代码里）");
    let m = matrix(&adapter);
    for row in &m.rows {
        let mark = if row.declared { "✓" } else { "·" };
        let kind = if row.fallback.is_fail_closed() {
            "断"
        } else {
            "降级"
        };
        println!(
            "   {} {:<26} 声明={:<5} 缺失时={} —— {}",
            mark,
            row.capability.tag(),
            row.declared,
            kind,
            row.fallback.note()
        );
    }
    println!("   出口可用：{}", if m.usable() { "是" } else { "否" });
    println!();

    // ── 2. 契约测试 ───────────────────────────────────────────────────
    //
    // ⚠ 契约必须排在声明自检**之前**。自检会真的 reload 一次（这正是它的意义），
    // 之后健康检查就报新版本号了；放在契约前面跑，"健康检查报当前版本"
    // 这条用例会假红。
    println!("2. 契约测试（§2A.4 ③：适配 = 这组 fixture 过没过）");
    let report: ContractReport = check(&adapter, &scenario);
    for r in &report.results {
        println!("   {} {}", if r.pass { "✓" } else { "✗" }, r.name);
    }
    println!("   {}", report.summary().lines().next().unwrap_or(""));
    println!();

    // ── 3. 声明自检：声明 ≠ 事实 ──────────────────────────────────────
    println!("3. 声明自检（§2A.4 ③：声称支持，就真打一次）");
    for c in audit_declaration(&adapter) {
        let verdict = match &c {
            DeclarationCheck::Honest(cap) => format!("诚实      {}", cap.tag()),
            DeclarationCheck::Lie { capability } => format!("撒谎！    {}", capability.tag()),
            DeclarationCheck::Broken { capability, reason } => {
                format!("做不了    {} —— {reason}", capability.tag())
            },
            DeclarationCheck::Unverifiable { capability, reason } => {
                format!("无法自检  {} —— {reason}", capability.tag())
            },
        };
        println!("   {verdict}");
    }
    println!("   注意 DefaultEgress 是「无法自检」：试一下就等于真的接管一次出口。");
    println!("   注意自检之后配置版本会被推到新版本——这就是它真的 reload 过的证据。");
    println!();

    // ── 4. 一次真实调用：TUN 起来了 ───────────────────────────────────
    println!("4. 问 TUN：放行列表里有一张起来了");
    let candidates = ["sing-box-tun".to_string(), "utun7".to_string()];
    println!(
        "   → {:?}",
        invoke_checked(
            &adapter,
            Op::TunPresent {
                candidates: &candidates
            }
        )
        .unwrap()
    );
    println!();

    // ── 5. TUN 起来了但没被放行：必须报错，不能静默说"没有" ───────────
    println!("5. 问 TUN：本机有 TUN 起来了，但没一张在放行列表里");
    let candidates = [UNPERMITTED_TUN.to_string()];
    let e = invoke_checked(
        &adapter,
        Op::TunPresent {
            candidates: &candidates,
        },
    )
    .unwrap_err();
    println!("   码   {} —— {}", e.code(), e);
    println!("   处置 {}", e.disposition());
    println!();

    // ── 6. 配置片段：只给片段，不接管配置 ─────────────────────────────
    println!("6. 生成配置片段（§2A.4 ④：不解析对方的全部规则）");
    let out = invoke_checked(&adapter, Op::Fragment { profile: "campus" }).unwrap();
    match out {
        Outcome::Fragment { text, notes } => {
            println!("   片段 {} 字节，注解 {} 条", text.len(), notes.len());
            print!("   内容：{}", text.replace('\n', "\n         "));
        },
        other => println!("   {other:?}"),
    }
    println!(
        "   参考实现产出的是同一段文本：{} 字节",
        fragment_text("campus").len()
    );
    println!();

    // ── 7. 故障一：撒谎的适配器 ───────────────────────────────────────
    println!("7. 故障一 —— 声明了 Reload，却回 Unsupported");
    let liar = Liar;
    let liar_report = check(&liar, &scenario);
    println!("   {}", liar_report.summary().replace('\n', "\n   "));
    println!();

    // ── 8. 故障二：答非所问 ───────────────────────────────────────────
    println!("8. 故障二 —— 问 DNS，回了个 Healthy");
    let e = invoke_checked(&Confused, Op::Dns).unwrap_err();
    println!("   码   {}", e.code());
    println!("   原因 {}", e);
    println!();

    // ── 9. 故障三：契约全绿，但能力不够 ───────────────────────────────
    println!("9. 故障三 —— 诚实但能力不够（最阴的一种）");
    let mut partial = ReferenceAdapter::new("半吊子", scenario.clone());
    partial.declare(&[
        Capability::TunInterfacePresent,
        Capability::ConfigFragmentGenerate,
    ]);
    let partial_matrix = matrix(&partial);
    let partial_report = check(&partial, &scenario);
    println!(
        "   契约：{}/{} 通过（一条都没红）",
        partial_report.passed_count(),
        partial_report.total()
    );
    println!(
        "   矩阵：Fail-Closed 缺口 = {:?}",
        partial_matrix
            .fail_closed_gaps()
            .iter()
            .map(|c| c.tag())
            .collect::<Vec<_>>()
    );
    println!(
        "   出口可用：{}",
        if partial_matrix.usable() {
            "是"
        } else {
            "否 ← 契约红了才怪"
        }
    );
    println!();

    println!("结论：契约过 ≠ 能用。契约验的是「诚不诚实」，矩阵验的是「够不够」。");
}

/// 声明了全部能力，但 `Reload` 回 `Unsupported` —— 撒谎。
struct Liar;

impl Adapter for Liar {
    fn name(&self) -> &'static str {
        "撒谎的适配器"
    }
    fn capabilities(&self) -> &[Capability] {
        &Capability::ALL
    }
    fn invoke(&self, op: Op<'_>) -> Result<Outcome, AdapterError> {
        if matches!(op, Op::Reload) {
            return Err(AdapterError::Unsupported(Capability::Reload));
        }
        ReferenceAdapter::new("inner", Scenario::sample()).invoke(op)
    }
}

/// 声明了全部能力，但问 DNS 回 `Healthy` —— 答非所问。
struct Confused;

impl Adapter for Confused {
    fn name(&self) -> &'static str {
        "搞混了的适配器"
    }
    fn capabilities(&self) -> &[Capability] {
        &Capability::ALL
    }
    fn invoke(&self, op: Op<'_>) -> Result<Outcome, AdapterError> {
        match op {
            Op::Dns => Ok(Outcome::Healthy {
                version: "1".into(),
            }),
            _ => ReferenceAdapter::new("inner", Scenario::sample()).invoke(op),
        }
    }
}
