//! 编排核心只读推演（planning dry run）。
//!
//! 采集一次本机拓扑，输出：
//!   1. 每张物理网卡的角色裁决结果与判定依据
//!   2. 哪些网卡策略猜不出来、必须人工分配
//!   3. 编排器状态机的关键路径与绝缘等级
//!
//! **全程只读**，不修改任何系统状态、不需要管理员权限。
//!
//! ```text
//! cargo run -p aegis-core --example plan
//!
//! # 显式声明"这张网是手机热点 / 是校园网"，看裁决如何变化
//! cargo run -p aegis-core --example plan -- --free MMi
//! cargo run -p aegis-core --example plan -- --campus Campus-WiFi
//! ```
//!
//! `--free` / `--campus` 对应配置文件里的 `[roles].known_free_ssids` /
//! `[roles].known_campus_ssids`。之所以需要它们：关键字 + 网关前缀这两种
//! 启发式覆盖不了个人手机热点——它的 SSID 是个人化的（例如 `MMi`），
//! 既不含 `hotspot` 关键字，网关也不在校园网段。声明权留给用户，
//! 代码不替用户猜。

// 采集侧单独引：aegis-core 本身只依赖零依赖的数据模型，不碰 Win32。
use aegis_core::role::{adjudicate_all, Confidence, RolePolicy, RoleTable};
use aegis_core::state::{insulation, next, Event, State};
use aegis_core::version;
use aegis_sense::snapshot;

fn main() {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  Aegis · aegis-core 编排核心只读推演                        ║");
    println!("║  纯逻辑：不注入规则 / 不启停进程 / 不改系统状态             ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!("  {}", version::banner());
    println!();

    // 极简参数解析：--free <SSID> / --campus <SSID>，均可重复。
    let mut declared_free: Vec<String> = Vec::new();
    let mut declared_campus: Vec<String> = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--free" => {
                if let Some(v) = args.next() {
                    declared_free.push(v);
                }
            },
            "--campus" => {
                if let Some(v) = args.next() {
                    declared_campus.push(v);
                }
            },
            other => {
                eprintln!("[WARN] 忽略未知参数：{other}（可用：--free <SSID> / --campus <SSID>）");
            },
        }
    }

    let snap = match snapshot() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[FATAL] 拓扑采集失败: {e}");
            std::process::exit(1);
        },
    };

    println!("── 1. 物理网卡角色裁决（§20.5）───────────────────────────────");
    println!(
        "参与指纹：{}（{} 张）",
        snap.fingerprint_scope, snap.fingerprint_participants
    );
    println!();

    let policy = RolePolicy {
        known_free_ssids: declared_free.clone(),
        known_campus_ssids: declared_campus.clone(),
        ..Default::default()
    };
    if !declared_free.is_empty() || !declared_campus.is_empty() {
        println!(
            "本次显式声明：自由出海 {:?} / 校园网 {:?}",
            declared_free, declared_campus
        );
        println!("（等价于写进 config.toml 的 [roles] 段）");
        println!();
    }
    let decisions = adjudicate_all(&snap.interfaces, &policy);

    if decisions.is_empty() {
        println!("未发现物理网卡。");
    }

    let mut table = RoleTable::new();
    let mut need_human = 0usize;

    for d in &decisions {
        println!(
            "● {}  [{}]",
            d.alias,
            if d.up { "Up" } else { "未插线/未连接" }
        );
        println!("    identity : {}", d.identity);
        println!("    角色     : {}  [{}]", d.role, d.confidence);
        println!("    依据     : {}", d.reason);
        println!(
            "    出网     : {} / 锁 53 : {}",
            if d.role.allows_egress() {
                "允许"
            } else {
                "禁止"
            },
            if d.role.locks_dns() { "是" } else { "否" }
        );
        println!();

        let confirmed = d.confidence == Confidence::Confirmed;
        if !confirmed {
            need_human += 1;
        }
        table.assign(d.identity.clone(), d.role, confirmed);
    }

    println!("── 2. 需要人工介入的网卡 ────────────────────────────────────");
    if need_human == 0 {
        println!("无（全部由策略命中）");
    } else {
        println!("{need_human} 张网卡策略无法确定，必须人工分配角色后才能放行。");
        for (id, role, confirmed) in table.unconfirmed() {
            println!(
                "  · {id} → 暂定 {role}（{}）",
                if *confirmed { "已确认" } else { "待确认" }
            );
        }
        println!();
        println!("Fail-closed：猜不出来就绝缘，绝不放开通往外网的口子。");
        println!();
        println!("  提示：若其中某张其实是手机热点 / 校园网，可直接声明，免去每次开机手动放行：");
        println!("        cargo run -p aegis-core --example plan -- --free <SSID>");
        println!("        或写入 config.toml 的 [roles].known_free_ssids / known_campus_ssids");
    }
    println!();

    println!("── 3. 状态机关键路径与绝缘等级（§26）─────────────────────────");
    let path = [
        ("开机自检通过后等待人工授权", Event::PreflightPassed),
        ("用户点击【确认并放行】", Event::ManualApprove),
        ("上层代理不健康", Event::ProxyUnhealthy),
        ("网口变动", Event::TopologyChanged),
    ];
    let mut s = State::Boot;
    println!("  {:<12} {}", "起始", State::Boot);
    println!("  {:<12} {}", "绝缘等级", insulation(s));
    for (label, ev) in path {
        match next(s, ev) {
            Some(n) => {
                println!("  ─ {label} ─▶ {n}");
                println!("  {:<12} {}", "绝缘等级", insulation(n));
                s = n;
            },
            None => println!("  ─ {label} ─▶ （当前状态下不适用，已忽略）"),
        }
    }
    println!();

    println!("── 4. 铁律自检 ──────────────────────────────────────────────");
    println!(
        "  只有 Controlled 不绝缘            : {}",
        insulation(State::Controlled) == aegis_core::state::Insulation::None
    );
    println!(
        "  Degraded 仍完全绝缘（降级不降防）: {}",
        insulation(State::Degraded) == aegis_core::state::Insulation::Full
    );
    println!(
        "  Controlled 下网口变动立即熔断     : {}",
        next(State::Controlled, Event::TopologyChanged) == Some(State::Airgap)
    );
    println!();

    println!("✅ 推演完成。全程只读且为纯逻辑计算，本机网络状态未被修改。");
    println!("   Aegis {}", version::full());
}
