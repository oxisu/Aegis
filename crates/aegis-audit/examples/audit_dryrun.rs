//! 审计与证据链干跑：造几条事件 → 建链 → 演示"什么抓得住、什么抓不住"。
//!
//! **不需要管理员权限**，不碰系统任何状态，纯粹在内存里推演。
//!
//! ```text
//! cargo run -p aegis-audit --example audit_dryrun
//! ```
//!
//! 这个例子刻意把**尾部截断抓不住**这件事也演示出来。它是哈希链的固有
//! 性质，藏着不说会让人误以为"上了链就防删"，那是比没有更危险的虚假安全感。

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use aegis_audit::{chain, Action, AuditEvent, AuditRing, EvidenceChain, InterfaceRole, Protocol};

fn addr(ip: [u8; 4], port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port)
}

/// 五条有代表性的事件：覆盖四种动作与两种角色。
fn sample_events() -> Vec<AuditEvent> {
    vec![
        AuditEvent {
            ts_ms: 1_700_000_000_000,
            pid: 4188,
            process_path: r"C:\Program Files\Browser\browser.exe".to_string(),
            src: addr([10, 12, 8, 33], 51234),
            dst: addr([223, 5, 5, 5], 53),
            protocol: Protocol::Udp,
            host: Some("dns.alidns.com".to_string()),
            rule: Some("ALLOW-DNS".to_string()),
            luid: 1689399631429632,
            role: InterfaceRole::CampusStrict,
            action: Action::Allow,
        },
        AuditEvent {
            ts_ms: 1_700_000_000_120,
            pid: 4188,
            process_path: r"C:\Program Files\Browser\browser.exe".to_string(),
            src: addr([10, 12, 8, 33], 51240),
            dst: addr([93, 184, 216, 34], 80),
            protocol: Protocol::Tcp,
            host: Some("example.com".to_string()),
            rule: Some("BLOCK-PLAINTEXT".to_string()),
            luid: 1689399631429632,
            role: InterfaceRole::CampusStrict,
            action: Action::PlaintextBlock,
        },
        AuditEvent {
            ts_ms: 1_700_000_000_340,
            pid: 9024,
            process_path: r"C:\Users\me\AppData\Local\Tool\tool.exe".to_string(),
            src: addr([10, 12, 8, 33], 51255),
            dst: addr([8, 8, 8, 8], 53),
            protocol: Protocol::Udp,
            host: None,
            rule: Some("LOCK-DNS-53".to_string()),
            luid: 1689399631429632,
            role: InterfaceRole::CampusStrict,
            action: Action::FirewallBlock,
        },
        AuditEvent {
            ts_ms: 1_700_000_000_900,
            pid: 7788,
            process_path: r"C:\Users\me\Downloads\sync.exe".to_string(),
            src: addr([10, 12, 8, 33], 51300),
            dst: addr([1, 1, 1, 1], 443),
            protocol: Protocol::Tcp,
            host: Some("one.one.one.one".to_string()),
            rule: Some("FINAL,REJECT".to_string()),
            luid: 1689399631429632,
            role: InterfaceRole::CampusStrict,
            action: Action::Reject,
        },
        AuditEvent {
            ts_ms: 1_700_000_004_500,
            pid: 4188,
            process_path: r"C:\Program Files\Browser\browser.exe".to_string(),
            src: addr([192, 168, 43, 77], 51400),
            dst: addr([93, 184, 216, 34], 443),
            protocol: Protocol::Tcp,
            host: Some("example.com".to_string()),
            rule: None,
            luid: 2248146931122176,
            role: InterfaceRole::FreeOutbound,
            action: Action::Allow,
        },
    ]
}

fn main() {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  Aegis · aegis-audit 证据链干跑（纯内存，不碰系统）         ║");
    println!("║  不需要管理员权限                                            ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    // ── 1. 捕获：回调侧只往缓冲里推 ───────────────────────────────────
    let ring = AuditRing::new(3);
    for e in sample_events() {
        ring.push(e);
    }
    println!("1. 回调侧推入 5 条，缓冲容量只有 3");
    println!("   缓冲内剩余：{} 条", ring.len());
    println!("   被覆盖丢弃：{} 条（必须可见，否则 UI 那张表会被当成全量）", ring.dropped());
    println!();

    // ── 2. 完整捕获一遍（容量给足），建链 ─────────────────────────────
    let events = sample_events();
    let mut chain = EvidenceChain::new();
    let links: Vec<_> = events
        .iter()
        .map(|e| {
            let link = chain.append(e);
            println!(
                "2. 第 {} 条  prev={}… hash={}…  {} → {}",
                link.seq,
                &chain::hex(&link.prev)[..8],
                &chain::hex(&link.hash)[..8],
                e.action,
                e.role
            );
            link
        })
        .collect();
    println!();
    println!("   链头 = {}…", &chain::hex(&chain.head())[..16]);
    println!("   ⚠ 链头要**定期外置**（打印 / 只读归档），这是防尾部截断的唯一办法");
    println!();

    // ── 3. 正常校验 ───────────────────────────────────────────────────
    println!("3. 原样校验：{:?}", aegis_audit::verify(&events, &links));
    println!();

    // ── 4. 篡改：把一条"阻断"改成"放行" ───────────────────────────────
    println!("4. 篡改 —— 把第 4 条的「规则拒绝」改成「放行」：");
    let mut tampered = events.clone();
    tampered[3].action = Action::Allow;
    println!("   {:?}", aegis_audit::verify(&tampered, &links));
    println!();

    // ── 5. 删中间一条，并把链节也一起删掉 + 重编号（更狡猾的那种）──────
    println!("5. 删掉第 2 条（明文阻断那条），链节也一起删、序号重新编过：");
    let holed: Vec<_> = events
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != 1)
        .map(|(_, e)| e.clone())
        .collect();
    let mut forged: Vec<_> = links
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != 1)
        .map(|(_, l)| *l)
        .collect();
    for (i, link) in forged.iter_mut().enumerate() {
        link.seq = i as u64 + 1;
    }
    println!("   {:?}", aegis_audit::verify(&holed, &forged));
    println!("   → 序号骗过去了，但前驱哈希骗不过：第 2 条的前驱应是");
    println!("     被删掉那条，而它现在接的是第 1 条。");
    println!();

    // ── 6. 尾部截断：抓不住 ───────────────────────────────────────────
    println!("6. 尾部截断 —— 把最后两条连着删掉：");
    println!(
        "   {:?}",
        aegis_audit::verify(&events[..3], &links[..3])
    );
    println!("   → 仍然通过。哈希链**抓不住**尾部删除：剩下那部分自洽，");
    println!("     链头就变成了新的结尾。这是固有性质，不是实现缺陷。");
    println!("     唯一的缓解是定期把链头写到攻击者改不到的地方。");
    println!();

    // ── 7. 规范化编码 ─────────────────────────────────────────────────
    println!("7. 规范化编码（哈希输入，不是落盘格式）：");
    for (i, e) in events.iter().enumerate() {
        let b = aegis_audit::canonical_bytes(e);
        println!(
            "   第 {} 条：{} 字节，版本 v{}",
            i + 1,
            b.len(),
            aegis_audit::CANONICAL_VERSION
        );
    }
    println!();

    // ── 8. 落盘：写 → 重开 → 续写 ─────────────────────────────────────
    let dir = std::env::temp_dir().join(format!(
        "aegis-audit-dryrun-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).expect("建临时目录");
    let path = dir.join("audit.log");

    println!("8. 落盘：写 5 条 → 关掉 → 重开 → 再写 1 条");
    let head_before = {
        let mut log = aegis_audit::AuditLog::create(&path).expect("新建日志");
        for e in &events {
            log.append(e).expect("追加");
        }
        log.flush().expect("刷盘");
        log.head()
    };

    let mut reopened = aegis_audit::AuditLog::open(&path).expect("重开");
    println!("   重开后：{} 条，链头 = {}…", reopened.len(), &chain::hex(&reopened.head())[..16]);
    println!(
        "   与关掉前一致：{}",
        reopened.head() == head_before
    );
    let resumed = reopened.append(&events[0]).expect("续写");
    println!("   续写这条是第 {} 号，前驱 = {}…", resumed.seq, &chain::hex(&resumed.prev)[..16]);
    reopened.flush().expect("刷盘");
    println!();

    // ── 9. 改文件里的一个字节 ─────────────────────────────────────────
    println!("9. 改文件里的一个字节：");
    drop(reopened);
    let mut raw = std::fs::read(&path).expect("读文件");
    let at = raw.len() / 2;
    raw[at] ^= 0xFF;
    println!("   改的是偏移 {} 处的那个字节", at);
    std::fs::write(&path, &raw).expect("写回");
    println!("   {:?}", aegis_audit::read_records(&path).err());
    println!();

    // ── 10. 证据导出：CSV ────────────────────────────────────────────
    println!("10. 证据导出 —— CSV（自证用）：");
    // 用内存里那份干净的：文件在上一步已被故意改坏，读回来是空的
    let records: Vec<aegis_audit::Record> = events
        .iter()
        .zip(links.iter())
        .map(|(e, l)| aegis_audit::Record {
            event: e.clone(),
            link: *l,
        })
        .collect();
    let head = records.last().map(|r| r.link.hash).unwrap_or(chain::GENESIS);
    println!("   {}", "─".repeat(60));
    for line in aegis_audit::to_csv(&records).trim_end().split('\n') {
        // 列很多，只打前几列，能看清结构就行
        let short: Vec<&str> = line.split(',').take(6).collect();
        println!("   {}", short.join(","));
    }
    println!("   {}（后略：链节哈希等列）", "─".repeat(60));
    println!();

    // ── 11. 证据包：自带校验结论 ─────────────────────────────────────
    println!("11. 证据包（自带链头与校验结论，对外给得出手）：");
    let pkg = aegis_audit::EvidencePackage::build(records, head, 1_760_779_587_000);
    println!("   Aegis 版本：{}", pkg.aegis_version);
    println!("   链头      ：{}…", &chain::hex(&pkg.chain_head)[..16]);
    println!("   条数      ：{}", pkg.chain_len);
    println!("   校验      ：{}", if pkg.verified { "通过" } else { "**未通过**" });
    let json = aegis_audit::to_json(&pkg);
    println!("   JSON {} 字节，前 2 行：", json.len());
    for line in json.lines().take(2) {
        println!("     {}", line.trim());
    }
    println!();

    // ── 12. 只导出被拦下的 ───────────────────────────────────────────
    println!("12. 自证场景常用：只导出被本地拦下的");
    let all = sample_events();
    let kept: Vec<_> = all
        .iter()
        .filter(|e| aegis_audit::ExportFilter::blocked_only().keep(e))
        .collect();
    println!(
        "   {} 条里有 {} 条是被拦下的（放行 {} 条）",
        all.len(),
        kept.len(),
        all.len() - kept.len()
    );
    println!();

    let _ = std::fs::remove_dir_all(&dir);
    println!("   临时目录已清理：{}", dir.display());
    println!();
    println!("全程干跑：只碰临时目录下的一个文件，且已删除。");
}
