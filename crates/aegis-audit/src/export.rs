//! 证据导出：把审计记录变成**能拿出去给人看**的 CSV / JSON（§F3）。
//!
//! # 这是审计存在的理由
//!
//! 证据链做得再漂亮，如果拿不出来给网络中心看，就只是自我安慰。
//! 本模块负责那个"拿出来"的动作。
//!
//! # 三条不显然但必须处理的
//!
//! 1. **CSV 公式注入**。进程路径是**攻击者可控**的：一个恶意进程可以把
//!    自己命名为 `=cmd|'/c calc'!A0`，导出后用 Excel 打开就会执行。
//!    按 RFC 4180 加双引号**挡不住**——引号是 CSV 语法，Excel 解析后
//!    看到的仍是以 `=` 开头的内容。必须在这些字段前补一个前导 `'`。
//! 2. **时间统一用 UTC**。本机时区导出的"2026-10-18 09:26"在另一台机器上
//!    无从比对，而证据包恰恰是要跨系统看的。毫秒时间戳一并保留，
//!    因为它是唯一无歧义的那一列。
//! 3. **证据包必须自带校验结论**。只导出事件不导出链头与校验结果，
//!    对方无从判断这批数据有没有被改过——那等于把证据链的作用全丢了。

use crate::chain::{hex, Hash};
use crate::event::{Action, AuditEvent};
use crate::store::Record;
use aegis_core::InterfaceRole;

/// 导出筛选条件（§F3「检索与筛选」）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExportFilter {
    /// 起始时刻（含）
    pub since_ms: Option<u64>,
    /// 结束时刻（含）
    pub until_ms: Option<u64>,
    pub action: Option<Action>,
    pub role: Option<InterfaceRole>,
    /// 只要被拦下的（`blocked_only`）。自证场景最常用的一种。
    pub blocked_only: bool,
}

impl ExportFilter {
    pub fn new() -> Self {
        Self::default()
    }

    /// 只要被本地拦下的记录：自证"没有违规连接出去"时导这个。
    pub fn blocked_only() -> Self {
        Self {
            blocked_only: true,
            ..Self::default()
        }
    }

    pub fn keep(&self, event: &AuditEvent) -> bool {
        if let Some(since) = self.since_ms {
            if event.ts_ms < since {
                return false;
            }
        }
        if let Some(until) = self.until_ms {
            if event.ts_ms > until {
                return false;
            }
        }
        if let Some(a) = self.action {
            if event.action != a {
                return false;
            }
        }
        if let Some(r) = self.role {
            if event.role != r {
                return false;
            }
        }
        if self.blocked_only && !event.action.is_blocked() {
            return false;
        }
        true
    }
}

/// 一份证据包：事件 + 链 + 校验结论 + 生成器版本。
///
/// ⚠ `verified` 是**导出时算出来的**，不是事后填的。
/// 导出必须顺带完成校验，否则对方拿到的只是一堆自称没被改过的数据。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidencePackage {
    /// 生成这份证据包的 Aegis 版本
    pub aegis_version: String,
    pub generated_at_ms: u64,
    /// 链头。**防尾部截断的唯一手段**就是把它外置，这里正是外置的场合
    pub chain_head: Hash,
    pub chain_len: u64,
    pub verified: bool,
    pub records: Vec<Record>,
}

impl EvidencePackage {
    /// 由记录与链头构造，并**立即校验**。
    pub fn build(records: Vec<Record>, chain_head: Hash, generated_at_ms: u64) -> Self {
        let events: Vec<AuditEvent> = records.iter().map(|r| r.event.clone()).collect();
        let links: Vec<_> = records.iter().map(|r| r.link).collect();
        let verified = crate::chain::verify(&events, &links).is_ok();
        Self {
            aegis_version: crate::full_version(),
            generated_at_ms,
            chain_head,
            chain_len: links.len() as u64,
            verified,
            records,
        }
    }
}

// ── CSV ────────────────────────────────────────────────────────────────

const CSV_HEADER: &str = "seq,ts_utc,ts_ms,pid,process_path,src_ip,src_port,dst_ip,dst_port,\
                          protocol,host,rule,luid,role,action,link_prev,link_hash";

/// 导出 CSV。
///
/// 所有文本字段一律按 RFC 4180 加引号；**额外**对以 `= + - @` 或空白开头的
/// 字段补一个前导 `'`，防公式注入（见模块文档）。
pub fn to_csv(records: &[Record]) -> String {
    let mut out = String::with_capacity(records.len() * 160);
    out.push_str(CSV_HEADER);
    out.push('\n');
    for r in records {
        let e = &r.event;
        let row = [
            r.link.seq.to_string(),
            iso8601_utc(e.ts_ms),
            e.ts_ms.to_string(),
            e.pid.to_string(),
            cell(&e.process_path),
            cell(&e.src.ip().to_string()),
            e.src.port().to_string(),
            cell(&e.dst.ip().to_string()),
            e.dst.port().to_string(),
            cell(e.protocol.tag()),
            cell(e.host.as_deref().unwrap_or("")),
            cell(e.rule.as_deref().unwrap_or("")),
            e.luid.to_string(),
            cell(role_tag_str(e.role)),
            cell(e.action.tag()),
            hex(&r.link.prev),
            hex(&r.link.hash),
        ];
        out.push_str(&row.join(","));
        out.push('\n');
    }
    out
}

/// 一个 CSV 单元格：**先按 RFC 4180 引用，再防公式注入**。
///
/// 两步都要：只引用挡不住注入（引号是语法，Excel 解析后仍看到 `=`），
/// 只补 `'` 而不引用则会让含逗号/换行的字段把整行撑坏。
fn cell(s: &str) -> String {
    let mut v = String::with_capacity(s.len() + 2);
    v.push('"');
    // 前导 `'`：Excel / LibreOffice 见到它就把后面当文本，不再当公式。
    //
    // 必须在引号**里面**。放在引号外面（`'=cmd...`）会让整个字段变成
    // 未被引用的裸文本，里面的逗号与引号就不再被按 RFC 4180 解析，
    // 一行照样会被撑开。
    if starts_like_formula(s) {
        v.push('\'');
    }
    for c in s.chars() {
        match c {
            '"' => {
                v.push('"');
                v.push('"');
            }
            // 控制字符写成转义序列**文本**，而不是原样放进去。
            //
            // RFC 4180 允许引用字段里含换行，但那样一条记录就占了多行，
            // 而审计条数本身是要拿去对账的——表格里"共 N 行"必须对得上
            // "共 N 条"。进程名里带换行是攻击者完全做得到的。
            '\n' => v.push_str("\\n"),
            '\r' => v.push_str("\\r"),
            '\t' => v.push_str("\\t"),
            c => v.push(c),
        }
    }
    v.push('"');
    v
}

/// 会不会被表格软件当成公式。
fn starts_like_formula(s: &str) -> bool {
    matches!(s.chars().next(), Some('=' | '+' | '-' | '@' | '\t' | '\r'))
}

fn role_tag_str(role: InterfaceRole) -> &'static str {
    match role {
        InterfaceRole::CampusStrict => "campus-strict",
        InterfaceRole::FreeOutbound => "free-outbound",
        InterfaceRole::Aggregated => "aggregated",
        InterfaceRole::Isolated => "isolated",
    }
}

// ── JSON ───────────────────────────────────────────────────────────────

/// 导出 JSON 证据包。手写转义，不引 serde —— 与帧编码同样的理由：
/// 证据格式要能跨版本稳定复现，交给序列化库就等于把格式交给别人。
pub fn to_json(pkg: &EvidencePackage) -> String {
    let mut out = String::with_capacity(pkg.records.len() * 260 + 400);
    out.push_str("{\n");
    out.push_str("  \"format\": \"aegis-evidence/1\",\n");
    out.push_str(&format!(
        "  \"aegis_version\": \"{}\",\n",
        json_str(&pkg.aegis_version)
    ));
    out.push_str(&format!(
        "  \"generated_at_utc\": \"{}\",\n",
        iso8601_utc(pkg.generated_at_ms)
    ));
    out.push_str(&format!(
        "  \"chain_head\": \"{}\",\n",
        hex(&pkg.chain_head)
    ));
    out.push_str(&format!("  \"chain_len\": {},\n", pkg.chain_len));
    out.push_str(&format!("  \"verified\": {},\n", pkg.verified));
    out.push_str(&format!("  \"record_count\": {},\n", pkg.records.len()));
    out.push_str("  \"records\": [\n");

    for (i, r) in pkg.records.iter().enumerate() {
        let e = &r.event;
        out.push_str("    {");
        out.push_str(&format!("\"seq\":{},", r.link.seq));
        out.push_str(&format!("\"ts_utc\":\"{}\",", iso8601_utc(e.ts_ms)));
        out.push_str(&format!("\"ts_ms\":{},", e.ts_ms));
        out.push_str(&format!("\"pid\":{},", e.pid));
        out.push_str(&format!("\"process_path\":{},", json_str(&e.process_path)));
        out.push_str(&format!("\"src\":\"{}\",", json_str(&e.src.to_string())));
        out.push_str(&format!("\"dst\":\"{}\",", json_str(&e.dst.to_string())));
        out.push_str(&format!("\"protocol\":\"{}\",", e.protocol.tag()));
        out.push_str(&format!(
            "\"host\":{},",
            e.host.as_deref().map(json_str).unwrap_or("null".into())
        ));
        out.push_str(&format!(
            "\"rule\":{},",
            e.rule.as_deref().map(json_str).unwrap_or("null".into())
        ));
        out.push_str(&format!("\"luid\":{},", e.luid));
        out.push_str(&format!("\"role\":\"{}\",", role_tag_str(e.role)));
        out.push_str(&format!("\"action\":\"{}\",", e.action.tag()));
        out.push_str(&format!("\"link_prev\":\"{}\",", hex(&r.link.prev)));
        out.push_str(&format!("\"link_hash\":\"{}\"", hex(&r.link.hash)));
        out.push('}');
        if i + 1 < pkg.records.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str("  ]\n}\n");
    out
}

/// JSON 字符串转义。控制字符一律走 `\u00XX`，不省事写成裸换行——
/// 裸换行在 JSON 里非法，而这正是手写转义最容易漏的一处。
fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

// ── 时间 ───────────────────────────────────────────────────────────────

/// epoch 毫秒 → `YYYY-MM-DDTHH:MM:SS.mmmZ`（**恒为 UTC**）。
///
/// 刻意不引 chrono / time：一个日期换算不值得拉进一个依赖，
/// 而证据格式要的是跨十年也能复现，算法写死在这里反而更稳。
pub fn iso8601_utc(ms: u64) -> String {
    let secs = ms / 1000;
    let millis = ms % 1000;
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        y,
        m,
        d,
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60,
        millis
    )
}

/// 1970-01-01 起的天数 → 公历 (年, 月, 日)。Howard Hinnant 算法。
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::EvidenceChain;
    use crate::event::Protocol;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn event(n: u16, action: Action) -> AuditEvent {
        AuditEvent {
            ts_ms: 1_700_000_000_000 + u64::from(n) * 1000,
            pid: 1000 + u32::from(n),
            process_path: format!(r"C:\App\app{n}.exe"),
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 50000 + n),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443),
            protocol: Protocol::Tcp,
            host: Some("example.com".to_string()),
            rule: None,
            luid: 42,
            role: InterfaceRole::CampusStrict,
            action,
        }
    }

    fn records() -> Vec<Record> {
        let mut chain = EvidenceChain::new();
        let actions = [
            Action::Allow,
            Action::Reject,
            Action::FirewallBlock,
            Action::PlaintextBlock,
        ];
        actions
            .iter()
            .enumerate()
            .map(|(i, a)| {
                let e = event(i as u16, *a);
                let link = chain.append(&e);
                Record { event: e, link }
            })
            .collect()
    }

    #[test]
    fn iso8601_is_utc_and_matches_known_values() {
        assert_eq!(iso8601_utc(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso8601_utc(1_700_000_000_000), "2023-11-14T22:13:20.000Z");
        assert_eq!(iso8601_utc(1_700_000_000_123), "2023-11-14T22:13:20.123Z");
        assert_eq!(iso8601_utc(1_760_779_587_000), "2025-10-18T09:26:27.000Z");
    }

    /// 跨年与闰年边界：日期算法最容易在 2 月 29 日翻车。
    #[test]
    fn leap_day_and_year_boundary_are_correct() {
        // 2024-02-29T00:00:00Z
        assert!(iso8601_utc(1_709_164_800_000).starts_with("2024-02-29"));
        // 2023-12-31T23:59:59Z → 2024-01-01
        assert!(iso8601_utc(1_704_067_199_000).starts_with("2023-12-31"));
        assert!(iso8601_utc(1_704_067_200_000).starts_with("2024-01-01"));
        // 2100 不是闰年（格里高利百年规则），算法必须知道
        assert!(iso8601_utc(4_107_542_400_000).starts_with("2100-03-01"));
    }

    // ── CSV 公式注入（本模块最重要的安全点）────────────────────────

    /// 恶意进程可以把自己命名成公式。只加 RFC4180 引号**挡不住**——
    /// 引号是 CSV 语法，Excel 解析后看到的仍是以 `=` 开头的内容。
    #[test]
    fn csv_formula_injection_is_neutralised() {
        for nasty in [
            r"=cmd|'/c calc'!A0",
            r"+SUM(1+1)",
            r"-2+3+cmd|'/c calc'!A0",
            r"@SUM(1+1)*cmd|'/c calc'!A0",
        ] {
            let c = cell(nasty);
            // 引号内必须以 ' 打头，这样表格软件把它当文本
            assert!(c.starts_with("\"'"), "未中和公式：{c}");
            assert!(c.contains(nasty), "原文应保留，只是加了前导符：{c}");
        }
    }

    /// 普通路径不该被无谓地改样——只在真的像公式时才动。
    #[test]
    fn ordinary_paths_are_left_alone() {
        assert_eq!(cell(r"C:\App\app.exe"), "\"C:\\App\\app.exe\"");
        assert_eq!(cell(""), "\"\"");
    }

    /// 引号与换行必须转义，否则一行会被撑成多行 —— 那会让"5 条记录"
    /// 在表格里变成 9 行，而审计条数本身就是要拿去对账的。
    #[test]
    fn quotes_and_newlines_do_not_break_the_row_structure() {
        assert_eq!(cell(r#"a"b"#), "\"a\"\"b\"");
        assert_eq!(cell(r#"a""b"#), "\"a\"\"\"\"b\"");
        // 控制字符写成字面转义序列：一条记录必须只占一行，
        // 否则"共 N 行"对不上"共 N 条"，而条数是拿去对账的
        assert_eq!(cell("a\nb"), "\"a\\nb\"");
        assert_eq!(cell("a\tb"), "\"a\\tb\"");
        assert_eq!(cell("a,b"), "\"a,b\"");

        let mut e = event(0, Action::Allow);
        e.process_path = "a,b\nc\"d".to_string();
        let csv = to_csv(&[Record {
            event: e,
            link: EvidenceChain::new().append(&event(0, Action::Allow)),
        }]);
        let lines: Vec<&str> = csv.trim_end().split('\n').collect();
        assert_eq!(lines.len(), 2, "表头 + 1 条数据，不该被撑开：{csv}");
    }

    #[test]
    fn csv_has_a_header_and_one_line_per_record() {
        let rs = records();
        let csv = to_csv(&rs);
        let lines: Vec<&str> = csv.trim_end().split('\n').collect();
        assert_eq!(lines.len(), rs.len() + 1, "{csv}");
        assert!(lines[0].starts_with("seq,ts_utc,ts_ms"));
        // 每条都带上链节，否则对方无法验证
        assert!(!lines[1].contains("link_hash"));
        assert!(lines[1].split(',').count() == lines[0].split(',').count());
    }

    // ── JSON ────────────────────────────────────────────────────────

    #[test]
    fn json_is_wellformed_with_escaping() {
        let mut e = event(0, Action::Reject);
        e.process_path = r#"C:\path\with"quote\and\backslash.exe"#.to_string();
        let link = EvidenceChain::new().append(&e);
        let pkg = EvidencePackage::build(vec![Record { event: e, link }], link.hash, 0);
        let s = to_json(&pkg);
        assert!(s.contains(r#""process_path":"C:\\path\\with\"quote\\and\\backslash.exe""#), "{s}");
        assert!(s.trim_end().ends_with('}'));
    }

    #[test]
    fn json_marks_missing_enrichment_as_null_not_empty_string() {
        let mut e = event(0, Action::Allow);
        e.host = None;
        let link = EvidenceChain::new().append(&e);
        let pkg = EvidencePackage::build(vec![Record { event: e, link }], link.hash, 0);
        assert!(to_json(&pkg).contains("\"host\":null"), "缺失应显 null");
    }

    // ── 证据包自带校验 ──────────────────────────────────────────────

    /// 导出必须顺带校验：只导出事件不导出结论，
    /// 对方无从判断这批数据有没有被改过。
    #[test]
    fn a_healthy_package_reports_verified() {
        let rs = records();
        let head = rs.last().unwrap().link.hash;
        let pkg = EvidencePackage::build(rs, head, 1_700_000_000_000);
        assert!(pkg.verified);
        assert_eq!(pkg.chain_len, 4);
        assert!(pkg.verified);
        assert!(!pkg.aegis_version.is_empty());
        assert!(to_json(&pkg).contains("\"verified\": true"));
    }

    /// 被改过的记录，证据包必须自己说"我没通过校验"——
    /// 而不是让人拿到后才发现对不上。
    #[test]
    fn a_tampered_package_reports_unverified() {
        let mut rs = records();
        rs[2].event.action = Action::Allow; // 把阻断改成放行
        let head = rs.last().unwrap().link.hash;
        let pkg = EvidencePackage::build(rs, head, 0);
        assert!(!pkg.verified);
        assert!(to_json(&pkg).contains("\"verified\": false"));
    }

    // ── 筛选 ────────────────────────────────────────────────────────

    #[test]
    fn blocked_only_keeps_the_three_blocking_actions() {
        let rs = records();
        let kept: Vec<_> = rs
            .iter()
            .filter(|r| ExportFilter::blocked_only().keep(&r.event))
            .collect();
        assert_eq!(kept.len(), 3, "放行那条应被滤掉");
        assert!(kept.iter().all(|r| r.event.action.is_blocked()));
    }

    #[test]
    fn time_range_and_action_filters_compose() {
        let rs = records();
        let f = ExportFilter {
            since_ms: Some(1_700_000_001_000),
            until_ms: Some(1_700_000_002_000),
            ..Default::default()
        };
        let kept: Vec<_> = rs.iter().filter(|r| f.keep(&r.event)).collect();
        assert_eq!(kept.len(), 2);

        let f = ExportFilter {
            action: Some(Action::Reject),
            ..Default::default()
        };
        assert_eq!(rs.iter().filter(|r| f.keep(&r.event)).count(), 1);
    }

    #[test]
    fn filter_boundaries_are_inclusive() {
        let e = event(1, Action::Allow);
        let ts = e.ts_ms;
        let f = ExportFilter {
            since_ms: Some(ts),
            until_ms: Some(ts),
            ..Default::default()
        };
        assert!(f.keep(&e), "边界应为闭区间");
        let f = ExportFilter {
            since_ms: Some(ts + 1),
            ..Default::default()
        };
        assert!(!f.keep(&e));
    }
}
