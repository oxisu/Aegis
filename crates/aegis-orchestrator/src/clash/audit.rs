//! 把 mihomo / Clash 的连接级元数据翻译成 `aegis-audit` 的审计事件。
//!
//! # 这是**第二审计源**（可选富化），不是裁决
//!
//! 设计文档（design-spec §2A / §12 F3）把审计分成两层：
//!
//! - **第一审计源（权威）**：WFP ALE 内核层。它知道每条包**有没有被裁决**、
//!   从**哪张物理网卡**出去——这才是"出网"这件事的真相。
//! - **第二审计源（可选富化）**：就是这里的 mihomo `/connections`。
//!   它**只**能看到"经过代理的那批连接"，而且有两件事它给不了：它**没有**
//!   WFP 裁决——"出现在代理连接表"只说明包没被本地掐死，不代表"本机允许它
//!   出去"（WFP 可能在真实网卡前 DROP 了它，那种包根本不会进代理表）；它
//!   **不知道**这条连接最终从哪张物理网卡出去（那是 WFP / 路由表的事）。
//!
//! 因此本模块的映射**绝不伪造裁决证据**：
//!
//! | 字段 | 取值 | 为什么 |
//! |---|---|---|
//! | `action` | [`Action::Observed`] | 代理侧观测，非裁决、非阻断（`is_blocked() == false`） |
//! | `role`   | [`InterfaceRole::Unknown`] | 代理不知道出口网卡，硬塞进某角色等于伪造证据 |
//! | `luid`   | `0` | 同上，没有真实网卡的 LUID |
//! | `pid`    | `0` | mihomo 不给进程 PID（只给路径） |
//! | `host` / `rule` | `Option` | 富化字段，拉不到就是 `None`，不影响基本记录 |
//!
//! ⚠ `InterfaceRole::Unknown` 在 `aegis-core` 里被钉死为 **fail-closed**
//! （`allows_egress()` / `locks_dns()` 都返回 `false`）：一条"不知道走了哪张
//! 网卡"的记录，绝不能因此被当成"走白名单放行了"。这正是第二审计源接入时
//! 最容易犯的错——把代理看到的连接冒充成"已裁决放行"。

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use aegis_audit::event::{Action, AuditEvent, Protocol};
use aegis_core::InterfaceRole;

use crate::clash::wire::{Connection, Connections};

/// 把**一条** mihomo 连接翻译成一条审计事件。
///
/// `now_ms` 是"本机当前时刻（毫秒）"，**仅当** `start` 解析失败时用作兜底——
/// 正常情况下时间戳取连接真实建立时刻（`start`，RFC3339）。
///
/// 单条连接解析失败（例如 IP 畸形）不会让整批失败：畸形 IP 退化为
/// `0.0.0.0:<port>`，连接本身仍是可观测事实，丢掉它反而隐藏了活动。
pub fn connection_to_audit_event(conn: &Connection, now_ms: u64) -> AuditEvent {
    let src = socket_addr(&conn.metadata.source_ip, conn.metadata.source_port.as_u16());
    let dst = socket_addr(
        &conn.metadata.destination_ip,
        conn.metadata.destination_port.as_u16(),
    );
    let protocol = protocol_from_transport(&conn.metadata.transport);
    let host = if conn.metadata.host.is_empty() {
        None
    } else {
        Some(conn.metadata.host.clone())
    };
    let rule = combine_rule(&conn.rule, &conn.rule_payload);
    let ts_ms = parse_rfc3339_to_ms(&conn.start).unwrap_or(now_ms);

    AuditEvent {
        ts_ms,
        pid: 0,
        process_path: conn.metadata.process_path.clone(),
        src,
        dst,
        protocol,
        host,
        rule,
        luid: 0,
        role: InterfaceRole::Unknown,
        action: Action::Observed,
    }
}

/// 批量映射。空连接表返回空 `Vec`，不报错——第二审计源"没有连接"不是故障。
pub fn connections_to_audit_events(conns: &Connections, now_ms: u64) -> Vec<AuditEvent> {
    conns
        .connections
        .iter()
        .map(|c| connection_to_audit_event(c, now_ms))
        .collect()
}

// ── 内部：把 mihomo 的字段安全翻译成 `AuditEvent` 的子值 ──────────────────

/// 拼出 `SocketAddr`。IP 解析失败退化为 `0.0.0.0`，端口缺失退化为 `0`。
///
/// ⚠ 退化但不丢弃：审计要的是"这条连接存在过"，地址解析失败是代理的
///   数据质量问题，不是"这条连接不存在"的理由。
fn socket_addr(ip: &str, port: Option<u16>) -> SocketAddr {
    let parsed: IpAddr = match ip.trim().parse() {
        Ok(ip) => ip,
        Err(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    };
    SocketAddr::new(parsed, port.unwrap_or(0))
}

/// mihomo 的 `type` 字段是**传输层类型**（`tcp` / `udp`）。
/// 其它取值（理论上不会出现）没有对应的 IP 协议号，归到 `Other(0)` 并标注
/// "代理未给出 IP 协议号"，绝不猜成某个具体协议。
fn protocol_from_transport(t: &str) -> Protocol {
    match t {
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        _ => Protocol::Other(0),
    }
}

/// 命中规则：类型 + 载荷拼成一条可读记录（如 `GeoSite/cn`）。
///
/// 两者都为空 → `None`（没富化到，不是"富化到了空串"）。只命中类型
/// （`rule` 非空、`rule_payload` 空）也要保留——"命中了 GeoSite"本身有意义。
fn combine_rule(rule: &str, payload: &str) -> Option<String> {
    if rule.is_empty() {
        return None;
    }
    if payload.is_empty() {
        return Some(rule.to_string());
    }
    Some(format!("{rule}/{payload}"))
}

// ── 内部：RFC3339 → 毫秒时间戳 ───────────────────────────────────────────
//
// mihomo 给 `start` 的是 RFC3339 字符串（实测形如
// `2026-10-20T04:32:11.123456789Z`）。本 crate 刻意不引 chrono 之类的日期库
// （与"手写 HTTP/1.1"同一哲学：只为了一个解析就拖一整套日历库不划算），
// 这里手写一个**只覆盖 mihomo 实际产出形态**的最小解析器并钉死测试。
//
// 解析失败返回 `None`，由调用方回退到 `now_ms`。

/// 把 RFC3339 时间戳解析成"自 Unix 纪元起的毫秒"。
///
/// 支持：`YYYY-MM-DDTHH:MM:SS(.fffffffff)?(Z | ±HH:MM)`。
/// 偏移量按"本地 = UTC + 偏移"处理，UTC = 本地 − 偏移。
fn parse_rfc3339_to_ms(s: &str) -> Option<u64> {
    let s = s.trim();
    let (date, time_off) = s.split_once('T')?;
    let (y, m, d) = parse_ymd(date)?;
    if !is_valid_ymd(y, m, d) {
        return None;
    }

    // 在 time_off 里找偏移起点（'Z' / '+' / '-'），之前是时间、之后是偏移。
    let (time, offset) = match time_off.find(|c| ['Z', '+', '-'].contains(&c)) {
        Some(i) => (&time_off[..i], &time_off[i..]),
        None => (time_off, "Z"), // 没写偏移按 UTC 处理（宽松，mihomo 不会这样）
    };

    let (hh, mm, ss, frac_ms) = parse_time(time)?;
    let offset_ms = parse_offset(offset)?;

    let days = days_from_civil(y, m, d)?;
    // 用 i64 算，避免 2038 问题；允许闰秒（ss=60）
    let local_ms = days * 86_400 * 1000 + hh * 3_600_000 + mm * 60_000 + ss * 1000 + frac_ms;
    let utc_ms = local_ms - offset_ms;
    if utc_ms < 0 {
        return None; // 早于纪元，本场景不会出现，直接判失败
    }
    Some(utc_ms as u64)
}

fn parse_ymd(s: &str) -> Option<(i64, i64, i64)> {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 3 {
        return None;
    }
    let y = parts[0].parse::<i64>().ok()?;
    let m = parts[1].parse::<i64>().ok()?;
    let d = parts[2].parse::<i64>().ok()?;
    Some((y, m, d))
}

/// 严格校验日历日期合法（含月长与闰年）。`days_from_civil` 只做算术、
/// 不拒绝"2 月 29 日出现在平年"这类非法日期，所以这里补一层。
fn is_valid_ymd(y: i64, m: i64, d: i64) -> bool {
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return false;
    }
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let max = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if leap {
                29
            } else {
                28
            }
        },
        _ => return false,
    };
    d <= max
}

/// `HH:MM:SS(.frac)?` → (时, 分, 秒, 毫秒小数)。
fn parse_time(t: &str) -> Option<(i64, i64, i64, i64)> {
    let (hms, frac) = match t.split_once('.') {
        Some((hms, frac)) => (hms, frac),
        None => (t, ""),
    };
    let parts: Vec<&str> = hms.split(':').collect();
    if parts.len() != 3 {
        return None;
    }
    let hh = parts[0].parse::<i64>().ok()?;
    let mm = parts[1].parse::<i64>().ok()?;
    let ss = parts[2].parse::<i64>().ok()?;
    if !(0..=23).contains(&hh) || !(0..=59).contains(&mm) || !(0..=60).contains(&ss) {
        return None;
    }
    Some((hh, mm, ss, frac_to_ms(frac)))
}

/// 小数秒 → 毫秒（最多取前 3 位，超出截断）。`.1` → 100ms，`.1234` → 123ms。
fn frac_to_ms(frac: &str) -> i64 {
    let mut v = 0i64;
    let mut scale = 100; // 第一位小数是 100ms
    for c in frac.chars().take(3) {
        let d = match c.to_digit(10) {
            Some(d) => d as i64,
            None => break,
        };
        v += d * scale;
        scale /= 10;
    }
    v
}

/// 解析偏移量（毫秒，正 = 本地比 UTC 早）。`Z`/`z` → 0；`+08:00` → +28800000。
fn parse_offset(off: &str) -> Option<i64> {
    match off.chars().next() {
        None | Some('Z') | Some('z') => Some(0),
        Some('+') | Some('-') => {
            let sign = if off.starts_with('+') { 1 } else { -1 };
            let body = &off[1..];
            let (h, m) = body.split_once(':')?;
            let h: i64 = h.parse().ok()?;
            let m: i64 = m.parse().ok()?;
            Some(sign * (h * 3600 + m * 60) * 1000)
        },
        _ => None,
    }
}

/// Howard Hinnant 的 `days_from_civil` 算法（Gregorian，1..=9999 年，截断除法
/// 在 Rust 下对负数也正确）。返回"自 1970-01-01 起的天数"。
fn days_from_civil(y: i64, m: i64, d: i64) -> Option<i64> {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    Some(era * 146097 + doe - 719468)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // 与 wire.rs 的 REAL_CONN 同形，但作为本模块解析/映射的钉死样本。
    const CONN_TCP: &str = r#"{
        "id": "abc123",
        "upload": 1234,
        "download": 5678,
        "start": "2026-10-20T04:32:11.123456789Z",
        "chains": ["DIRECT"],
        "rule": "GeoSite",
        "rulePayload": "cn",
        "providerChains": [],
        "metadata": {
            "sourceIP": "192.168.1.5",
            "sourcePort": "54321",
            "destinationIP": "1.2.3.4",
            "destinationPort": "443",
            "host": "example.com",
            "type": "tcp",
            "network": "tcp",
            "processPath": "C:\\Program Files\\x\\y.exe",
            "process": "y.exe",
            "specialProxy": ""
        }
    }"#;

    const CONN_UDP_NO_HOST: &str = r#"{
        "id": "udp1",
        "upload": 0,
        "download": 0,
        "start": "2026-10-20T04:33:00Z",
        "chains": [],
        "metadata": {
            "sourceIP": "fe80::1",
            "sourcePort": 54321,
            "destinationIP": "2606:4700::1111",
            "destinationPort": "53",
            "type": "udp",
            "processPath": ""
        }
    }"#;

    fn one_connection(raw: &str) -> Connection {
        serde_json::from_str(raw).expect("CONN JSON 必须能解析")
    }

    #[test]
    fn maps_tcp_connection_fields_honestly() {
        let c = one_connection(CONN_TCP);
        let e = connection_to_audit_event(&c, 9_999_999_999_999);

        // 诚实标注：代理侧观测 + 未知网卡 + 无 LUID + 无 PID
        assert_eq!(e.action, Action::Observed);
        assert_eq!(e.role, InterfaceRole::Unknown);
        assert_eq!(e.luid, 0);
        assert_eq!(e.pid, 0);
        assert!(!e.action.is_blocked(), "Observed 绝不能进被阻断专视图");

        // 地址与传输层
        assert_eq!(
            e.src,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)), 54321)
        );
        assert_eq!(
            e.dst,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443)
        );
        assert_eq!(e.protocol, Protocol::Tcp);

        // 富化字段按需填充
        assert_eq!(e.host.as_deref(), Some("example.com"));
        assert_eq!(e.rule.as_deref(), Some("GeoSite/cn"));
        assert_eq!(e.process_path, r"C:\Program Files\x\y.exe");

        // 时间戳取真实建立时刻，而不是兜底值（兜底值 9_999_999_999_999 不该出现）
        assert_ne!(e.ts_ms, 9_999_999_999_999);
    }

    #[test]
    fn maps_udp_with_empty_host_and_rule_to_nones() {
        let c = one_connection(CONN_UDP_NO_HOST);
        let e = connection_to_audit_event(&c, 0);

        assert_eq!(e.protocol, Protocol::Udp);
        // IPv6 源/目的
        assert_eq!(
            e.src,
            SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
                54321
            )
        );
        assert_eq!(
            e.dst,
            SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1111)),
                53
            )
        );
        // host / rule 都空 → None（第二审计源缺失富化字段）
        assert_eq!(e.host, None);
        assert_eq!(e.rule, None);
        // 数字形态的端口也要收（wire.rs 已保证 as_u16）
        assert_eq!(e.dst.port(), 53);
    }

    #[test]
    fn empty_connections_yield_empty_events() {
        let conns: Connections = serde_json::from_str(r#"{"connections":[]}"#).unwrap();
        let out = connections_to_audit_events(&conns, 0);
        assert!(out.is_empty());
    }

    #[test]
    fn batch_maps_every_connection() {
        let body = format!(r#"{{"connections":[{}]}}"#, CONN_TCP);
        let conns: Connections = serde_json::from_str(&body).unwrap();
        let out = connections_to_audit_events(&conns, 0);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].action, Action::Observed);
    }

    #[test]
    fn bad_start_falls_back_to_now() {
        let mut c = one_connection(CONN_TCP);
        c.start = "not-a-timestamp".to_string();
        let e = connection_to_audit_event(&c, 7_777_777_777_777);
        assert_eq!(e.ts_ms, 7_777_777_777_777, "解析失败必须回退到 now_ms");
    }

    #[test]
    fn malformed_ip_degrades_without_dropping_record() {
        let mut c = one_connection(CONN_TCP);
        c.metadata.source_ip = "not-an-ip".to_string();
        let e = connection_to_audit_event(&c, 0);
        // 退化成 0.0.0.0，但记录仍在、其它字段正常
        assert_eq!(e.src.ip(), IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(e.src.port(), 54321);
        assert_eq!(e.action, Action::Observed);
    }

    // ── RFC3339 解析器钉死测试 ─────────────────────────────────────────

    #[test]
    fn epoch_beginning_is_zero() {
        assert_eq!(parse_rfc3339_to_ms("1970-01-01T00:00:00Z"), Some(0));
    }

    #[test]
    fn one_day_is_86400000_ms() {
        let a = parse_rfc3339_to_ms("1970-01-02T00:00:00Z").unwrap();
        let b = parse_rfc3339_to_ms("1970-01-01T00:00:00Z").unwrap();
        assert_eq!(a - b, 86_400_000);
    }

    #[test]
    fn fractional_seconds_scale_correctly() {
        let base = parse_rfc3339_to_ms("2026-10-20T04:32:11Z").unwrap();
        let ms100 = parse_rfc3339_to_ms("2026-10-20T04:32:11.1Z").unwrap();
        let ms123 = parse_rfc3339_to_ms("2026-10-20T04:32:11.123Z").unwrap();
        let ms123_trunc = parse_rfc3339_to_ms("2026-10-20T04:32:11.123456789Z").unwrap();
        assert_eq!(ms100 - base, 100, ".1 应等于 100ms");
        assert_eq!(ms123 - base, 123, ".123 应等于 123ms");
        assert_eq!(ms123_trunc - base, 123, "超过 3 位应截断到 123ms");
    }

    #[test]
    fn positive_offset_shifts_back_to_utc() {
        // 本地 12:32:11 +08:00 == UTC 04:32:11
        let local = parse_rfc3339_to_ms("2026-10-20T12:32:11+08:00").unwrap();
        let utc = parse_rfc3339_to_ms("2026-10-20T04:32:11Z").unwrap();
        assert_eq!(local, utc, "+08:00 的本地时刻应换算回同一 UTC 瞬间");
    }

    #[test]
    fn negative_offset_shifts_forward_to_utc() {
        // 本地 00:32:11 -05:00 == UTC 05:32:11
        let local = parse_rfc3339_to_ms("2026-10-20T00:32:11-05:00").unwrap();
        let utc = parse_rfc3339_to_ms("2026-10-20T05:32:11Z").unwrap();
        assert_eq!(local, utc);
    }

    #[test]
    fn leap_day_valid_only_in_leap_years() {
        assert!(
            parse_rfc3339_to_ms("2024-02-29T00:00:00Z").is_some(),
            "2024 是闰年"
        );
        assert!(
            parse_rfc3339_to_ms("2023-02-29T00:00:00Z").is_none(),
            "2023 不是闰年"
        );
    }

    #[test]
    fn garbage_timestamp_is_rejected() {
        assert_eq!(parse_rfc3339_to_ms(""), None);
        assert_eq!(parse_rfc3339_to_ms("hello"), None);
        assert_eq!(
            parse_rfc3339_to_ms("2026-13-01T00:00:00Z"),
            None,
            "月份越界"
        );
        assert_eq!(
            parse_rfc3339_to_ms("2026-10-20T25:00:00Z"),
            None,
            "小时越界"
        );
        assert_eq!(parse_rfc3339_to_ms("2026-10-20"), None, "缺 T");
    }

    // ── 端到端：适配器拉取 → 解析 → 映射成 Observed（数据通路钉死）────────
    //
    // 起一个假 mihomo 控制口，喂一份真实形状的 `/connections` 响应，确认
    // `ClashAdapter::connections()` 能解析、且映射产物是诚实的 `Observed`。
    #[test]
    fn end_to_end_adapter_fetch_maps_to_observed() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        let body = r#"{"connections":[{"id":"x1","upload":0,"download":0,
            "start":"2026-10-20T04:32:11Z",
            "rule":"GeoSite","rulePayload":"cn",
            "metadata":{"sourceIP":"10.0.0.1","sourcePort":"1111",
            "destinationIP":"1.1.1.1","destinationPort":"443",
            "type":"tcp","host":"example.com","processPath":"C:\\a.exe"}}],
            "uploadTotal":0,"downloadTotal":0}"#;

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(resp.as_bytes());
        });

        let adapter = crate::clash::ClashAdapter::new(crate::clash::ClashConfig {
            addr,
            secret: String::new(),
            tun_candidates: Vec::new(),
            expected_providers: Vec::new(),
        });
        let conns = adapter.connections().expect("应成功拉取连接");
        let events = connections_to_audit_events(&conns, 0);

        assert_eq!(events.len(), 1, "1 条连接 → 1 条事件");
        assert_eq!(events[0].action, aegis_audit::event::Action::Observed);
        assert_eq!(events[0].role, aegis_core::InterfaceRole::Unknown);
        assert_eq!(events[0].host.as_deref(), Some("example.com"));
        assert_eq!(events[0].rule.as_deref(), Some("GeoSite/cn"));
        assert_eq!(events[0].dst.port(), 443);

        server.join().unwrap();
    }
}
