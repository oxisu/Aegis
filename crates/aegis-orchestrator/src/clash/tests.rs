//! 适配器的行为测试。
//!
//! 用**本地假 mihomo**（一个 `TcpListener`）而不是用户的真实 Clash：
//! 真实实例的规则集、连接数、端口都不受控，而且测试不该去碰别人正在跑的
//! 代理软件。夹具里的 JSON 全部取自 2026-10-20 对 v1.19.32 的实测。

use super::*;
use crate::spi::invoke_checked;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

/// 起一个假控制口。`routes` 是 `(路径, 响应体)`，按路径匹配（忽略 `?query`）。
/// 返回 `addr`。
fn mock(routes: &[(&str, &str)]) -> String {
    // 转成 owned 再进线程：`thread::spawn` 要 `'static`，借用的夹具进不去。
    // 这样调用方也能用运行时拼出来的路径，不必全是字面量。
    let routes: Vec<(String, String)> = routes
        .iter()
        .map(|(p, b)| (p.to_string(), b.to_string()))
        .collect();
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap().to_string();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let mut buf = [0u8; 8192];
            let Ok(n) = s.read(&mut buf) else { continue };
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let path = req.split_whitespace().nth(1).unwrap_or("");
            let base = path.split('?').next().unwrap_or("");
            let body = routes
                .iter()
                .find(|(p, _)| p == base)
                .map(|(_, b)| b.as_str())
                .unwrap_or("{}");
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = s.write_all(resp.as_bytes());
        }
    });
    addr
}

/// 指向一个**没人监听**的端口（用来测"控制口连不上"）。
fn dead_addr() -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();
    drop(l);
    addr
}

fn adapter(addr: &str, expected: &[&str]) -> ClashAdapter {
    ClashAdapter::new(ClashConfig {
        addr: addr.to_string(),
        secret: "s".into(),
        tun_candidates: vec!["Mihomo".into()],
        expected_providers: expected.iter().map(|s| s.to_string()).collect(),
    })
}

const CFG_TUN_OFF: &str = r#"{"mode":"rule","mixed-port":7897,"allow-lan":false,"log-level":"info",
        "tun":{"enable":false,"device":"","stack":"gVisor"}}"#;
const CFG_TUN_ON: &str = r#"{"mode":"rule","mixed-port":7897,"allow-lan":false,
        "log-level":"info","tun":{"enable":true,"device":"Mihomo","stack":"gVisor"}}"#;

// ── 能力声明 ────────────────────────────────────────────────────────

// 声明了 mihomo 没有的接口 = 骗调用方。DefaultEgress 改的是路由表，
// 上游根本没有这个 API —— 这一条钉住"别顺手把它加上"。
#[test]
fn declares_only_real_capabilities() {
    let a = adapter("127.0.0.1:1", &[]);
    let caps = a.capabilities();
    assert!(caps.contains(&Capability::HealthProbe));
    assert!(caps.contains(&Capability::RuleEffectiveness));
    assert!(
        !caps.contains(&Capability::DefaultEgress),
        "mihomo 没有改默认出口的 API，声明它等于骗调用方"
    );
    assert!(
        !caps.contains(&Capability::ConfigFragmentGenerate),
        "mihomo 自带配置，不需要 Aegis 产片段"
    );
}

// 未声明的能力调用即 Unsupported，且**不该**发出任何网络请求
#[test]
fn undeclared_capability_is_refused_before_any_io() {
    let a = adapter(&dead_addr(), &[]);
    let err = invoke_checked(
        &a,
        Op::DefaultEgress {
            interface: "以太网",
        },
    )
    .unwrap_err();
    assert!(matches!(err, AdapterError::Unsupported(_)));
}

// ── 健康探针 ────────────────────────────────────────────────────────

#[test]
fn health_reports_version() {
    let addr = mock(&[("/version", r#"{"meta":true,"version":"v1.19.32"}"#)]);
    let a = adapter(&addr, &[]);
    let out = invoke_checked(&a, Op::Health).unwrap();
    assert_eq!(
        out,
        Outcome::Healthy {
            version: "v1.19.32".into()
        }
    );
}

#[test]
fn health_failure_is_an_error_not_a_healthy_guess() {
    // 判不出版本就说判不出，绝不返回空字符串冒充"健康"
    let a = adapter(&dead_addr(), &[]);
    assert!(invoke_checked(&a, Op::Health).is_err());
}

// ── TUN ─────────────────────────────────────────────────────────────

#[test]
fn tun_absent_when_disabled() {
    let addr = mock(&[("/configs", CFG_TUN_OFF)]);
    let a = adapter(&addr, &[]);
    let out = invoke_checked(
        &a,
        Op::TunPresent {
            candidates: &["Mihomo".into()],
        },
    )
    .unwrap();
    assert_eq!(out, Outcome::TunAbsent);
}

#[test]
fn tun_present_when_device_matches_allowlist() {
    let addr = mock(&[("/configs", CFG_TUN_ON)]);
    let a = adapter(&addr, &[]);
    let out = invoke_checked(
        &a,
        Op::TunPresent {
            candidates: &["Mihomo".into()],
        },
    )
    .unwrap();
    assert_eq!(
        out,
        Outcome::TunPresent {
            name: "Mihomo".into()
        }
    );
}

// 有 TUN 但不是放行名单里那张 —— 与"没有"同样不可用，不能报 Present
#[test]
fn tun_present_but_not_in_allowlist_is_absent() {
    let addr = mock(&[("/configs", CFG_TUN_ON)]);
    let a = adapter(&addr, &[]);
    let out = invoke_checked(
        &a,
        Op::TunPresent {
            candidates: &["WLAN".into()],
        },
    )
    .unwrap();
    assert_eq!(out, Outcome::TunAbsent);
}

// 实测本机 tun.enable=false，device 为空串。空设备名无法比对，不能当成"有"
#[test]
fn tun_enabled_without_device_name_is_absent() {
    let raw = r#"{"mode":"rule","mixed-port":1,"allow-lan":false,"log-level":"info",
        "tun":{"enable":true,"device":"","stack":"gVisor"}}"#;
    let addr = mock(&[("/configs", raw)]);
    let a = adapter(&addr, &[]);
    let out = invoke_checked(
        &a,
        Op::TunPresent {
            candidates: &["Mihomo".into()],
        },
    )
    .unwrap();
    assert_eq!(out, Outcome::TunAbsent);
}

// ── DNS 归属 ────────────────────────────────────────────────────────

#[test]
fn dns_owned_follows_tun() {
    let on = mock(&[("/configs", CFG_TUN_ON)]);
    assert_eq!(
        invoke_checked(&adapter(&on, &[]), Op::Dns).unwrap(),
        Outcome::DnsOwned {
            owner: "Mihomo".into()
        }
    );
    let off = mock(&[("/configs", CFG_TUN_OFF)]);
    assert_eq!(
        invoke_checked(&adapter(&off, &[]), Op::Dns).unwrap(),
        Outcome::DnsNotOwned
    );
}

// ── 规则生效性：整段设计里最要紧的一组 ──────────────────────────────

// ⚠⚠ 这条是本模块存在的理由：控制口连不上必须映射成 **RulesUnknown**（永不收紧），
// 而**不是** RulesIneffective（收紧）。误断整机的代价远高于漏判。
#[test]
fn unreachable_controller_is_unknown_never_ineffective() {
    let a = adapter(&dead_addr(), &["campus"]);
    let out = invoke_checked(&a, Op::RulesEffective).unwrap();
    assert!(
        matches!(out, Outcome::RulesUnknown { .. }),
        "控制口连不上必须判不了，得到 {out:?}"
    );
}

// 响应不是合法 JSON：同样判不了（而不是"没生效"）
#[test]
fn malformed_response_is_unknown() {
    let addr = mock(&[("/providers/rules", "not json at all")]);
    let a = adapter(&addr, &["campus"]);
    assert!(matches!(
        invoke_checked(&a, Op::RulesEffective).unwrap(),
        Outcome::RulesUnknown { .. }
    ));
}

#[test]
fn missing_provider_is_ineffective() {
    // 规则集没加载 = 静默失效的经典形态：进程好好的、端口通着、
    // 但白名单根本没生效
    let addr = mock(&[
        ("/providers/rules", r#"{"providers":{}}"#),
        (
            "/rules",
            r#"{"rules":[{"type":"Match","payload":"","proxy":"DIRECT"}]}"#,
        ),
    ]);
    let a = adapter(&addr, &["campus"]);
    match invoke_checked(&a, Op::RulesEffective).unwrap() {
        Outcome::RulesIneffective { failed } => {
            assert!(failed.iter().any(|f| f.contains("campus")), "{failed:?}");
        },
        other => panic!("期望 RulesIneffective，得到 {other:?}"),
    }
}

// ruleCount=0 是另一个陷阱：provider 在、内容是空的
#[test]
fn empty_provider_is_ineffective() {
    let addr = mock(&[
        (
            "/providers/rules",
            r#"{"providers":{"campus":{"name":"campus","type":"Rule",
                "vehicleType":"File","ruleCount":0,"updatedAt":"1700000000000"}}}"#,
        ),
        (
            "/rules",
            r#"{"rules":[{"type":"Match","payload":"","proxy":"DIRECT"}]}"#,
        ),
    ]);
    let a = adapter(&addr, &["campus"]);
    match invoke_checked(&a, Op::RulesEffective).unwrap() {
        Outcome::RulesIneffective { failed } => {
            assert!(
                failed.iter().any(|f| f.contains("ruleCount=0")),
                "{failed:?}"
            );
        },
        other => panic!("期望 RulesIneffective，得到 {other:?}"),
    }
}

// 规则集加载了、但规则链为空 —— 比完全没加载更隐蔽，因为"规则集在"让人以为生效了
#[test]
fn empty_rule_chain_is_ineffective() {
    let addr = mock(&[
        (
            "/providers/rules",
            r#"{"providers":{"campus":{"name":"campus","type":"Rule",
                "vehicleType":"File","ruleCount":42,"updatedAt":"1700000000000"}}}"#,
        ),
        ("/rules", r#"{"rules":[]}"#),
    ]);
    let a = adapter(&addr, &["campus"]);
    assert!(matches!(
        invoke_checked(&a, Op::RulesEffective).unwrap(),
        Outcome::RulesIneffective { .. }
    ));
}

#[test]
fn healthy_setup_reports_effective() {
    let addr = mock(&[
        (
            "/providers/rules",
            r#"{"providers":{"campus":{"name":"campus","type":"Rule",
                "vehicleType":"File","ruleCount":42,"updatedAt":"1700000000000"},
                "hotspot":{"name":"hotspot","type":"Rule",
                "vehicleType":"File","ruleCount":9,"updatedAt":"1700000000000"}}}"#,
        ),
        (
            "/rules",
            r#"{"rules":[{"type":"GeoSite","payload":"cn","proxy":"DIRECT","index":0},
                {"type":"Match","payload":"","proxy":"REJECT","index":1}]}"#,
        ),
    ]);
    let a = adapter(&addr, &["campus", "hotspot"]);
    assert_eq!(
        invoke_checked(&a, Op::RulesEffective).unwrap(),
        Outcome::RulesEffective
    );
}

// 没配置期望的规则集时，只看规则链非空即可 —— 不能因为 Aegis 没填
// expected_providers 就报"未加载"，那是自己打自己
#[test]
fn no_expectations_only_needs_non_empty_chain() {
    let addr = mock(&[
        ("/providers/rules", r#"{"providers":{}}"#),
        (
            "/rules",
            r#"{"rules":[{"type":"Match","payload":"","proxy":"DIRECT"}]}"#,
        ),
    ]);
    assert_eq!(
        invoke_checked(&adapter(&addr, &[]), Op::RulesEffective).unwrap(),
        Outcome::RulesEffective
    );
}

// ── 连接读取（审计数据源的入口）─────────────────────────────────────

#[test]
fn connections_parse_from_real_shaped_payload() {
    let body = r#"{"connections":[{
        "id":"abc","upload":10,"download":20,"start":"2026-10-20T04:32:11Z",
        "chains":["DIRECT"],"rule":"GeoSite","rulePayload":"cn","providerChains":[],
        "metadata":{"sourceIP":"192.168.1.5","sourcePort":"54321",
        "destinationIP":"1.2.3.4","destinationPort":"443","host":"example.com",
        "type":"tcp","network":"tcp","processPath":"","process":"","specialProxy":""}
        }],"uploadTotal":10,"downloadTotal":20}"#;
    let addr = mock(&[("/connections", body)]);
    let c = adapter(&addr, &[]).connections().unwrap();
    assert_eq!(c.len(), 1);
    let first = &c.connections[0];
    assert_eq!(first.metadata.host, "example.com");
    assert_eq!(first.metadata.destination_port.to_text(), "443");
    assert_eq!(first.rule, "GeoSite");
}

// ── 形状纪律 ────────────────────────────────────────────────────────

// 名字是协议的一部分：改了它，配置文件里的 [proxy.clash] 就该失效
#[test]
fn adapter_name_is_stable() {
    assert_eq!(adapter("127.0.0.1:1", &[]).name(), "mihomo");
}

// 默认配置**不含** secret：空 secret 不带头（带空 Bearer 反而会被 mihomo 拒）
#[test]
fn default_config_has_no_secret() {
    let d = ClashConfig::default();
    assert!(d.secret.is_empty());
    assert!(d.expected_providers.is_empty());
}
