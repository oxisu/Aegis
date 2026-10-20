//! mihomo / Clash 适配器 —— 本项目第一个**真实**适配器。
//!
//! # 为什么手写而不是用 reqwest
//!
//! 见 [`http`] 模块文档：控制口只在 `127.0.0.1` 明文，引入 tokio + TLS 栈
//! 换来的能力一个都用不上，却会把同步的 SPI 拖进异步。
//!
//! # 能力声明的依据是实测（2026-10-20，本机 mihomo v1.19.32）
//!
//! | 能力 | 声明 | 依据 |
//! |---|---|---|
//! | `HealthProbe` | ✅ | `GET /version` 返回 `{"meta":true,"version":"v1.19.32"}` |
//! | `Reload` | ✅ | `PUT /configs?force=true` 触发热重载 |
//! | `DnsOwnership` | ✅ | `GET /configs` 有 `tun.enable`；**实测本机为 false** |
//! | `RuleEffectiveness` | ✅ | `GET /providers/rules` 能看出规则集**加载成功没有** |
//! | `TunInterfacePresent` | ✅ | `GET /configs` 的 `tun.device`（实测为空串） |
//! | `DefaultEgress` | ❌ | **mihomo 没有这个 API**。改默认出口是路由表操作，属 Aegis 底座 |
//! | `ConfigFragmentGenerate` | ❌ | mihomo 自带配置，不需要 Aegis 产片段 |
//!
//! ⚠ 声明一个能力等于**每次调用都会真的去打那个接口**。所以上面两行 ❌
//!   不是"暂时没实现"，而是"上游没有这个接口"——声明了就是骗人。
//!
//! # 最要紧的一条：`Err` ≠ `RulesIneffective`
//!
//! 守卫（`docs/DOWNSTREAM-GUARD.md`）要区分三态：
//!
//! · 规则**真的**没生效 → [`Outcome::RulesIneffective`] → 走收紧
//! · 规则生效         → [`Outcome::RulesEffective`]   → 放行
//! · **判不了**       → [`AdapterError::Failed`]       → `None` → **永不收紧**
//!
//! 也就是说：**控制口连不上必须走 `Err`，绝不能报 `RulesIneffective`**。
//! 混起来的后果是"网明明是好的，守卫却把它收了"——而收紧的代价是整机断网。

pub mod http;
pub mod wire;

#[cfg(test)]
mod tests;

use serde_json::json;

use crate::capability::Capability;
use crate::error::AdapterError;
use crate::op::{Op, Outcome};
use crate::spi::Adapter;

/// 适配器配置。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClashConfig {
    /// 控制口，形如 `127.0.0.1:9097`。
    pub addr: String,
    /// 控制口密钥。⚠ **不要**提交到版本库；用配置或环境变量传入。
    pub secret: String,
    /// Aegis 放行名单里认可的 TUN 设备名（用于 `Op::TunPresent`）。
    pub tun_candidates: Vec<String>,
    /// 期望存在的规则集 provider 名（用于 `Op::RulesEffective`）。
    ///
    /// ⚠ 这个列表是 Aegis **期望**下游加载的规则集；mihomo 侧实际有没有，
    ///   是 `RuleEffectiveness` 要回答的问题。
    pub expected_providers: Vec<String>,
}

impl Default for ClashConfig {
    /// ⚠ 默认值**不含** secret，也不假设端口。mihomo 的控制口常被改过
    ///   （Clash Verge 默认 9097，vanilla mihomo 默认 9090），猜错就是
    ///   "连不上"这种看不出原因的错误。地址必须显式给。
    fn default() -> Self {
        Self {
            addr: "127.0.0.1:9097".to_string(),
            secret: String::new(),
            tun_candidates: Vec::new(),
            expected_providers: Vec::new(),
        }
    }
}

/// mihomo / Clash 适配器。
pub struct ClashAdapter {
    config: ClashConfig,
    declared: Vec<Capability>,
}

impl ClashAdapter {
    pub fn new(config: ClashConfig) -> Self {
        Self {
            config,
            // 与模块文档的表格一一对应。少声明一个 = 调用方以为它有；
            // 多声明一个 = 每次调用都会打一个上游没有的接口。
            declared: vec![
                Capability::TunInterfacePresent,
                Capability::HealthProbe,
                Capability::Reload,
                Capability::DnsOwnership,
                Capability::RuleEffectiveness,
            ],
        }
    }

    pub fn config(&self) -> &ClashConfig {
        &self.config
    }

    /// 覆盖能力声明（测试与"用户不想让 Aegis 碰某个能力"时用）。
    pub fn declare(&mut self, caps: &[Capability]) {
        self.declared = caps.to_vec();
    }

    // ── 内部：一次 GET，返回已解析的 JSON ──────────────────────────────

    /// 取已解析的 JSON。
    ///
    /// ⚠ 返回 `String` 的**失败原因**而不是 [`AdapterError`]：同一个失败在不同
    ///   能力下语义不同——健康探针连不上是"故障"，规则生效性连不上是"判不了"。
    ///   在这里就压成一种错误，就等于替调用方做了那个不该做的判断。
    fn get_json<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T, String> {
        let raw = http::request(
            &self.config.addr,
            http::Method::Get,
            path,
            Some(&self.config.secret),
            None,
        )
        .map_err(|e| format!("GET {path} 失败：{e}"))?;
        serde_json::from_str(&raw.body).map_err(|e| format!("GET {path} 的响应不是合法 JSON：{e}"))
    }

    /// 读版本。**这是最便宜的健康探针**——它不碰任何状态。
    pub fn version(&self) -> Result<String, AdapterError> {
        self.get_json("/version")
            .map(|v: wire::Version| v.version)
            .map_err(|why| fail(Capability::HealthProbe, why))
    }

    /// 当前活跃连接。这是审计数据源（`docs/DOWNSTREAM-GUARD.md` 的读侧）。
    pub fn connections(&self) -> Result<wire::Connections, AdapterError> {
        self.get_json("/connections")
            .map_err(|why| fail(Capability::RuleEffectiveness, why))
    }

    /// 当前规则链（声明了什么）。
    pub fn rules(&self) -> Result<wire::Rules, AdapterError> {
        self.get_json("/rules")
            .map_err(|why| fail(Capability::RuleEffectiveness, why))
    }

    /// 已加载的规则集 provider（**实际**加载了什么）。
    pub fn rule_providers(&self) -> Result<wire::Providers, AdapterError> {
        self.get_json("/providers/rules")
            .map_err(|why| fail(Capability::RuleEffectiveness, why))
    }

    /// 当前配置。
    pub fn configs(&self) -> Result<wire::Configs, AdapterError> {
        self.get_json("/configs")
            .map_err(|why| fail(Capability::HealthProbe, why))
    }

    /// 热重载：让 mihomo 重新读自己的配置文件。
    ///
    /// ⚠ 这是**读自己的配置文件**，不是"接受 Aegis 推来的配置"。Aegis 往
    ///   mihomo 推规则集是另一回事（[`Self::put_rule_provider`]），
    ///   那个会改变流量去向，性质完全不同。
    pub fn reload(&self) -> Result<String, AdapterError> {
        let raw = http::request(
            &self.config.addr,
            http::Method::Put,
            "/configs?force=true",
            Some(&self.config.secret),
            None,
        )
        .map_err(|e| fail(Capability::Reload, format!("热重载失败：{e}")))?;
        // mihomo 的热重载返回 204 空体；能到这一步就是成功
        let _ = raw;
        self.version()
    }

    /// **热替换规则集**（`PUT /providers/rules/{name}`）。
    ///
    /// ⚠⚠ **这会改变这台机器的流量去向**，是把 B1 那两套模板装上去的唯一入口。
    ///   本 crate 只提供能力，**调用与否由人决定**。
    pub fn put_rule_provider(&self, name: &str, yaml_body: &str) -> Result<(), AdapterError> {
        let path = format!("/providers/rules/{name}");
        http::request(
            &self.config.addr,
            http::Method::Put,
            &path,
            Some(&self.config.secret),
            Some(yaml_body),
        )
        .map_err(|e| fail(Capability::Reload, format!("热替换规则集 {name} 失败：{e}")))?;
        Ok(())
    }

    /// 切换工作模式（`PATCH /configs`，`mode` 取 `rule`/`global`/`direct`）。
    ///
    /// ⚠ 同上：改变流量去向。
    pub fn set_mode(&self, mode: &str) -> Result<(), AdapterError> {
        let body = json!({ "mode": mode }).to_string();
        http::request(
            &self.config.addr,
            http::Method::Put,
            "/configs",
            Some(&self.config.secret),
            Some(&body),
        )
        .map_err(|e| fail(Capability::Reload, format!("切换模式失败：{e}")))?;
        Ok(())
    }

    // ── 各能力的实现 ────────────────────────────────────────────────

    fn tun(&self, candidates: &[String]) -> Result<Outcome, AdapterError> {
        let cfg = self.configs()?;
        let tun = cfg.tun.unwrap_or(wire::TunSection {
            enable: false,
            device: String::new(),
        });
        // TUN 没开 = 这个形态下不存在 TUN 设备，如实说"没有"
        if !tun.enable {
            return Ok(Outcome::TunAbsent);
        }
        // 设备名为空时无法与放行名单比对 → 不能当成"有一张认可的 TUN"
        let device = tun.device.trim();
        if device.is_empty() {
            return Ok(Outcome::TunAbsent);
        }
        if candidates.iter().any(|c| c == device) {
            Ok(Outcome::TunPresent {
                name: device.to_string(),
            })
        } else {
            // 有 TUN，但不是 Aegis 放行名单里的那张 —— 与"没有"同样不可用
            Ok(Outcome::TunAbsent)
        }
    }

    /// 回答"你的规则此刻有没有真的在拦"。
    ///
    /// 三态映射（守卫的接缝就在这里，见 `docs/GUARD-WIRING.md` §5.0.4）：
    ///
    /// | 现状 | 结果 | 守卫会做的事 |
    /// |---|---|---|
    /// | 控制口连不上 / 响应不是 JSON | [`Outcome::RulesUnknown`] | **永不收紧** |
    /// | 期望的规则集没加载或空集 | [`Outcome::RulesIneffective`] | 收紧 |
    /// | 规则链为空 | [`Outcome::RulesIneffective`] | 收紧 |
    /// | 规则集在、规则链非空 | [`Outcome::RulesEffective`] | 放行 |
    ///
    /// ⚠ **第一行是整段设计里最容易搞错的一格**。控制口连不上时若报
    ///   `RulesIneffective`，守卫会收网——而实际原因只是"我连不上"，
    ///   网本身可能好得很。收紧的代价是整机断网，误断比漏放行更难挽回。
    fn rules_effective(&self) -> Result<Outcome, AdapterError> {
        let (providers, rules) = match (self.rule_providers(), self.rules()) {
            (Ok(p), Ok(r)) => (p, r),
            // 任一个读不到 → **判不了**，不是"没生效"
            (Err(e), _) | (_, Err(e)) => {
                return Ok(Outcome::RulesUnknown {
                    why: format!("读不到 mihomo 的规则状态：{e}"),
                });
            },
        };

        let mut missing = Vec::new();
        for want in &self.config.expected_providers {
            match providers.providers.get(want) {
                None => missing.push(format!("{want}（未加载）")),
                Some(p) if p.rule_count == 0 => {
                    missing.push(format!("{want}（ruleCount=0，空集）"));
                },
                Some(_) => {},
            }
        }

        if !missing.is_empty() {
            return Ok(Outcome::RulesIneffective { failed: missing });
        }
        if rules.rules.is_empty() {
            // 规则集加载了但规则链为空 —— 比完全没加载更隐蔽，
            // 因为"规则集在"这件事会让人以为生效了
            return Ok(Outcome::RulesIneffective {
                failed: vec!["规则链为空（规则集加载了，但一条规则都没有）".to_string()],
            });
        }
        Ok(Outcome::RulesEffective)
    }

    fn dns(&self) -> Result<Outcome, AdapterError> {
        let cfg = self.configs()?;
        // 接管 53 靠的是 TUN（把 UDP/TCP 53 一起劫持），不是 mixed-port
        match cfg.tun {
            Some(t) if t.enable => Ok(Outcome::DnsOwned {
                owner: if t.device.is_empty() {
                    "mihomo-tun".to_string()
                } else {
                    t.device
                },
            }),
            // TUN 没开：53 归谁管不由 mihomo 决定（可能根本没有 DNS 服务）
            _ => Ok(Outcome::DnsNotOwned),
        }
    }
}

fn fail(capability: Capability, reason: String) -> AdapterError {
    AdapterError::Failed { capability, reason }
}

impl Adapter for ClashAdapter {
    fn name(&self) -> &'static str {
        "mihomo"
    }

    fn capabilities(&self) -> &[Capability] {
        &self.declared
    }

    fn invoke(&self, op: Op<'_>) -> Result<Outcome, AdapterError> {
        match op {
            Op::TunPresent { candidates } => self.tun(candidates),
            Op::Health => Ok(Outcome::Healthy {
                version: self.version()?,
            }),
            Op::Reload => Ok(Outcome::Reloaded {
                version: self.reload()?,
            }),
            Op::Dns => self.dns(),
            Op::RulesEffective => self.rules_effective(),
            // 这两个能力本适配器**不声明**，`invoke_checked` 会先拦掉。
            // 走到这里说明调用方绕过了检查 —— 那就把话说死，不给"碰巧能用"的机会。
            Op::DefaultEgress { .. } | Op::Fragment { .. } => {
                Err(AdapterError::Unsupported(op.capability()))
            },
        }
    }
}
