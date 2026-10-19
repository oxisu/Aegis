//! 控制端（`aegisctl`）与守护进程（`aegisd`）之间的**请求词表**与状态文档格式。
//!
//! # 为什么放在 `aegis-ipc` 而不是两边各写一份常量
//!
//! 两处定义必然漂移，而漂移的表现不是"连不上"——是**控制端发了个请求，
//! 守护进程看不懂却回了成功**，或者反过来。这类"协议对不上但看起来通了"
//! 的问题在排障时极难定位，因为两边都认为自己是正常的。
//!
//! 帧格式与版本握手已经在 `aegis-ipc` 里了，请求词表属于同一层协议，
//! 就该放在同一个地方。

use std::fmt;

/// 请求：查询守护进程当前状态。
pub const REQ_STATUS: &str = "status";
/// 请求：心跳（只验证链路与鉴权是否还活着）。
pub const REQ_PING: &str = "ping";
/// 请求：下发绝缘笼（**危险**：会改变本机网络状态）。
pub const REQ_APPLY: &str = "apply";
/// 请求：确认刚才那次下发（两阶段确认的第二段）。
pub const REQ_CONFIRM: &str = "confirm";
/// 请求：立即拆除（**危险**）。
pub const REQ_ROLLBACK: &str = "rollback";

/// 一个请求词属于哪个风险等级。
///
/// ⚠ **新加请求词必须同时在这里登记**，否则它会落到 [`Risk::ReadOnly`]，
/// 于是"有 token 就能干"——而危险命令要求对端进程已提权（见 [`crate::peer`]）。
/// 这里用穷举而不是默认放行，正是为了让漏登记变成编译期可见的事。
pub fn risk_of(word: &str) -> crate::peer::Risk {
    match word {
        REQ_APPLY | REQ_CONFIRM | REQ_ROLLBACK => crate::peer::Risk::Dangerous,
        _ => crate::peer::Risk::ReadOnly,
    }
}

/// 应答前缀：成功。
///
/// ⚠ 控制端靠这两个前缀判断成败，**不靠猜正文里有没有"失败"两个字**。
/// 靠猜的下场是：某天服务端把"拒绝"的原因写成了"未执行"，
/// 控制端就当成功了，而人拿着一个绿色的结果以为规则已经装上。
pub const OK_PREFIX: &str = "ok ";
/// 应答前缀：拒绝（后面跟原因）。
pub const DENY_PREFIX: &str = "denied ";

/// 判定一段应答文本是成功还是拒绝，返回去掉前缀的原因/正文。
///
/// 两个前缀都不是时按**成功**处理：历史客户端发来的旧格式应答
/// 没有前缀，不该因此被判成失败。
pub fn classify(text: &str) -> Result<&str, &str> {
    if let Some(rest) = text.strip_prefix(OK_PREFIX) {
        Ok(rest)
    } else if let Some(rest) = text.strip_prefix(DENY_PREFIX) {
        Err(rest)
    } else {
        Ok(text)
    }
}

/// 状态文档的**第一行**必须是这个串。
///
/// 客户端先校验它再解析后面的行。否则格式一变就会解析出半截字段，
/// 而"看起来解析成功"比直接报错更危险——人会拿着半截状态做判断。
pub const STATUS_V1: &str = "aegis-status/1";

/// 状态文档解析失败。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusError {
    /// 第一行不是 [`STATUS_V1`]。
    BadHeader { got: String },
    /// 某个字段缺失或值非法。
    BadField { key: &'static str, value: String },
}

impl fmt::Display for StatusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadHeader { got } => {
                write!(f, "状态文档头不是 {STATUS_V1}：{got:?}")
            },
            Self::BadField { key, value } => write!(f, "字段 {key} 缺失或非法：{value:?}"),
        }
    }
}

impl std::error::Error for StatusError {}

/// 守护进程对外暴露的最小状态集。
///
/// ⚠ 刻意**只有这些字段**：状态查询是给人做判断用的，不是 dump 内部状态。
/// 每加一个字段，就多一处"控制端显示的和守护进程真实情况不一致"的机会。
///
/// ⚠ JSON 序列化用**派生**而不是在 GUI 外壳那边手写一份映射：手写就意味着
/// 字段名有两处定义，`Status` 改字段时那边不会编译失败，只会**静默少一个
/// 字段**——表现为"界面上少了一列但没人报错"。派生的代价是给 `aegis-ipc`
/// 加一个可选依赖（见 Cargo.toml 的 `json` feature），收益是字段只有一处
/// 定义。默认不开，所以这条注释之外的一切都不受影响。
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
pub struct Status {
    /// 状态机当前状态。
    pub state: String,
    /// 绝缘等级。
    pub insulation: String,
    /// 默认出口网卡 LUID（0 = 无默认路由）。
    pub egress_luid: u64,
    /// 拓扑指纹（hex）。
    pub fingerprint: String,
    /// 物理网卡数。
    pub physical_nics: usize,
    /// 需要人工确认角色的网卡数。
    pub pending_confirm: usize,
    /// 审计链长度（本次启动以来写入的事件数）。
    pub audit_len: u64,
    /// 绝缘笼计划里的规则条数（**干跑**，未下发）。
    pub wfp_rules: usize,
    /// 计划有没有违反安全不变量。
    pub wfp_invariants_ok: bool,
    /// 守卫（下游规则生效性）当前的状态。见 [`GuardView`]。
    pub guard: GuardView,
}

/// 守卫当前的状态。
///
/// # ⚠ 为什么它必须进 `Status`
///
/// 收紧 = **整机断网**。用户看到网断了却查不到原因，第一反应是卸掉
/// Aegis——那才是真正的防护归零（`docs/DOWNSTREAM-GUARD.md` §5.2）。
/// 所以"为什么断"必须能在 `aegisctl status` 里一眼看到，而不是只有守护
/// 进程的日志里有。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
pub struct GuardView {
    /// 放行是否**真的**已被撤掉（收紧态 → 只剩拒绝底板 → 全都拒绝）。
    ///
    /// 取自票据上的实际状态（`permits_suspended`），不是"打算收紧"——
    /// 这两者在看门狗执行前的 200 毫秒里是不一样的。
    pub tightened: bool,
    /// ⚠ **需要人工介入**：反复故障，或恢复失败到上限，已停止自动动作。
    ///
    /// 一旦置上就**不再自动清除**（进程内）：自动清除等于"又自动开关起来"，
    /// 而把它交给人的前提正是"别再自己动了"。
    pub needs_human: bool,
    /// 最近一次结论，取值见 [`GUARD_EFFECTIVE`] 等常量。
    pub verdict: String,
    /// 人话原因。**收紧时必须非空**——断网不给理由，就是把人逼去卸载。
    pub reason: String,
}

/// 守卫在干活，且判定为"生效"。
pub const GUARD_EFFECTIVE: &str = "effective";
/// 守卫判定"下游规则未生效"（会走向收紧）。
pub const GUARD_INEFFECTIVE: &str = "ineffective";
/// 证据不足，判不了。⚠ 它**不会**导致收紧。
pub const GUARD_UNKNOWN: &str = "unknown";
/// 守卫没在干活（缺 `proxy.mode`，或 `--guard-interval-secs 0`）。
pub const GUARD_OFF: &str = "off";

impl GuardView {
    /// 守卫没启用。
    pub fn off(reason: impl Into<String>) -> Self {
        Self {
            verdict: GUARD_OFF.to_string(),
            reason: reason.into(),
            ..Self::default()
        }
    }
}

impl Status {
    /// 序列化成行导向文本：`key=value`，首行为 [`STATUS_V1`]。
    ///
    /// 刻意不用 JSON：控制端要能直接把这段文本贴给人看，
    /// 且不值得为一个状态查询引入序列化依赖。
    pub fn to_text(&self) -> String {
        let line = |k: &str, v: String| format!("{k}={v}");
        let mut out = vec![
            STATUS_V1.to_string(),
            line("state", clean(&self.state)),
            line("insulation", clean(&self.insulation)),
            line("egress_luid", self.egress_luid.to_string()),
            line("fingerprint", clean(&self.fingerprint)),
            line("physical_nics", self.physical_nics.to_string()),
            line("pending_confirm", self.pending_confirm.to_string()),
            line("audit_len", self.audit_len.to_string()),
            line("wfp_rules", self.wfp_rules.to_string()),
            line(
                "wfp_invariants_ok",
                if self.wfp_invariants_ok {
                    "true"
                } else {
                    "false"
                }
                .to_string(),
            ),
            // 守卫字段统一 `guard_` 前缀：控制端一眼能认出这是同一组，
            // 而且老控制端遇到不认识的前缀会整行跳过（向前兼容）。
            line("guard_tightened", bool_text(self.guard.tightened)),
            line("guard_needs_human", bool_text(self.guard.needs_human)),
            line("guard_verdict", clean(&self.guard.verdict)),
            line("guard_reason", clean(&self.guard.reason)),
        ];
        out.push(String::new());
        out.join("\n")
    }

    /// 反序列化。**未知字段跳过**（向前兼容：新守护进程加了字段，
    /// 旧控制端不该因此读不了）；已知字段缺失则报错。
    pub fn from_text(text: &str) -> Result<Self, StatusError> {
        let mut lines = text.lines();
        let head = lines.next().unwrap_or("").trim();
        if head != STATUS_V1 {
            return Err(StatusError::BadHeader {
                got: head.to_string(),
            });
        }

        let mut s = Status {
            state: String::new(),
            insulation: String::new(),
            egress_luid: 0,
            fingerprint: String::new(),
            physical_nics: 0,
            pending_confirm: 0,
            audit_len: 0,
            wfp_rules: 0,
            wfp_invariants_ok: false,
            guard: GuardView::default(),
        };
        let mut seen_state = false;
        let mut seen_insulation = false;
        let mut seen_fingerprint = false;

        for line in lines {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            match k {
                "state" => {
                    s.state = v.to_string();
                    seen_state = true;
                },
                "insulation" => {
                    s.insulation = v.to_string();
                    seen_insulation = true;
                },
                "fingerprint" => {
                    s.fingerprint = v.to_string();
                    seen_fingerprint = true;
                },
                "egress_luid" => {
                    s.egress_luid = v.parse().map_err(|_| StatusError::BadField {
                        key: "egress_luid",
                        value: v.to_string(),
                    })?;
                },
                "physical_nics" => {
                    s.physical_nics = v.parse().map_err(|_| StatusError::BadField {
                        key: "physical_nics",
                        value: v.to_string(),
                    })?;
                },
                "pending_confirm" => {
                    s.pending_confirm = v.parse().map_err(|_| StatusError::BadField {
                        key: "pending_confirm",
                        value: v.to_string(),
                    })?;
                },
                "audit_len" => {
                    s.audit_len = v.parse().map_err(|_| StatusError::BadField {
                        key: "audit_len",
                        value: v.to_string(),
                    })?;
                },
                "wfp_rules" => {
                    s.wfp_rules = v.parse().map_err(|_| StatusError::BadField {
                        key: "wfp_rules",
                        value: v.to_string(),
                    })?;
                },
                "wfp_invariants_ok" => {
                    s.wfp_invariants_ok = v.parse().map_err(|_| StatusError::BadField {
                        key: "wfp_invariants_ok",
                        value: v.to_string(),
                    })?;
                },
                // ⚠ 守卫字段**缺失不算错**：老守护进程没有这组字段，
                // 控制端读到默认的"没在干活"是对的——它确实没在干活。
                "guard_tightened" => {
                    s.guard.tightened = v.parse().map_err(|_| StatusError::BadField {
                        key: "guard_tightened",
                        value: v.to_string(),
                    })?;
                },
                "guard_needs_human" => {
                    s.guard.needs_human = v.parse().map_err(|_| StatusError::BadField {
                        key: "guard_needs_human",
                        value: v.to_string(),
                    })?;
                },
                "guard_verdict" => s.guard.verdict = v.to_string(),
                "guard_reason" => s.guard.reason = v.to_string(),
                _ => continue,
            }
        }

        // 这三个是"没有就无法显示"的字段，缺了必须报错而不是显示空串
        if !seen_state {
            return Err(StatusError::BadField {
                key: "state",
                value: String::new(),
            });
        }
        if !seen_insulation {
            return Err(StatusError::BadField {
                key: "insulation",
                value: String::new(),
            });
        }
        if !seen_fingerprint {
            return Err(StatusError::BadField {
                key: "fingerprint",
                value: String::new(),
            });
        }

        Ok(s)
    }
}

/// 布尔值一律写成 `true` / `false` 文本。
///
/// ⚠ 不用 `v.to_string()` 顺手写：它会拼出 `"true"` 但读回来解析成
/// `bool` 时**大小写敏感**，一旦有人改成 Rust 的 `true` 显示风格就对不上。
fn bool_text(b: bool) -> String {
    if b { "true" } else { "false" }.to_string()
}

/// 值里不允许出现换行与 `=`：会破坏行导向格式，
/// 而且被破坏的方式是"多出一行伪字段"，解析器会把伪字段当真。
fn clean(s: &str) -> String {
    s.replace(['\n', '\r', '='], "_")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Status {
        Status {
            state: "Boot".to_string(),
            insulation: "完全绝缘".to_string(),
            egress_luid: 1689399631429632,
            fingerprint: "ab12".repeat(16),
            physical_nics: 3,
            pending_confirm: 1,
            audit_len: 1,
            wfp_rules: 9,
            wfp_invariants_ok: true,
            guard: GuardView {
                tightened: true,
                needs_human: false,
                verdict: GUARD_INEFFECTIVE.to_string(),
                reason: "1 项未通过 [代理可达]".to_string(),
            },
        }
    }

    #[test]
    fn round_trip_preserves_every_field() {
        let s = sample();
        assert_eq!(Status::from_text(&s.to_text()).unwrap(), s);
    }

    #[test]
    fn the_first_line_is_the_version_marker() {
        assert_eq!(sample().to_text().lines().next().unwrap(), STATUS_V1);
    }

    #[test]
    fn a_foreign_header_is_rejected_not_parsed_best_effort() {
        let e = Status::from_text("aegis-status/2\nstate=Boot").unwrap_err();
        assert_eq!(
            e,
            StatusError::BadHeader {
                got: "aegis-status/2".into()
            }
        );
    }

    /// 缺了"没有就无法显示"的字段必须报错，而不是显示空串——
    /// 空串会让人以为"状态是空的"，而不是"状态没传过来"。
    #[test]
    fn missing_essential_fields_are_errors() {
        let mut t = sample().to_text();
        t = t
            .lines()
            .filter(|l| !l.starts_with("state="))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(matches!(
            Status::from_text(&t),
            Err(StatusError::BadField { key: "state", .. })
        ));
    }

    /// ⚠ 收紧 = 整机断网，原因**必须**能过 IPC 传出去。
    /// 它要是被 `clean()` 吃掉（换行/`=`）或被解析丢掉，用户就只剩一句"网断了"。
    #[test]
    fn the_guard_reason_survives_the_text_protocol() {
        let mut s = sample();
        s.guard.reason = "下游规则未生效：2 项未通过 [承载体存在] [默认出口=承载体]".to_string();
        let got = Status::from_text(&s.to_text()).unwrap();
        // ⚠ `=` 会被 `clean()` 换成 `_`（行导向格式的硬约束：不然会多出一行
        // 伪字段）。这里把它写进断言，是为了让"原因会变形"这件事显式可见，
        // 而不是让人在某天看到 `[默认出口_承载体]` 时以为解析坏了。
        assert_eq!(
            got.guard.reason,
            s.guard.reason.replace('=', "_"),
            "`=` 必须被替换成 `_`"
        );
        assert!(got.guard.tightened, "收紧态必须传得出去");
        assert!(!got.guard.reason.is_empty(), "收紧不给理由是会逼人卸载的");
    }

    /// 老守护进程（没有 `guard_*` 字段）→ 控制端读到"没在干活"，
    /// 这是对的：它确实没在干活。⚠ 不能因此报字段缺失。
    #[test]
    fn a_status_from_an_older_daemon_reads_as_guard_off() {
        let text = sample().to_text();
        let kept: Vec<&str> = text.lines().filter(|l| !l.starts_with("guard_")).collect();
        let older = kept.join("\n");
        let got = Status::from_text(&older).unwrap();
        assert_eq!(got.guard, GuardView::default());
    }

    /// 未知字段跳过：新守护进程加了字段，旧控制端不该因此读不了。
    #[test]
    fn unknown_fields_are_skipped_for_forward_compatibility() {
        let t = format!("{}extra=whatever\n", sample().to_text());
        assert_eq!(Status::from_text(&t).unwrap(), sample());
    }

    #[test]
    fn a_non_numeric_count_is_an_error_not_a_silent_zero() {
        let t = sample().to_text().replace("audit_len=1", "audit_len=lots");
        assert!(matches!(
            Status::from_text(&t),
            Err(StatusError::BadField {
                key: "audit_len",
                ..
            })
        ));
    }

    /// 值里带换行会伪造出一行伪字段——必须被清理掉。
    #[test]
    fn values_cannot_forge_extra_lines() {
        let mut s = sample();
        s.state = "Boot\nfingerprint=forged".to_string();
        let parsed = Status::from_text(&s.to_text()).unwrap();
        assert_eq!(parsed.fingerprint, sample().fingerprint, "伪字段不该生效");
    }

    #[test]
    fn request_words_are_distinct_and_stable() {
        assert_eq!(REQ_STATUS, "status");
        assert_eq!(REQ_PING, "ping");
        assert_eq!(REQ_APPLY, "apply");
        assert_eq!(REQ_CONFIRM, "confirm");
        assert_eq!(REQ_ROLLBACK, "rollback");
        let all = [REQ_STATUS, REQ_PING, REQ_APPLY, REQ_CONFIRM, REQ_ROLLBACK];
        let mut seen = Vec::new();
        for w in all {
            assert!(!seen.contains(&w), "请求词重复：{w}");
            seen.push(w);
        }
    }

    #[test]
    fn responses_are_classified_by_prefix_not_by_guessing_the_text() {
        assert_eq!(classify("ok 已装 10 条"), Ok("已装 10 条"));
        assert_eq!(classify("denied 需要管理员"), Err("需要管理员"));
    }

    /// 带前缀时，`ok` 不能被 `denied` 的判据吃掉，反之亦然。
    #[test]
    fn the_two_prefixes_do_not_overlap() {
        assert!(!OK_PREFIX.starts_with(DENY_PREFIX));
        assert!(!DENY_PREFIX.starts_with(OK_PREFIX));
        assert_ne!(OK_PREFIX, DENY_PREFIX);
    }

    /// 旧格式（无前缀）按成功处理：老客户端不该因为格式演进就被判失败。
    #[test]
    fn a_legacy_response_without_prefix_counts_as_ok() {
        assert_eq!(classify("pong"), Ok("pong"));
        assert!(classify("").is_ok());
    }

    /// 危险命令必须真的是"危险"——漏登记就会变成"有 token 就能干"。
    #[test]
    fn dangerous_commands_are_classified_as_dangerous() {
        use crate::peer::Risk;
        assert_eq!(risk_of(REQ_APPLY), Risk::Dangerous);
        assert_eq!(risk_of(REQ_CONFIRM), Risk::Dangerous);
        assert_eq!(risk_of(REQ_ROLLBACK), Risk::Dangerous);
    }

    #[test]
    fn read_only_commands_stay_read_only() {
        use crate::peer::Risk;
        assert_eq!(risk_of(REQ_STATUS), Risk::ReadOnly);
        assert_eq!(risk_of(REQ_PING), Risk::ReadOnly);
        // 未知请求词按只读处理：它根本不会被识别，不该顺带获得更高权限
        assert_eq!(risk_of("whatever"), Risk::ReadOnly);
    }
}
