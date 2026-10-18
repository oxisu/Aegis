//! 绝缘笼的**规则计划**（纯逻辑：只描述"要装什么"，绝不装）。
//!
//! # 为什么先做这一层，而不是直接调 `FwpmFilterAdd0`
//!
//! 绝缘笼是 Aegis 里唯一一个"装错了就断网"的部件，而且断的是**整机**的网。
//! 有两条失败路径都是不可逆的，且都源自同一类错误——放行规则被自己写的
//! 默认拒绝吃掉：
//!
//! 1. **忘了放行回环**：GUI（非提权）连不上 SYSTEM 服务，用户失去了唯一
//!    能把笼子拆掉的界面 → 自锁死。
//! 2. **忘了放行 DHCP**：开机时在 TCP/IP 栈起来之前就把 67/68 挡了，
//!    机器连 IP 都拿不到，而此时任何界面都还没起来 → 永久锁死。
//!
//! 这两条都不会报错，只会表现为"网不通了"。所以规则集合本身必须能被
//! **静态验证**：在真正下发之前，先回答"这份计划会不会把我自己锁死？"
//! 这一步不需要管理员权限，可以在 CI 里跑，也因此必须最先做。
//!
//! # 权重是本模块的核心，不是装饰
//!
//! WFP 在同一层内按**权重从高到低**评估，先匹配到的终止型动作胜出。
//! 所以"放行"和"默认拒绝"的相对权重一旦写反，放行规则就是一张废纸——
//! 它不会被报错，只会静默失效。这里的每条常量权重都是一个安全承诺，
//! 由 [`verify`] 和它的一组不变量测试钉死。
//!
//! # 关于 Boot-Time 持久背板（§28.2 地雷）
//!
//! [`Tier::Boot`] 层的规则必须带 `PERSISTENT | BOOTTIME`，也就是**进程死了、
//! 重启了都还在**。这是唯一能在 TCP/IP 栈启动前生效的手段，代价是装错即变砖。
//! 因此：
//! - 默认策略 [`CagePolicy::default`] **不启用** Boot 背板；
//! - Boot 层规则的条件必须**全部静态可判定**（不能引用进程 ID——
//!   引导时间进程还不存在，写上去就是一条永不匹配的死规则，见
//!   [`Condition::is_static`]）；
//! - 任何 Boot 层规则存在时，[`verify`] 都会给出 `Warn` 级提示，
//!   要求显式确认后才可下发。

use std::fmt;
use std::net::Ipv4Addr;

use windows::core::GUID;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform as wfp;

/// WFP 过滤器权重的取值上限。
///
/// `FWPM_FILTER0.weight` 是 `FWP_UINT8`，微软建议只用 0–15 这一段；
/// 越界的值在部分系统上会被静默截断。这里显式设上限并由测试钉死，
/// 免得某天有人写个 200 上去还以为生效了。
pub const WEIGHT_MAX: u8 = 15;

// ── 各条规则的权重 ────────────────────────────────────────────────────────
// 这些数字的大小关系本身就是安全承诺：放行必须严格高于默认拒绝，
// 否则放行规则会被自己的默认拒绝先吃掉（静默失效，不报错）。

/// 回环放行：必须最高，否则 GUI↔服务 IPC 自己把自己掐死（自锁死）。
pub const W_LOOPBACK: u8 = 15;
/// DHCP 放行：次高，否则开机拿不到 IP（永久锁死）。
pub const W_DHCP: u8 = 14;
/// 53 端口封锁：针对"绕过国内 DNS"的定向阻断，优先级低于两条保命放行。
pub const W_DNS_LOCK: u8 = 13;
/// LLMNR/mDNS/NetBIOS 广播泄密封锁。
pub const W_BROADCAST_LOCK: u8 = 12;
/// 存量连接兜底 DROP（挂在传输层，覆盖 ALE 层管不到的已建立流）。
pub const W_FLOW_DROP: u8 = 10;
/// 默认拒绝：兜底，**必须是最低的一条**。
pub const W_DEFAULT_DENY: u8 = 5;

pub const PORT_DNS: u16 = 53;
pub const PORT_DHCP_SERVER: u16 = 67;
pub const PORT_DHCP_CLIENT: u16 = 68;

/// DHCP 客户端对应的 Windows 服务名。运行期按它解析 PID 做精细放行（§27.4）。
pub const DHCP_SERVICE: &str = "Dhcp";

/// 校园网严格模式下额外封死的广播类端口（§27.2）。
///
/// DNS 被拦之后，Windows 会转而向局域网广播域名——LLMNR(5355)、
/// mDNS(5353)、NetBIOS(137)。不封掉，等于把浏览记录广播给整层楼。
pub const PORTS_BROADCAST_LEAK: &[u16] = &[5353, 5355, 137];

/// 受限广播地址。Boot 层 DHCP 放行**只能**用它做目的地址条件。
pub const BROADCAST_V4: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 255);

/// Aegis 会下发规则的 WFP 层。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Layer {
    /// 出站连接授权（IPv4）——阻断策略的主战场
    AleAuthConnectV4,
    /// 出站连接授权（IPv6）
    AleAuthConnectV6,
    /// 出站传输层（IPv4）——包离开真实网卡前的最后一道，覆盖存量流
    OutboundTransportV4,
    /// 出站传输层（IPv6）
    OutboundTransportV6,
    /// 入站连接授权（IPv4）
    AleAuthRecvAcceptV4,
}

impl Layer {
    pub fn name(self) -> &'static str {
        match self {
            Self::AleAuthConnectV4 => "ALE_AUTH_CONNECT_V4",
            Self::AleAuthConnectV6 => "ALE_AUTH_CONNECT_V6",
            Self::OutboundTransportV4 => "OUTBOUND_TRANSPORT_V4",
            Self::OutboundTransportV6 => "OUTBOUND_TRANSPORT_V6",
            Self::AleAuthRecvAcceptV4 => "ALE_AUTH_RECV_ACCEPT_V4",
        }
    }

    /// 对应的 WFP 层 GUID。真下发时用得上，纯推演时用不到。
    pub fn guid(self) -> GUID {
        match self {
            Self::AleAuthConnectV4 => wfp::FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            Self::AleAuthConnectV6 => wfp::FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            Self::OutboundTransportV4 => wfp::FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
            Self::OutboundTransportV6 => wfp::FWPM_LAYER_OUTBOUND_TRANSPORT_V6,
            Self::AleAuthRecvAcceptV4 => wfp::FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        }
    }

    /// 该层是否属于"出站"方向。入站层不参与绝缘笼的默认拒绝。
    pub fn is_outbound(self) -> bool {
        !matches!(self, Self::AleAuthRecvAcceptV4)
    }
}

/// 终止型动作。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Permit,
    Block,
}

impl Action {
    pub fn name(self) -> &'static str {
        match self {
            Self::Permit => "放行",
            Self::Block => "阻断",
        }
    }

    /// 对应的 WFP 动作类型。
    pub fn to_wfp(self) -> wfp::FWP_ACTION_TYPE {
        match self {
            Self::Permit => wfp::FWP_ACTION_PERMIT,
            Self::Block => wfp::FWP_ACTION_BLOCK,
        }
    }
}

/// 匹配条件的抽象描述。
///
/// 刻意做成枚举而不是直接塞 `FWPM_FILTER_CONDITION0`：后者是 C 结构，
/// 构造过程本身就要求分配与 unsafe，没法在普通单元测试里推演。
/// 真下发时再翻译成条件数组。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Condition {
    /// 目的端口等于给定值
    RemotePort(u16),
    /// 目的 IPv4 地址等于给定值
    RemoteAddrV4(Ipv4Addr),
    /// 本机回环（127.0.0.0/8）
    Loopback,
    /// 接口类型是**真实物理网卡**（排除过滤器 / 隧道 / 伪接口）
    PhysicalInterface,
    /// 进程 ID —— **只有运行期才有意义**
    ProcessId(u64),
    /// 某个 Windows 服务的进程 ID，到下发时才解析。
    ///
    /// 之所以不直接存解析好的数字：计划是在**没有权限、可能还没开机**的
    /// 环境里生成的，那时拿不到 PID。存服务名，让下发方去填。
    ServicePid(&'static str),
}

impl Condition {
    /// 该条件是否在"TCP/IP 栈启动之前、任何进程存在之前"就能求值。
    ///
    /// 这是 Boot-Time 层（§20.2 / §28.1）的硬约束：引导时间 DHCP 放行若
    /// 写成"匹配 Dhcp 服务 PID"，那是一条**永不匹配的死规则**——
    /// 引导时间还没有进程。结果就是开机即断网，且没有任何界面能救。
    pub fn is_static(self) -> bool {
        !matches!(self, Self::ProcessId(_) | Self::ServicePid(_))
    }
}

impl fmt::Display for Condition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RemotePort(p) => write!(f, "目的端口={p}"),
            Self::RemoteAddrV4(a) => write!(f, "目的地址={a}"),
            Self::Loopback => write!(f, "回环"),
            Self::PhysicalInterface => write!(f, "接口类型=物理网卡"),
            Self::ProcessId(p) => write!(f, "进程ID={p}"),
            Self::ServicePid(s) => write!(f, "进程ID={s}服务(下发时解析)"),
        }
    }
}

/// 规则的生命周期层。
///
/// 决定"进程死了这条规则还在不在"——也就是 fail-closed 的反面。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// **引导时间**：带 `PERSISTENT | BOOTTIME`，TCP/IP 栈启动前生效。
    /// 进程死了、重启了都在。这是唯一能覆盖开机窗口的手段，
    /// 也是 §28.2 记的那颗能让整机变砖的雷。
    Boot,
    /// **运行期动态会话**：进程崩溃内核自动清空，fail-closed。
    /// Aegis 的绝大部分规则都必须是这一层。
    Runtime,
}

impl Tier {
    pub fn name(self) -> &'static str {
        match self {
            Self::Boot => "引导时间(持久)",
            Self::Runtime => "运行期(动态)",
        }
    }
}

/// 一条待下发的过滤器规格。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterSpec {
    pub name: &'static str,
    pub layer: Layer,
    pub action: Action,
    pub weight: u8,
    pub conditions: Vec<Condition>,
    pub tier: Tier,
}

impl FilterSpec {
    /// 是否"进程死了也不会消失"。
    pub fn survives_reboot(&self) -> bool {
        self.tier == Tier::Boot
    }

    /// 条件是否全部静态可判定。Boot 层规则必须为真，否则是死规则。
    pub fn conditions_are_static(&self) -> bool {
        self.conditions.iter().all(|c| c.is_static())
    }

    /// 是否无条件匹配（兜底规则）。
    pub fn is_catch_all(&self) -> bool {
        self.conditions.is_empty()
    }
}

/// 绝缘笼策略输入。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CagePolicy {
    /// 锁死 53 端口：阻断绕过适配器的直连 DNS 查询（§20.5）。
    pub dns_lock: bool,
    /// 校园网严格模式：额外封 LLMNR/mDNS/NetBIOS 广播（§27.2）。
    pub campus_strict: bool,
    /// **启用 Boot-Time 持久背板**（默认关闭）。
    ///
    /// 打开后会在引导时间就挂上静态 DHCP 放行 + 全局默认拒绝，
    /// 代价是这条规则不随进程退出消失——装错即变砖，需显式确认。
    pub boot_backbone: bool,
}

impl Default for CagePolicy {
    /// 默认只做运行期绝缘，**不开 Boot 背板**。
    ///
    /// Boot 背板是 §28.2 的雷：它能在开机窗口就挡住漏包，但一旦写错
    /// 连卸载都救不回来。默认关闭意味着默认状态下 Aegis 不会往机器上
    /// 留任何"清不掉"的东西。
    fn default() -> Self {
        Self {
            dns_lock: true,
            campus_strict: false,
            boot_backbone: false,
        }
    }
}

/// 按策略生成绝缘笼的完整规则集。
///
/// 返回的规则已经是 WFP 的评估顺序（同层内权重降序）。
pub fn cage_plan(p: CagePolicy) -> Vec<FilterSpec> {
    let mut out = Vec::new();

    // ── 运行期动态会话 ────────────────────────────────────────────────
    // 两条保命放行永远在最前面：回环（GUI↔服务）与 DHCP（拿 IP）。

    for layer in [Layer::AleAuthConnectV4, Layer::AleAuthConnectV6] {
        out.push(FilterSpec {
            name: "回环放行",
            layer,
            action: Action::Permit,
            weight: W_LOOPBACK,
            conditions: vec![Condition::Loopback],
            tier: Tier::Runtime,
        });
    }

    // 运行期 DHCP：已经能解析到 Dhcp 服务进程，因此用 PID 精确绑定，
    // 避免任何进程都能借 67/68 偷渡（§28.1 借壳偷渡）。
    //
    // **必须拆成两条**：WFP 的多条件是 AND 语义，"端口=67 且 端口=68"
    // 是一条永假条件——写上去不报错，只是这条放行永远不生效，
    // 表现就是开机断网。这是第一版踩到的坑，别再合回去。
    for port in [PORT_DHCP_SERVER, PORT_DHCP_CLIENT] {
        out.push(FilterSpec {
            name: dhcp_permit_name(port),
            layer: Layer::AleAuthConnectV4,
            action: Action::Permit,
            weight: W_DHCP,
            conditions: vec![
                Condition::ServicePid(DHCP_SERVICE),
                Condition::RemotePort(port),
            ],
            tier: Tier::Runtime,
        });
    }

    if p.dns_lock {
        for layer in [Layer::AleAuthConnectV4, Layer::AleAuthConnectV6] {
            out.push(FilterSpec {
                name: "53 端口封锁",
                layer,
                action: Action::Block,
                weight: W_DNS_LOCK,
                conditions: vec![Condition::RemotePort(PORT_DNS)],
                tier: Tier::Runtime,
            });
        }
    }

    if p.campus_strict {
        for port in PORTS_BROADCAST_LEAK {
            out.push(FilterSpec {
                name: "广播泄密封锁",
                layer: Layer::AleAuthConnectV4,
                action: Action::Block,
                weight: W_BROADCAST_LOCK,
                conditions: vec![Condition::RemotePort(*port)],
                tier: Tier::Runtime,
            });
        }
    }

    // 存量连接兜底：ALE 层管不到**已经建立**的流（§27.1 死角一），
    // 必须再在传输层挂一条常驻 DROP，否则熔断只对新连接有效。
    for layer in [Layer::OutboundTransportV4, Layer::OutboundTransportV6] {
        out.push(FilterSpec {
            name: "存量连接兜底阻断",
            layer,
            action: Action::Block,
            weight: W_FLOW_DROP,
            conditions: Vec::new(),
            tier: Tier::Runtime,
        });
    }

    // 默认拒绝：兜底，权重最低。
    for layer in [Layer::AleAuthConnectV4, Layer::AleAuthConnectV6] {
        out.push(FilterSpec {
            name: "默认拒绝",
            layer,
            action: Action::Block,
            weight: W_DEFAULT_DENY,
            conditions: Vec::new(),
            tier: Tier::Runtime,
        });
    }

    // ── 引导时间持久背板（可选）────────────────────────────────────────
    if p.boot_backbone {
        // 只能用静态条件：接口类型 + 端口 + 广播地址。
        // 绝不能出现 ServicePid —— 引导时间没有进程，写了就是死规则。
        // 同样按端口拆成两条（AND 语义）。
        for port in [PORT_DHCP_SERVER, PORT_DHCP_CLIENT] {
            out.push(FilterSpec {
                name: dhcp_permit_name(port),
                layer: Layer::AleAuthConnectV4,
                action: Action::Permit,
                weight: W_LOOPBACK,
                conditions: vec![
                    Condition::PhysicalInterface,
                    Condition::RemotePort(port),
                    Condition::RemoteAddrV4(BROADCAST_V4),
                ],
                tier: Tier::Boot,
            });
        }
        out.push(FilterSpec {
            name: "默认拒绝(引导时间)",
            layer: Layer::AleAuthConnectV4,
            action: Action::Block,
            weight: W_DEFAULT_DENY,
            conditions: Vec::new(),
            tier: Tier::Boot,
        });
    }

    apply_order(&out)
}

/// DHCP 放行规则的展示名（按端口区分）。
///
/// 名字里带上端口号：`AND` 语义下不同端口必须是不同规则，
/// 名字也必须能区分，否则排查时看到的会是两条同名规则。
fn dhcp_permit_name(port: u16) -> &'static str {
    match port {
        PORT_DHCP_SERVER => "DHCP 放行·服务端67",
        PORT_DHCP_CLIENT => "DHCP 放行·客户端68",
        _ => "DHCP 放行",
    }
}

/// 把规则排成 WFP 的实际评估顺序：同层内权重降序。
///
/// 层之间的顺序对 WFP 没有意义（各层独立分类），但同层内**有**意义。
pub fn apply_order(plan: &[FilterSpec]) -> Vec<FilterSpec> {
    let mut out = plan.to_vec();
    out.sort_by(|a, b| a.layer.cmp(&b.layer).then(b.weight.cmp(&a.weight)));
    out
}

/// 问题严重级别。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// 会导致自锁死或策略失效，**绝对不能下发**
    Error,
    /// 需要显式人工确认后才可下发
    Warn,
}

/// 一条静态检查结论。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub severity: Severity,
    pub code: &'static str,
    pub detail: String,
}

impl Finding {
    fn error(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            severity: Severity::Error,
            code,
            detail: detail.into(),
        }
    }

    fn warn(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warn,
            code,
            detail: detail.into(),
        }
    }

    pub fn is_error(&self) -> bool {
        self.severity == Severity::Error
    }
}

/// 静态验证一份规则计划：**这是我的笼子会不会把自己锁死**的唯一答案。
///
/// `Error` 级结论意味着下发后必然出问题且不会报错（只表现为"网不通"）；
/// `Warn` 级意味着可以下发，但必须先让人看一眼。
pub fn verify(plan: &[FilterSpec]) -> Vec<Finding> {
    let mut out = Vec::new();

    // 1. 权重越界：会被静默截断，等于写了个别的权重。
    for f in plan {
        if f.weight > WEIGHT_MAX {
            out.push(Finding::error(
                "WEIGHT_OUT_OF_RANGE",
                format!("{} 权重 {} 超过上限 {}", f.name, f.weight, WEIGHT_MAX),
            ));
        }
    }

    // 2. 同层同权重**且动作不同**：WFP 评估顺序不确定，
    //    放行/拒绝谁先命中全看运气——同一动作则无所谓先后，不算问题
    //    （比如三条同权重的端口封锁，命中哪条结果都一样）。
    for i in 0..plan.len() {
        for j in (i + 1)..plan.len() {
            if plan[i].layer == plan[j].layer
                && plan[i].weight == plan[j].weight
                && plan[i].action != plan[j].action
            {
                out.push(Finding::error(
                    "DUPLICATE_WEIGHT",
                    format!(
                        "{} 与 {} 在 {} 层权重同为 {} 但动作不同，评估顺序不确定",
                        plan[i].name,
                        plan[j].name,
                        plan[i].layer.name(),
                        plan[i].weight
                    ),
                ));
            }
        }
    }

    // 3. 回环放行缺失 / 被遮蔽 —— 自锁死路径之一。
    check_loopback(plan, &mut out);

    // 4. DHCP 放行缺失 / 被遮蔽 —— 永久锁死路径。
    check_dhcp(plan, &mut out);

    // 5. 默认拒绝缺失：绝缘笼没有兜底，等于没关。
    for layer in [Layer::AleAuthConnectV4, Layer::AleAuthConnectV6] {
        let has_default_deny = plan
            .iter()
            .any(|f| f.layer == layer && f.action == Action::Block && f.is_catch_all());
        if !has_default_deny && plan.iter().any(|f| f.layer == layer) {
            out.push(Finding::error(
                "NO_DEFAULT_DENY",
                format!("{} 层没有任何无条件阻断规则，绝缘笼没有兜底", layer.name()),
            ));
        }
    }

    // 6. 放行规则被自己的默认拒绝吃掉：静默失效，最阴的一类错误。
    for f in plan.iter().filter(|f| f.action == Action::Permit) {
        let shadowed = plan.iter().any(|d| {
            d.layer == f.layer
                && d.action == Action::Block
                && d.is_catch_all()
                && d.weight > f.weight
        });
        if shadowed {
            out.push(Finding::error(
                "PERMIT_SHADOWED",
                format!(
                    "{} 在 {} 层的放行被更高权重的默认拒绝遮蔽，永不生效",
                    f.name,
                    f.layer.name()
                ),
            ));
        }
    }

    // 7. Boot 层规则的条件必须全部静态，否则是死规则。
    for f in plan.iter().filter(|f| f.tier == Tier::Boot) {
        if !f.conditions_are_static() {
            let bad: Vec<String> = f
                .conditions
                .iter()
                .filter(|c| !c.is_static())
                .map(|c| c.to_string())
                .collect();
            out.push(Finding::error(
                "BOOT_CONDITION_NOT_STATIC",
                format!(
                    "{} 是引导时间规则，却用了非静态条件 [{}]，引导期永不匹配",
                    f.name,
                    bad.join(", ")
                ),
            ));
        }
    }

    // 8. Boot 层规则本身就要人看一眼 —— 这是 §28.2 的雷。
    if plan.iter().any(|f| f.tier == Tier::Boot) {
        out.push(Finding::warn(
            "BOOT_BACKBONE_PRESENT",
            "计划含引导时间持久规则：进程退出与重启都不会消失，装错即变砖，需显式确认后下发",
        ));
    }

    out
}

/// 回环放行检查：没有它，非提权 GUI 连不上 SYSTEM 服务，
/// 用户就失去了唯一能拆掉笼子的界面。
fn check_loopback(plan: &[FilterSpec], out: &mut Vec<Finding>) {
    for layer in [Layer::AleAuthConnectV4, Layer::AleAuthConnectV6] {
        let permits: Vec<&FilterSpec> = plan
            .iter()
            .filter(|f| {
                f.layer == layer
                    && f.action == Action::Permit
                    && f.conditions.contains(&Condition::Loopback)
            })
            .collect();
        if permits.is_empty() {
            if plan.iter().any(|f| f.layer == layer) {
                out.push(Finding::error(
                    "LOOPBACK_MISSING",
                    format!(
                        "{} 层没有回环放行，GUI 与服务将互相失联（自锁死）",
                        layer.name()
                    ),
                ));
            }
            continue;
        }
        // 有放行还不够：同层若有更高权重的无条件阻断，放行照样不生效。
        for p in permits {
            let shadowed = plan.iter().any(|d| {
                d.layer == layer
                    && d.action == Action::Block
                    && d.is_catch_all()
                    && d.weight > p.weight
            });
            if shadowed {
                out.push(Finding::error(
                    "LOOPBACK_SHADOWED",
                    format!("{} 层的回环放行被更高权重的默认拒绝遮蔽", layer.name()),
                ));
            }
        }
    }
}

/// DHCP 放行检查：开机即挡 67/68，机器拿不到 IP，
/// 而此时任何界面都还没起来 —— 永久锁死。
fn check_dhcp(plan: &[FilterSpec], out: &mut Vec<Finding>) {
    // 空计划 = 什么都没装 = 不会锁死任何人。不在这里报 DHCP 缺失。
    if plan.is_empty() {
        return;
    }
    let is_dhcp = |f: &FilterSpec| {
        f.action == Action::Permit
            && f.conditions.iter().any(|c| {
                matches!(c, Condition::RemotePort(p) if *p == PORT_DHCP_SERVER || *p == PORT_DHCP_CLIENT)
            })
    };
    if !plan.iter().any(is_dhcp) {
        out.push(Finding::error(
            "DHCP_MISSING",
            "没有任何 DHCP(67/68) 放行规则，开机将拿不到 IP 且无法恢复（永久锁死）",
        ));
        return;
    }
    for f in plan.iter().filter(|f| is_dhcp(f)) {
        let shadowed = plan.iter().any(|d| {
            d.layer == f.layer
                && d.action == Action::Block
                && d.is_catch_all()
                && d.weight > f.weight
        });
        if shadowed {
            out.push(Finding::error(
                "DHCP_SHADOWED",
                "DHCP 放行被更高权重的默认拒绝遮蔽，开机必然断网",
            ));
        }
    }
}

/// 是否存在会阻止下发的 `Error` 级结论。
pub fn is_safe(plan: &[FilterSpec]) -> bool {
    verify(plan).iter().all(|f| !f.is_error())
}

/// 是否存在需要人工确认的 `Warn` 级结论。
pub fn needs_confirmation(plan: &[FilterSpec]) -> bool {
    verify(plan).iter().any(|f| f.severity == Severity::Warn)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(name: &'static str, layer: Layer, action: Action, weight: u8) -> FilterSpec {
        FilterSpec {
            name,
            layer,
            action,
            weight,
            conditions: Vec::new(),
            tier: Tier::Runtime,
        }
    }

    // ── 权重关系：本模块最重要的不变量 ──────────────────────────────

    /// 放行必须严格高于默认拒绝，且回环最高、DHCP 次之。
    ///
    /// 用 `const` 块断言：编译期就锁死，改错一个数字直接编不过，
    /// 而不是等运行时测试跑到才发现。
    const _: () = {
        assert!(W_LOOPBACK > W_DHCP);
        assert!(W_DHCP > W_DNS_LOCK);
        assert!(W_DNS_LOCK > W_BROADCAST_LOCK);
        assert!(W_BROADCAST_LOCK > W_FLOW_DROP);
        assert!(W_FLOW_DROP > W_DEFAULT_DENY);
        assert!(W_LOOPBACK <= WEIGHT_MAX);
    };

    #[test]
    fn weight_values_are_pinned() {
        assert_eq!(WEIGHT_MAX, 15);
        assert_eq!(W_LOOPBACK, 15);
        assert_eq!(W_DHCP, 14);
        assert_eq!(W_DNS_LOCK, 13);
        assert_eq!(W_BROADCAST_LOCK, 12);
        assert_eq!(W_FLOW_DROP, 10);
        assert_eq!(W_DEFAULT_DENY, 5);
    }

    #[test]
    fn port_constants_are_pinned() {
        assert_eq!(PORT_DNS, 53);
        assert_eq!(PORT_DHCP_SERVER, 67);
        assert_eq!(PORT_DHCP_CLIENT, 68);
        assert_eq!(PORTS_BROADCAST_LEAK, &[5353, 5355, 137]);
        assert_eq!(BROADCAST_V4, Ipv4Addr::new(255, 255, 255, 255));
    }

    // ── 默认计划必须干净 ────────────────────────────────────────────

    #[test]
    fn default_plan_is_safe() {
        let plan = cage_plan(CagePolicy::default());
        let findings = verify(&plan);
        assert!(is_safe(&plan), "默认计划不应有 Error：{findings:?}");
    }

    #[test]
    fn default_plan_does_not_touch_boot_tier() {
        let plan = cage_plan(CagePolicy::default());
        assert!(
            plan.iter().all(|f| f.tier == Tier::Runtime),
            "默认策略绝不能往机器上留清不掉的东西"
        );
        assert!(!needs_confirmation(&plan));
    }

    #[test]
    fn default_plan_has_loopback_dhcp_and_default_deny() {
        let plan = cage_plan(CagePolicy::default());
        for layer in [Layer::AleAuthConnectV4, Layer::AleAuthConnectV6] {
            assert!(
                plan.iter().any(|f| f.layer == layer
                    && f.action == Action::Permit
                    && f.conditions.contains(&Condition::Loopback)),
                "{:?} 必须有回环放行",
                layer
            );
            assert!(
                plan.iter()
                    .any(|f| f.layer == layer && f.action == Action::Block && f.is_catch_all()),
                "{:?} 必须有默认拒绝",
                layer
            );
        }
        assert!(plan.iter().any(|f| f
            .conditions
            .iter()
            .any(|c| matches!(c, Condition::RemotePort(p) if *p == PORT_DHCP_SERVER))));
    }

    /// 存量连接兜底必须在**传输层**也挂一条：ALE 层管不到已建立的流（§27.1）。
    #[test]
    fn default_plan_drops_established_flows_at_transport_layer() {
        let plan = cage_plan(CagePolicy::default());
        for layer in [Layer::OutboundTransportV4, Layer::OutboundTransportV6] {
            assert!(
                plan.iter()
                    .any(|f| f.layer == layer && f.action == Action::Block && f.is_catch_all()),
                "{:?} 必须有存量连接兜底 DROP",
                layer
            );
        }
    }

    #[test]
    fn dns_lock_is_on_by_default_and_can_be_turned_off() {
        let on = cage_plan(CagePolicy::default());
        assert!(on.iter().any(|f| f.name == "53 端口封锁"));
        let off = cage_plan(CagePolicy {
            dns_lock: false,
            ..CagePolicy::default()
        });
        assert!(!off.iter().any(|f| f.name == "53 端口封锁"));
        assert_eq!(on.len() - off.len(), 2, "53 封锁在 V4/V6 各一条");
    }

    #[test]
    fn campus_strict_adds_three_broadcast_blocks() {
        let base = cage_plan(CagePolicy::default());
        let strict = cage_plan(CagePolicy {
            campus_strict: true,
            ..CagePolicy::default()
        });
        let added = strict.len() - base.len();
        assert_eq!(added, PORTS_BROADCAST_LEAK.len());
        assert!(is_safe(&strict));
    }

    // ── Boot 背板 ────────────────────────────────────────────────────

    #[test]
    fn boot_backbone_is_off_by_default() {
        assert!(!CagePolicy::default().boot_backbone);
    }

    #[test]
    fn boot_backbone_plan_is_still_safe_but_needs_confirmation() {
        let plan = cage_plan(CagePolicy {
            boot_backbone: true,
            ..CagePolicy::default()
        });
        assert!(is_safe(&plan));
        assert!(needs_confirmation(&plan), "Boot 层规则必须要求人工确认");
        assert!(plan.iter().any(|f| f.survives_reboot()));
    }

    /// §20.2 硬约束：引导时间放行只能用静态条件。
    #[test]
    fn generated_boot_rules_use_only_static_conditions() {
        let plan = cage_plan(CagePolicy {
            boot_backbone: true,
            ..CagePolicy::default()
        });
        for f in plan.iter().filter(|f| f.tier == Tier::Boot) {
            assert!(
                f.conditions_are_static(),
                "{} 不得含非静态条件：{:?}",
                f.name,
                f.conditions
            );
        }
    }

    // ── verify 的捕获能力（变异测试的主战场）────────────────────────

    #[test]
    fn empty_plan_is_safe() {
        assert!(is_safe(&[]));
        assert!(verify(&[]).is_empty());
    }

    #[test]
    fn weight_above_max_is_rejected() {
        let plan = vec![spec("x", Layer::AleAuthConnectV4, Action::Block, 200)];
        let f = verify(&plan);
        assert!(f
            .iter()
            .any(|x| x.code == "WEIGHT_OUT_OF_RANGE" && x.is_error()));
    }

    #[test]
    fn duplicate_weight_in_same_layer_is_rejected() {
        let plan = vec![
            spec("a", Layer::AleAuthConnectV4, Action::Block, 5),
            spec("b", Layer::AleAuthConnectV4, Action::Permit, 5),
        ];
        let f = verify(&plan);
        assert!(f
            .iter()
            .any(|x| x.code == "DUPLICATE_WEIGHT" && x.is_error()));
    }

    /// 同权重但**不同层**是合法的：各层独立分类，没有顺序歧义。
    #[test]
    fn same_weight_across_layers_is_fine() {
        let plan = vec![
            spec("a", Layer::AleAuthConnectV4, Action::Block, 5),
            spec("b", Layer::AleAuthConnectV6, Action::Block, 5),
        ];
        assert!(!verify(&plan).iter().any(|x| x.code == "DUPLICATE_WEIGHT"));
    }

    /// 同权重但**同动作**也是合法的：三条端口封锁命中哪条结果都一样。
    /// 一开始这里报了假警报——把"顺序不确定"直接当成"有歧义"是过严的。
    #[test]
    fn same_weight_same_action_is_fine() {
        let plan = vec![
            FilterSpec {
                name: "广播封锁-5353",
                layer: Layer::AleAuthConnectV4,
                action: Action::Block,
                weight: W_BROADCAST_LOCK,
                conditions: vec![Condition::RemotePort(5353)],
                tier: Tier::Runtime,
            },
            FilterSpec {
                name: "广播封锁-5355",
                layer: Layer::AleAuthConnectV4,
                action: Action::Block,
                weight: W_BROADCAST_LOCK,
                conditions: vec![Condition::RemotePort(5355)],
                tier: Tier::Runtime,
            },
        ];
        assert!(!verify(&plan).iter().any(|x| x.code == "DUPLICATE_WEIGHT"));
    }

    #[test]
    fn missing_loopback_is_rejected() {
        let plan = vec![spec("默认拒绝", Layer::AleAuthConnectV4, Action::Block, 5)];
        let f = verify(&plan);
        assert!(f
            .iter()
            .any(|x| x.code == "LOOPBACK_MISSING" && x.is_error()));
    }

    /// 有回环放行还不够：权重低于默认拒绝就等于没有。
    #[test]
    fn loopback_shadowed_by_higher_default_deny_is_rejected() {
        let plan = vec![
            spec("默认拒绝", Layer::AleAuthConnectV4, Action::Block, 15),
            FilterSpec {
                name: "回环放行",
                layer: Layer::AleAuthConnectV4,
                action: Action::Permit,
                weight: 5,
                conditions: vec![Condition::Loopback],
                tier: Tier::Runtime,
            },
        ];
        let f = verify(&plan);
        assert!(
            f.iter()
                .any(|x| x.code == "LOOPBACK_SHADOWED" && x.is_error()),
            "被遮蔽的回环放行必须被抓到：{f:?}"
        );
    }

    #[test]
    fn missing_dhcp_is_rejected() {
        let plan = vec![
            FilterSpec {
                name: "回环放行",
                layer: Layer::AleAuthConnectV4,
                action: Action::Permit,
                weight: 15,
                conditions: vec![Condition::Loopback],
                tier: Tier::Runtime,
            },
            spec("默认拒绝", Layer::AleAuthConnectV4, Action::Block, 5),
        ];
        let f = verify(&plan);
        assert!(f.iter().any(|x| x.code == "DHCP_MISSING" && x.is_error()));
    }

    #[test]
    fn missing_default_deny_is_rejected() {
        let plan = vec![FilterSpec {
            name: "回环放行",
            layer: Layer::AleAuthConnectV4,
            action: Action::Permit,
            weight: 15,
            conditions: vec![Condition::Loopback],
            tier: Tier::Runtime,
        }];
        let f = verify(&plan);
        assert!(f
            .iter()
            .any(|x| x.code == "NO_DEFAULT_DENY" && x.is_error()));
    }

    /// 放行被无条件阻断遮蔽：不报错，只是静默失效——最阴的一类。
    #[test]
    fn shadowed_permit_is_rejected() {
        let plan = vec![
            spec("默认拒绝", Layer::OutboundTransportV4, Action::Block, 15),
            FilterSpec {
                name: "某放行",
                layer: Layer::OutboundTransportV4,
                action: Action::Permit,
                weight: 5,
                conditions: vec![Condition::RemotePort(443)],
                tier: Tier::Runtime,
            },
        ];
        let f = verify(&plan);
        assert!(f
            .iter()
            .any(|x| x.code == "PERMIT_SHADOWED" && x.is_error()));
    }

    /// §20.2 / §28.1：Boot 层写 PID 条件 = 永不匹配的死规则 = 开机即断网。
    #[test]
    fn boot_rule_with_pid_condition_is_rejected() {
        let plan = vec![FilterSpec {
            name: "DHCP 放行(引导时间)",
            layer: Layer::AleAuthConnectV4,
            action: Action::Permit,
            weight: 14,
            conditions: vec![Condition::ProcessId(1234), Condition::RemotePort(67)],
            tier: Tier::Boot,
        }];
        let f = verify(&plan);
        assert!(
            f.iter()
                .any(|x| x.code == "BOOT_CONDITION_NOT_STATIC" && x.is_error()),
            "引导时间规则用了进程 ID 必须被抓到：{f:?}"
        );
    }

    #[test]
    fn boot_rule_presence_raises_a_warning() {
        let plan = vec![FilterSpec {
            name: "默认拒绝(引导时间)",
            layer: Layer::AleAuthConnectV4,
            action: Action::Block,
            weight: 5,
            conditions: Vec::new(),
            tier: Tier::Boot,
        }];
        let f = verify(&plan);
        assert!(f
            .iter()
            .any(|x| x.code == "BOOT_BACKBONE_PRESENT" && !x.is_error()));
        assert!(needs_confirmation(&plan));
    }

    #[test]
    fn static_condition_classification() {
        assert!(Condition::RemotePort(53).is_static());
        assert!(Condition::RemoteAddrV4(BROADCAST_V4).is_static());
        assert!(Condition::Loopback.is_static());
        assert!(Condition::PhysicalInterface.is_static());
        assert!(!Condition::ProcessId(1).is_static());
        assert!(!Condition::ServicePid("Dhcp").is_static());
    }

    /// **回归**：WFP 多条件是 AND 语义，"端口=67 且 端口=68" 是永假条件。
    /// 第一版把 DHCP 放行写成了这种形式——不报错，只是永远不生效，
    /// 表现是开机断网。这条测试就是为了让那个错误再也回不来。
    #[test]
    fn no_filter_contradicts_itself_on_remote_port() {
        for policy in [
            CagePolicy::default(),
            CagePolicy {
                campus_strict: true,
                ..CagePolicy::default()
            },
            CagePolicy {
                boot_backbone: true,
                ..CagePolicy::default()
            },
        ] {
            for f in cage_plan(policy) {
                let ports: Vec<u16> = f
                    .conditions
                    .iter()
                    .filter_map(|c| match c {
                        Condition::RemotePort(p) => Some(*p),
                        _ => None,
                    })
                    .collect();
                let distinct: std::collections::BTreeSet<u16> = ports.iter().copied().collect();
                assert_eq!(
                    distinct.len(),
                    ports.len(),
                    "{} 对目的端口提出了互斥要求 {ports:?}（AND 语义下永不匹配）",
                    f.name
                );
            }
        }
    }

    /// DHCP 必须 67 和 68 各有一条，缺一条都会在某种 DHCP 交互下断网。
    #[test]
    fn dhcp_is_permitted_on_both_ports() {
        let plan = cage_plan(CagePolicy::default());
        for port in [PORT_DHCP_SERVER, PORT_DHCP_CLIENT] {
            assert!(
                plan.iter().any(|f| f.action == Action::Permit
                    && f.conditions.contains(&Condition::RemotePort(port))),
                "缺少目的端口 {port} 的 DHCP 放行"
            );
        }
        // 运行期放行绑定的是服务名，等下发时再解析 PID
        assert!(plan
            .iter()
            .any(|f| f.conditions.contains(&Condition::ServicePid(DHCP_SERVICE))));
    }

    #[test]
    fn boot_dhcp_permit_binds_to_broadcast_and_physical_only() {
        let plan = cage_plan(CagePolicy {
            boot_backbone: true,
            ..CagePolicy::default()
        });
        let boot: Vec<&FilterSpec> = plan
            .iter()
            .filter(|f| f.tier == Tier::Boot && f.action == Action::Permit)
            .collect();
        assert_eq!(boot.len(), 2);
        for f in boot {
            assert!(f.conditions.contains(&Condition::PhysicalInterface));
            assert!(f
                .conditions
                .contains(&Condition::RemoteAddrV4(BROADCAST_V4)));
        }
    }

    // ── 排序 ─────────────────────────────────────────────────────────

    #[test]
    fn apply_order_is_descending_within_a_layer() {
        let plan = cage_plan(CagePolicy::default());
        let ordered = apply_order(&plan);
        for w in ordered.windows(2) {
            if w[0].layer == w[1].layer {
                assert!(
                    w[0].weight >= w[1].weight,
                    "同层必须按权重降序：{:?} 后接 {:?}",
                    w[0].name,
                    w[1].name
                );
            }
        }
    }

    #[test]
    fn apply_order_preserves_every_rule() {
        let plan = cage_plan(CagePolicy {
            campus_strict: true,
            boot_backbone: true,
            ..CagePolicy::default()
        });
        let ordered = apply_order(&plan);
        assert_eq!(ordered.len(), plan.len());
        for f in &plan {
            assert!(ordered.contains(f), "排序不能丢规则：{}", f.name);
        }
    }

    // ── 层与动作 ─────────────────────────────────────────────────────

    #[test]
    fn layer_names_are_pinned() {
        assert_eq!(Layer::AleAuthConnectV4.name(), "ALE_AUTH_CONNECT_V4");
        assert_eq!(Layer::AleAuthConnectV6.name(), "ALE_AUTH_CONNECT_V6");
        assert_eq!(Layer::OutboundTransportV4.name(), "OUTBOUND_TRANSPORT_V4");
        assert_eq!(Layer::OutboundTransportV6.name(), "OUTBOUND_TRANSPORT_V6");
        assert_eq!(Layer::AleAuthRecvAcceptV4.name(), "ALE_AUTH_RECV_ACCEPT_V4");
    }

    /// 层 GUID 必须与 `layers.rs` 里登记的是同一层，否则下发到别的层去了。
    #[test]
    fn layer_guids_match_the_watched_layers() {
        use crate::layers::layer_name;
        for l in [
            Layer::AleAuthConnectV4,
            Layer::AleAuthConnectV6,
            Layer::OutboundTransportV4,
            Layer::OutboundTransportV6,
            Layer::AleAuthRecvAcceptV4,
        ] {
            assert_eq!(layer_name(&l.guid()), l.name(), "{:?} GUID 漂移", l);
        }
    }

    #[test]
    fn outbound_classification() {
        assert!(Layer::AleAuthConnectV4.is_outbound());
        assert!(Layer::OutboundTransportV4.is_outbound());
        assert!(!Layer::AleAuthRecvAcceptV4.is_outbound());
    }

    #[test]
    fn action_names_and_wfp_mapping() {
        assert_eq!(Action::Permit.name(), "放行");
        assert_eq!(Action::Block.name(), "阻断");
        assert_eq!(Action::Permit.to_wfp(), wfp::FWP_ACTION_PERMIT);
        assert_eq!(Action::Block.to_wfp(), wfp::FWP_ACTION_BLOCK);
    }

    #[test]
    fn tier_names_are_pinned() {
        assert!(Tier::Boot.name().contains("引导时间"));
        assert!(Tier::Runtime.name().contains("运行期"));
    }

    #[test]
    fn condition_display_is_readable() {
        assert_eq!(Condition::RemotePort(53).to_string(), "目的端口=53");
        assert_eq!(Condition::Loopback.to_string(), "回环");
        assert_eq!(
            Condition::RemoteAddrV4(BROADCAST_V4).to_string(),
            "目的地址=255.255.255.255"
        );
        assert!(Condition::ProcessId(7).to_string().contains('7'));
    }

    #[test]
    fn finding_severity_helpers() {
        let e = Finding::error("X", "d");
        assert!(e.is_error());
        let w = Finding::warn("Y", "d");
        assert!(!w.is_error());
    }

    /// 全开策略也必须是安全的——最复杂的组合最容易留死角。
    #[test]
    fn fully_enabled_policy_is_still_safe() {
        let plan = cage_plan(CagePolicy {
            dns_lock: true,
            campus_strict: true,
            boot_backbone: true,
        });
        assert!(is_safe(&plan), "{:?}", verify(&plan));
        assert!(needs_confirmation(&plan));
    }
}
