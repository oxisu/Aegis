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

/// 明文 HTTP 端口（非 TLS）。
///
/// 设计（§9 阶段 4 / §20.6）：校园网模式下，明文 80 流量在离开真实网卡前
/// 即被拦截——靠 WFP ALE 出站层 DROP，包根本不离开本机。这条端口单独成
/// 规则是为了"意图显式 + 可独立告警"，而不是藏进默认拒绝里看不出来。
pub const PORT_PLAINTEXT_HTTP: u16 = 80;

/// 明文 80 阻断规则的权重。
///
/// 高于"存量连接兜底"(10) 与"默认拒绝"(5)，低于广播封锁(12)——它只针对
/// 一个具体端口，不该盖过广播/53 这类更宽的封锁。
pub const W_PLAINTEXT_HTTP: u8 = 11;

/// 受限广播地址。 Boot 层 DHCP 放行**只能**用它做目的地址条件。
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
    /// **本地**端口等于给定值（配合 `RemotePort` 可以钉死一个方向）
    LocalPort(u16),
    /// 目的 IPv4 地址等于给定值
    RemoteAddrV4(Ipv4Addr),
    /// 本机回环（127.0.0.0/8）
    Loopback,
    /// 接口类型是**真实物理网卡**（排除过滤器 / 隧道 / 伪接口）
    PhysicalInterface,
    /// 进程 ID —— **只有运行期才有意义**
    ProcessId(u64),
    /// **远端主机名**（⛔ 实测无效，见下）。
    ///
    /// # 实测结论：它不是"按域名拦"的字段
    ///
    /// WFP 的过滤条件里**没有**一个叫"域名"的字段。最接近的是
    /// `FWPM_CONDITION_ALE_EFFECTIVE_NAME`（`B1277B9A-B781-40FC-9671-E5F1B989F34E`，
    /// blob 类型），它确实出现在 `ALE_AUTH_CONNECT_V4` 的字段表里，
    /// 名字听起来就像"远端主机名"。
    ///
    /// 于是实测（见 `examples/name_probe` 第二幕）：把 `www.baidu.com`
    /// 以 UTF-16LE + NUL 塞进 blob，装一条 Block 规则，**装住不拆**再测：
    ///
    /// ```text
    /// ✅ 内核接受了（id=[…]）—— 只说明参数合法
    ///    直连 183.2.172.177:443     通    ← 没拦住
    /// ```

    /// 换言之：**装得上 ≠ 拦得住**。内核接受这条规则只能证明参数合法，
    /// 证明不了它按你想的那样匹配。
    ///
    /// ⚠ 因此它**不在** [`crate::apply::mappable`] 白名单里：
    /// `preflight` 会拒绝任何含这条条件的计划。只有探针能绕过 preflight
    /// 直接调 `apply`，目的就是让人还能复现这个结论，而不是重新踩一遍。
    RemoteName(&'static str),

    /// 进程是**系统服务宿主**（`%SystemRoot%\system32\svchost.exe`）。
    ///
    /// # 为什么不叫 `ServicePid`（一次真机事故改掉的命名）
    ///
    /// 第一版写作"某个 Windows 服务的进程 ID"，下发时翻译成
    /// `FWPM_CONDITION_ALE_APP_ID` + `UINT64(pid)`。真机下发时内核直接
    /// 返回 `0x80320027`（`FWP_E_TYPE_MISMATCH`）：**WFP 根本没有"按 PID
    /// 过滤"这个字段**，`ALE_APP_ID` 的值是**字节 blob**，不是整数。
    ///
    /// 用只读探针（见 `examples/probe_appid.rs`）实测后确认的语义是：
    ///
    /// - 传服务短名（`"Dhcp"`）→ 失败 `ERROR_FILE_NOT_FOUND`，
    ///   也就是说"按服务名绑定"这条路根本不通；
    /// - 传可执行文件路径 → 成功，返回形如
    ///   `\device\harddiskvolume1\windows\system32\svchost` 的 blob；
    /// - 传带参数的整条命令行 → 失败，只认纯路径。
    ///
    /// 于是"按服务绑定"在 WFP 里**做不到**：DHCP 跑在共享的 `svchost.exe`
    /// 里，同一个宿主下还挂着 `Dnscache`、`Schedule` 等等，AppId 无法
    /// 区分它们。这条条件只能收紧到"系统服务宿主进程"。
    ///
    /// ⚠ 因此 §28.1 的"借壳偷渡"**没有被完全堵住**：同宿主的其他服务
    /// 理论上仍可借 67/68 端口外联。这比"任何进程都能借"好得多，
    /// 但不是零。彻底解决要靠 ALE callout 在内核里按 PID 判，那是后续工作。
    SystemServiceHost,

    /// 数据包要从**这张网卡**出去（`NET_LUID`，值来自 `aegis-sense`）。
    ///
    /// # 这是沙漏模型第二层漏斗的原语
    ///
    /// 代理软件（Clash / sing-box）跑在用户态、懂域名；Aegis 在内核里
    /// **不懂域名也不需要懂**——它只认一件事：
    ///
    /// > 这一跳是不是从**该走的网卡**出去的？不是就截掉。
    ///
    /// 于是"域名该怎么走"交给代理规则，"走错网卡一律砍"交给 Aegis。
    /// 两层各自只做自己擅长的事，合起来才是纵深防御。
    ///
    /// # 为什么必须按网卡、不能按进程
    ///
    /// **TUN 模式**下，应用自己的 socket 连的仍然是真实远端 IP，
    /// 系统只是按路由把包送进 TUN；随后由代理进程另起一条连接出去。
    /// 于是一条"只放行代理进程"的规则会把应用自己的 socket 一起拦掉，
    /// TUN 模式直接废掉。按出口网卡放行才是 TUN 模式的正确原语。
    ///
    /// 反过来，**系统代理模式**（SOCKS/HTTP）下应用连的是 127.0.0.1，
    /// 此时按进程放行代理进程才是对的。两种模式要的原语不同。
    ///
    /// # 实测依据
    ///
    /// 用 `Session::fields` 问引擎（见 `examples/egress_probe`），
    /// `ALE_AUTH_CONNECT_V4` 的 41 个字段里有：
    ///
    /// ```text
    /// ✅ IP_LOCAL_INTERFACE  值类型 FWP_UINT64   ← 就是 NET_LUID
    /// ✅ INTERFACE_INDEX     值类型 FWP_UINT32
    /// ✅ IP_NEXTHOP_INTERFACE / NEXTHOP_INTERFACE_INDEX …
    /// ```
    ///
    /// 选 `IP_LOCAL_INTERFACE` 是因为 `aegis-sense` 产出的正是网卡
    /// **LUID**（`default_egress_luid`），两边是同一个标识，不用再做一次转换。
    ///
    /// ⚠ **字段在 ≠ 分类时带着正确的值。** 值对不对由
    /// `examples/iface_probe` 做行为实验（含阴性对照）判定。
    EgressInterfaceLuid(u64),
}

impl Condition {
    /// 该条件是否在"TCP/IP 栈启动之前、任何进程存在之前"就能求值。
    ///
    /// 这是 Boot-Time 层（§20.2 / §28.1）的硬约束：引导时间 DHCP 放行若
    /// 写成"匹配某个进程"，那是一条**永不匹配的死规则**——
    /// 引导时间还没有进程。结果就是开机即断网，且没有任何界面能救。
    pub fn is_static(self) -> bool {
        !matches!(
            self,
            Self::ProcessId(_)
                | Self::SystemServiceHost
                | Self::RemoteName(_)
                // 网卡 LUID 也是运行期才有的：引导时间网卡还没枚举出来，
                // 写上去就是一条永不匹配的死规则（开机即断网且没有界面能救）
                | Self::EgressInterfaceLuid(_)
        )
    }

    /// 这条条件是不是"按进程身份"匹配，且我们**真的能**翻译成 WFP 字段。
    ///
    /// 今天只有 [`Self::SystemServiceHost`] 满足（走 `ALE_APP_ID` blob）。
    /// [`Self::ProcessId`] **永远不可映射**：WFP 在 ALE 层没有"按 PID 过滤"
    /// 这个字段，硬填数字只会换来 `FWP_E_TYPE_MISMATCH`。
    pub fn is_mappable_process_identity(self) -> bool {
        matches!(self, Self::SystemServiceHost)
    }
}

impl fmt::Display for Condition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RemotePort(p) => write!(f, "目的端口={p}"),
            Self::LocalPort(p) => write!(f, "本地端口={p}"),
            Self::RemoteAddrV4(a) => write!(f, "目的地址={a}"),
            Self::Loopback => write!(f, "回环"),
            Self::PhysicalInterface => write!(f, "接口类型=物理网卡"),
            Self::ProcessId(p) => write!(f, "进程ID={p}"),
            Self::RemoteName(n) => write!(f, "远端主机名={n}"),
            Self::SystemServiceHost => write!(f, "进程=系统服务宿主(svchost)"),
            Self::EgressInterfaceLuid(l) => write!(f, "出口网卡=LUID {l:#x}"),
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

    // 运行期 DHCP：按"方向 + 宿主进程"放行。
    //
    // **必须拆成两条**：WFP 的多条件是 AND 语义，"端口=67 且 端口=68"
    // 是一条永假条件——写上去不报错，只是这条放行永远不生效，
    // 表现就是开机断网。这是第一版踩到的坑，别再合回去。
    //
    // 每条再钉死**本地端口**，把放行收窄成"客户端方向"与"服务端方向"
    // 两个具体方向，而不是"远端端口是 67 或 68 就放行"。
    //
    // ⚠ 这里**没有**"按 Dhcp 服务精确绑定"——WFP 做不到（见
    // [`Condition::SystemServiceHost`] 的注释）。残余风险写在那儿了。
    for (local, remote) in [
        (PORT_DHCP_CLIENT, PORT_DHCP_SERVER),
        (PORT_DHCP_SERVER, PORT_DHCP_CLIENT),
    ] {
        out.push(FilterSpec {
            name: dhcp_permit_name(remote),
            layer: Layer::AleAuthConnectV4,
            action: Action::Permit,
            weight: W_DHCP,
            conditions: vec![
                Condition::SystemServiceHost,
                Condition::LocalPort(local),
                Condition::RemotePort(remote),
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
        // 绝不能出现 SystemServiceHost —— 引导时间没有进程，写了就是死规则。
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

/// 明文 HTTP（端口 80）阻断计划（§9 阶段 4 / §20.6）。
///
/// # 与 [`cage_plan`] 的关系
///
/// [`cage_plan`] 的默认拒绝已经把 80 一起兜住了；这里把它**单独拎出来**，
/// 是为了两件事：
/// 1. **意图显式**：审计/排障时能一眼看到"我们在主动拦明文 HTTP"，
///    而不是从一堆默认拒绝里猜；
/// 2. **可独立应用**：可以**不装整副绝缘笼**就只拦明文 HTTP——
///    例如桌面用户只想屏蔽明文流量、不想全盘断网时的轻量选项。
///
/// ⚠ **可逆**：这条计划里全是运行期动态会话规则（[`Tier::Runtime`]），
/// 走与 [`cage_plan`] 完全相同的 [`crate::apply`] / [`crate::rollback`]
/// 两阶段闸门——进程退出内核自动清空，也可 `rollback` 一键复原。
///
/// ⚠ **不碰回环**：回环放行（GUI↔服务）权重更高，本计划不会阻断
/// 本机自身的 127.0.0.1 通信。
pub fn plaintext_http_block_plan() -> Vec<FilterSpec> {
    let mut out = Vec::new();
    for layer in [Layer::AleAuthConnectV4, Layer::AleAuthConnectV6] {
        out.push(FilterSpec {
            name: "明文 HTTP(80) 阻断",
            layer,
            action: Action::Block,
            weight: W_PLAINTEXT_HTTP,
            conditions: vec![Condition::RemotePort(PORT_PLAINTEXT_HTTP)],
            tier: Tier::Runtime,
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

/// 这条结论属于**哪一层**（对应 §20.6 的两层模型）。
///
/// - [`Self::Invariant`]：第一层**安全不变量**。是"宪法"，不参与普通规则
///   排序，任何来源的用户定制都不得覆盖。违反它意味着"这份计划不配叫
///   绝缘笼"，报给用户的第一句话必须是"底线没守住"。
/// - [`Self::Hygiene`]：第二层写法问题。不违反底线，但会**静默失效**——
///   比如权重越界被截断、条件自相矛盾。违反它意味着"这份计划写错了"。
///
/// ⚠ 分开的意义在于报错的可信度：两者都不能下发，但如果混为一谈，
///   用户会把"权重写越界"误当成"我改了底线"，也会把"底线没兑现"
///   误当成"只是没写好"。前者让人不敢定制，后者让人不当回事。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingKind {
    /// 第一层：安全不变量，不可覆盖。
    Invariant,
    /// 第二层：写法问题，会静默失效但不触及底线。
    Hygiene,
}

impl FindingKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Invariant => "不变量",
            Self::Hygiene => "写法",
        }
    }
}

/// 一条静态检查结论。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// 能不能下发（处置）。
    pub severity: Severity,
    /// 属于哪一层（归属）。与 `severity` 正交：
    /// `severity` 回答"要不要拦"，`kind` 回答"为什么拦"。
    pub kind: FindingKind,
    pub code: &'static str,
    pub detail: String,
}

impl Finding {
    /// 报一条问题。**必须显式声明归属层**——刻意没有不带 `kind` 的重载：
    /// 逼每个检查点在写下时就想清楚"我这条到底是不变量还是写法问题"。
    fn error(kind: FindingKind, code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            severity: Severity::Error,
            kind,
            code,
            detail: detail.into(),
        }
    }

    fn warn(kind: FindingKind, code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warn,
            kind,
            code,
            detail: detail.into(),
        }
    }

    pub fn is_error(&self) -> bool {
        self.severity == Severity::Error
    }

    /// 这条是否命中第一层不变量。
    pub fn is_invariant(&self) -> bool {
        self.kind == FindingKind::Invariant
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
                FindingKind::Hygiene,
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
                    FindingKind::Hygiene,
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
                FindingKind::Invariant,
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
                FindingKind::Invariant,
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
                FindingKind::Hygiene,
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
            FindingKind::Invariant,
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
                    FindingKind::Invariant,
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
                    FindingKind::Invariant,
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
            FindingKind::Invariant,
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
                FindingKind::Invariant,
                "DHCP_SHADOWED",
                "DHCP 放行被更高权重的默认拒绝遮蔽，开机必然断网",
            ));
        }
    }
}

/// **策略兑现对账**：`CagePolicy` 声明了什么，`cage_plan` 是不是真的产出了什么。
///
/// # 为什么需要这一层
///
/// [`verify`] 回答的是"这份计划会不会把我锁死"，是自保视角。
/// 但它**不管**"这份计划兑现了策略没有"——把 `dns_lock` 关掉，
/// 计划照样自洽、照样安全，只是 DNS 不再被锁。用户从配置上看是"DNS 已锁"，
/// 实际机器上是没锁的。**声明与产出脱节**是最阴的一类静默失败：
/// 不报错、不崩溃、日志干净，只是底线悄悄没了。
///
/// # 最危险的是反方向
///
/// `boot_backbone = false` 却产出了 `Tier::Boot` 规则，比"声明了没做"更糟：
/// Aegis 悄悄往机器上留了**进程退出与重启都清不掉**的东西，
/// 而用户在配置里明明写的是"不要"。这一条单独给错误码，且**不可覆盖**。
pub fn verify_policy(plan: &[FilterSpec], policy: &CagePolicy) -> Vec<Finding> {
    let mut out = Vec::new();

    // 声明锁 53，就得真有 53 阻断
    if policy.dns_lock && !plan.iter().any(blocks_port(PORT_DNS)) {
        out.push(Finding::error(
            FindingKind::Invariant,
            "POLICY_DNS_LOCK_NOT_HONORED",
            format!(
                "策略声明要锁 {} 端口，但计划里没有任何针对它的阻断 —— \
                 用户以为 DNS 锁着，实际没锁",
                PORT_DNS
            ),
        ));
    }

    // 声明校园网严格，就得真有广播泄密封锁
    if policy.campus_strict
        && !PORTS_BROADCAST_LEAK
            .iter()
            .all(|p| plan.iter().any(blocks_port(*p)))
    {
        let missing: Vec<String> = PORTS_BROADCAST_LEAK
            .iter()
            .filter(|p| !plan.iter().any(blocks_port(**p)))
            .map(|p| p.to_string())
            .collect();
        out.push(Finding::error(
            FindingKind::Invariant,
            "POLICY_BROADCAST_LOCK_NOT_HONORED",
            format!(
                "策略声明校园网严格，但广播泄漏端口 [{}] 没有对应阻断",
                missing.join(", ")
            ),
        ));
    }

    // 声明要 Boot 背板，就得真有持久规则
    if policy.boot_backbone && !plan.iter().any(|f| f.tier == Tier::Boot) {
        out.push(Finding::error(
            FindingKind::Invariant,
            "POLICY_BOOT_BACKBONE_MISSING",
            "策略声明启用引导时间持久背板，但计划里没有任何 Boot 层规则",
        ));
    }

    // ⚠ 反方向：没声明却出现了持久规则。这是最危险的脱节。
    if !policy.boot_backbone && plan.iter().any(|f| f.tier == Tier::Boot) {
        out.push(Finding::error(
            FindingKind::Invariant,
            "UNDECLARED_BOOT_RULE",
            "策略**没有**声明启用持久背板，计划里却有 Boot 层规则 —— \
             Aegis 会往机器上留下进程退出与重启都清不掉的东西，\
             而用户从配置上看不出来",
        ));
    }

    out
}

/// 组合校验：`verify` + [`verify_policy`]。平时用这个。
pub fn verify_with(plan: &[FilterSpec], policy: &CagePolicy) -> Vec<Finding> {
    let mut out = verify(plan);
    out.extend(verify_policy(plan, policy));
    out
}

/// 有没有不变量被违反（**不可覆盖**，与"能不能下发"是两个维度）。
///
/// 之所以单独暴露：`is_safe` 只回答"要不要拦"，但运维需要知道
/// "这次是被底线拦了，还是只是写错了"——两者的处置完全不同：
/// 底线被违反要回头改策略，写法问题改规则就行。
pub fn invariants_violated(findings: &[Finding]) -> bool {
    findings.iter().any(|f| f.is_invariant() && f.is_error())
}

fn blocks_port(port: u16) -> impl Fn(&FilterSpec) -> bool {
    move |f: &FilterSpec| {
        f.action == Action::Block
            && f.conditions
                .iter()
                .any(|c| matches!(c, Condition::RemotePort(p) if *p == port))
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

    /// `verify` 产生的**去重后**结论码集合。
    ///
    /// 断言"含某个码"是不够的：变异测试里出现过把 `>` 改成 `>=`、
    /// 把 `==` 改成 `!=` 之后，结论码多出一个而测试照样通过——
    /// 因为测试只检查了"我要的那个码在不在"。要抓这类偏差，
    /// 必须断言**整个集合**。
    fn codes(plan: &[FilterSpec]) -> Vec<&'static str> {
        let mut v: Vec<&'static str> = verify(plan).iter().map(|f| f.code).collect();
        v.sort_unstable();
        v.dedup();
        v
    }

    /// 一份只覆盖 IPv4 的最小可用计划（回环 + DHCP + 默认拒绝）。
    fn minimal_v4_plan() -> Vec<FilterSpec> {
        vec![
            FilterSpec {
                name: "回环放行",
                layer: Layer::AleAuthConnectV4,
                action: Action::Permit,
                weight: W_LOOPBACK,
                conditions: vec![Condition::Loopback],
                tier: Tier::Runtime,
            },
            FilterSpec {
                name: "DHCP 放行·服务端67",
                layer: Layer::AleAuthConnectV4,
                action: Action::Permit,
                weight: W_DHCP,
                conditions: vec![
                    Condition::SystemServiceHost,
                    Condition::LocalPort(68),
                    Condition::RemotePort(67),
                ],
                tier: Tier::Runtime,
            },
            spec(
                "默认拒绝",
                Layer::AleAuthConnectV4,
                Action::Block,
                W_DEFAULT_DENY,
            ),
        ]
    }

    /// 只建 V4 的计划不该被要求"V6 层也得有回环放行和默认拒绝"。
    ///
    /// 这对 `==` / `!=` 的变异很敏感：一旦层的匹配条件写反，
    /// 这个计划会凭空多出两条关于 V6 的结论。
    #[test]
    fn single_layer_plan_is_not_asked_about_the_other_layer() {
        assert_eq!(
            codes(&minimal_v4_plan()),
            Vec::<&str>::new(),
            "{:?}",
            verify(&minimal_v4_plan())
        );
    }

    /// 无条件的**放行**不算默认拒绝：兜底必须是阻断。
    #[test]
    fn catch_all_permit_does_not_count_as_default_deny() {
        let plan = vec![
            FilterSpec {
                name: "回环放行",
                layer: Layer::AleAuthConnectV4,
                action: Action::Permit,
                weight: W_LOOPBACK,
                conditions: vec![Condition::Loopback],
                tier: Tier::Runtime,
            },
            spec("全放行", Layer::AleAuthConnectV4, Action::Permit, 10),
            FilterSpec {
                name: "DHCP 放行·服务端67",
                layer: Layer::AleAuthConnectV4,
                action: Action::Permit,
                weight: W_DHCP,
                conditions: vec![
                    Condition::SystemServiceHost,
                    Condition::LocalPort(68),
                    Condition::RemotePort(67),
                ],
                tier: Tier::Runtime,
            },
        ];
        assert!(
            codes(&plan).contains(&"NO_DEFAULT_DENY"),
            "只有无条件放行时绝缘笼等于没关：{:?}",
            codes(&plan)
        );
    }

    /// **同权重**不是"遮蔽"，是"顺序不确定"：只该报 DUPLICATE_WEIGHT，
    /// 不该同时报一堆 SHADOWED。这条专门盯 `>` 被改成 `>=` / `==` 的变异。
    #[test]
    fn equal_weight_is_ambiguity_not_shadowing() {
        let plan = vec![
            FilterSpec {
                name: "回环放行",
                layer: Layer::AleAuthConnectV4,
                action: Action::Permit,
                weight: 10,
                conditions: vec![Condition::Loopback],
                tier: Tier::Runtime,
            },
            spec("默认拒绝", Layer::AleAuthConnectV4, Action::Block, 10),
            FilterSpec {
                name: "DHCP 放行·服务端67",
                layer: Layer::AleAuthConnectV4,
                action: Action::Permit,
                weight: 11,
                conditions: vec![
                    Condition::SystemServiceHost,
                    Condition::LocalPort(68),
                    Condition::RemotePort(67),
                ],
                tier: Tier::Runtime,
            },
        ];
        // 先确认"真的被遮蔽"这个判据本身还灵，否则下面三条否定断言
        // 可能只是因为判据整个失效才通过的
        let mut shadowed = plan.clone();
        shadowed[2].weight = 9;
        assert!(
            codes(&shadowed).contains(&"PERMIT_SHADOWED"),
            "DHCP 权重低于默认拒绝时确实应报遮蔽：{:?}",
            codes(&shadowed)
        );

        let c = codes(&plan);
        assert!(c.contains(&"DUPLICATE_WEIGHT"), "{c:?}");
        assert!(!c.contains(&"LOOPBACK_SHADOWED"), "同权重不是遮蔽：{c:?}");
        assert!(!c.contains(&"PERMIT_SHADOWED"), "同权重不是遮蔽：{c:?}");
        assert!(!c.contains(&"DHCP_SHADOWED"), "同权重不是遮蔽：{c:?}");
    }

    /// `is_safe` 必须真的能返回 false——之前只断言了结论码，
    /// 导致"恒返回 true"这个变异活了下来。
    #[test]
    fn is_safe_returns_false_for_a_self_locking_plan() {
        assert!(!is_safe(&[spec(
            "默认拒绝",
            Layer::AleAuthConnectV4,
            Action::Block,
            W_DEFAULT_DENY
        )]));
        assert!(is_safe(&minimal_v4_plan()));
        assert!(is_safe(&[]));
    }

    #[test]
    fn survives_reboot_is_exactly_the_boot_tier() {
        let mut boot = spec("b", Layer::AleAuthConnectV4, Action::Block, 5);
        boot.tier = Tier::Boot;
        assert!(boot.survives_reboot());
        let mut runtime = spec("r", Layer::AleAuthConnectV4, Action::Block, 5);
        runtime.tier = Tier::Runtime;
        assert!(!runtime.survives_reboot());
        // 生成的默认计划里一条都不该留下
        assert!(cage_plan(CagePolicy::default())
            .iter()
            .all(|f| !f.survives_reboot()));
    }

    #[test]
    fn is_catch_all_is_exactly_empty_conditions() {
        let catch = spec("c", Layer::AleAuthConnectV4, Action::Block, 5);
        assert!(catch.is_catch_all());
        let mut cond = catch.clone();
        cond.conditions = vec![Condition::RemotePort(53)];
        assert!(!cond.is_catch_all());
    }

    /// 名字要能区分端口：`AND` 语义下 67 和 68 必须是两条规则，
    /// 同名会让排查时看到两条一模一样的条目。
    #[test]
    fn dhcp_permit_names_distinguish_the_ports() {
        assert_eq!(dhcp_permit_name(PORT_DHCP_SERVER), "DHCP 放行·服务端67");
        assert_eq!(dhcp_permit_name(PORT_DHCP_CLIENT), "DHCP 放行·客户端68");
        assert_ne!(
            dhcp_permit_name(PORT_DHCP_SERVER),
            dhcp_permit_name(PORT_DHCP_CLIENT)
        );
        let plan = cage_plan(CagePolicy::default());
        let names: Vec<&str> = plan
            .iter()
            .filter(|f| f.name.starts_with("DHCP"))
            .map(|f| f.name)
            .collect();
        assert_eq!(names.len(), 2);
        assert_ne!(names[0], names[1], "{names:?}");
    }

    /// 结论的 detail 必须指名哪条条件不合规，否则运维看到
    /// "BOOT_CONDITION_NOT_STATIC" 也不知道该改什么。
    #[test]
    fn boot_violation_detail_names_the_offending_condition() {
        let plan = vec![FilterSpec {
            name: "DHCP 放行(引导时间)",
            layer: Layer::AleAuthConnectV4,
            action: Action::Permit,
            weight: 14,
            conditions: vec![Condition::ProcessId(1234), Condition::RemotePort(67)],
            tier: Tier::Boot,
        }];
        let f = verify(&plan);
        let bad = f
            .iter()
            .find(|x| x.code == "BOOT_CONDITION_NOT_STATIC")
            .expect("应报出非静态条件");
        assert!(
            bad.detail.contains("1234") || bad.detail.contains("进程ID"),
            "detail 必须点名违规条件：{}",
            bad.detail
        );
        assert!(
            !bad.detail.contains("目的端口"),
            "不该把静态条件报成违规：{}",
            bad.detail
        );
    }

    // ── 逐层判定：`check_loopback` / `check_dhcp` 的层匹配 ──────────────
    // 变异测试指出这五个判据的"层"维度没被覆盖：把 `==` 改成 `!=`、
    // 把 `&&` 改成 `||` 之后，别的层的规则会被拉进来参与判断，
    // 于是凭空多出遮蔽结论。

    /// 别的层的无条件阻断**不能**遮蔽本层的回环放行。
    #[test]
    fn loopback_shadowing_is_judged_within_one_layer() {
        let plan = vec![
            FilterSpec {
                name: "回环放行",
                layer: Layer::AleAuthConnectV4,
                action: Action::Permit,
                weight: 5,
                conditions: vec![Condition::Loopback],
                tier: Tier::Runtime,
            },
            FilterSpec {
                name: "DHCP 放行·服务端67",
                layer: Layer::AleAuthConnectV4,
                action: Action::Permit,
                weight: W_DHCP,
                conditions: vec![
                    Condition::SystemServiceHost,
                    Condition::LocalPort(68),
                    Condition::RemotePort(67),
                ],
                tier: Tier::Runtime,
            },
            spec("默认拒绝", Layer::AleAuthConnectV4, Action::Block, 3),
            // V6 层有一条权重更高的无条件阻断，但它管不到 V4 的回环放行
            spec("默认拒绝", Layer::AleAuthConnectV6, Action::Block, 15),
        ];
        let c = codes(&plan);
        assert!(
            !c.contains(&"LOOPBACK_SHADOWED"),
            "跨层不应判定为遮蔽：{c:?}"
        );
        // V6 确实没有回环放行，这条该报——顺便确认判据本身还活着
        assert!(c.contains(&"LOOPBACK_MISSING"), "{c:?}");
    }

    /// 别的层的无条件阻断**不能**遮蔽本层的 DHCP 放行。
    #[test]
    fn dhcp_shadowing_is_judged_within_one_layer() {
        let mut plan = minimal_v4_plan();
        plan.push(spec("默认拒绝", Layer::AleAuthConnectV6, Action::Block, 15));
        let c = codes(&plan);
        assert!(!c.contains(&"DHCP_SHADOWED"), "跨层不应判定为遮蔽：{c:?}");
    }

    /// **阻断** 67/68 的规则不算 DHCP 放行——放行必须是 Permit。
    #[test]
    fn blocking_dhcp_ports_does_not_count_as_a_permit() {
        let plan = vec![
            FilterSpec {
                name: "回环放行",
                layer: Layer::AleAuthConnectV4,
                action: Action::Permit,
                weight: W_LOOPBACK,
                conditions: vec![Condition::Loopback],
                tier: Tier::Runtime,
            },
            FilterSpec {
                name: "阻断 67",
                layer: Layer::AleAuthConnectV4,
                action: Action::Block,
                weight: W_DNS_LOCK,
                conditions: vec![Condition::RemotePort(PORT_DHCP_SERVER)],
                tier: Tier::Runtime,
            },
            spec(
                "默认拒绝",
                Layer::AleAuthConnectV4,
                Action::Block,
                W_DEFAULT_DENY,
            ),
        ];
        assert!(
            codes(&plan).contains(&"DHCP_MISSING"),
            "只有阻断 67 的规则时不算放行：{:?}",
            codes(&plan)
        );
    }

    /// 权重**低于**默认拒绝时，DHCP 放行确实被遮蔽——确认判据活着，
    /// 否则下面那条"同权重不算遮蔽"的否定断言可能只是判据失效才通过。
    #[test]
    fn dhcp_below_default_deny_is_shadowed() {
        let mut plan = minimal_v4_plan();
        plan[1].weight = 1;
        assert!(
            codes(&plan).contains(&"DHCP_SHADOWED"),
            "{:?}",
            codes(&plan)
        );
    }

    /// DHCP 放行与默认拒绝**同权重**：那是顺序不确定，不是遮蔽。
    #[test]
    fn dhcp_at_same_weight_as_default_deny_is_not_shadowed() {
        let mut plan = minimal_v4_plan();
        plan[1].weight = W_DEFAULT_DENY;
        let c = codes(&plan);
        assert!(c.contains(&"DUPLICATE_WEIGHT"), "{c:?}");
        assert!(!c.contains(&"DHCP_SHADOWED"), "同权重不是遮蔽：{c:?}");
    }

    /// 权重**等于**上限是合法的：只有超过才该报。
    #[test]
    fn weight_exactly_at_max_is_accepted() {
        let mut plan = minimal_v4_plan();
        plan[0].weight = WEIGHT_MAX;
        assert!(
            !codes(&plan).contains(&"WEIGHT_OUT_OF_RANGE"),
            "{:?}",
            codes(&plan)
        );
        plan[0].weight = WEIGHT_MAX + 1;
        assert!(codes(&plan).contains(&"WEIGHT_OUT_OF_RANGE"));
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

    // ── 结论的归属层（§20.6 两层模型）────────────────────────────────

    /// 不变量类结论必须被标成 Invariant：它们不是"写得不好"，
    /// 而是"底线没守住"，两者的处置完全不同。
    #[test]
    fn self_locking_findings_are_marked_as_invariants() {
        // 只有一条无条件阻断：既无回环放行、也无 DHCP 放行
        let bare = vec![spec("默认拒绝", Layer::AleAuthConnectV4, Action::Block, 5)];
        // 有规则但没有任何无条件阻断 → 笼子没有兜底
        let no_deny = vec![FilterSpec {
            name: "53 封锁",
            layer: Layer::AleAuthConnectV4,
            action: Action::Block,
            weight: W_DNS_LOCK,
            conditions: vec![Condition::RemotePort(PORT_DNS)],
            tier: Tier::Runtime,
        }];
        // 放行权重低于默认拒绝 → 永不见天日
        let shadowed = vec![
            spec("默认拒绝", Layer::AleAuthConnectV4, Action::Block, 10),
            FilterSpec {
                name: "低权重放行",
                layer: Layer::AleAuthConnectV4,
                action: Action::Permit,
                weight: 5,
                conditions: vec![Condition::Loopback],
                tier: Tier::Runtime,
            },
        ];

        for (code, plan) in [
            ("LOOPBACK_MISSING", &bare),
            ("DHCP_MISSING", &bare),
            ("NO_DEFAULT_DENY", &no_deny),
            ("PERMIT_SHADOWED", &shadowed),
        ] {
            let f = verify(plan);
            let hit = f
                .iter()
                .find(|x| x.code == code)
                .unwrap_or_else(|| panic!("{code} 应在该计划上触发：{f:?}"));
            assert!(
                hit.is_invariant(),
                "{code} 属于第一层不变量，却被标成了 {:?}",
                hit.kind
            );
            assert!(hit.is_error(), "{code} 必须阻止下发");
        }
    }

    /// 写法问题不该被误标成不变量：否则用户会把"权重写越界"
    /// 当成"我改了底线"，从此不敢定制。
    #[test]
    fn hygiene_findings_are_not_invariants() {
        let mut plan = minimal_v4_plan();
        plan[0].weight = WEIGHT_MAX + 1;
        let f = verify(&plan);
        let hit = f
            .iter()
            .find(|x| x.code == "WEIGHT_OUT_OF_RANGE")
            .expect("应触发权重越界");
        assert_eq!(hit.kind, FindingKind::Hygiene);
        assert!(hit.is_error(), "写法问题同样不能下发");
    }

    /// `invariants_violated` 只看第一层：一个纯写法问题的计划
    /// 不该被报成"底线被违反"。
    #[test]
    fn invariants_violated_looks_only_at_the_first_layer() {
        let mut plan = minimal_v4_plan();
        plan[0].weight = WEIGHT_MAX + 1;
        assert!(!is_safe(&plan), "写法问题也要拦下");
        assert!(
            !invariants_violated(&verify(&plan)),
            "权重越界不是不变量违反"
        );

        let broken = vec![spec("默认拒绝", Layer::AleAuthConnectV4, Action::Block, 5)];
        assert!(invariants_violated(&verify(&broken)));
    }

    // ── 策略兑现对账：声明 vs 产出 ────────────────────────────────────

    /// 生成器产出的计划必须兑现它自己的策略声明——这是回归防线，
    /// 保证 cage_plan 与 verify_policy 不会因为各自演化而对不上。
    #[test]
    fn generated_plans_always_honor_their_own_policy() {
        for policy in [
            CagePolicy::default(),
            CagePolicy {
                dns_lock: true,
                campus_strict: true,
                boot_backbone: false,
            },
            CagePolicy {
                dns_lock: true,
                campus_strict: false,
                boot_backbone: true,
            },
            CagePolicy {
                dns_lock: false,
                campus_strict: true,
                boot_backbone: false,
            },
        ] {
            let plan = cage_plan(policy);
            let f = verify_policy(&plan, &policy);
            assert!(f.is_empty(), "策略 {policy:?} 未被兑现：{f:?}");
        }
    }

    /// 把 53 封锁从计划里抽掉，但策略仍声明要锁 —— 必须报不变量违反。
    /// 这就是"用户以为 DNS 锁着、实际没锁"的那类静默失败。
    #[test]
    fn removing_the_dns_lock_from_the_plan_is_caught() {
        let policy = CagePolicy {
            dns_lock: true,
            campus_strict: false,
            boot_backbone: false,
        };
        let plan: Vec<FilterSpec> = cage_plan(policy)
            .into_iter()
            .filter(|f| {
                !(f.action == Action::Block
                    && f.conditions.contains(&Condition::RemotePort(PORT_DNS)))
            })
            .collect();
        let f = verify_policy(&plan, &policy);
        assert!(
            f.iter()
                .any(|x| x.code == "POLICY_DNS_LOCK_NOT_HONORED" && x.is_invariant()),
            "抽掉 53 封锁必须被抓：{f:?}"
        );
        // 注意：光靠 verify() 抓不到这个 —— 计划照样自洽、照样"安全"
        assert!(is_safe(&plan), "这正是 verify() 的盲区：计划没有自锁死问题");
    }

    /// 广播封锁缺失同理。
    ///
    /// ⚠ 必须验告警**点名了哪几个端口**，不能只验"有没有这条告警"。
    /// 只验存在性的话，把 `missing` 那个 filter 的 `!` 删掉照样通过——
    /// 那样改之后列表里是"**已经封住的**端口"而不是"缺失的端口"：
    /// 告警照样弹，但它指错了方向，排查会直奔一个根本没问题的端口。
    #[test]
    fn removing_the_broadcast_lock_from_the_plan_is_caught() {
        let policy = CagePolicy {
            dns_lock: true,
            campus_strict: true,
            boot_backbone: false,
        };
        let plan: Vec<FilterSpec> = cage_plan(policy)
            .into_iter()
            .filter(|f| {
                !(f.action == Action::Block && f.conditions.contains(&Condition::RemotePort(5353)))
            })
            .collect();
        let f = verify_policy(&plan, &policy);
        let hit = f
            .iter()
            .find(|x| x.code == "POLICY_BROADCAST_LOCK_NOT_HONORED")
            .expect("抽掉 5353 封锁必须被抓");
        assert!(hit.is_invariant());
        assert!(
            hit.detail.contains("5353"),
            "必须点名缺的那个端口：{}",
            hit.detail
        );
        assert!(
            !hit.detail.contains("5355"),
            "5355 还在，不该报成缺失：{}",
            hit.detail
        );
        assert!(
            !hit.detail.contains("137"),
            "137 还在，不该报成缺失：{}",
            hit.detail
        );
    }

    /// ⚠ 最危险的脱节：策略说不要持久背板，计划里却有 Boot 规则。
    /// Aegis 会悄悄往机器上留下清不掉的东西，而用户在配置里看不到。
    #[test]
    fn an_undeclared_boot_rule_is_the_worst_kind_of_drift() {
        let policy = CagePolicy {
            dns_lock: true,
            campus_strict: false,
            boot_backbone: false,
        };
        let mut plan = cage_plan(policy);
        plan.push(FilterSpec {
            name: "偷偷加的持久规则",
            layer: Layer::AleAuthConnectV4,
            action: Action::Block,
            weight: W_DEFAULT_DENY,
            conditions: vec![Condition::RemotePort(9999)],
            tier: Tier::Boot,
        });
        let f = verify_policy(&plan, &policy);
        assert!(f
            .iter()
            .any(|x| x.code == "UNDECLARED_BOOT_RULE" && x.is_invariant()));
        assert!(invariants_violated(&f));
    }

    /// 声明了要背板却没生成，也是脱节（方向相反，但同样要报）。
    #[test]
    fn a_declared_but_missing_backbone_is_caught() {
        let policy = CagePolicy {
            dns_lock: true,
            campus_strict: false,
            boot_backbone: true,
        };
        let plan: Vec<FilterSpec> = cage_plan(policy)
            .into_iter()
            .filter(|f| f.tier != Tier::Boot)
            .collect();
        let f = verify_policy(&plan, &policy);
        assert!(f.iter().any(|x| x.code == "POLICY_BOOT_BACKBONE_MISSING"));
    }

    /// `verify_with` = verify + verify_policy，两者都得跑到。
    #[test]
    fn verify_with_runs_both_layers() {
        let policy = CagePolicy::default();
        let mut plan = cage_plan(policy);
        // 造一个卫生问题
        plan[0].weight = WEIGHT_MAX + 1;
        let f = verify_with(&plan, &policy);
        assert!(f.iter().any(|x| x.code == "WEIGHT_OUT_OF_RANGE"));
        // 再造一个不变量问题
        let plan2: Vec<FilterSpec> = cage_plan(policy)
            .into_iter()
            .filter(|f| {
                !(f.action == Action::Block
                    && f.conditions.contains(&Condition::RemotePort(PORT_DNS)))
            })
            .collect();
        assert!(verify_with(&plan2, &policy)
            .iter()
            .any(|x| x.code == "POLICY_DNS_LOCK_NOT_HONORED"));
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
        assert!(!Condition::SystemServiceHost.is_static());
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
        // 运行期放行绑定到系统服务宿主，并钉死本地端口（方向）
        assert!(plan
            .iter()
            .any(|f| f.conditions.contains(&Condition::SystemServiceHost)));
        assert!(
            plan.iter()
                .any(|f| f.conditions.contains(&Condition::LocalPort(68))
                    && f.conditions.contains(&Condition::RemotePort(67))),
            "DHCP 客户端方向（本地 68 → 远端 67）必须存在"
        );
        assert!(
            plan.iter()
                .any(|f| f.conditions.contains(&Condition::LocalPort(67))
                    && f.conditions.contains(&Condition::RemotePort(68))),
            "DHCP 服务端方向（本地 67 → 远端 68）必须存在"
        );
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

    /// `FindingKind::name()` 会被打进 `wfp_plan` 的每一行输出
    /// （`[{tag}/{kind.name()}]`），也是运维区分"必须改"与"可以商量"的依据。
    ///
    /// ⚠ 必须钉确切字面值。只验"非空"的话，把整个函数换成 `"xyzzy"` 照样通过，
    /// 而那样改的后果是：不变量和写法问题在输出里再无区别——
    /// 用户会把"可以商量的卫生问题"当成"必须修的底线"，或者反过来。
    #[test]
    fn finding_kind_names_are_pinned() {
        assert_eq!(FindingKind::Invariant.name(), "不变量");
        assert_eq!(FindingKind::Hygiene.name(), "写法");
        assert_ne!(FindingKind::Invariant.name(), FindingKind::Hygiene.name());
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
        let e = Finding::error(FindingKind::Hygiene, "X", "d");
        assert!(e.is_error());
        let w = Finding::warn(FindingKind::Invariant, "Y", "d");
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

    /// 明文 80 阻断计划：恰好两条（V4+V6），都 Block 目的端口 80，且是运行期规则。
    #[test]
    fn plaintext_http_block_plan_targets_only_port_80() {
        let plan = plaintext_http_block_plan();
        assert_eq!(plan.len(), 2, "V4 + V6 各一条");
        for f in &plan {
            assert_eq!(f.action, Action::Block, "必须是阻断");
            assert_eq!(
                f.conditions,
                vec![Condition::RemotePort(PORT_PLAINTEXT_HTTP)],
                "只匹配目的端口 80，不牵连其它端口"
            );
            assert_eq!(f.tier, Tier::Runtime, "必须是运行期（进程退出即清空）规则");
            assert!(!f.survives_reboot(), "绝不能写进 Boot 层——装错即变砖");
        }
    }

    /// 明文 80 计划必须通过 preflight：无 Boot 规则、条件可映射。
    #[test]
    fn plaintext_http_block_plan_passes_preflight() {
        assert!(crate::preflight(&plaintext_http_block_plan()).is_ok());
    }

    /// 它不是"默认拒绝"——不含任何无条件的兜底规则，独立应用时不会全盘断网。
    #[test]
    fn plaintext_http_block_plan_is_not_a_catch_all() {
        assert!(
            plaintext_http_block_plan()
                .iter()
                .all(|f| !f.is_catch_all()),
            "明文 80 计划只拦 80，不能兜底断网"
        );
    }
}
