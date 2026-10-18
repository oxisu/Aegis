# 变更日志

本项目所有值得注意的变更都会记录在此文件。
格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)；
版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

版本号的完整定义、递增规则与发版流程见 **[`docs/VERSIONING.md`](docs/VERSIONING.md)**。
当前权威版本号存放在仓库根目录的 [`VERSION`](VERSION) 文件。

## [Unreleased]

### Changed

- **架构：新增 `aegis-model`，策略层彻底脱离 Win32**（性能 + 分层双修）
  - 把 `aegis-sense/src/model.rs` 整块下沉为独立的 `aegis-model` crate
    （该文件本身只用 `serde` + `std`，grep 不到任何 `windows::`）
  - `aegis-core` 的依赖从 `aegis-sense` 换成 `aegis-model`。原来为了拿
    `InterfaceInfo` / `InterfaceKind` / `if_flags` 这 3 个类型，策略层被迫
    依赖整个感知层，把 `windows` crate 拖进了纯逻辑的依赖图
  - 实测（改一行代码后 `cargo test -p X`，含 examples，稳态第 2 轮）：

    | crate | 改前 | 改后 |
    |---|---|---|
    | aegis-core | 7.4–22.5s | **3.9s** |
    | aegis-config | 13.8–16.3s | **3.6s** |
    | aegis-sense | 6.7–14.9s | **3.6s** |
    | aegis-wfp | 4.1–19.7s | 4.0s（未动） |

    现在全部 crate 都落在 2–4s 区间。`cargo tree -p aegis-core | grep -c windows` = 0
  - 顺带把「策略层必须能在普通用户下只读干跑」从口号变成事实：
    原来光是编译策略层就得先把 WFP 绑定编一遍
  - `example plan` 需要真的采一次拓扑，属接线演示，故 `aegis-sense`
    降级为 `[dev-dependencies]`——**库与单测永不碰 Win32**

### Added

- **`aegis-fuse` 接上 `NotifyIpInterfaceChange`**（FFI 层落地）
  - 模块分层：`debounce` / `notify` / `signal` **零 Win32 依赖**（可完整单测），
    `unsafe` 只出现在 `watch.rs` 一个文件里
  - **回调即弃**：系统回调只做 `ChangeKind` 分类 → `should_react` → 一次
    `fetch_add`。绝不分配内存、加锁、打日志、碰 WFP——它跑在系统线程池上，
    堵住的后果是网络栈死锁而不是"慢一点"
  - `initialnotification` 传 **false**：传 true 会在注册瞬间把所有现存接口
    喂一遍，那不是变动，响应它会**让服务一启动就把网断了**，
    而日志上只写"检测到网口变动"，看不出为什么
  - `ChangeSignal` 用**计数**而不是布尔标志：布尔会丢事件，"震荡 30 次"
    和"变动 1 次"在日志与告警里含义完全不同（有并发测试钉住）
  - `examples/fuse_watch`：网口变动干跑，无需管理员权限，插拔网线即可看到
    Trip / Coalesced / 叫醒 Worker 的完整时序；已在本机实测跑通
  - ⚠ 残留风险已记录：`CancelMibChangeNotify2` 返回后仍有极短窗口的回调在
    飞行中；彻底解法是回调里先把引用计数 +1（需全局注册表），留到接 `aegisd` 时做

- **`aegis-fuse` 拓扑震荡熔断器**（新建 crate，**当前纯逻辑**）
  - `ShockDebouncer`：§20.3 / §28.3「回调风暴」的修正是**先熔断、后分析**——
    第一个网口变动事件**立刻**切绝缘（不等去抖，等了就给了 OS 一个用
    默认路由发包的窗口），后续震荡合并掉，去抖窗口（50–100ms）过后
    才叫醒异步 Worker 做重活，且**只叫醒一次**
  - 时间从外部注入、不依赖 Win32，因此时钟回拨、时钟跳变这类边界
    都能在普通单测里推演；FFI 层之后单独加，把 unsafe 关在那一层
  - 实现时单测抓出一个自己写错的地方：时钟回拨用 `saturating_sub` 得到 0
    = "窗口还没过" → Worker 永远不被唤醒 → **用户一直断网且不报错**

- **`tools/mutate-changed.sh`**：日常只跑「我刚改的文件」的变异测试。
  全工作区 572 个变异体单机要一个多小时；只跑改动文件通常几分钟

- **`aegis-wfp` 绝缘笼规则计划与静态自检**（纯逻辑，**不下发任何东西**）
  - `CagePolicy` → `cage_plan()` → `Vec<FilterSpec>`：把"要装哪些规则"做成
    可推演、可单测的纯数据，而不是埋在 `FwpmFilterAdd0` 调用里
  - `verify()` 在**不下发**的前提下回答"这份规则会不会把我自己锁死"：
    权重关系、回环/DHCP 放行是否缺失或被遮蔽、每层是否有无条件兜底阻断、
    Boot-Time 层条件是否全部静态可判定
  - 权重常量本身即安全承诺（回环 15 > DHCP 14 > 53 封锁 13 > 广播封锁 12 >
    存量流 DROP 10 > 默认拒绝 5），用 `const { assert! }` 在编译期锁死
  - 条件抽象为枚举（`RemotePort` / `RemoteAddrV4` / `Loopback` /
    `PhysicalInterface` / `ProcessId` / `ServicePid`）而非直接构造
    `FWPM_FILTER_CONDITION0`：后者要求分配与 unsafe，没法在普通单测里推演
  - Boot-Time 持久背板默认关闭；启用后 `verify()` 给出 `Warn` 要求显式确认
  - `examples/wfp_plan`：干跑 CLI，按层打印权重 / 动作 / 生命周期层 / 条件
    并给结论（可下发 / 需确认 / 不可下发），无需管理员权限

- **`aegis-wfp` WFP 状态勘察**（新建 crate，**当前仅只读**）
  - 打开**动态会话**（`FWPM_SESSION_FLAG_DYNAMIC`）：崩溃时引擎自动回收
    该会话的一切对象。写在会话标志里而非"退出前记得清理"，因为崩溃路径上
    没有机会执行清理代码
  - 枚举过滤器与 Provider，输出层 / 动作 / 归属（过滤器的 `providerKey`
    只是 GUID，靠 Provider 索引翻译成人能读的名字与服务名）
  - **持久背板审计**（§28.2 变砖地雷）：挑出 persistent / boottime 过滤器，
    按归属分为"系统自带底板"与"第三方 / 未知归属"，只有后者才算雷
  - 层与动作的可读化（纯逻辑，可脱离 Windows 权限单测）；未知层回退成 GUID，
    宁可显示得朴素也不显示错
  - `examples/wfp_inspect`：只读勘察，权限不足时明确报出错误码与处置建议，
    而不是假装"什么都没有"

### Fixed

- **持久背板审计的首版是假警报**
  只要见到 persistent/boottime + 阻断就报"可导致变砖"，本机实测立刻翻车：
  48 条持久 / 引导时间过滤器**全是 Windows 自带的引导时间底板**
  （归属 `@bfe.dll,-1211`，服务 `mpssvc`），BFE 启动后自行撤销。
  假警报的代价与假漂移同类——用户被无意义告警淹没后会不再看告警，
  真正危险的那次也被一起忽略。改为按归属再分一层。
- **`SYSTEM_SERVICES` 里 `IKEEXT` 被拼错成 `ikkext`**，导致 IKE 相关
  Provider 的过滤器被误判为第三方。已由单测捕获并修正（拼写以实测输出为准）
- **DHCP 放行写成"目的端口=67 且 目的端口=68"**——WFP 的多条件是 **AND**
  语义，这是一条**永假条件**：写上去不报错，只是永远不生效，表现就是开机
  断网。已按端口拆成两条独立规则，并补回归测试
  `no_filter_contradicts_itself_on_remote_port`
- **同权重检查过严**：三条同权重的端口封锁（5353/5355/137）动作相同，
  命中哪条结果都一样，不该判为"评估顺序不确定"。改为只在**动作不同**时报
- **空计划被判 `DHCP_MISSING`**：空计划等于什么都没装，不会锁死任何人。
  检查已改为只在计划非空时生效

## [0.1.0-alpha.2] - 2026-10-18

自 `v0.1.0-alpha.1`（`a6797cb`）以来的 21 个提交。新增三个 crate
（`aegis-ipc` / `aegis-config`）与 `aegis-core` 的角色策略与状态机测试补强。
**接口仍未冻结**，IPC 协议与配置 schema 均未定型。

### Added

- **`aegis-ipc` 本地 IPC 协议层**（新建 crate）
  - 帧格式手写，**刻意不引入 serde / bincode**：帧布局是跨进程二进制契约，
    交给序列化库后，库的一次升级就可能悄悄改变线上帧布局，而 `aegisd` 与
    `aegisctl` 的升级节奏并不一致
  - 定长 16 字节头 + 载荷 + FNV-1a 32 校验和；保留位非 0 直接拒绝，
    不允许旧实现对着看不懂的新格式"猜着解析"
  - 载荷上限 64 KiB，防止对端被攻破后用巨大长度字段打爆内存
  - `FrameReader` 把分片 / 粘包收进类型内：命名管道是字节流，一次 read
    的边界与帧边界无关，直接 decode 单次 read 会在分片时误判为坏帧
  - 版本握手：严格按本项目 0.x 约定，**MINOR 不同即判不兼容**
    （照抄"主版本号相同即兼容"会在 0.x 阶段静默放行不兼容的两端）
  - 纯逻辑，不创建管道 / 不设 ACL / 不碰特权对象，因此可在 CI 上完整测试
- **角色策略支持用户精确声明 SSID 名单**
  - 启发式（SSID 关键字 + 网关网段前缀）覆盖不了**个人手机热点**：SSID 是
    个人化的（如 `MMi`），不含 `hotspot` 关键字，网关也不在校园网段
  - 本机实测 WLAN：`MMi` 两种启发式都命中不了 → `Isolated` / `Unassigned`
  - 新增 `known_free_ssids` / `known_campus_ssids`：精确相等匹配、优先级高于
    关键字（用户可覆盖误判）、置信度标为 `Confirmed` 而非 `Inferred`
  - 不写入代码默认值——个人化 SSID 属用户生活习惯，声明权始终在用户手上
  - `plan` 示例新增 `--free` / `--campus`，可直接对比声明前后的裁决差异
- **`aegis-config` 配置加载与 schema 版本校验**（新建 crate）
  - **Fail-Closed**：配置里写着"哪些网卡可以出网"，解析失败若退回默认值，
    等于用一套用户没批准过的策略放行。因此任何失败都拒绝加载并明确报错，
    没有任何 `unwrap_or_default()` 式兜底
  - `config_schema_version` 单独校验：配置是对外契约，升级后字段语义可能已变，
    读旧配置按新语义解释 = 安全策略静默降级
  - 规则复用 `aegis_version::compat`（与 IPC 握手同一套）；0.x 阶段
    schema MINOR 不同（如 `0.2`）即拒绝
  - 严格性分层：已实现的段（`meta` / `roles` / `topology`）一律
    `deny_unknown_fields`，拼写错误必须报错而非静默忽略；顶层宽容，
    兼容本版本尚未实现的段
  - `roles` 段直接反序列化成 `RolePolicy`，不另建 DTO（两个结构必然漂移）
  - 两条护栏测试：配置声明 `MMi` → 裁决放行的端到端链路；
    仓库内 `config.example.toml` 必须能被本程序加载
- **变异回归测试（`cargo-mutants`）**
  - 单测全绿只证明"代码通过了我们想到的用例"，变异测试反过来问：
    注入一个 bug，测试会不会红
  - 配置见 `.cargo/mutants.toml`；CI 的 `mutation` job 每周一 + 手动触发，
    阈值 `MUTATION_MAX_MISSED=0`，产物以 artifact 上传
  - `CONTRIBUTING.md` 写入本地运行方式、漏检的处理办法与三条经验
  - 首轮 `aegis-core` 79 个变异体**漏检 26 个**，绝大多数是
    "delete match arm in next"——删掉任意一条状态迁移边测试仍全绿，
    用户真走到那条边时系统不会迁移
  - 修法：把 §26 状态图的 29 条边抄进测试逐边穷举（11 状态 × 15 事件 =
    165 种组合），并新增"无死锁状态"与"任何状态都能回到 Controlled"两条
    结构性不变量；`insulation()` / `awaits_user()` / `Display` 改为逐值
    钉死、布尔函数双向断言
  - 复测结果：**79 变异体，65 被杀死，14 不可行，漏检 0**（耗时 11 分钟）

### Changed

- **契约版本判定下沉到 `aegis-version::compat`**
  配置 schema 校验与 IPC 版本握手要用同一套规则；留在 `aegis-ipc` 里会让
  `aegis-config` 要么分层倒置依赖 IPC，要么另写一份而必然漂移。
  `aegis-version` 保持零依赖（手写 `Display` / `Error`，不引 `thiserror`）。
  顺带修正 `parse("")` 由 `NotANumber` 改为 `MissingSegment`。

### Fixed

- **变异测试在本机的两个假死现象**（详见 CONTRIBUTING.md）
  - 不带 `-v` 时输出走块缓冲，重定向后长时间不落盘，日志停在基线那一行，
    看起来像卡死（实测 45 秒 0 行）
  - `-j` 开并行是负优化：cargo 对 target 目录独占锁，`-j 8` 时单次构建
    从 5s 膨胀到 30~56s 并全部超时，`--copy-target` 亦无效。改为单线程
- **`aegis-core` 编排核心**（新建 crate）
  - 角色裁决（§20.5）：`InterfaceRole` 从感知层迁出——角色是策略而非感知事实，
    两处定义必然各自漂移，必须收敛为单一定义
  - 裁决顺序先硬约束后软提示：非物理网卡一律 `Isolated`
    （伪接口背后仍是同一张物理网卡，给它们单独分配角色等于开出第二条通路）；
    再匹配自由出海 / 校园网的 SSID 关键字与网关前缀
  - **兜底 Fail-Closed**：猜不出来就 `Isolated` + `Unassigned`
  - `RolePolicy` 全部可配置，不内置任何具体机构名 / 运营商名
  - 每条裁决带 `reason`：安全策略必须可解释
  - 状态机（§26）：11 状态 / 15 事件迁移表；两条铁律写成可执行函数 `insulation()`
    ——只有 `Controlled` 不绝缘、`Degraded` 仍完全绝缘（降级降的是监控不是防护）
  - `examples/plan`：只读推演，输出角色裁决与依据、需人工介入的网卡、铁律自检
- **`aegis-sense` 拓扑差分**（`delta` 模块）
  - `diff()` 比较两次快照，输出新增 / 消失 / 字段变化的接口
  - 把变更分成噪声与信号两级：`physical_changed()` 才触发重新确认，
    虚拟 / 过滤器 / 隧道变化只记录
  - `needs_reconfirmation()`：指纹漂移 / 默认出口变更 / 物理网卡增删改任一成立
  - `dry_run` 新增"稳定性自检"：连续两次采集差分，正常情况下必须零变化

### Changed

- **拓扑指纹收敛为仅物理网卡**（重要）
  - 原实现把所有 Up 接口都计入指纹，导致物理环境没变也会漂移：
    WFP / QoS / 杀软等 NDIS 轻量过滤器会为每张物理网卡派生若干伪接口，
    其数量与 LUID 随驱动装卸载、系统更新、PnP 重枚举而变
  - 假漂移代价很高：强制回 `[LOCKED]` 并反复打断用户，
    久了会养成"无脑点确认"的习惯，零信任直接失效
  - 新增 `InterfaceKind { Physical, Filter, Tunnel, Loopback, Virtual }`，
    判据为 `MIB_IF_ROW2.InterfaceAndOperStatusFlags` 位域；
    判定顺序刻意"先伪后真"（过滤器伪接口同时带 HARDWARE 位）
  - 参与集合 `Physical → NonFilter → AllUp` 逐级放宽，绝不对空集算指纹
  - 指纹格式版本 **v1 → v2**；补上 gateway 分量（早期实现文档写了但代码漏了）
  - 本机实测：44 张网卡 = 3 物理 / 25 过滤器 / 7 隧道 / 1 回环 / 8 虚拟，
    指纹仅由 2 张 Up 的物理网卡算出

## [0.1.0-alpha.1] - 2026-10-17

首个内部验证版本。感知层（只读）跑通，可在本机校园网环境下安全干跑。
**接口未冻结**，IPC 协议与配置 schema 均未定型。

### Added

- **项目正式命名 `Aegis`（宙斯的神盾）**，英文为主、中文为辅；
  `aegis` 直接进入代码结构——全部 crate 统一 `aegis-` 前缀，
  守护进程 `aegisd`、控制端 `aegisctl`，并在 workspace 清单里固定完整 crate 版图
- **版本编号体系**（SemVer `MAJOR.MINOR.PATCH[-PRERELEASE][+g<hash>]`）
  - 新增零依赖 crate `aegis-version`：版本号的单一事实来源，
    提供 `full()` / `banner()` / `banner_long()` 与版本号解析
  - 新增 `VERSION` 文件与 `docs/VERSIONING.md`（形态、0.x 约定、四处存放位置、
    一致性校验、发版流程、Git tag 规范、演进路线）
  - 新增 `examples/version`：打印完整版本号，供 CI 归档
  - 构建期采集 Git 短哈希与分支；**刻意不启动子进程**，直接读 `.git` 目录
- **项目标准化骨架**：Git 忽略规则、行尾策略（`.gitattributes`）、编辑器规范
- **Cargo workspace**：统一 crate 元数据与依赖版本，Release profile 面向最小体积
- **工具链标准**：`rust-toolchain.toml`、`rustfmt.toml`、`clippy.toml`
- **采用 GNU AGPL-3.0 许可证**
- **`aegis-sense` 感知层（只读）**
  - 数据模型：网卡信息、角色枚举、运营状态、拓扑快照（与 Win32 API 解耦）
  - 统一错误类型 `SenseError`，任何 Win32 失败向上传递而非 panic
  - `GetIfTable2` 网卡枚举（LUID / MAC / 别名 / 类型 / 运营状态）
  - `GetAdaptersAddresses` 采集 IPv4 与 DHCP 服务器
  - `GetIpForwardTable2` 路由采集 + 默认出口裁决
  - `GetIpInterfaceTable` 采集**接口度量**（正确裁决默认出口的关键输入）
  - WLAN AutoConfig API 采集 **SSID**（失败时降级为 `None`）
  - **SHA-256 拓扑指纹**（§20.4）：仅 Up 接口参与，按 LUID 排序保证可重复
  - `dry_run` 示例：纯只读自检，打印三条度量明细使裁决依据可人工核对
- **`tools/clean-ghost-nics.ps1`**：幽灵网卡（安卓 USB 共享 RNDIS 残留）
  盘点与清理。默认只读，带系统组件保护名单，删除前自动备份
- **编排器配置样例** `config/config.example.toml`（对齐 §22 schema）
- **CI 工作流**：格式校验、Clippy、Windows 构建与干跑、版本号一致性校验

### Fixed

- **默认出口裁决误判（静默错误，危害高于崩溃）**
  `MIB_IPFORWARD_ROW2.Metric` 只是"路由度量偏移量"，DHCP 自动度量下恒为 0；
  原实现直接拿它比大小，等于在 0 和 0 之间比较，结果由路由表内部顺序决定。
  本机实测：`以太网 4`（接口度量 25）与 `WLAN`（接口度量 55）两条默认路由的
  偏移都是 0，修复前裁决为 `WLAN`，修复后正确为 `以太网 4`。
  现改为按**合成度量 = 接口度量 + 路由度量偏移**裁决，度量相同时按 LUID 取小，
  并补了 4 个回归测试。
- **幽灵网卡清理**：移除两个 RNDIS 幽灵设备
  （`USB\VID_2717&PID_FF88` 小米系、`USB\VID_2D95&PID_600B`）。
  这两个 `Present=False` 的残留会让 Windows 每次插拔生成新 LUID，
  导致拓扑指纹无故漂移。在用的两块物理网卡与两条默认路由均未受影响。
- **`*.ps1` 脚本在本机完全不可用**
  文件为无 BOM 的 UTF-8 + LF，Windows PowerShell 5.1 按 GBK 解码后中文错位，
  连解析都失败；另有 `??` 空合并等 PS 7+ 语法。统一改为 UTF-8 BOM + CRLF
  并使用 5.1 兼容语法。
- **`build.rs` 的 Git 哈希不更新**
  只监听 `.git/HEAD` 时，同分支新增提交不会触发重跑，版本号里的哈希会停在
  首次构建那次提交。补上 `refs/heads/<当前>` 与 `packed-refs` 两个触发点。

### Security

- 感知层确立"四不"硬约束：不注入防火墙规则、不启停进程、不改注册表、
  不要求管理员权限。任何代理软件的启停都必须由用户显式授权。
- 幽灵网卡清理脚本默认**只读盘点**，需显式 `-Apply` 才执行删除；
  系统自带组件（WAN Miniport / Wi-Fi Direct / 蓝牙 PAN / 隧道接口 / 内核调试器 /
  虚拟化网卡）一律列入保护名单不删。
