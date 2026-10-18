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

- **`aegis-audit` 审计与证据链**（新建 crate，**当前纯内存，未落盘**）
  - `event::AuditEvent`：一条出站连接的完整事实（谁 / 哪到哪 / 协议 /
    走哪张网卡的哪个角色 / 结果如何）。`host` 与 `rule` 是**可空富化字段**——
    按 §12 F3 的修正，第二审计源拉不到不影响基本审计，绝不为了凑齐而丢记录
  - `encode::canonical_bytes`：**手写版本化 + 长度前缀**的规范化编码作为哈希
    输入，刻意不用 `serde_json` / `bincode`
    - 库升级会改字节布局，而证据包是要拿出来给网络中心看的，那时没法重算
    - 给 struct 调字段顺序是最普通的重构，却会静默改变哈希
    - 分隔符拼接可被"挪字段边界"撞车（`("ab","c")` vs `("a","bc")`），
      而进程路径是攻击者部分可控的
    - `None` 与 `Some("")` 必须可区分：前者是数据缺失，后者是数据为空
  - `chain::EvidenceChain`：SHA-256 哈希链，`hash = SHA256(prev ‖ canonical)`
    - ⚠ **尾部截断抓不住**，这是哈希链的固有性质。文档 + 单测
      （`trailing_truncation_is_inherently_undetectable`）+ 干跑示例三处都写明：
      唯一缓解是**链头定期外置**。不写清楚会让人以为"上了链就防删"，
      那是比没有更危险的虚假安全感
    - 删中间一条并把链节重编号：序号骗得过去，前驱哈希骗不过
    - 防篡改 ≠ 防伪造（持有密钥者可整链重算），要防伪造得上签名，后话
  - `ring::AuditRing`：有界内存缓冲（§15「不长期驻留内存」）
    - **丢弃必须可观测**：`dropped` 只增不减。UI 那张"最近 N 条"的表格
      会被当成全量，而缺口在哪用户无从得知
    - `drain()` 一次性换出整个缓冲，落盘 I/O 在**锁外**做——
      否则一次磁盘抖动就能堵住内核回调路径
  - 整 crate 零 Win32 调用、无需管理员权限

- **设计文档 §3.1 组件依赖图 + §3.2 时序图**（§21 第 1 项）
  - §3 原图只有"分层职责"，没有 crate 级依赖方向；且图里还写着已被 §2A.4
    取代的 `ProxyAdapter / MultiWanAdapter / AuditEnricher`，已一并更正为
    **能力接口**
  - §3.1 含依赖方向铁律与实测性能对比表（core 22.5s → 3.9s），
    以及每个 crate 的 `unsafe` 落点表（每 crate 最多一处）
  - §3.2 时序图覆盖：开机绝缘笼 → 拓扑指纹 → 角色放行 → 网口变动熔断，
    并钉住**四条不能改的顺序**（先关笼子再问问题 / 指纹只算物理网卡 /
    熔断不等去抖 / 放行权重必须高于默认拒绝）

- **设计文档：三处架构修订**（吸收外部评审，有取有舍）
  - **§2A.4 SPI 改为「能力接口」而非「软件接口」**。原 `ProxyAdapter` /
    `MultiWanAdapter` / `AuditEnricher` 是按软件类别切的，且 `Result<()>`
    无法表达"这个能力我不支持"——失败与不支持混为一谈。改为 `Capability`
    枚举 + 能力矩阵
    - 补强一：`Unsupported`（契约信息，不是故障）与 `Failed`（真故障）
      **必须分开**。混在一起会让"Aegis 一直重试一个永远不可能成功的能力"，
      也会让"真的挂了"被当成"本来就不支持"而静默吞掉
    - 补强二：**每个能力缺失时的处置必须预先定死**，不能笼统说"走保守策略
      （Fail-Closed 或告警）"。这个二选一一旦留给运行时判断，就会出现
      "本该断网的时候只是弹了个提示"。`DnsOwnership` /
      `TunInterfacePresent` / `DefaultEgress` 缺失 = Fail-Closed；
      `Reload` / `HealthProbe` / `ConfigFragmentGenerate` 缺失 = 告警降级
    - 补强三：**能力声明 ≠ 能力事实**。声明必须由 fixture 契约测试 +
      运行时能力自检验证；声称支持却做不到要报 `Failed` 而不是信它
    - 目标从"确保能适配"改为"把不确定性显式化，并保证不适配时不漏流量"
  - **§20.10 规则模型改为「不变量层 + 可覆盖策略层」，不做全局优先级链**。
    每一级用户都能定制，硬编码"Aegis > 网卡融合 > 代理"一改就失效。
    5 条不变量是"宪法"，**不参与规则引擎排序**；Aegis 只做不变量校验器，
    不替用户排序
  - **§12.0 范围刹车**：「监测」与「截住/放出去」分三档，先做事件级审计与
    关键协议阻断，**全量裁决/截包后做**（需 callout 或驱动，成本极高）。
    明确 Aegis 出**裁决**（permit/block/audit），不碰 NAT、不碰代理链

- **`aegis-wfp`：校验结论按归属层分开 + 策略兑现对账**
  - `Finding` 新增 `kind`：`Invariant`（第一层不变量，底线没守住）与
    `Hygiene`（第二层写法问题，会静默失效）。两者都阻止下发，但报错语义
    不同——混为一谈会让用户把"权重写越界"误当成"我改了底线"（从此不敢
    定制），也会把"底线没兑现"误当成"只是没写好"（从此不当回事）
  - `Finding::error` / `warn` **必须显式传 kind**（刻意没有不带 kind 的
    重载），逼每个检查点在写下时就想清楚归属
  - `verify_policy(plan, policy)`：策略声明 vs 计划产出的**对账**。抓的是
    `verify()` 的盲区——把 `dns_lock` 关掉，计划照样自洽、照样"安全"，
    只是 DNS 不再被锁，而用户从配置上看是"DNS 已锁"
  - `UNDECLARED_BOOT_RULE`：策略说**不要**持久背板，计划里却有 Boot 规则。
    这是最危险的脱节方向——Aegis 悄悄往机器上留下进程退出与重启都清不掉的
    东西，而用户在配置里看不到
  - `invariants_violated()` 只统计第一层，让运维能区分"被底线拦了"与
    "只是写错了"（两者处置完全不同）
  - 测试 100 → 109

- **`aegis-audit` 证据导出**（§F3「自证」的实际出口）
  - 证据链做得再漂亮，拿不出来给网络中心看就只是自我安慰。这是那个
    "拿出来"的动作
  - **CSV 公式注入**：进程路径是**攻击者可控**的，恶意进程可以把自己命名成
    `=cmd|'/c calc'!A0`，导出后用 Excel 打开就会执行。按 RFC 4180 加双引号
    **挡不住**——引号是 CSV 语法，Excel 解析后看到的仍是以 `=` 开头的内容。
    必须在引号**内部**补一个前导 `'`（放外面会破坏引用结构，行照样被撑开）
  - **控制字符写成字面转义序列**：RFC 4180 允许引用字段含换行，但那样一条
    记录占多行，而审计条数本身是要拿去对账的——表格里"共 N 行"必须对得上
    "共 N 条"。进程名里带换行是攻击者完全做得到的
  - **时间恒为 UTC**：本机时区导出的时间跨系统无从比对，而证据包恰恰是要
    跨系统看的。毫秒时间戳一并保留（唯一无歧义的那一列）
  - **证据包自带校验结论**（`verified`），且是**导出时算出来的**不是事后填的。
    只导出事件不导出链头与校验结果，对方无从判断有没有被改过
  - 手写 JSON 转义、手写 ISO 8601 换算（Hinnant 算法），都不引依赖：
    证据格式要跨十年可复现，算法写死在这里反而更稳
  - 筛选：时间范围 / 动作 / 角色 / `blocked_only`（自证场景最常用）
  - 测试 54 → 67

- **`aegis-audit` 落盘层**（只追加的二进制日志，§15）
  - ⚠ **暂不用 SQLite**：设计文档 §15 写的是 SQLite，但 `rusqlite` bundled
    要编译一份 C 的 SQLite，正是刚在 `aegis-model` 那次重构里费力清掉的
    东西（策略层构建 22s → 3.9s）。检索与索引后补；先把"落得下来、
    重开接得上"做实
  - **只追加，绝不改写**：改写已写出的记录 = 证据可被事后修订，那链就没意义
  - **重开必须接着走**：`open` 重放已有记录恢复链头与计数。不重放就只能从
    `GENESIS` 重新开始，于是服务每重启一次历史记录就与新链脱节一次，
    而脱节的表现正像"有人删了记录"
  - **分片只是文件边界，不是证据边界**：新分片首条的前驱仍是上一分片的链头。
    若在新分片里重开链，每个分片边界都变成断链点，而"分片处断链"
    看起来跟"有人删了整个分片"一模一样
  - 分片里序号是**全局连续**的，所以续接分片必须带 `ReadCtx` 读，
    不能假设它从 1 号 / `GENESIS` 开始
  - **先算链节 → 写盘 → 成功才进链**：写盘失败时链不动，
    "链上有的"必然是"盘上有的"
  - 读回遇到损坏**停下并报错**，不跳过继续：跳过会让后面所有记录的前驱
    都对不上，用户看到"链断了"却不知道是因为少读了几条
  - 崩溃语义说清楚：`flush` 只进 OS，`sync` 才真落盘；默认定期 sync 而非
    每条 sync（每条 sync 会把 WFP 事件速率压到磁盘速率上），代价是掉电
    可能丢最后几条
  - `create` 若文件已存在则失败：覆盖已有日志 = 销毁证据，不能静默发生

- **`aegis-ipc` 命名管道本体 + 显式 DACL + 一次性 token 鉴权**（§23.1 落地）
  - **显式 DACL**：建管道必传 SDDL（`SY`/`BA` 完全控制，`AU` 读写）。
    传 `NULL` 会继承 SYSTEM 的默认 DACL，GUI 不提权就**连不上**，而失败
    表现只是"连接被拒绝"，看不出是 ACL 的锅——正是 §16/§20 修正 #5 那件事
  - **`FILE_FLAG_FIRST_PIPE_INSTANCE`**：少了它，任何进程都能抢先建同名
    管道冒充服务（squatting）。GUI 不提权，它无法区分真假服务，
    这是第一个能被提权的口子
  - **句柄不可继承**（`bInheritHandle = false`）：否则服务启动的子进程会
    继承管道句柄，鉴权等于开了后门
  - 字节流模式而非消息模式：帧本就带长度前缀，分片/粘包由 `FrameReader`
    负责；消息模式会多引入 `ERROR_MORE_DATA` 半截读语义，反而多一处错点
  - `IpcToken`：32 字节 `BCryptGenRandom`，**常量时间比对**（`acc |= x ^ y`
    累积而非覆盖），`Debug` 只打印 `IpcToken(..)` 防日志泄露
  - `unsafe` 只出现在 `pipe.rs` 一个文件里；端点常量、帧、版本、token
    全部零 Win32 依赖，可完整单测
  - `examples/ipc_dryrun`：进程内真实命名管道跑通
    建管道 → 连接 → 握手 → 鉴权 → 伪造 token 被拒 → 篡改帧被校验和抓住，
    无需管理员权限

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

- **对端关闭被误判成协议故障**：客户端 `CloseHandle` 后，阻塞中的 `ReadFile`
  **不会**返回 `got == 0`，而是直接以 `ERROR_BROKEN_PIPE`（109）失败。
  原先只认 `got == 0`，于是"客户端正常退出"被当成读失败上报，服务会去
  告警、去重连。已把 109 / `ERROR_PIPE_NOT_CONNECTED`（233）归一到
  `Disconnected`。
- **`ConnectNamedPipe` 的两个合法失败被当成故障**：`ERROR_PIPE_CONNECTED`
  （535，客户端在 `CreateNamedPipeW` 与 `ConnectNamedPipe` 之间就连上）是
  **成功**；`ERROR_NO_DATA`（232，连上又立刻断开）是 `Disconnected`。
  一律报 `AcceptFailed` 会让服务在竞态窗口里随机拒绝合法客户端。
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
