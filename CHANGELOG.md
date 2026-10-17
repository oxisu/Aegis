# 变更日志

本项目所有值得注意的变更都会记录在此文件。
格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)；
版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

版本号的完整定义、递增规则与发版流程见 **[`docs/VERSIONING.md`](docs/VERSIONING.md)**。
当前权威版本号存放在仓库根目录的 [`VERSION`](VERSION) 文件。

## [Unreleased]

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
  - 配置见 `mutants.toml`；CI 的 `mutation` job 每周一 + 手动触发，
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
