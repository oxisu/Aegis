# 变更日志

本项目所有值得注意的变更都会记录在此文件。
格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)；
版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

版本号的完整定义、递增规则与发版流程见 **[`docs/VERSIONING.md`](docs/VERSIONING.md)**。
当前权威版本号存放在仓库根目录的 [`VERSION`](VERSION) 文件。

## [Unreleased]

### Added

- **`tools/cage-drill.sh`：绝缘笼全流程演练，**自动恢复**，不需要人在场**
  - 装上去的那一刻网络就没了，人在这时候能做的事非常有限；
    AI 也没法在对面断网的时候跟人配合。所以整套动作事先写死在脚本里，
    靠**时间**而不是靠**人**来恢复
  - 四层兜底，任何一层生效网络就回来：

    | 层 | 手段 | 上界 |
    |---|---|---|
    | 0 | 10 秒倒计时自动撤销 | 10s |
    | 1 | 脚本 `trap` 里 kill aegisd | 脚本一结束 |
    | 2 | `aegisd --serve-secs 45` 到点自己退出 | **45s（硬上界）** |
    | 3 | `tools/aegis-restore.sh` | 一条命令 |
    | 4 | 手动：结束 aegisd / 重启 | — |

    第 2 层是真正的安全网：脚本被杀、终端被关、机器卡住都无所谓，
    45 秒后 aegisd 一定退出，动态会话随之清空。**最坏情况有硬上界**
  - 每一步都写进 `.aegis-run/drill-<时间>.log`；守护进程输出单独存
    `drill-daemon.log`。事后能完整复盘
  - 真机演练结果（5 项全过）：

    ```text
    ✅ 装之前外网通      ✅ 装之后外网断（绝缘笼真的拦住了）
    ✅ 断网期间 IPC 仍活 ✅ 倒计时后自动恢复      ✅ 收尾后外网通
    ```

    「断网期间 IPC 仍活」是关键一条——它把"没网也能用本地 IPC 强拆"
    从说法变成了实测

- **`tools/aegis-restore.sh`：一键恢复**。先走 IPC 强拆（不需要网络），
  再结束 aegisd，每步都验证一次；还是不通就打印手动步骤和日志路径

- **`docs/CAGE-PLAN.md`：那十条规则逐条在防什么**。只报条数没有判断价值——
  十条里有 4 条是"无条件"的，正是它们决定整机通不通

- `aegisd` 第 6 步现在**逐条打印**计划（层/动作/权重/条件），
  而不是只报一个数字

- **`aegisctl` 拆出 `apply` / `confirm` / `rollback` 三个子命令 + 10 秒防呆倒计时**
  - `apply` 装完**只是待确认**：10 秒内没有 `confirm` 就看门狗自动撤销。
    装错了、手滑了、人不在机器旁边，都不需要做任何事，网络自己会回来
  - **看门狗线程持有会话**，每 200ms 巡检。会话**不能**提前释放：
    动态会话一旦关闭，内核就把这次装的全部规则清掉——所以确认之后也要继续守着
  - ⚠ `Session` 里是原始 HANDLE，**不是 `Send`**，所以会话**生在**看门狗线程里，
    从头到尾没离开过那个线程（反过来先装再想办法交给守护线程是搬不动的）
  - `rollback` 能撤掉**已确认**的规则（`force_teardown`）。这是紧急拆除的命脉：
    "一条命令能救回来"和"必须重启"是两种事故等级
  - 过期后 `confirm` 必须失败，否则"超时回滚 → 再确认一次 → 又装回去"，
    而这第二次没人兜底
  - **命令分级闸门**：`apply` / `confirm` / `rollback` 除 token 外还要求
    对端进程**已提权**（`TokenIsElevated`），否则以退出码 8 拒绝
  - 应答带 `ok ` / `denied ` 前缀，控制端按**前缀**判成败，不在正文里搜"失败"

- **`SECURITY.md` + `docs/EMERGENCY-TEARDOWN.md`**：出事之后怎么把网络救回来
  - 手册第一条路是本机 IPC 强拆——**命名管道走内核 NPFS，不经过 IP 栈**，
    所以"网断了"不影响拆除；第二条路是结束 `aegisd`（动态会话随之清空）；
    第三条路是重启（本版不装 Boot 层规则，所以重启一定是干净的）
  - 明确写出哪些是"刻意留下的取舍"而不是疏漏：token 文件 AU 可读、
    规则不跨进程存活、无法按服务精确放行

- **真实下发通路 + 三个探针（只读 / 只装放行 / 只拦一个网站）**
  - `examples/apply_probe`：把计划里所有**放行类**规则逐条"装上再按 id 拆掉"。
    放行规则装上去等于什么都没变，但能验证"会话能开 → 翻译得对 → 内核接受 →
    按 id 删得回去"。**它一条阻断规则都不装**
  - `examples/probe_appid`：只读探针，实测 `FwpmGetAppIdFromFileName0` 的语义
  - `examples/name_probe`：**"按域名拦"到底能不能做到**，两幕
    - 第一幕（真能用）：把域名解析成 IP 集合，逐 IP 装 Block。
      实测 `www.baidu.com:443` 断、`www.qq.com:443` **仍通**、拆掉后恢复。
      但这是**代换**：CDN/轮询 DNS 换 IP 就 silently 失效、共享 IP 误伤、
      V4 层管不到 AAAA
    - 第二幕（此路不通）：`FWPM_CONDITION_ALE_EFFECTIVE_NAME` 确实在这一层的
      字段表里、名字听着就像"远端主机名"，但把主机名塞进 blob 装一条 Block，
      **装住不拆**地测 —— 目标仍然可达
    - ⚠ **装得上 ≠ 拦得住**，这已经是第三次撞到了（blob 类型 → 字节序 →
      名字匹配）。内核接受一条规则只证明参数合法
    - 结论印证 §2 的分工：**域名是 App Level 的概念**，底座只认 IP。
      所以 `Condition::RemoteName` 刻意**不在** `mappable` 白名单里，
      `preflight` 会拒绝任何含它的计划

  - `examples/block_probe`：**阻断规则真机自证**。解析百度拿到真实 IP，
    装一条只拦"这个 IP 的 443"的规则，自己做前后对照：

    ```text
    ✅ 装之前 443 通        ✅ 装之后 443 断（规则生效）
    ✅ 装之后 80 仍通       ✅ 拆之后 443 恢复（回滚干净）
    ```

    80 必须仍通——它要是也断了，说明拦的范围比声明的大，那比装不上更危险。
    判通断用 **TCP 握手不用 ping**：ALE 层不管 ICMP，用 ping 会得到假的
    "没生效"结论。只拦一个网站的 443 几秒钟，把"阻断真的生效"
    从信念变成实测

- **`tools/crash-drill.sh`：崩溃安全演练——进程被硬杀之后规则还在不在**
  - 正常退出验了不算数：它证明的是"我们的 rollback 写得对"，不是
    "崩溃路径安全"。要验的是**清理代码一行都没跑**的那条路径
  - 做法：装一条只拦 `www.baidu.com:443` 的规则 → 进程**挂住不动**
    （不拆、不 drop、没有 Drop impl）→ `taskkill /F`（`TerminateProcess`：
    没有 atexit、没有 DLL 分离、没有析构）→ 再测连通性
  - 只拦一个 IP 而不是整副笼子：整副笼子的 blast radius 是整机断网，
    万一验证不成立就只剩重启能救；一个 IP 验证的是同一件事，
    最坏情况只是百度暂时打不开
  - 真机演练结果（5 项全过）：

    ```text
    ✅ 装之前通                 ✅ 装之后断（规则确实生效）
    ✅ 阳性对照：BFE 里查得到它（1 条）
    ✅ 强杀之后通（内核清了）   ✅ BFE 里查不到了（0 条）
    ```

    **兜底在内核侧，不在我们的代码里** —— 这正是断电 / 蓝屏要的保证：
    崩溃路径上没有机会执行清理代码，所以清理必须不由我们来执行
  - ⚠ **差点放过的一个假测量**：`netsh wfp show filters` **不往 stdout 输出**，
    它在**当前目录**写 `filters.xml`（本机 2.9 MB）。第一版 `netsh ... | grep -c`
    恒为 0，看起来通过了其实什么都没测。现在加了**阳性对照**：
    装着时必须先查得到（1 条），强杀后"查不到"才算证据。
    没有阳性对照的 "0" 不是证据，只是没测到

- **`docs/CRASH-SAFETY.md`：断电 / 蓝屏 / 强杀之后会留下什么**
  - 五种场景逐条给结论 + 依据来源（**哪些实测、哪些推断**，标明）：
    A 装着笼子断电 / B 没装断电 / C 蓝屏 / D 数据损坏导致无法联网 / E BFE 起不来
  - 结论：重启后一定干净且一定能联网。动态会话里的对象只存在于内核内存，
    从不写入 BFE 持久存储；本版还**从不装 Boot 层规则**（`preflight` 拒绝
    `Tier::Boot`）、不写注册表 / 不注册服务 / 不装驱动（grep 可复核，0 处）
  - ⚠ 诚实标注：E 的危险方向是**没有防护**（fail-open），不是断网；
    断电 / 蓝屏本身**没在这台机器上实测**（不该为验证而弄崩正在用的机器）
  - 也写清了代价：**掉电会丢最后几条审计记录**（定期 sync 的取舍）。

- **`docs/HOURGLASS.md`：沙漏模型落成工程语言 —— 代理管域名，Aegis 管网卡**
  - 上层（Clash/sing-box）懂域名做精细分流；底层（Aegis/WFP）**不懂也不需要
    懂**域名，只判"这一跳从哪张网卡出去，走错就砍"。两层判据不重叠、覆盖互补
  - 三条实测依据，都能复现：

    | 命题 | 结果 | 复现 |
    |---|---|---|
    | WFP 能按域名过滤吗 | **不能**（`ALE_EFFECTIVE_NAME` 装得上但拦不住） | `examples/name_probe` |
    | ALE 层有没有出口网卡字段 | **有**：`IP_LOCAL_INTERFACE`（UINT64 = `NET_LUID`） | `examples/egress_probe` |
    | 分类时带着正确的值吗 | **带**（真 LUID 断 / 假 LUID 通 / 传输层亦可） | `examples/iface_probe` |

  - ⚠ 补上原讨论漏掉的一条：**TUN 模式与系统代理模式要的原语不同**。
    TUN 模式下应用 socket 仍连真实远端 IP，必须按**出口网卡**放行——按
    "放行代理进程"会把应用自己的 socket 一起拦掉，TUN 模式直接废掉。
    系统代理模式才按**进程**（AppId blob）放行
  - ⚠ 网卡 LUID **会变**（禁用/启用、驱动重载、USB 重插）→ 第二层不能在配置里
    写死一个 LUID，必须靠 `aegis-sense::delta` 拓扑差分驱动重算，
    重算失败按 Fail-Closed（全断，不是全放行）
  - 还列出"今天还没装上"的清单：配置面（`campus.luid` / `proxy.mode` /
    `proxy.tun_luid` / `proxy.image_path`）、把无条件默认拒绝改成"走错网卡
    才拒绝"、适配器 SPI 读代理规则给 GUI

- `aegis-wfp` 新增条件 `Condition::EgressInterfaceLuid(u64)`
  - 翻译成 `FWPM_CONDITION_IP_LOCAL_INTERFACE` + `FWP_UINT64`（`NET_LUID`）
  - ⚠ `FWP_UINT64` 在 `FWP_CONDITION_VALUE0` 里是 `*mut u64`（**不是内联值**），
    得自己持有缓冲区并活到 `FwpmFilterAdd0` 返回之后（和 blob 一样的道理）
  - ⚠ 它不是 `is_static`：引导时间网卡还没枚举出来，Boot 层写上就是死规则

- **`docs/PERSISTENT-CAGE.md`：持久化绝缘笼的技术可行性与架构变更方案**
  （**仅方案，未实施**；落地前必须先跑完文内 §8 的 7 项验证实验）
  - 起因是一个成立的能力缺口批评：动态会话防的是"我们写错代码"，
    不是"别人来杀我们"。结束 `aegisd` 进程 = 防线全没，防君子不防小人
  - ⚠ **目标必须换个说法**：真正的进程防杀（PPL / 受保护服务）需要
    **ELAM 驱动 + 微软签发的证书**，开源项目结构性拿不到；内核回调要写驱动。
    所以目标是 **"你杀了也没用"**（结果仍是保持封锁），不是"你杀不掉我"
  - 三个维度可行性：**持久化规则 ✅**（不需驱动）、**服务化 + SCM 失败自动
    重启 ✅**（不需驱动）、**进程防杀 ❌**（拿不到）
  - 核心架构：**底板持久化（无条件 Block）+ 放行保持动态**。
    "放行随进程消失"本身就是最可靠的心跳，不需要额外机制
  - ⚠ 微软文档里一条此前没人提的机制，几乎是量身定做：给 Provider 指定
    **Windows 服务名**后，"BFE 只在关联服务设为 auto-start 时才加载持久对象"。
    这同时给了**自带的逃生开关**和干净的卸载语义（服务一禁用，重启不留残党）
  - ⚠ 一个必须知道的差别：任务管理器"结束任务"走的是 SCM 停止服务，
    **不触发**失败重启动作；`taskkill /F` / `TerminateProcess` 才触发
  - 保住"最坏情况有硬上界"：持久化后 `--serve-secs` 上界失效，
    改用 SCM `SC_ACTION_RUN_COMMAND`——连续失败 3 次自动跑 `aegisctl --purge`。
    ⚠ `--purge` **绝不能加载配置文件**（配置错误正是启动失败的主因之一）
  - 逃生舱 5 条路径按"依赖越少越靠前"排序，含**离线挂 SYSTEM hive 删
    `HKLM\...\BFE\Parameters\Policy\Persistent`**
  - 明确**不做**：Boot-Time 过滤器（装错即砖，`preflight` 的拒绝继续保留）、
    写驱动、追求 PPL、放行规则持久化、用读 minidump 当判据
  - 实施顺序里有一条硬约束：**`--purge` 必须先于持久化功能完成并测过**

- `SECURITY.md` 增补 §7：把"动态会话防君子不防小人"写进已知的能力缺口，
  并指向上面的方案

### Fixed

- **一次掉电会让 `aegisd` 永久起不来（崩溃安全，实测 `exit 5`）**
  - 启动用的是 `AuditLog::create`（`create_new`，拒绝覆盖）。于是断电留下的
    日志文件会让**之后每一次**启动都失败：`无法创建审计日志：文件存在。(os error 80)`
  - 这正好是崩溃安全的反面：**一次断电把服务永久打趴在地上**
  - 修法：`AuditLog::open_or_create`——存在就**续写**（保住证据），
    不存在才新建。返回 `OpenAction` 让启动日志**如实汇报**做了什么：
    `新建` / `续写（已有 N 条）` / `**修复**：末尾 N 字节残记录已截断丢弃`
  - 连续三次重启（`.aegis-run` 一个文件都不删）实测：退出码 0，链连续

- **写到一半的审计记录被误判成"证据被篡改"**
  - 掉电时最后一条只写了一半是**正常工况**，不是有人动手脚。原逻辑一律判
    `ReadError::Corrupt` → `open` 失败 → 守护进程又起不来
  - 修法：`store::scan` 严格分开**掉电**与**篡改**。只有两种**可证明的不完整**
    才当掉电丢弃：长度前缀不足 4 字节；或前缀写全了但声明长度超过实际剩余
  - 其余照旧报 `Corrupt`：内容哈希对不上、序号跳号、前驱不连续、声明长度
    小到连链节都放不下。另加 `MAX_RECORD_LEN`（1 MiB）上限——把长度前缀改成
    离谱的大数不会被当成掉电静默吞掉
  - 残记录**真的从文件里截断**，不只是"读时跳过"。留着它，下一条会接在残记录
    后面，下次重开就会把它判成篡改，而它只是上次掉电的遗物
  - 端到端实测（真实 binlog 砍掉尾部 30 字节）：
    `819 → 789 字节` → `打开方式：**修复**…保留 3 条` → `回读校验 OK（4 条）`

- **`docs/EMERGENCY-TEARDOWN.md` §5 的诊断命令是错的**
  - 原写 `netsh wfp show filters > C:\wfp-filters.txt`。实测：netsh **不写 stdout**，
    它在**当前目录**生成 `filters.xml`（2.9 MB）。照原命令跑会得到一个**空文件**，
    于是"系统里一条过滤器都没有"——在最需要看清楚的时刻给了个假的干净结果
  - 改成先 `cd` 到临时目录再读 `filters.xml`；`filters.xml` 已进 `.gitignore`
  - 顺带记下同款陷阱：`grep -c` 计数为 0 时**既打印 0 又返回 1**，
    `grep -c X f || echo 0` 会得到 `0\n0`。要写 `|| true`

- **真机下发失败 `0x80320027`（`FWP_E_TYPE_MISMATCH`）：条件类型填错了**
  - 第一版把"绑定到 Dhcp 服务"翻译成 `FWPM_CONDITION_ALE_APP_ID` + `UINT64(pid)`。
    内核不接受：`ALE_APP_ID` 的值是**字节 blob**，不是整数
  - 用只读探针实测出的语义：传**服务短名** → `ERROR_FILE_NOT_FOUND`；
    传**可执行文件路径** → 成功；传带参数的命令行 → 失败（只认纯路径）
  - 结论：**WFP 里没有"按 PID/服务过滤"这个字段**。于是删掉
    `Condition::ServicePid`，换成 `Condition::SystemServiceHost`
    （收紧到系统服务宿主进程）+ `Condition::LocalPort`（钉死方向）
  - ⚠ 残余风险写进 `SECURITY.md`：DHCP 跑在共享 `svchost.exe` 里，
    同宿主的其他服务理论上仍可借 67/68 外联，§28.1 借壳偷渡**没有完全堵住**

- **真机下发失败 `0x80320002`（`FWP_E_CONDITION_NOT_FOUND`）：地址字段选错了**
  - 用了 `FWPM_CONDITION_IP_REMOTE_ADDRESS_V4` + `FWP_V4_ADDR_MASK`。
    用新增的 `Session::fields`（只读枚举层字段）实测发现：
    `ALE_AUTH_CONNECT_V4` 的字段表里**根本没有** `IP_REMOTE_ADDRESS_V4`，
    只有 `IP_REMOTE_ADDRESS`，且值类型是 **`FWP_UINT32`**
  - ⚠ "层支持哪些字段"会随版本/SKU/已装驱动变化，**不能靠背文档**。
    `Session::fields` 让它变成"问引擎"而不是"猜"
  - ⚠ 装得上 ≠ 拦得住：字节序写反内核照样接受（它只看到一个数字），
    但规则永远不匹配。所以 `block_probe` 装上后立刻做连通性实测

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

- **最小可运行链路：`aegisd` + `aegisctl`**（新建两个二进制 crate）
  把已落地的各层串成一次真实启动，证明链路通：
  ```text
  启动 → 加载配置（失败就 exit 2）→ 生成 token + 开命名管道（exit 3）
       → 拓扑快照（exit 4）→ 角色裁决 → 绝缘等级 → WFP 干跑（不下发）
       → 审计写"启动完成"（exit 5）→ 应答 aegisctl
  ```
  - **配置失败就退出，不退回默认值**：带病运行的守护进程比不运行的更危险——
    它看起来在工作，实际按一套没人审核过的策略在放行
  - **感知失败就退出**：不知道机器长什么样就不能裁决角色，此时放行是盲放行
  - **WFP 只干跑**：一条规则都不下发。真正下发需提权且改变本机网络状态，
    **必须先征求用户同意**
  - 审计写完还会**回读并校验哈希链**，证明"写进去的和读出来的是同一条"
  - `aegisctl`：握手 → token 鉴权 → status/ping。鉴权失败**不重试**
    （自动重试会把"token 不对"变成一次慢速拒绝服务），退出码 2/3/4/5/6/7 各有含义
  - ⚠ **踩到一个真坑**：`PipeServer` 里握着原始 HANDLE，**不是 `Send`**，
    不能跨线程搬；且一个管道实例连过一次后必须显式 `disconnect()` 才能再 accept，
    否则表现为"第一次连接好好的，之后全部连不上"——这种半死状态最难排查

- **`aegis-ipc::ctl`**：控制端与守护进程的**请求词表 + 状态文档格式**。
  放在 ipc 而不是两边各写一份常量：两处定义必然漂移，而漂移的表现不是"连不上"，
  是"控制端发了请求，守护进程看不懂却回了成功"。状态文档首行是版本标记
  `aegis-status/1`，客户端先验头再解析；未知字段跳过（向前兼容），
  必需字段缺失则报错；值里的换行/`=` 会被清理，防止伪造出一行伪字段

- **`aegis-orchestrator` 应用层适配器 SPI**（新建 crate，§2A.4）。
  对应外部评审第 1 点：**薄适配器无法"确保"适配，只能靠契约测试和失败模式**
  - `capability::Capability`：SPI 按**能力**切，不按软件类别切。
    按软件切的下场是换个软件就改 trait，那不叫可插拔
    - `Capability::fallback()`：逐能力的失败模式**写死在代码里**，
      不给运行时留"Fail-Closed 还是告警"的二选一。留给运行时，就会出现
      "本该断网的时候只是弹了个提示"
      - Fail-Closed 三条：`TunInterfacePresent` / `DefaultEgress` / `DnsOwnership`
      - 降级三条：`Reload` / `HealthProbe` / `ConfigFragmentGenerate`
  - `error::AdapterError`：**`Unsupported` 与 `Failed` 必须分开**
    - 混在一起的后果不是代码难看：`Unsupported` 被当 `Failed` → Aegis 一直
      重试一个永远不可能成功的能力；`Failed` 被当 `Unsupported` → 适配器真挂了
      却被静默吞掉，一个该 Fail-Closed 的出口悄悄变成放行
    - `is_fault()` 是运维侧唯一该用来判断"要不要告警"的入口
  - `spi::invoke_checked`：**所有调用的唯一入口**，两件事由底座保证而非靠适配器自觉
    - 未声明的能力调用即 `Unsupported`（不进适配器）
    - **答非所问即故障**：问 DNS 却回 `Healthy` 会升级成 `Failed`。
      这种错不表现为失败，只表现为"结果看起来不对"
  - `spi::matrix` 能力矩阵：`usable()` = 无 Fail-Closed 缺口。
    降级项不影响——"少了健康检查"不等于"在漏流量"
  - `spi::audit_declaration` 声明自检（§2A.4 ③：声明 ≠ 事实）
    - 声明了却回 `Unsupported` = 撒谎（`Lie`），必须按 `Failed` 处置
    - `Reload` 还会验证**配置版本号真的变了**——只回 `Reloaded` 但版本纹丝不动
      的适配器，它的 Reload 是假的，后果是"以为配置生效了其实没有"
    - `DefaultEgress` 标记为 `Unverifiable`：**它无法无害自检**，
      "试一下"就等于真的接管一次出口
    - ⚠ 自检有副作用（会真的 reload 一次），**必须排在契约之后**，
      否则契约里"健康检查报当前版本"会假红
  - `contract` 契约测试夹具：把"适配"从形容词变成可判定的命题
    （**适配 = 这组 fixture 过没过**）
    - `suite(scenario, declared)` 由场景 + 声明生成完整用例：
      声明了 → 期望真做对；没声明 → 期望 `Unsupported`。
      **少实现一个能力不会让契约红，声明了却做不到一定红**
    - `SUITE_ORDER` 里 `Reload` 必须排在 `HealthProbe` 之后（注释写明理由）
  - `reference::ReferenceAdapter`：**由场景驱动的纯模型**，不启进程、不提权、
    不改路由表。契约验的是适配器的**语义**，不是"这个软件装没装"
    - TUN 三态：`TunPresent` / `TUN_NOT_PERMITTED`（起来了但没被放行，
      **必须报错，不能静默说"没有"**）/ `TunAbsent`
    - DNS 双边接管 53 = `DNS_OWNERSHIP_CONFLICT` 冲突，不是"以谁为准"
  - `examples/orchestrator_dryrun`：演示三类"看起来适配了其实在漏"——
    ① 撒谎（声明 Reload 却回 Unsupported）② 答非所问 ③ **诚实但能力不够
    （契约 7/7 全绿，却有 Fail-Closed 缺口，出口不可用）**
  - ⚠ 结论写进 §21.2：**契约过 ≠ 能用**。契约验"诚不诚实"，
    矩阵验"够不够"，合成一个"通过/不通过"会把"诚实但能力不够"伪装成"适配好了"

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

- **变异测试补漏（aegis-audit 安全核心 106 个变异体：8 漏网 → 0）**
  - `EvidenceChain::is_empty` / `AuditRing::is_empty` 只测了"空的时候为真"，
    恒返回 `true` 的实现能蒙混过关。已补"有记录时必须为假"
    （前者用于校验前判空，后者用于 UI 判断有没有新事件）
  - `decode` 的尾随字节数只验了 1 个字节——"剩余 = 总长 − 位置"和
    "剩余 = 总长 ÷ 位置"在这个取值上恰好都等于 1。已补 3 / 9 个字节两种
    **确切值**断言，把减法写成除法的实现立刻暴露
  - `Cursor::take` 的 `Truncated.have` 只用了 `matches!` 验过，
    把它从"还剩几个字节"算成"缓冲区总长"的实现抓不到；已补
    `Truncated { need: 4, have: 3 }` 这种确切值
  - `Action::tag()` / `Protocol::tag()` 只验了"是 ASCII 且非空"，
    把整个函数换成常量 `"xyzzy"` 照样通过。它们是**证据包的字段值**
    （不是给人看的文案），已钉住确切字面值
  - 两个 `Display` 实现同样补了字面值断言：空掉它不会让任何校验失败，
    只会让人在核对时看到一片空白

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
