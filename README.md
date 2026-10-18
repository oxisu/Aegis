# Aegis —— 宙斯的神盾

> 原生运行在 Windows 内核网络栈（WFP）之上的**零信任网络编排守护进程**，
> 而非又一个代理软件。
>
> 版本 `0.1.0-alpha.2` · 许可证 AGPL-3.0 · 版本规范见 [`docs/VERSIONING.md`](docs/VERSIONING.md)

## 它是什么

Aegis 建立一张**独立于任何上层代理软件的 OS 级安全底座**：内核级出站审计、
物理网口微秒级熔断、拓扑指纹防伪、网卡角色裁决；并通过**可插拔适配器 SPI**
去兼容接管 Clash Verge / HypoMux / sing-box 等上层工具。

核心分工——**底座（OS Level）与代理（App Level）彻底解耦**：
换掉 mihomo、换成 sing-box、甚至一个代理都不装，WFP 绝缘笼、开机防漏、
网口熔断、出站存证依然照常运行。

📄 **设计文档（单一事实来源）：[`design-spec.md`](design-spec.md)** —— 所有架构决策以其为准。

### 名字

**Aegis**（英文为主）/ **宙斯的神盾**（中文为辅）。盾牌的含义正对应这套系统的定位：
它不替你选择走哪条路，而是保证**无论走哪条路都不会漏**。
`aegis` 直接进入代码结构——所有 crate 统一 `aegis-` 前缀，守护进程叫 `aegisd`，
控制端叫 `aegisctl`，版本标识由 `aegis-version` 统一供给。

## 目标场景

| 通道 | 定位 | 策略 |
|---|---|---|
| 校园网 | **纯洁通道** | 纯白名单、物理级禁 53/LLMNR/mDNS Broadcast，源头掐断 |
| 移动热点 | **自由出海通道** | 物理绕开校园网认证与 DPI 审计 |

设计前提**不碰网关漏洞**：即便存在绕过认证的口子，出口 DPI 仍会做特征提取，
本地白名单 + 物理隔离才是成本最优解。

## 当前进度

设计面（§1–§30）已闭环；编码面（§21）正在进行，第一步做的就是**只读感知层**：

| Crate | 状态 | 说明 |
|---|---|---|
| `aegis-version` | ✅ 可用 | 版本标识单一事实来源（零依赖） |
| `aegis-model` | ✅ 可用 | 拓扑事实的共享类型（**零依赖**，感知层产出 / 策略层消费） |
| `aegis-sense` | ✅ 可用 | 感知层：拓扑采集 / 接口分类 / 默认出口裁决 / SSID / 拓扑指纹 / 拓扑差分 |
| `aegis-core` | ✅ 可用 | 角色裁决（§20.5）+ 状态机（§26） |
| `aegis-wfp` | 🚧 只读 + 干跑 | WFP 状态勘察（枚举 / Provider / **持久背板审计**）+ **绝缘笼规则计划与静态自检**（未下发） |
| `aegis-fuse` | 🚧 纯逻辑阶段 | 拓扑震荡熔断器：去抖 + **先熔断后分析**（`NotifyIpInterfaceChange` 待接） |
| `aegis-audit` | ⬜ 待建 | 审计与证据链落盘 |
| `aegis-ipc` | ✅ 可用 | 本地 IPC 帧编解码 + 版本握手（未建管道） |
| `aegis-config` | ✅ 可用 | 配置加载与 schema 版本校验（Fail-Closed） |
| `aegis-orchestrator` | ⬜ 待建 | 应用层代理适配器（SPI，可插拔） |
| `aegisd` / `aegisctl` | ⬜ 待建 | 守护进程 / 控制端二进制 |

### 依赖方向铁律

```text
aegis-version ──▶ 所有层
aegis-model   ──▶ aegis-sense（产出）、aegis-core / aegis-config（消费）
aegis-sense   ──▶ 只有"真要读 Win32"的层才碰它
```

⚠ **策略层（`aegis-core` / `aegis-config`）只依赖 `aegis-model`，绝不依赖
`aegis-sense`。** `aegis-sense` 会拉进 `windows` crate（WFP + IP Helper 全量
绑定）；一旦策略层碰它，纯逻辑的增量构建会从约 3s 涨到约 22s，而且
「策略层可在普通用户下只读干跑」这条硬约束就名存实亡——光编译就得先
把 WFP 绑定编一遍。

已完成的决策链路（全部只读、无需管理员权限）：

```text
GetIfTable2 / GetAdaptersAddresses / GetIpForwardTable2 / GetIpInterfaceTable / WLAN API
        │
        ▼  aegis-sense::snapshot()
   拓扑快照（44 张网卡分类为 3 物理 / 25 过滤器 / 7 隧道 / 1 回环 / 8 虚拟）
        │
        ├─ 指纹：只算物理 Up 网卡 → 消除伪接口引起的假漂移
        └─ 差分：两次快照比对 → 输出"该不该打断用户"
                    │
                    ▼  aegis-core
              角色裁决（Fail-Closed）+ 状态机绝缘等级

WFP 侧（只读勘察，需管理员权限才能枚举）：
FwpmEngineOpen0（动态会话）+ FwpmFilterEnum0 / FwpmProviderEnum0
        ▼  aegis-wfp::Session::snapshot()
   过滤器的层 / 动作 / 归属 / persistent-boottime 标志
        └─ 持久背板审计：区分"系统自带底板"与"第三方持久阻断"

绝缘笼（纯逻辑，**不下发任何东西**）：
CagePolicy ──cage_plan()──▶ Vec<FilterSpec> ──verify()──▶ 结论
        └─ 先回答"这份规则会不会把我自己锁死"，再谈下发

拓扑震荡熔断（纯逻辑，时间从外部注入）：
网口变动 ──ShockDebouncer::on_change()──▶ 立刻熔断（不等去抖）
        └─ 去抖窗口过后 ──▶ 只叫醒异步 Worker **一次**去重算
```

## 目录结构

```text
Aegis/
├── design-spec.md          # 设计文档（唯一事实来源）
├── VERSION                 # 权威版本号，与 Cargo.toml 严格一致
├── docs/
│   └── VERSIONING.md       # 版本编号规范（发版必读）
├── Cargo.toml              # workspace
├── rust-toolchain.toml     # 工具链锁定
├── rustfmt.toml / clippy.toml
├── config/
│   └── config.example.toml # 编排器配置样例
├── tools/
│   ├── dev-env.ps1         # MSVC 路线的构建入口
│   └── clean-ghost-nics.ps1# 幽灵网卡盘点与清理（默认只读）
└── crates/
    ├── aegis-version/      # 版本标识（零依赖）
    ├── aegis-model/        # 共享数据模型（零依赖）：拓扑事实的类型
    ├── aegis-sense/        # 感知层（纯只读）：采集 / 分类 / 指纹 / 差分
    │   └── examples/dry_run.rs
    ├── aegis-core/         # 编排核心（纯逻辑）：角色裁决 / 状态机
    │   └── examples/plan.rs
    ├── aegis-fuse/         # 拓扑震荡熔断器（纯逻辑）：去抖 + 先熔断后分析
    ├── aegis-wfp/          # OS 级底座（只读勘察 + 规则计划）：枚举 / 持久背板审计 / 绝缘笼计划
    │   ├── examples/wfp_inspect.rs   # 只读勘察（需管理员）
    │   └── examples/wfp_plan.rs      # 绝缘笼干跑（无需管理员，不装任何规则）
    ├── aegis-ipc/          # IPC 帧编解码 + 版本握手（纯逻辑）
    └── aegis-config/       # 配置加载 + schema 版本校验（Fail-Closed）
```

## 安全边界（`aegis-sense` 的硬约束）

感知层刻意做成**纯只读**且**不需管理员权限**，因此可以在任何环境（尤其是已接入校园网时）放心干跑：

- ✅ 读取网卡拓扑、网关、默认出口、SSID，计算拓扑指纹
- ❌ 不注入任何 WFP / 防火墙规则
- ❌ 不启停任何进程或服务（**含任何上层代理软件**）
- ❌ 不修改注册表、系统代理、路由表

`aegis-wfp` 当前同样**只做只读勘察**：打开动态会话、枚举、审计，
**不添加 / 不修改 / 不删除任何 WFP 对象**。会话使用
`FWPM_SESSION_FLAG_DYNAMIC`，即使进程崩溃，引擎也会自动回收该会话的
一切对象——这条写在会话标志里，而不是依赖"退出前记得清理"，
因为崩溃路径上没有机会执行清理代码。

> 注：枚举 WFP 通常需要管理员权限。权限不足时 `wfp_inspect` 会明确报出
> 错误码与处置建议，而不是假装"什么都没有"。

## 构建与运行

### 当前已验证的开发环境（本机）

| 组件 | 位置 | 说明 |
|---|---|---|
| Rust 工具链 | `D:\Dev\Rust` | **gnu 宿主** `stable-x86_64-pc-windows-gnu`，由 `rust-toolchain.toml` 锁定 |
| MinGW-w64 (gcc 16.2.0) | `D:\Dev\msys64\mingw64` | 作为链接后端，从 MSYS2 腾讯云镜像装 |
| crates 镜像 | rsproxy.cn | 写在 `D:\Dev\Rust\.cargo\config.toml` |

> 为什么是 gnu 而不是 msvc：本机此前没有 MSVC 生成工具，且 VS Build Tools 安装器
> 在本机会因环境变量 `Path`/`PATH` 重复而崩溃（详见下方"已知坑"）。
> 等 MSVC 装好后，把 `rust-toolchain.toml` 的 `channel` 改回
> `stable-x86_64-pc-windows-msvc` 即可切换。

Rust 装在 D 盘而非默认位置，因此**每次开新终端都要显式指定这两个变量**，
否则 rustup 会回到 `C:\Users\<你>\.rustup` 并报 "no installed toolchains"：

```bash
export RUSTUP_HOME="D:\\Dev\\Rust\\.rustup"
export CARGO_HOME="D:\\Dev\\Rust\\.cargo"
export PATH="/d/Dev/Rust/.cargo/bin:$PATH"
```

### 打印完整版本号

```bash
cargo run -p aegis-version --example version            # 单行
cargo run -p aegis-version --example version -- --verbose # 多行
```

```text
Aegis —— 宙斯的神盾
  版本      : 0.1.0-alpha.2+g64abfd2
  语义版本  : 0.1.0-alpha.2
  预发布    : alpha.2
  构建配置  : debug
  目标平台  : x86_64-pc-windows-gnu
  Git 分支  : master
  Git 提交  : 64abfd2
  稳定性    : 0.x 阶段，MINOR 递增即破坏性变更
```

（`+g<hash>` 由构建期采集，随提交变化。）

### 运行只读干跑

```bash
export PATH="/d/Dev/msys64/mingw64/bin:$PATH"   # Git Bash；把 gcc 放进 PATH
cargo run -p aegis-sense --example dry_run   # 感知层：拓扑 + 指纹 + 稳定性自检
cargo run -p aegis-core  --example plan      # 编排核心：角色裁决 + 状态机推演
cargo run -p aegis-core  --example plan -- --free MMi   # 声明手机热点后再裁决
cargo run -p aegis-wfp   --example wfp_inspect # WFP 只读勘察：枚举 + 持久背板审计（需管理员）
cargo run -p aegis-wfp   --example wfp_plan    # 绝缘笼干跑：打印要装什么，一条都不装
cargo run -p aegis-wfp   --example wfp_plan -- --campus-strict --boot-backbone
```

### 绝缘笼：为什么先做"计划"而不是直接下发

绝缘笼是 Aegis 里唯一一个**装错了就断整机网**的部件，而两条最致命的失败
路径**都不会报错**，只会表现为"网不通了"：

| 漏掉的东西 | 后果 |
|---|---|
| 回环放行 | 非提权 GUI 连不上 SYSTEM 服务——用户失去**唯一能把笼子拆掉**的界面 |
| DHCP 放行 | 开机拿不到 IP，而此时任何界面都还没起来——**永久锁死** |

所以规则集合先做成可静态验证的纯数据，`verify()` 在**不下发**的前提下
回答"会不会把自己锁死"：

- 权重关系（放行必须严格高于默认拒绝，否则放行规则是一张废纸，静默失效）
- 回环 / DHCP 放行是否存在、**是否被更高权重的默认拒绝遮蔽**
- 每层是否有无条件兜底阻断
- Boot-Time 层规则的条件是否**全部静态可判定**（引导时间没有进程，
  写成"匹配 Dhcp 服务 PID"就是一条永不匹配的死规则 → 开机即断网）

Boot-Time 持久背板默认关闭。启用后 `verify()` 会给出 `Warn`：
这类规则进程退出、重启都不会消失，装错即变砖，必须显式确认。

本机实测输出（节选）：

```text
共 44 张网卡，按性质分类：
    物理 : 3 张 / 过滤器 : 25 张 / 隧道 : 7 张 / 回环 : 1 张 / 虚拟 : 8 张

── 默认出口裁决 ────────────────────────────────────────────────
  接口                                 接口度量       路由偏移       合成度量
  WLAN                                 55          0         55
  以太网 4                                25          0         25  ← 选中

── 拓扑指纹（§20.4）───────────────────────────────────────────
SHA-256 : 3f9c1d0a…（示例值，随本机物理网卡集合变化）
格式版本: v2
参与集合: 仅物理网卡（2 张）

参与网卡：
  ● 以太网 4 [物理] XX-XX-XX-XX-XX-XX
  ● WLAN [物理] YY-YY-YY-YY-YY-YY

── 稳定性自检（连续两次快照差分）─────────────────────────────
拓扑无变化
```

（以上为脱敏后的示例输出：网卡物理地址与拓扑指纹已替换为占位值，实际值随机器的硬件集合而变。）

两处刻意的设计，都不是装饰：

> **"接口度量 / 路由偏移 / 合成度量"三列**：Windows 选路用的是
> **接口度量 + 路由度量偏移**，而 DHCP 自动度量下路由偏移恒为 0；
> 只看偏移就会在两条 0 之间比大小，把出口判错（本机实测会把 `以太网 4` 误判成 `WLAN`）。
> 详见 `crates/aegis-sense/src/route.rs`。
>
> **指纹只算物理网卡**：44 张网卡里真正是硬件的只有 3 张（其中 2 张 Up）。
> 其余 25 张是 WFP / QoS 等 NDIS 过滤器为物理网卡派生的伪接口，
> 数量会随驱动装卸载和系统更新变化。若把它们计入指纹，物理环境没变也会"漂移"，
> 用户会被反复要求重新确认——久了就会无脑点确认，**零信任直接失效**。
> 详见 `crates/aegis-sense/src/fingerprint.rs`。

### ⚠️ 本机环境四个已知坑（重要）

1. **`link.exe` 名字冲突**（仅在用 MSVC 时）
   Git Bash 会在 PATH 里放一份 GNU coreutils 的 `link.exe`（`/usr/bin/link`）。
   若在 Git Bash 里直接构建 msvc 目标，rustc 会调错程序，报：
   `link: extra operand ...` / `Try 'link --help'`。
   **解决**：在 PowerShell 里构建，或让 MSVC 的 `VC\Tools\MSVC\<ver>\bin\Hostx64\x64`
   排到 PATH 最前。
2. **失效的系统代理**
   Internet 选项里残留了指向已停止运行的本地代理（`127.0.0.1:7897`，无进程监听），
   cargo 会去连它并报 `Could not connect to server over proxy 127.0.0.1`。
   **解决**：构建前清空代理环境变量即可直连：

   ```bash
   unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy ALL_PROXY all_proxy
   ```
3. **VS Build Tools 安装器崩溃**（`0x80070057`）
   本机工具会话的进程环境里同时存在 `Path` 与 `PATH`（注册表本身是干净的，
   由 MSYS/Git Bash 会话注入）。VS Installer Engine 派生 MSI 子进程时，其 .NET
   `ProcessStartInfo.EnvironmentVariables` 用大小写不敏感字典，插入重复键即抛异常，
   最终以 `vital failure` 收场。
   同一个坑也会让 PowerShell 的 `Start-Process` 直接抛
   `已添加项。字典中的关键字:"Path"所添加的关键字:"PATH"`。
   **规避**：不要在本工具会话里装 VS；需要起进程时用 `&` 调用运算符直调
   （`& pnputil.exe ...`），不要走 `Start-Process`。
4. **PowerShell 脚本的编码与版本**（`*.ps1`）
   本机是 Windows PowerShell **5.1**。无 BOM 的 UTF-8 会被按 GBK 解码，
   中文错位到连解析器都报错；且 `??`（空合并）、`if` 作表达式等 PS 7+ 语法不可用。
   **约定**：仓库内所有 `.ps1` 一律写成 **UTF-8 BOM + CRLF**，且只用 5.1 兼容语法。

## 幽灵网卡（安卓 USB 共享残留）

长期插拔安卓 USB 有线共享（RNDIS）会让 Windows 每次生成全新的 NET_LUID，
并留下 `Present=False` 的设备残留。后果是拓扑指纹在物理环境没变的情况下漂移，
误触发"拓扑变更"告警。

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\clean-ghost-nics.ps1          # 只读盘点
powershell -ExecutionPolicy Bypass -File .\tools\clean-ghost-nics.ps1 -Apply   # 确认后删除
```

脚本自带保护名单（WAN Miniport / Wi-Fi Direct / 蓝牙 PAN / 6to4 / Teredo /
IP-HTTPS / 内核调试器 / 虚拟化网卡等系统组件一律不删），
删除前自动备份设备清单到 `evidence/`。

## 许可证

本项目采用 **GNU AGPL-3.0** —— 与参考调研的 HypoMux 保持一致。详见 [`LICENSE`](LICENSE)。
