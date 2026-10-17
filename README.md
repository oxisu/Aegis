# Aegis —— 宙斯的神盾

> 原生运行在 Windows 内核网络栈（WFP）之上的**零信任网络编排守护进程**，
> 而非又一个代理软件。
>
> 版本 `0.1.0-alpha.1` · 许可证 AGPL-3.0 · 版本规范见 [`docs/VERSIONING.md`](docs/VERSIONING.md)

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
| `aegis-sense` | 🚧 进行中 | 感知层：拓扑采集 / 默认出口裁决 / SSID / SHA-256 拓扑指纹 |
| `aegis-core` | ⬜ 待建 | 角色模型、状态机、IPC 协议 |
| `aegis-wfp` | ⬜ 待建 | WFP 绝缘笼、Boot-Time 背板、DNS 封锁 |
| `aegis-fuse` | ⬜ 待建 | 微秒级网络端口熔断器 |
| `aegis-audit` | ⬜ 待建 | 审计与证据链落盘 |
| `aegis-ipc` | ⬜ 待建 | 本地 IPC 协议（命名管道 + token 鉴权） |
| `aegis-orchestrator` | ⬜ 待建 | 应用层代理适配器（SPI，可插拔） |
| `aegisd` / `aegisctl` | ⬜ 待建 | 守护进程 / 控制端二进制 |

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
    ├── aegis-version/      # 版本标识
    └── aegis-sense/        # 感知层（纯只读）
        └── examples/dry_run.rs
```

## 安全边界（`aegis-sense` 的硬约束）

感知层刻意做成**纯只读**且**不需管理员权限**，因此可以在任何环境（尤其是已接入校园网时）放心干跑：

- ✅ 读取网卡拓扑、网关、默认出口、SSID，计算拓扑指纹
- ❌ 不注入任何 WFP / 防火墙规则
- ❌ 不启停任何进程或服务（**含任何上层代理软件**）
- ❌ 不修改注册表、系统代理、路由表

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
  版本      : 0.1.0-alpha.1+g05d624e
  语义版本  : 0.1.0-alpha.1
  预发布    : alpha.1
  构建配置  : debug
  目标平台  : x86_64-pc-windows-gnu
  Git 分支  : master
  Git 提交  : 05d624e
  稳定性    : 0.x 阶段，MINOR 递增即破坏性变更
```

### 运行感知层干跑

```bash
export PATH="/d/Dev/msys64/mingw64/bin:$PATH"   # Git Bash；把 gcc 放进 PATH
cargo run -p aegis-sense --example dry_run
```

本机实测输出（节选）：

```text
Aegis 0.1.0-alpha.1+g05d624e (宙斯的神盾) [debug/x86_64-pc-windows-gnu @ master]

── 默认出口裁决 ────────────────────────────────────────────────
  接口                                 接口度量       路由偏移       合成度量
  WLAN                                 55          0         55
  以太网 4                                25          0         25  ← 选中

默认出口 : 以太网 4  [1689399750295552]
  网关     : 10.41.0.1

── 拓扑指纹（§20.4）───────────────────────────────────────────
SHA-256 : 4b558969ae0ecbc5b11ce7bc6d966e8acc7821afe002fc978d072bad25181820

采集耗时: 16.5988ms
✅ 干跑完成。全程只读，本机网络状态未被修改。
```

> 上面"接口度量 / 路由偏移 / 合成度量"三列不是装饰。Windows 选路用的是
> **接口度量 + 路由度量偏移**，而 DHCP 自动度量下路由偏移恒为 0；
> 只看偏移就会在两条 0 之间比大小，把出口判错（本机实测会把 `以太网 4` 误判成 `WLAN`）。
> 详见 `crates/aegis-sense/src/route.rs` 的模块注释与回归测试。

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
