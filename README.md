# InterBoot · 本地网络编排代理

> 原生运行在 Windows 内核网络栈（WFP）之上的**零信任网络编排守护进程**，
> 而非又一个代理软件。

## 它是什么

InterBoot 建立一张**独立于任何上层代理软件的 OS 级安全底座**，包含：内核级出站审计、
物理网口微秒级熔断、拓扑指纹防伪、网卡角色裁决；并通过**可插拔适配器 SPI**
去兼容接管 Clash Verge / HypoMux / sing-box 等上层工具。

核心分工——**底座（OS Level）与代理（App Level）彻底解耦**：
换掉 mihomo、换成 sing-box、甚至一个代理都不装，WFP 绝缘笼、开机防漏、
网口熔断、出站存证依然照常运行。

📄 **设计文档（单一事实来源）：[`design-spec.md`](design-spec.md)** —— 所有架构决策以其为准。

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
| `ob-sense` | 🚧 进行中 | 感知层：拓扑采集 / 默认出口裁决 / SSID / SHA-256 拓扑指纹 |
| `ob-netfilter` | ⬜ 待建 | WFP 绝缘笼、Boot-Time 背板、DNS 封锁 |
| `ob-core` | ⬜ 待建 | 角色模型、状态机、IPC 协议 |
| `ob-service` | ⬜ 待建 | Windows Service 宿主（SYSTEM） |

## 目录结构

```text
InterBoot/
├── design-spec.md          # 设计文档（唯一事实来源）
├── Cargo.toml              # workspace
├── rust-toolchain.toml     # 工具链锁定
├── rustfmt.toml / clippy.toml
├── config/
│   └── config.example.toml # 编排器配置样例
└── crates/
    └── ob-sense/           # 感知层（纯只读）
        └── examples/dry_run.rs
```

## 安全边界（`ob-sense` 的硬约束）

感知层刻意做成**纯只读**且**不需管理员权限**，因此可以在任何环境（尤其是已接入校园网时）放心干跑：

- ✅ 读取网卡拓扑、网关、默认出口、SSID，计算拓扑指纹
- ❌ 不注入任何 WFP / 防火墙规则
- ❌ 不启停任何进程或服务（**含任何上层代理软件**）
- ❌ 不修改注册表、系统代理、路由表

## 构建与运行

### 前置条件

1. **Rust 工具链**（stable、含 `rustfmt` + `clippy`）
2. **MSVC 生成工具**（Windows Service / WFP 项目的官方路线）
   —— 装 Build Tools for Visual Studio + Windows 11 SDK

### 运行感知层干跑

```powershell
cargo run -p ob-sense --example dry_run
```

输出示例包含：网卡列表（别名 / MAC / LUID / IPv4 / 网关 / SSID）、默认出口裁决、SHA-256 拓扑指纹。

### ⚠️ 本机环境两个已知坑（重要）

1. **`link.exe` 名字冲突**
   Git Bash 会在 PATH 里放一份 GNU coreutils 的 `link.exe`（`/usr/bin/link`）。
   若在 Git Bash 里直接 `cargo build`，rustc 会调错程序，报：
   `link: extra operand ...` / `Try 'link --help'`。
   **解决**：在 **PowerShell（或原生终端）** 里构建，或让 MSVC 的
   `VC\Tools\MSVC\<ver>\bin\Hostx64\x64` 排在 PATH 最前（推荐用 VS 开发者命令行)。
2. **失效的系统代理**
   若 Internet 选项里残留了指向某个已停止运行的本地代理（例如 `127.0.0.1:7897`），
   cargo 拉取依赖会卡住报 `Could not connect to server over proxy 127.0.0.1`。
   **解决**：构建前清空代理环境变量即可直连：

   ```powershell
   $env:HTTP_PROXY=""; $env:HTTPS_PROXY=""; $env:CARGO_HTTP_PROXY=""; $env:ALL_PROXY=""
   ```

## 许可证

本项目采用 **GNU AGPL-3.0** —— 与参考调研的 HypoMux 保持一致。详见 [`LICENSE`](LICENSE)。
