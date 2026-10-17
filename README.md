# Aegis · 本地网络编排代理

> 原生运行在 Windows 内核网络栈（WFP）之上的**零信任网络编排守护进程**，
> 而非又一个代理软件。

## 它是什么

Aegis 建立一张**独立于任何上层代理软件的 OS 级安全底座**，包含：内核级出站审计、
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
| `aegis-sense` | 🚧 进行中 | 感知层：拓扑采集 / 默认出口裁决 / SSID / SHA-256 拓扑指纹 |
| `ob-netfilter` | ⬜ 待建 | WFP 绝缘笼、Boot-Time 背板、DNS 封锁 |
| `aegis-core` | ⬜ 待建 | 角色模型、状态机、IPC 协议 |
| `ob-service` | ⬜ 待建 | Windows Service 宿主（SYSTEM） |

## 目录结构

```text
Aegis/
├── design-spec.md          # 设计文档（唯一事实来源）
├── Cargo.toml              # workspace
├── rust-toolchain.toml     # 工具链锁定
├── rustfmt.toml / clippy.toml
├── config/
│   └── config.example.toml # 编排器配置样例
└── crates/
    └── aegis-sense/           # 感知层（纯只读）
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

### 运行感知层干跑

```bash
export PATH="/d/Dev/msys64/mingw64/bin:$PATH"   # Git Bash；把 gcc 放进 PATH
cargo run -p aegis-sense --example dry_run
```

本机实测输出（节选）：

```text
● 以太网 4 [有线/其它] Up
    MAC      : 1C-86-0B-01-B6-AB
    IPv4     : 10.41.0.229
    网关     : 10.41.0.1
    DHCP     : 10.41.0.1

── 默认出口裁决 ──
默认出口 : 以太网 4  [1689399750295552]
  网关     : 10.41.0.1

── 拓扑指纹（§20.4）──
SHA-256 : fb9aaf7d159e841f73833b934eb1d2641605176b8239ed27e309651c95a052c4

采集耗时: 17.6251ms
✅ 干跑完成。全程只读，本机网络状态未被修改。
```

### ⚠️ 本机环境三个已知坑（重要）

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
   **规避**：不要在本工具会话里装 VS；直接在资源管理器双击安装器，
   或改用 MSYS2 + MinGW（本项目当前采用）。

## 许可证

本项目采用 **GNU AGPL-3.0** —— 与参考调研的 HypoMux 保持一致。详见 [`LICENSE`](LICENSE)。
