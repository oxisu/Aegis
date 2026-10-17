# 变更日志

本项目所有值得注意的变更都会记录在此文件。
格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)；
版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### Added

- **项目标准化骨架**：Git 忽略规则、行尾策略（`.gitattributes`）、编辑器规范（`.editorconfig`）
- **Cargo workspace**：统一 crate 元数据与依赖版本，Release profile 面向最小体积与快速冷启动
- **工具链标准**：`rust-toolchain.toml`（stable + rustfmt + clippy）、`rustfmt.toml`、`clippy.toml`
- **采用 GNU AGPL-3.0 许可证**
- **`aegis-sense` 感知层（只读）**
  - 数据模型：网卡信息、角色枚举、运营状态、拓扑快照（与 Win32 API 解耦）
  - 统一错误类型 `SenseError`，任何 Win32 失败向上传递而非 panic
  - `GetIfTable2` 网卡枚举（LUID / MAC / 别名 / 类型 / 运营状态）
  - `GetAdaptersAddresses` 采集 IPv4 与 DHCP 服务器
  - `GetIpForwardTable2` 路由采集 + **默认出口裁决**（默认路由中 Metric 最小者）
  - WLAN AutoConfig API 采集 **SSID**（失败时降级为 `None`，不中断整体采集）
  - **SHA-256 拓扑指纹**（§20.4）：仅 Up 接口参与，按 LUID 排序保证可重复
  - `dry_run` 示例：纯只读自检，不修改任何系统状态
- **编排器配置样例** `config/config.example.toml`（对齐 §22 schema）

### Security

- 感知层确立"四不"硬约束：不注入防火墙规则、不启停进程、不改注册表、
  不要求管理员权限。任何代理软件的启停都必须由用户显式授权。
