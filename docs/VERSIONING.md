# Aegis 版本编号规范

> 本文档是 Aegis 版本号的**单一事实来源**。
> 任何发版动作（打 tag、写 CHANGELOG、改 `Cargo.toml`）都必须先读这里。

## 1. 版本号形态

```text
MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]
│     │     │      │            └─ 构建元数据：g<Git 短哈希>
│     │     │      └────────────── 预发布标签与序号：alpha.N / beta.N / rc.N
│     │     └───────────────────── PATCH：缺陷修复、无接口变化
│     └─────────────────────────── MINOR：新增能力；0.x 阶段也承载破坏性变更
└───────────────────────────────── MAJOR：架构级破坏性变更
```

**完整版本号示例**：`0.1.0-alpha.1+ge06dab0`

| 段 | 含义 | 递增时机 |
|---|---|---|
| `MAJOR` | 架构级不兼容变更 | 分层结构、IPC 协议、配置 schema 发生不兼容重构 |
| `MINOR` | 新增能力 /（0.x 阶段）破坏性变更 | 新增一个层或一条主干能力 |
| `PATCH` | 缺陷修复、性能改进、文档 | 不改变对外契约 |
| `-alpha.N` | 内部验证：接口未冻结，可能推倒重来 | 每个内部可跑通的里程碑 +1 |
| `-beta.N` | 功能已齐，进入真机实测 | 每轮实测修复后 +1 |
| `-rc.N` | 发布候选：只修阻塞性缺陷 | 每个候选 +1 |
| `+g<hash>` | 构建元数据（**不参与版本大小比较**） | 每次构建由 `aegis-version` 自动附加 |

> **`+g<hash>` 不是发布号的一部分。** SemVer 规定 build metadata 在比较时忽略，
> 即 `0.1.0+gaaa` 与 `0.1.0+gbbb` 视为同一版本。它只用于把二进制回溯到提交。

## 2. 0.x 阶段的特殊约定

`MAJOR = 0` 表示**对外契约尚未冻结**。此阶段：

- 破坏性变更通过 **MINOR** 递增表达（`0.1.x` → `0.2.0`）
- `PATCH` 只用于不破坏契约的修复
- 首个对外可用版本发布时直接跳到 `1.0.0`

Aegis 是安全底座，契约包括：IPC 协议帧格式、配置 schema、审计记录结构、
守护进程对外行为。**任何一项变更都必须体现在版本号上**，不允许静默改动。

## 3. 版本号的存放位置（四处必须一致）

| 位置 | 内容 | 用途 |
|---|---|---|
| `VERSION`（仓库根） | `0.1.0-alpha.1` | 发布脚本与 CI 读取的权威值 |
| `Cargo.toml` → `[workspace.package].version` | `0.1.0-alpha.1` | 所有 crate 继承（不含 build metadata） |
| `crates/aegis-version/src/lib.rs` | 编译期从 `CARGO_PKG_VERSION*` 派生 | 代码内常量与 `--version` 输出 |
| `CHANGELOG.md` 顶部条目 | `## [0.1.0-alpha.1] - YYYY-MM-DD` | 人类可读的变更归档 |

运行时完整版本号由 `aegis_version::full()` 拼装：
`CARGO_PKG_VERSION` + `+g<Git 短哈希>`（哈希由 `aegis-version/build.rs` 在构建期
**直接读 `.git` 目录**得到，不启动子进程，避免在受限环境里挂起构建）。

### 一致性校验

```bash
# VERSION 文件与 Cargo.toml 必须逐字相同（CI 会强制校验）
diff <(cat VERSION) <(grep -m1 '^version' Cargo.toml | sed 's/.*= *"\(.*\)".*/\1/')
```

## 4. 发版流程

1. **确认工作区干净**：`git status` 无未提交改动。
2. **决定版本号**：按上表判断该动哪一段。
3. **改四个位置**：`VERSION`、`Cargo.toml` 的 `version`、`CHANGELOG.md`
   （把 `[Unreleased]` 的内容转成一个新版本条目并补日期）、`aegis-version` 单测里的断言。
4. **提交**：`chore(release): 发布 v0.1.0-alpha.1`（仅版本号与 CHANGELOG）。
5. **打 tag**：`git tag -a v0.1.0-alpha.1 -m "Aegis 0.1.0-alpha.1"`
6. **推送**：`git push --follow-tags`
7. **验证**：`cargo run -p aegis-version --example version -- --verbose`

## 5. Git tag 约定

- 格式严格为 `v<完整语义版本>`，例如 `v0.1.0-alpha.1`
- 用**附注 tag**（`-a`），带上该版本的 headline 变更
- 预发布版本也打 tag——内部版本同样需要可回溯
- **tag 一旦推送即视为不可变**，不允许移动或删除

## 6. 各层如何引用版本

```rust
// 推荐：经 aegis-version，保证与全工作区一致
println!("{}", aegis_version::full());     // 0.1.0-alpha.1+ge06dab0
println!("{}", aegis_version::banner());   // 单行横幅，用于启动日志

// 也可以从任一 crate 的 re-export 取
println!("{}", aegis_sense::aegis_version());
```

**禁止**在各 crate 里直接 `env!("CARGO_PKG_VERSION")`：一旦某个 crate 漏同步
workspace 版本，IPC 的版本握手会因版本错配拒绝服务。

## 7. 版本演进路线（规划）

| 版本 | 目标 |
|---|---|
| `0.1.0-alpha.N` | 感知层 + 只读自检可跑通；接口持续变动 |
| `0.1.0-beta.N` | 编排核心与状态机成型，进入真机实测 |
| `0.1.0-rc.N` | WFP 底座接入，只修阻塞缺陷 |
| `0.1.0` | 首个可日常使用的版本（只读防护 + 审计） |
| `0.2.0` | 引入熔断与角色模型（0.x 阶段的破坏性变更走 MINOR） |
| `1.0.0` | 对外契约冻结 |
