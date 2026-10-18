# 贡献指南

## 项目身份

**Aegis**（英文为主）/ **宙斯的神盾**（中文为辅）。

## 重要前提：这是一台接入校园网的开发机

在提交任何涉及**网络状态变更**的代码或执行任何变更前，请遵守：

- 🚫 **未获明确授权，绝不启动 / 重启任何上层代理工具**（Clash Verge、HypoMux、sing-box 等）。
- 🚫 **未获明确授权，绝不下发任何 WFP / 防火墙规则**，尤其是持久化的 Boot-Time 规则
  （§28.2：装了清理不掉的持久背板会让整机直接变砖）。
- ✅ 新增能力若牵涉特权操作，请**先做只读版本**（参考 `aegis-sense` 的做法），
  在干跑模式验证通过后再谈落地。

## 分支与提交约定

### 分支命名

```text
feat/<scope>      新能力      feat/sense-topology
fix/<scope>       修复        fix/wfp-dhcp-deadlock
docs/<scope>      文档        docs/readme-env-notes
chore/<scope>     工程杂项    chore/deps-bump
```

### 提交信息（Conventional Commits）

```text
<type>(<scope>): <中文简述>

feat(sense): 实现默认出口裁决与拓扑指纹
build(workspace): 建立 Cargo workspace 与工具链标准
fix(wfp): 修正 DHCP 豁免在 Boot-Time 阶段的死锁
```

`type` 取值：`feat` / `fix` / `docs` / `refactor` / `test` / `chore` / `build` / `ci`。

**请保持细粒度提交**：一个逻辑变更一次提交，便于追溯与回滚（这也是本仓库的要求）。
提交信息的**正文请写清楚"为什么"**——尤其是踩坑类修复，把现象、根因和实测数据写进去。

## 命名约定

| 对象 | 约定 | 示例 |
|---|---|---|
| crate | `aegis-` 前缀 | `aegis-sense` / `aegis-wfp` / `aegis-fuse` |
| 守护进程二进制 | `aegisd` | |
| 控制端二进制 | `aegisctl` | |
| 版本号 | 统一引用 `aegis-version`，**禁止**各 crate 自己 `env!("CARGO_PKG_VERSION")` | `aegis_version::full()` |

分层铁律：`aegis-wfp` 及以上属 OS 级底座，绝不依赖任何应用层代理；
`aegis-orchestrator` 只通过 SPI trait 与底座解耦，可整体替换。

## 版本号

发版前**必读 [`docs/VERSIONING.md`](docs/VERSIONING.md)**。要点：

- 形态：`MAJOR.MINOR.PATCH[-alpha/beta/rc.N][+g<hash>]`
- `MAJOR = 0` 期间，破坏性变更走 **MINOR** 递增
- 版本号四处必须一致：`VERSION`、`Cargo.toml` 的 `[workspace.package].version`、
  `aegis-version` 的单测断言、`CHANGELOG.md` 顶部条目
- Git tag 严格用 `v<版本>`，附注 tag，推送后不可变

## 代码规范

提交前请通过本地检查：

```powershell
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

要点：

- 本平台**仅 Windows**，不要在 `aegis-wfp` 以外引入跨平台抽象成本。
- 所有 `unsafe` 块必须写明**为什么安全**（SAFETY 注释）。
- FFI 失败必须向上传递 `Result`，**禁止 panic**（守护进程 panic = fail-closed 断网）。
- 涉及 `windows` crate 结构体 union 字段时，优先按稳定内存布局取字节，
  避免依赖 windows-rs 版本相关的 union 命名（见 `route.rs` 的做法）。
- **构建脚本（`build.rs`）禁止启动子进程**，受限环境下可能长时间挂起。
  需要 Git 元数据时直接读 `.git` 目录下的文件。

### PowerShell 脚本（本机是 5.1）

- 一律写成 **UTF-8 BOM + CRLF**；无 BOM 会被按 GBK 解码，中文错位到无法解析
- 只用 5.1 兼容语法：**不要**用 `??` 空合并、`if` 作表达式（尤其在 `param()` 默认值里）
- 起进程用 `&` 调用运算符直调，**不要**用 `Start-Process`
  （本机 `Path`/`PATH` 重复键会让 .NET 抛出）
- 提交前用 `Parser::ParseFile` 做一次语法自检

## 测试要求：必须通过变异回归测试

**单测全绿 ≠ 用例有效。** 本项目用 [`cargo-mutants`](https://mutants.rs) 做变异测试：
它会往源码里注入一个个"人造 bug"（变异体），然后跑测试；
**测试没变红的变异体 = 漏检（missed）= 一块没有被真正守护的逻辑**。

对 Aegis 这类安全底座，漏检不是"测试覆盖率不好看"的问题，而是真实事故：

> 删掉 `next()` 里的某条 `match arm` 后测试仍然全绿，
> 意味着用户真的走到那条状态边时系统不会迁移——而我们一直以为它是好的。

### 本地运行

```powershell
# 全量（分钟级，建议挂后台）
cargo mutants --no-shuffle -v --output mutants.out

# 只跑某个 crate
cargo mutants --package aegis-core -v

# 只跑某个文件
cargo mutants --file crates/aegis-core/src/state.rs -v
```

> **务必带 `-v`。**
> 不带时输出走块缓冲，重定向到文件后要等缓冲区满才落盘，
> 于是日志长时间停在基线那一行，**看起来像卡死，其实在跑**。
> 本机实测：不带 `-v` 时 45 秒内日志 0 行、采样到的 CPU 增量 0.7s，
> 一度被误判为挂起；带 `-v` 后同一环境下 75 秒跑完 7 个变异体。
>
> **不要用 `-j` 开高并行。**
> cargo 对 target 目录是独占锁，多个 cargo 进程并发会互相等锁：
> 实测 `-j 8` 时每个变异体的构建耗时从 5s 膨胀到 30~56s，
> 全部以 TIMEOUT 告终（`--copy-target` 也未能救回）。
> 变异测试的成本是「变异体数 × 单次构建时间」，
> 提高 `-j` 在共享 target 下是负优化，默认单线程即可。

配置见仓库根目录 `mutants.toml`。产物落在 `mutants.out/`（已 gitignore）：
`missed.txt` 是漏检清单，`caught.txt` 是已被杀死的，`unviable.txt` 是无法编译的注入。

### 判定标准

- **漏检必须为 0**（CI 里 `MUTATION_MAX_MISSED=0`）。
- 提交新逻辑时，请顺手跑一次对应 crate 的变异测试，确保自己写的用例**真的能杀死 bug**。

### 漏检了怎么办

先分辨两类漏检，处理方式完全不同：

| 类型 | 现象 | 处理 |
|---|---|---|
| **测试不够** | 逻辑确实有行为差异，但没人断言 | 补断言。迁移表/语义矩阵/展示文案这类"穷举型"逻辑，用**表驱动**一次钉死全部取值，比一条条手写 `assert` 更能杀死注入 |
| **等价变异体** | 改了也没差别（如 `is_empty` 在永远非空的表上） | 在 `.cargo/mutants.toml` 的 `exclude_re` 登记，并写明原因 |

补测试时的经验：

- **只测快乐路径会漏掉整片状态图**——把整张迁移表抄进测试逐边穷举。
- **单向断言会被"恒为真/恒为假"的注入骗过**——`is_empty`、`awaits_user`、
  任何返回 `bool` 的函数都要**两侧都断言**。
- **只断言"含某个结论码"不够强**——`>` 改成 `>=`、`==` 改成 `!=` 之后
  结论码会多出一个而测试照样通过。要断言**整个集合**。
- **`Display` 也是契约**——它是给运维看的诊断信息，串了会误导排障，逐条钉死。
- **校验和要有标准测试向量**——否则"校验和"只是几个无意义的字节。

### 变异测试为什么慢，怎么让它快

成本 = 变异体总数 ×（一次编译 + 一次跑测试）。几件事必须知道：

- **配置文件是 `.cargo/mutants.toml`**，不是仓库根的 `mutants.toml`。
  放错位置不会报错，只会**整份配置静默失效**（踩过）。
- **`test_timeout` 不是合法的配置字段**，而 cargo-mutants 对未知字段是
  **拒绝解析整个文件**的——写上去同样让整份配置失效。用命令行 `-t`。
- **`-j` 并行是负优化**。16 核实测：`-j 8 --copy-target=true` 让单次编译
  从 7s 涨到 45s（每个 job 拿到冷 target 副本）还炸出 5 个超时；
  `-j 4` 共享 target 是 113s，比 `-j 1` 的 100s **还慢**（cargo 对 target
  目录是独占锁，并发只会互相等锁）。**单机上不要加 -j。**
- **`--profile mutants` 是最大的单项收益**（单次编译 7s → 3s）。
  它关掉了 debuginfo——Windows 上链接阶段写 PDB 最贵，而变异测试
  根本不需要它。注意 `profile` 写在配置文件里也会被忽略，只能走命令行。
- **要压墙钟时间只能换机器并行**：CI 的 mutation job 用
  `matrix.shard: [1..8]` + `--shard k/8`，8 个 runner 各跑一份。
- **限定范围要用 `-F` 正则，不要用 `--file`**。配置里的 `examine_globs`
  会把 `--file` 覆盖掉，传了跟没传一样（实测 `--file plan.rs` 仍是 193 个
  变异体；`-F 'plan\.rs'` 才真的限定到 94 个）。
- **日常就用 `tools/mutate-changed.sh`**：它自动取 `git diff` 里改动的
  源码文件拼成正则，只跑那几个文件，通常几分钟。
  全工作区 572 个变异体留给 CI 分片去跑。

### CI 中的变异测试

`.github/workflows/ci.yml` 的 `mutation` job **不在每次推送时跑**（太慢），
触发方式是：

- 每周一 03:17 UTC 定时
- 手动 `workflow_dispatch`

该 job 是**分片并行**的（`matrix.shard: [1..8]`，每个 runner 跑
`--shard k/8`），因为单机并行无效，只能靠多机器把墙钟时间压下来。
任一分片出现漏检即整体失败，阈值语义与单任务时一致。
产物会以 `mutants-report` artifact 上传。

## 设计文档同步

`design-spec.md` 是**单一事实来源**。任何设计决策发生变更时，
请**先更新设计文档，再改代码**，并在提交信息里注明受影响的章节编号。
项目命名与版本编号规范见 §31。
