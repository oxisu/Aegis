# 贡献指南

## 重要前提：这是一台接入校园网的开发机

在提交任何涉及**网络状态变更**的代码或执行任何变更前，请遵守：

- 🚫 **未获明确授权，绝不启动 / 重启任何上层代理工具**（Clash Verge、HypoMux、sing-box 等）。
- 🚫 **未获明确授权，绝不下发任何 WFP / 防火墙规则**，尤其是持久化的 Boot-Time 规则
  （§28.2：装了清理不掉的持久背板会让整机直接变砖）。
- ✅ 新增能力若牵涉特权操作，请**先做只读版本**（参考 `ob-sense` 的做法），
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
fix(netfilter): 修正 DHCP 豁免在 Boot-Time 阶段的死锁
```

`type` 取值：`feat` / `fix` / `docs` / `refactor` / `test` / `chore` / `build` / `ci`。

**请保持细粒度提交**：一个逻辑变更一次提交，便于追溯与回滚（这也是本仓库的要求）。

## 代码规范

提交前请通过本地检查：

```powershell
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
```

要点：

- 本平台**仅 Windows**，不要在 `ob-netfilter` 以外引入跨平台抽象成本。
- 所有 `unsafe` 块必须写明**为什么安全**（SAFETY 注释）。
- FFI 失败必须向上传递 `Result`，**禁止 panic**（守护进程 panic = fail-closed 断网）。
- 涉及 `windows` crate 结构体 union 字段时，优先按稳定内存布局取字节，
  避免依赖 windows-rs 版本相关的 union 命名（见 `route.rs` 的做法）。

## 设计文档同步

`design-spec.md` 是**单一事实来源**。任何设计决策发生变更时，
请**先更新设计文档，再改代码**，并在提交信息里注明受影响的章节编号。
