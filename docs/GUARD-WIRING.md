# 守卫运行时接线方案（`aegisd`）

> 上游文档：[`DOWNSTREAM-GUARD.md`](DOWNSTREAM-GUARD.md) 回答了
> **"什么叫规则生效"**；本文回答**"谁来定时判、判出来之后怎么动手"**。
>
> 本文只出方案，**未动运行时代码**。

---

## 1. 差的那一小段是什么

判决、防抖、配置、采集、SPI 契约都已经落地。剩下的是把它们接成一条
**在 `aegisd` 里持续跑的链**：

```text
定时采拓扑 ──▶ guard_facts_from ──▶ evaluate ──▶ GuardTracker::observe
                                                        │
                          ┌─────────────────────────────┼─────────────────┐
                          ▼                             ▼                 ▼
                      Nothing                       Tighten             Relax
                     （不动）                    （撤掉放行）        （重装放行）
```

## 2. 关键发现：**撤放行这条通道已经有了**

看一眼 `aegisd` 现有的看门狗：

```rust
fn watch(session: &Session, slot: &TicketSlot) {
    loop {
        thread::sleep(Duration::from_millis(200));
        let due = /* slot 里的 ticket.must_roll_back(now) */;
        if due { /* rollback(session, &ids) */ }
    }
}
```

而 `ApplyTicket::force_teardown()` 的存在理由就是
"**已确认**的规则也必须能被一条命令撤掉"（兜底手册的命脉）。

于是 `GuardAction::Tighten` 的实现就是：

```rust
ticket.force_teardown();      // 看门狗下一轮（≤200ms）就会按 id 撤掉放行
```

**不需要新机制。** 撤完之后默认拒绝底板仍在 → 全都拒绝。这正是
`DOWNSTREAM-GUARD.md` §4 要求的"撤掉放行，而不是新增拒绝"。

⚠ 但**反方向没有现成的**：`Relax` 要**重新装**放行规则，而装要走
`apply()`（10 秒两阶段确认）。这就引出下面第 4 个问题。

---

## 3. 线程模型（绕开 `Session` 不是 `Send` 这条坑）

`Session` 里是原始 HANDLE，**不是 `Send`**，所以现有代码让会话
**生在看门狗线程里、从头到尾没离开过那个线程**。守卫不能例外。

```text
主线程
  ├─ IPC 线程（已有）：收 apply/confirm/rollback
  ├─ 看门狗线程（已有）：**持有会话**，按 ticket 撤
  └─ Supervisor 线程（新）：不碰 Session
        │
        ├─ 每 N 秒：snapshot() → guard_facts_from → evaluate → observe
        ├─ Tighten  → ticket.force_teardown()      （看门狗去撤）
        ├─ Relax    → spawn 新线程：apply + 自动 confirm（新会话生在新线程里）
        └─ NeedsHuman → 只记审计 + 置状态，不动手
```

`Relax` 那个新线程和现有 `aegisctl apply` 走的是**同一条** `apply()` 路径，
区别只是它由 Supervisor 自动 confirm。

---

## 4. 六个必须先答的问题

### 4.1 巡检周期取多少

`GuardTracker` 要求**连续 3 次**失败才收紧，所以泄漏窗口 ≈ `3 × 周期`。

| 周期 | 收紧延迟 | 代价 |
|---|---|---|
| 1s | 3s | 每秒一次 `GetIfTable2`+`GetAdaptersAddresses`，常驻 CPU |
| **3s（建议默认）** | **9s** | 折中 |
| 10s | 30s | 泄漏窗口太长 |

建议 **3s**，做成配置项 `guard.interval_sec`，先跑起来再调。

### 4.2 `proxy_reachable`（断言 A）从哪来

分两步走，先把不需要真实适配器的一半接上：

| 版本 | 断言 A 的来源 |
|---|---|
| v1（本次接线） | `Op::Health` 调用成功即视为可达（真实适配器有了也一样） |
| v2 | 适配器声明了 `RuleEffectiveness` 就用 `Op::RulesEffective`，三态直接映射 |

⚠ 三态映射要**严格对应**，不能压成 bool：

```text
Outcome::RulesEffective          → 计入"通过"
Outcome::RulesIneffective{failed} → 计入"失败"，failed 进 reason
Outcome::RulesUnknown{why}        → **不计数**（Unknown 永不触发收紧）
```

### 4.3 自动放宽要不要走两阶段确认

**要装规则，但不要人点确认。** 区分一下两种场景：

| 场景 | 谁发起 | 要不要倒计时 |
|---|---|---|
| `aegisctl apply` | 人 | **要**（手滑装错是全项目最怕的事故） |
| 守卫 `Relax` | 自动 | **不要**（它是"恢复"，不是"新装"；再等 10 秒确认等于罚用户） |

实现上给 `apply` 加一个"自动确认"标志，或者 Supervisor 装完立刻
`confirm(now)`。⚠ 但**审计必须记清是自动恢复**，不能和人工确认混在一起。

### 4.4 启动首轮不能立刻收紧

进程刚起来还没判过，此时 `consecutive_failures == 0`，
`GuardTracker` 天然不会收紧。✅ 不需要额外逻辑——**这是把防抖放进了
tracker 而不是散在调用方的好处**。

### 4.5 进程退出时怎么样

会话是动态的 → 进程一退，放行规则全没 → **自动断**。
这正是 fail-closed，不需要任何清理代码。

⚠ 因此**守卫只在 `aegisd` 存活期间有意义**。
当前 `aegisd` 是 `--serve-secs N` 到点退出（演练形态），
真正的长期形态是 Windows Service —— 那也是守卫真正上岗的时候。
这一点要在 GUI 上说清楚，否则用户会以为"装了 Aegis 就一直有人看着"。

### 4.6 收紧了必须能说清为什么

`Status` 里现在只有 `insulation`。要加 `guard_reason`，内容来自
`GuardVerdict::reason()`（已含"哪条断言失败"）。

⚠ 这不是锦上添花：`DOWNSTREAM-GUARD.md` §5.2 说过，
用户不知道为什么断 → 会**卸掉 Aegis** → 防护彻底归零。

---

## 5. 分步实施

| 步 | 内容 | 风险 |
|---|---|---|
| 1 | `Status` 增加 `guard_reason`；Supervisor 线程只判 + 只记日志，**不动手** | 无（纯观测） |
| 2 | 接 `Tighten → force_teardown` | 中（会真的断网） |
| 3 | 接 `Relax → 重装放行 + 自动 confirm` | 中 |
| 4 | `NeedsHuman` → 置状态 + 审计，等人工 | 低 |
| 5 | 断言 A 接 `Op::Health`，再接 `Op::RulesEffective` | 低 |

### 5.1 验收：一个**不需要改代码**就能复现的实验

把配置里的 `proxy.tun_luid` 填成**一张真实存在但不是代理 TUN 的网卡**的 LUID
（比如校园物理网卡自己）。于是断言 C 必然失败：

```text
预期：连续 3 次（约 9 秒）→ Tighten → 放行被撤 → 全网断
     把 tun_luid 改回正确值 → 连续 3 次通过 + 过冷却 → Relax → 恢复
```

这比"造一个假适配器"实在得多：**它验的是真链路**，包括真的动网络。

⚠ 所以要写成脚本 `tools/guard-drill.sh`，并且和 `cage-drill.sh` 一样
**自带恢复**（`trap` 里强制把 ticket 撤掉 + 结束进程）。

---

## 6. 风险与开放问题

1. **误收紧的代价是整机断网。** 所以步 1（只观测）必须先跑一段时间，
   确认在真机上不会平白无故报 `Ineffective`，再接步 2。
2. **`Relax` 重装失败怎么办？** 装失败 = 继续断。要有重试上限，
   超限转 `NeedsHuman`，不能无限重试刷屏。
3. **`Tighten` 和 `aegisctl rollback` 撞车**：两者都动 ticket，
   需要明确优先级（人工 > 自动）。
4. **要不要给用户一个"别再自动收紧了"的开关**？
   反复误报时，用户需要一个能让自己先上网的出口
   （`EMERGENCY-TEARDOWN.md` 的强拆通道可复用）。
