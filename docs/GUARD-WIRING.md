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

| 步 | 内容 | 状态 |
|---|---|---|
| 1 | Supervisor 线程只判 + 只记日志，**不动手** | ✅ 已落地 |
| 2 | 接 `Tighten → force_teardown` | ✅ 已落地，但**默认不开**（`--guard-act`） |
| 3 | 接 `Relax → 重装放行 + 自动 confirm` | ⬜ |
| 4 | `NeedsHuman` → 置状态 + 审计，等人工 | ⬜ |
| 5 | 断言 A 接 `Op::Health`，再接 `Op::RulesEffective` | ⬜ |
| — | `Status` 增加 `guard_reason` | 推迟到步 2（真正会收紧时才需要 GUI 显示原因，不必为纯观测动 IPC schema） |

### 5.0 步 1 已落地的样子

```bash
aegisd --config <配置> --data-dir .aegis-run --serve-secs 600 --guard-interval-secs 3
```

```text
守卫：下游规则生效性观测（步 1，只观测不动手）
  周期      : 3 秒
  断言      : B 承载体在 / C 默认出口指向承载体
  ⚠ 断言 A（代理可达）尚未接 SPI，暂按可达处理
  日志      : .aegis-run/guard-observe.log

[守卫 #1] 生效
[守卫 #2] 生效
```

⚠ **断言 A 目前是占位值**（一律按"可达"）。后果要说清楚：
**"代理进程死了"这一条现在抓不到**，只看 B/C。接上 SPI 后改真实结果。

刻意做成"连续失败计数"而不是直接用 `GuardTracker`：还没真的收紧过，
喂给 tracker 会让它以为已经收紧，进而输出没有意义的"会放宽"。
计数规则 `next_streak` 与 `GuardTracker` **逐条一致**（`Unknown` 既不清零
也不累加），并有单测钉住——否则"观测期没报警"推不出"接上动作也不误收紧"。

### 5.0.1 步 2 已落地的样子（`Tighten` 真的撤放行）

```bash
aegisd --config <配置> --data-dir .aegis-run --serve-secs 600 \
       --guard-interval-secs 3 --guard-act
```

⚠ `--guard-act` **默认关闭**。收紧的代价是整机断网，不能让一次手滑的
命令行把它打开；而且步 3（`Relax`）还没接线，**收紧之后不会自动恢复**。

动作分三种，落到票据上的效果各不相同：

| 票据阶段 | 动作 | 为什么 |
|---|---|---|
| `Committed` | `force_teardown()` | 已确认的规则也要能撤（兜底通道） |
| `Pending` | `request_abort()` | 规则**已经装上**了，Pending 只表示没点确认；普通 abort 足够，不必动用强拆 |
| `RolledBack` | **不动作** | filter id 会复用，再删一次可能删到别人的规则 |
| 无票据 | **不动作** | 从没下发过就没有放行可撤。⚠ 此时**绝不能**临时装一条拒绝规则——那是让守卫凭空造出它没能力安全撤掉的东西 |

真机演练（`tun_luid = 1`，周期 2s，**全程没有下发过任何 WFP 规则**）：

```text
[守卫 #1] 未生效（下游规则未生效：2 项未通过 [承载体存在] [默认出口=承载体]）
[守卫 #2] 未生效（...）
[守卫 #3] ⚠ 该收紧，但当前**没有票据**（没下发过放行）→ 无放行可撤，不动作
[守卫 #4] 未生效（...）     ← 已置"已收紧"，不再重复动作
```

✅ 第 3 拍准确走到收紧分支，并且如实说出"撤不了"的原因——
**"该收紧但收不了"必须被看见**，否则会误以为已经全都拒绝了。

⚠ **还没验的是真断网那一段**：需要有票据（先 `aegisctl apply` + `confirm`）
才能看到放行被撤掉。那一步会真的断网，属于要人工在场的演练。

### 5.1 验收：一个**不需要改代码**就能复现的实验（步 1 已实测两组）

把配置里的 `proxy.tun_luid` 填成**一张真实存在但不是代理 TUN 的网卡**的 LUID
（比如校园物理网卡自己）。于是断言 C 必然失败：

```text
预期：连续 3 次（约 9 秒）→ Tighten → 放行被撤 → 全网断
     把 tun_luid 改回正确值 → 连续 3 次通过 + 过冷却 → Relax → 恢复
```

这比"造一个假适配器"实在得多：**它验的是真链路**，包括真的动网络。

⚠ 所以要写成脚本 `tools/guard-drill.sh`，并且和 `cage-drill.sh` 一样
**自带恢复**（`trap` 里强制把 ticket 撤掉 + 结束进程）。

#### 步 1 的两组实测（本机，周期 2s）

**A. 配对了（`tun_luid` = 本机真实默认出口 LUID）→ 应当一直"生效"**

```text
[守卫 #1] 生效
[守卫 #2] 生效
[守卫 #3] 生效
[守卫 #4] 生效
[守卫 #5] 生效
```

✅ **无误报**——这是步 2 敢接动作的前提。

#### 5.1.1 A 组的**长跑**（周期 3s，连续约 12 分钟）

上面 5 拍只能说明"刚启动那会儿是对的"。真正要排除的是**跑久了会平白
报 Ineffective**——比如拓扑采集偶发失败、默认路由瞬时抖动、LUID 复用。
所以让它在真机上连续跑了 **237 拍**：

```text
总行数: 237
=== 全量判定分布 ===
    237 生效
=== 非『生效』行 ===
（空）
```

- 配置：`config/config.example.toml` 复制一份，`tun_luid = 1689399750295552`
  （本机真实默认出口，合成度量 35，网关 `10.41.0.1`）。
- 命令：`aegisd --config .aegis-run/guard-observe.toml --data-dir .aegis-run
  --pipe \\.\pipe\aegis --serve-secs 780 --guard-interval-secs 3`
- 覆盖：学校日常用网（挂着网、有流量）。**没有**插拔网线 / 开关 Wi-Fi ——
  这一段只能证明"稳态不误报"。

✅ **结论：稳态零误报**，`Tighten` 可以接。

⚠ **还没验的**：网络切换瞬间（拔网线 → 默认出口消失 → `Unknown`）。
这一段按设计是"判不了就**不动手**"（`next_streak` 对 `Unknown` 原样返回），
但**真机上没跑到过**，属于纸面正确。要验就得人工插拔，
建议由使用者在自己方便的时候跑：

```bash
aegisd --config <填好 tun_luid 的配置> --data-dir .aegis-run \
       --serve-secs 600 --guard-interval-secs 2
# 跑起来之后：拔网线 → 等 30 秒 → 插回去
# 期望：全程只有「生效」与「判不了（…）→ 不动手」，不该出现「若已接线，此刻会收紧」
```

> **复现时踩到的坑（已修）**：`--pipe` 要的是 Win32 完整路径
> `\\.\pipe\<name>`。传裸名（`--pipe aegis-ob`）时内核回
> **os error 123「文件名、目录名或卷标语法不正确」**，而启动日志那句提示写的是
> "多半是已有实例占用"——**完全指错方向**，白查半天。
> 现在 `aegisd` 会自动补前缀（`normalize_pipe_name`，有单测）。
> 另外 Git Bash 会把 `\\.\pipe\aegis` 吃掉一个反斜杠（MSYS 路径转换），
> 起进程建议用 PowerShell 的 `&` 调用运算符，别用 `Start-Process`（本机
> `Path`/`PATH` 重复键会让它直接抛异常）。

**B. 故意填错 `tun_luid = 1` → 断言 C 必然失败**

```text
[守卫 #1] 未生效（下游规则未生效：2 项未通过 [承载体存在] [默认出口=承载体]）连续 1 次（阈值 3）
[守卫 #2] ... 连续 2 次（阈值 3）
[守卫 #3] ... 连续 3 次（阈值 3） ⚠ **若已接线，此刻会收紧**（撤掉放行 → 全都拒绝）
```

✅ 防抖生效：前两次**只报不动**，到阈值才提示"会收紧"。

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
