# Aegis 规则集（rulesets）

两份 **mihomo / Clash 规则提供者（rule-provider）** 模板，对应两个物理通道。

| 文件 | provider name | 通道 | 兜底语义 |
|---|---|---|---|
| `campus.yaml` | `campus` | 校园网 · 纯洁通道 | **Fail-Closed**：不在清单里一律拒绝 |
| `hotspot.yaml` | `hotspot` | 移动热点 · 自由出海通道 | **Fail-Open**：清单只挑直连，其余出海 |

---

## 0. 一句话说清这两份文件"是不是安全边界"

**不是。** 它们属于 §20.10 的**第二层（可覆盖策略）**，可以随便改，改坏了破坏不了底线。

真正的不变量在**第一层**，由 `aegis-wfp::plan` 的 `verify()` / `verify_policy()`
在内核层执行——默认拒绝底板、回环与 DHCP 放行、物理网口对 53 / LLMNR / mDNS
广播的封锁、拓扑震荡先熔断。这些**不随场景切换**，也不由这两份文件决定。

但要清楚一个方向上的缺口：

> 这里决定的是"**走代理还是直连**"，不是"**要不要拦**"。
> 把 `campus.yaml` 对应的主链收尾从 `FINAL,REJECT` 改成 `FINAL,🚀 节点选择`，
> 等于作废"纯洁通道"——**而这不在任何自动校验的保护范围内**，
> 只有人知道该不该那么改。

---

## 1. 为什么两套刻意不对称（别去"对齐"）

两边取舍是反的，看着不一致才是对的：

| | 校园网（`campus`） | 热点（`hotspot`） |
|---|---|---|
| 漏包代价 | **高**：被出口 DPI 审计到 | **≈0**：本来就是自由出海通道 |
| 连不上代价 | 低：少上几个网站 | 高：自己没法用网 |
| 因此 | 不确定就**掐** | 不确定就**放行** |

**Fail-Open 不等于没防护**——第一层不变量在热点模式下依然生效，
由 `aegis-wfp` 在内核层执行，这份规则集改不动也不需要改。

---

## 2. 怎么接到 mihomo

### 2.1 主配置里挂 provider

```yaml
rule-providers:
  campus:
    type: file
    behavior: classical
    path: ./rulesets/campus.yaml      # 或用 http 类型从远端拉

  hotspot:
    type: file
    behavior: classical
    path: ./rulesets/hotspot.yaml
```

### 2.2 rules 链的收尾决定一切

`payload` 只是"命中清单"，**动作写在主链末尾**：

```yaml
rules:
  # ... 其它来源的规则 ...

  # 校园网严格模式：命中清单的直连，其余拒绝
  - RULE-SET,campus,DIRECT
  - FINAL,REJECT                 # ← 这一句才是"纯洁通道"的定义

  # 热点自由模式：命中清单的直连（省流量+低延迟），其余出海
  #- RULE-SET,hotspot,DIRECT
  #- FINAL,🚀 节点选择           # ← 兜底是"出海"，不是"拒绝"
```

⚠ **两套不要同时挂 FINAL**。`FINAL` 是链的终点，挂两个等于后者永远不生效，
而现象是"切到热点模式却上不了外网"——看起来像规则集写错了，其实是链写错了。

### 2.3 切换由谁触发

**不是这两份文件自己切。** 流程是：

```
aegis-sense 采集拓扑（含 SSID）
    ↓
aegis-core 角色裁决 → CampusStrict / FreeOutbound / Isolated / Aggregated
    ↓
aegis-orchestrator 适配器 → PUT /providers/rules/{province}（campus 或 hotspot）
```

⚠ 适配器侧的实现见 §2A.4 的能力接口 `RuleEffectiveness`：
Aegis 只负责"**检查切换结果有没有违反不变量**"，不替用户排序规则。

---

## 3. 使用前必须做的两件事

1. **填校园网认证门户域名**（`campus.yaml` 第 2 段，默认注释掉）
   不填的后果不是"少上几个网站"，而是**整套规则表现为完全不能上网**，
   且 REJECT 是静默丢包，不给任何"你需要先认证"的提示——
   人的第一反应是去翻防火墙，排错方向完全跑偏。
   填法：连上校园网、先别开这套规则，看跳转认证页的地址栏域名，取主域名。

2. **确认学校内网是否需要额外放行**（`campus.yaml` 第 4 段）
   多数学校的内网办事大厅 / 图书馆资源**不在** `GEOSITE,cn` 里。

---

## 4. 校验

```bash
python tools/check-rulesets.py            # 默认：有 ERR 才失败
python tools/check-rulesets.py --strict   # WARN 也算失败（CI 用）
```

检查的是"这两份文件自身是否自洽"：规则类型是否在白名单里、
CIDR 是否带掩码且合法、`DOMAIN` 类型的值是不是被误填成了 IP、
本地链路规则是否缺项、占位符是否被遗忘。

**为什么要有这个脚本**：mihomo 是**另一个软件**，本机没装就加载不了它，
语法写错不会被任何人发现——规则看起来存在，实际没生效。
这是 §20.10 说的那种最阴的失败：**声明与产出脱节**。
