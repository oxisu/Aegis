#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""规则集静态校验 —— 零依赖（只用标准库），任何 Python 3 都能跑。

为什么要用脚本校验而不是"人看一遍"：
mihomo 的 rule-provider 是**另一个软件**的配置文件，本机没有 mihomo 就加载不了，
写错不会被发现。而它的失败模式恰好是最坏的那种：

  · 语法错 / 类型写错（比如 `DOMAIN,10.0.0.1`）→ provider 加载失败或被整条忽略，
    规则看起来存在但实际没生效 —— **静默失效**
  · 少了回环或私有网段 → 不是"少上几个网站"，而是本机 IPC / 认证门户全断，
    现象看起来像"网坏了"或"Aegis 把网切了"，排错方向完全跑偏

所以把这些**不变量用脚本钉住**。这份脚本检查的是"这两份文件自身是否自洽"，
不检查 mihomo 主配置（那属于另一份家dup的责任）。

用法：
    python tools/check-rulesets.py
    python tools/check-rulesets.py --strict   # 把 WARN 也当成失败（CI 用）
退出码：0 = 通过，1 = 有 ERR（或 strict 下有 WARN）
"""

from __future__ import annotations

import ipaddress
import re
import sys
from pathlib import Path

RULESET_DIR = Path(__file__).resolve().parent.parent / "rulesets"

# mihomo 支持的规则类型（白名单）。写错类型是最容易发生的静默失败。
KNOWN_TYPES = {
    "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX",
    "GEOSITE", "GEOIP",
    "IP-CIDR", "IP-CIDR6", "IP-ASN", "IP-SUFFIX",
    "SRC-IP-CIDR", "SRC-IP-ASN", "SRC-GEOIP",
    "DST-PORT", "SRC-PORT", "IN-PORT", "IN-TYPE", "IN-USER", "IN-NAME",
    "PROCESS-NAME", "PROCESS-PATH", "NETWORK", "PROTOCOL",
    "DSCP", "UID", "SUB-RULE", "RULE-SET", "AND", "OR", "NOT",
}

# 这些属于**主配置 rules 链**的职责，写进 provider payload 等于这一个来源
# 独占裁决权 —— 正是 §20.10 明确不要的"全局优先级链"
FORBIDDEN_IN_PAYLOAD = {"FINAL", "MATCH"}

PLACEHOLDERS = ("your-campus", "<你的", "TODO", "XXX", "changeme")


def extract_payload(path: Path) -> list[str]:
    """零依赖解析：只要 `payload:` 下面那些 `- XXX` 列表项。

    注释行（`#- ...`）天然被跳过 —— 正好，模板里被注释掉的备选规则不算数。
    """
    items: list[str] = []
    in_payload = False
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        stripped = raw.strip()
        if stripped.startswith("payload:"):
            in_payload = True
            continue
        if not in_payload:
            continue
        if not stripped or stripped.startswith("#"):
            continue
        if not stripped.startswith("- "):
            break  # 缩进回到上一层，payload 块结束
        # 剥掉行尾注释：`- IP-CIDR,127.0.0.0/8    # 说明` → `IP-CIDR,127.0.0.0/8`
        # 只认「空白 + #」，规则值本身不含 #（mihomo 规则里没有这个字符）
        value = re.split(r"\s+#", stripped[2:].strip(), maxsplit=1)[0].strip()
        items.append((lineno, value))
    return items


class Report:
    def __init__(self) -> None:
        self.errs: list[str] = []
        self.warns: list[str] = []

    def err(self, msg: str) -> None:
        self.errs.append(msg)

    def warn(self, msg: str) -> None:
        self.warns.append(msg)


def looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def check_common(name: str, items: list[tuple[int, str]], rep: Report) -> None:
    """两套都要过的检查。"""
    for lineno, rule in items:
        # G2 语法：形如 TYPE,ARGUMENT（第二字段里不许再出现逗号以外的东西）
        if rule.count(",") < 1:
            rep.err(f"{name}:{lineno} 规则写法不对（缺逗号）: {rule!r}")
            continue
        rtype, _, rarg = rule.partition(",")

        # G3 类型白名单
        if rtype not in KNOWN_TYPES:
            rep.err(f"{name}:{lineno} 未知规则类型 {rtype!r} —— mihomo 会静默忽略整条规则")

        # G4 FINAL/MATCH 不允许出现在 payload 里
        if rtype in FORBIDDEN_IN_PAYLOAD:
            rep.err(
                f"{name}:{lineno} {rtype} 不能写进 provider payload —— "
                f"它属于主配置 rules 链；写在这里等于这一个来源独占裁决权（见 §20.10）"
            )

        # G7 DOMAIN 系列的值不许是 IP/CIDR（作者自己踩过：写成 DOMAIN,10.0.0.1）
        if rtype in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"} and looks_like_ip(rarg):
            rep.err(
                f"{name}:{lineno} {rtype} 的值 {rarg!r} 是 IP而非域名 —— "
                f"裸 IP 要用 IP-CIDR 并带掩码，如 IP-CIDR,10.0.0.1/32"
            )

        # G6 CIDR 必须带掩码且合法
        if rtype in {"IP-CIDR", "IP-CIDR6"}:
            if "/" not in rarg:
                rep.err(f"{name}:{lineno} {rtype} 缺掩码: {rarg!r}（应写成 x.x.x.x/n）")
            else:
                try:
                    net = ipaddress.ip_network(rarg, strict=True)
                except ValueError as e:
                    rep.err(f"{name}:{lineno} {rtype} 的 {rarg!r} 不合法: {e}")
                else:
                    expect_v6 = rtype == "IP-CIDR6"
                    if net.version == 6 and not expect_v6:
                        rep.err(f"{name}:{lineno} IPv6 网段 {rarg!r} 却用了 IP-CIDR（应用 IP-CIDR6）")
                    if net.version == 4 and expect_v6:
                        rep.err(f"{name}:{lineno} IPv4 网段 {rarg!r} 却用了 IP-CIDR6（应用 IP-CIDR）")
                    # G5 全放行 CIDR
                    if net.prefixlen == 0:
                        rep.err(
                            f"{name}:{lineno} {rtype},{rarg} 把整个地址空间放行了 —— "
                            f"这会让整套规则的收尾语义失效"
                        )

        # G8 占位符残留
        for ph in PLACEHOLDERS:
            if ph in rule:
                rep.err(
                    f"{name}:{lineno} 残留占位符 {ph!r}: {rule!r} —— "
                    f"占位符没替换就上线是最容易发生的静默失败"
                )


LOCAL_REQUIRED = [
    "IP-CIDR,127.0.0.0/8",          # 回环；不放会连本机 IPC 都掐
    "IP-CIDR6,::1/128",
    "IP-CIDR,10.0.0.0/8",           # 内网 / 认证门户常见
    "IP-CIDR,172.16.0.0/12",
    "IP-CIDR,192.168.0.0/16",
    "IP-CIDR,169.254.0.0/16",       # 链路本地，部分认证门户从这里跳出来
    "IP-CIDR6,fe80::/10",
]


def check_local(name: str, rules: list[str], rep: Report) -> None:
    """本地链路是两套共同的前提 —— 缺一条的现象都是"看起来像网坏了"。"""
    missing = [r for r in LOCAL_REQUIRED if r not in rules]
    for m in missing:
        rep.err(
            f"{name}: 缺少本地链路规则 {m!r}\n"
            f"      后果：使用该网段的所有连接被拒/绕远路，"
            f"现象看起来像\"网卡坏了\"而不是\"规则少了\""
        )


def check_campus(rules: list[str], rep: Report) -> None:
    # C3 白名单必须真的有内容，否则这套规则 = 全面断网（且没有提示）
    if not any(r.startswith(("GEOIP", "GEOSITE")) for r in rules):
        rep.err(
            "campus.yaml: 没有任何 GEOIP/GEOSITE 白名单条目 —— "
            "这套规则会变成\"除了内网什么都连不上\"，而 REJECT 是静默丢包，不给任何提示"
        )
    # 认证门户：如果一行带 your-campus 的都没启用，提醒（不是错，但风险高）
    if not any("DOMAIN-SUFFIX," in r for r in rules):
        rep.warn(
            "campus.yaml: 没有校园网认证门户的放行条目 —— "
            "不填的话连认证都做不了，整套规则会表现为完全不能上网。"
            "确认这是你要的；否则请填第 2 段并取消注释"
        )


def check_cross(campus_rules: list[str], hotspot_rules: list[str], rep: Report) -> None:
    """两边的本地链路必须一致：不一致意味着某个模式下会连不上路由器/本机。"""
    c = {r for r in campus_rules if r in LOCAL_REQUIRED}
    h = {r for r in hotspot_rules if r in LOCAL_REQUIRED}
    only_c = sorted(c - h)
    only_h = sorted(h - c)
    if only_c:
        rep.warn(f"campus 有而 hotspot 没有的本地链路规则: {only_c} —— 切换模式时会出现差异行为")
    if only_h:
        rep.warn(f"hotspot 有而 campus 没有的本地链路规则: {only_h} —— 切换模式时会出现差异行为")


def main(argv: list[str]) -> int:
    strict = "--strict" in argv
    rep = Report()

    files = {
        "campus.yaml": RULESET_DIR / "campus.yaml",
        "hotspot.yaml": RULESET_DIR / "hotspot.yaml",
    }

    parsed: dict[str, list[str]] = {}
    for name, path in files.items():
        if not path.exists():
            rep.err(f"{name} 不存在（期望 {path}）")
            continue
        items = extract_payload(path)
        if not items:
            rep.err(f"{name}: 没解析出任何 payload 条目 —— payload 块写坏了？")
            continue
        rules = [r for _, r in items]
        parsed[name] = rules
        check_common(name, items, rep)
        check_local(name, rules, rep)

    if "campus.yaml" in parsed:
        check_campus(parsed["campus.yaml"], rep)
    if len(parsed) == 2:
        check_cross(parsed["campus.yaml"], parsed["hotspot.yaml"], rep)

    print("规则集静态校验\n" + "-" * 46)
    for name in files:
        if name in parsed:
            print(f"  {name:<16} {len(parsed[name]):>3} 条规则")
    print("-" * 46)

    for w in rep.warns:
        print(f"WARN  {w}")
    for e in rep.errs:
        print(f"ERR   {e}")

    failed = bool(rep.errs) or (strict and bool(rep.warns))
    if failed:
        print(f"\n❌ 校验未通过：{len(rep.errs)} 个错误，{len(rep.warns)} 个警告")
        return 1
    tail = f"（另有 {len(rep.warns)} 个警告）" if rep.warns else ""
    print(f"\n✅ 全部通过 {tail}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
