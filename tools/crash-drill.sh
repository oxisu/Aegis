#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Aegis 崩溃安全演练 —— **进程被强杀之后，规则还在不在？**
#
#   bash tools/crash-drill.sh
#
# 它回答的是"非正常终止"这一类问题里**唯一能在本机实测**的那一条：
#
#   绝缘笼装着的时候，主机 / 进程被硬杀（断电、蓝屏在进程侧的等价形态），
#   清理代码一行都没跑 —— 规则会不会留在内核里清不掉？
#
# ---------------------------------------------------------------------------
# 为什么值得单独做一个脚本
#
# 正常退出有清理代码，验了也白验：它证明的是"我们的 rollback 写得对"，
# 不是"崩溃路径安全"。真正要验的是**清理代码没机会执行**的那条路径。
# 所以这里用 `taskkill /F`（TerminateProcess）：没有 atexit、没有 DLL 分离、
# 没有 Drop —— 跟断电在"进程侧"的效果一致。
#
# ---------------------------------------------------------------------------
# 为什么只拦一个 IP，而不是装整副笼子
#
# 装整副笼子的 blast radius 是"整机断网"。万一这一轮验证不成立，恢复手段
# 就只剩重启。改为只拦 www.baidu.com 的 443：最坏情况只是"百度暂时打不开"，
# 而它验证的是**同一件事**——动态会话里的对象随进程消亡。
#
# ---------------------------------------------------------------------------
# 断电 / 蓝屏本身能不能测
#
# **不能**，也不该在这台正在用的机器上测。但它们的结论可以从"进程被硬杀"
# 这一测外推，理由是：动态会话（`FWPM_SESSION_FLAG_DYNAMIC`）里的对象
# 只存在于**内核内存**，从不写入 BFE 的持久存储。进程没了 → 没了；
# 内核没了（蓝屏重启）→ 更没了。
#
# 另外本版**从不装 Boot 层规则**（`preflight` 明确拒绝 `Tier::Boot`），
# 也不写注册表、不注册服务、不装驱动 —— 用 grep 可复核：
#   grep -rn "RegSetValue\|CreateService\|OpenSCManager" crates/    → 0 处
# ---------------------------------------------------------------------------

set -u
cd "$(dirname "$0")/.." || exit 1
REPO="$(pwd)"

# ── 配置 ────────────────────────────────────────────────────────────────
PROBE_HOST="183.2.172.177"   # www.baidu.com 的一个 IP
PROBE_PORT=443
TIMEOUT=3

LOG_DIR=".aegis-run"
mkdir -p "$LOG_DIR"
LOG="$LOG_DIR/crash-$(date +%Y%m%d-%H%M%S).log"
PROBE_LOG="$LOG_DIR/crash-probe.log"

export RUSTUP_HOME="${RUSTUP_HOME:-D:\\Dev\\Rust\\.rustup}"
export CARGO_HOME="${CARGO_HOME:-D:\\Dev\\Rust\\.cargo}"
export PATH="/d/Dev/Rust/.cargo/bin:/d/Dev/msys64/mingw64/bin:$PATH"
unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy 2>/dev/null

PROBE_PID=""
rc=0

log()  { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*" | tee -a "$LOG"; }
step() { printf '\n=== %s ===\n' "$*" | tee -a "$LOG"; }
check() {
  if [ "$2" = "$3" ]; then log "  ✅ $1（$2）";
  else log "  ❌ $1（得到 $2，期望 $3）"; rc=1; fi
}

# 无论怎么退出，都别把一个拦着百度的进程留在后台
restore() {
  if [ -n "$PROBE_PID" ] && kill -0 "$PROBE_PID" 2>/dev/null; then
    log "收尾：结束残留的探针进程 $PROBE_PID"
    MSYS_NO_PATHCONV=1 taskkill /F /PID "$PROBE_PID" >/dev/null 2>&1
  fi
}
trap restore EXIT INT TERM

# ── 连通性探测：TCP 握手，不用 ping ─────────────────────────────────────
# WFP 的 ALE 层不管 ICMP，ping 在装了阻断规则之后照样通，会给出假的"没生效"。
probe() {
  python -c "
import socket
try:
    socket.create_connection(('$PROBE_HOST', $PROBE_PORT), $TIMEOUT).close()
    print('通')
except OSError:
    print('断')
" 2>/dev/null
}

step "0/5 准备"
log "仓库      : $REPO"
log "日志文件  : $(pwd)/$LOG"

log "编译 crash_probe"
cargo build -p aegis-wfp --example crash_probe >>"$LOG" 2>&1 \
  || { log "❌ 编译失败，看 $LOG"; exit 1; }

TARGET_DIR="$(python -c "
import json,subprocess
print(json.loads(subprocess.check_output(['cargo','metadata','--format-version','1','--no-deps']))['target_directory'])
" 2>/dev/null)"
log "target 目录: $TARGET_DIR"

step "1/5 基线（没装规则）"
before="$(probe)"
log "百度 $PROBE_HOST:$PROBE_PORT = $before   （期望：通）"
[ "$before" = "通" ] || { log "❌ 基线不通，对照失去意义。中止。"; exit 1; }

step "2/5 起探针：装一条只拦百度 443 的规则，然后**挂住不动**"
"$TARGET_DIR/debug/examples/crash_probe.exe" >"$PROBE_LOG" 2>&1 &
PROBE_PID=$!
log "探针已启动，shell pid=$PROBE_PID"

# 等它自己报 pid（它装完规则才会打印 BLOCKED 行）
PID=""
for _ in $(seq 1 40); do
  if grep -q '^BLOCKED pid=' "$PROBE_LOG" 2>/dev/null; then
    PID="$(grep '^BLOCKED pid=' "$PROBE_LOG" | tail -1 | sed 's/.*pid=//')"
    break
  fi
  sleep 0.5
done
if [ -z "$PID" ]; then
  log "❌ 没等到 BLOCKED 标记。探针输出："
  sed 's/^/     /' "$PROBE_LOG" | tee -a "$LOG"
  log "  （多半是没提权：WFP 引擎要求管理员）"
  exit 1
fi
log "规则已装，探针 pid=$PID"

step "3/5 硬杀进程（taskkill /F = TerminateProcess，**不给它跑任何清理代码**）"
after="$(probe)"
log "杀之前 外网 = $after   （期望：断 —— 规则确实生效了，后面的'消失'才有意义）"

# ── 阳性对照：装着的这一刻，BFE 里**必须能查到**它 ────────────────────
# ⚠ 不做阳性对照，后面那个"0 条"是空的：
#   `netsh wfp show filters` **不往 stdout 输出**，它在**当前目录**写
#   filters.xml（本机实测 2.9 MB）。第一版脚本 grep 的是空 stdout，
#   于是恒为 0 —— 看起来通过了，其实什么都没测。
#   所以这里先测一次"应该在"，再测一次"应该不在"。
FILTER_NAME="崩溃探针"
dump_filters() {   # $1 = 存到哪里
  rm -f filters.xml
  timeout 120 netsh wfp show filters >/dev/null 2>&1
  if [ -f filters.xml ]; then
    mv filters.xml "$1"
    # ⚠ 只能是 `|| true`，不能是 `|| echo 0`：`grep -c` 在计数为 0 时
    # **既打印 0 又返回 1**，再 echo 一次就变成 "0\n0"，把后续判定全搞乱。
    grep -c "$FILTER_NAME" "$1" 2>/dev/null || true
  else
    echo "-1"   # -1 = netsh 没产出文件，如实记为"没测到"，不能当成 0
  fi
}

BEFORE_N="$(dump_filters "$LOG_DIR/crash-filters-before.xml")"
log "BFE 里叫「$FILTER_NAME」的过滤器 = $BEFORE_N   （期望：≥1，**阳性对照**）"

MSYS_NO_PATHCONV=1 taskkill /F /PID "$PID" >/dev/null 2>&1 \
  || kill -9 "$PID" 2>/dev/null
log "已 taskkill /F $PID"
sleep 3
kill -0 "$PID" 2>/dev/null && log "  ⚠ 进程还在" || log "  进程确认已死"
PROBE_PID=""

step "4/5 进程没了之后，规则还在吗"
after_kill="$(probe)"
log "杀之后 外网 = $after_kill   （期望：通 —— 内核把动态会话里的规则清了）"

step "5/5 有没有留下跨重启的持久对象"
AFTER_N="$(dump_filters "$LOG_DIR/crash-filters-after.xml")"
log "BFE 里叫「$FILTER_NAME」的过滤器 = $AFTER_N   （期望：0）"
if [ "$AFTER_N" = "-1" ]; then
  log "⚠ netsh 没产出文件，这项**没测到**，不能记为通过"
fi

step "结论"
check "装之前通"                    "$before"     "通"
check "装之后断（规则生效）"        "$after"      "断"
check "阳性对照：BFE 里查得到它"    "$([ "$BEFORE_N" != "-1" ] && [ "$BEFORE_N" -ge 1 ] && echo ok || echo 缺)" "ok"
check "强杀之后通（内核清了）"      "$after_kill" "通"
check "BFE 里查不到了（无残留）"    "$AFTER_N"    "0"

echo
if [ "$rc" -eq 0 ]; then
  log "✅ 进程被硬杀、清理代码一行没跑，规则照样随进程消失。"
  log "   兜底在**内核侧**，不在我们的代码里 —— 这正是断电 / 蓝屏要的保证："
  log "   崩溃路径上没有机会执行清理代码，所以清理必须不由我们来执行。"
else
  log "❌ 有一项没过。当前最坏影响只是百度 443 打不开："
  log "   1) 结束名字里带 crash_probe 的进程"
  log "   2) 重启（本版不装 Boot 层规则，重启一定干净）"
fi
echo
log "完整日志：$REPO/$LOG"
log "探针输出：$REPO/$PROBE_LOG"
exit "$rc"
