#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# 持久化规则验证实验（docs/PERSISTENT-CAGE.md §8 第 1 / 4 / 7 项）
#
#   bash tools/persist-drill.sh
#
# 回答三件事：
#   1. 本机到底让不让装持久化规则？
#   2. 进程退出之后它是不是**真的还在**？（"死了也不放开"的全部意义）
#   3. 能不能可靠地**再删掉**？（删不掉 = 变砖）
#
# ---------------------------------------------------------------------------
# ⚠ 为什么这个脚本必须存在，而且必须在任何退出路径上强制 purge
#
# 装上去的那一刻起，那条规则就**不归任何进程管了**：进程退出它还在，
# 脚本被杀它还在，终端关掉它也还在。动态会话那套"进程一死全清"的兜底
# 在这里**完全失效**——这正是我们想要的，也正是它危险的地方。
#
# 所以：
#   · 每一步都写日志，出事能复盘；
#   · `trap` 里无条件再跑一次 purge（脚本怎么退的都跑）；
#   · 结尾独立复核一次连通性，**不通就大声报出恢复办法**。
#
# 只拦 www.baidu.com:443 —— 最坏情况只是百度暂时打不开。
# ---------------------------------------------------------------------------

set -u
cd "$(dirname "$0")/.." || exit 1
REPO="$(pwd)"

PROBE_HOST="183.2.172.177"
PROBE_PORT=443
TIMEOUT=3
LOG_DIR=".aegis-run"
mkdir -p "$LOG_DIR"
LOG="$LOG_DIR/persist-$(date +%Y%m%d-%H%M%S).log"

export RUSTUP_HOME="${RUSTUP_HOME:-D:\\Dev\\Rust\\.rustup}"
export CARGO_HOME="${CARGO_HOME:-D:\\Dev\\Rust\\.cargo}"
export PATH="/d/Dev/Rust/.cargo/bin:/d/Dev/msys64/mingw64/bin:$PATH"
unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy 2>/dev/null

rc=0
log()  { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*" | tee -a "$LOG"; }
step() { printf '\n=== %s ===\n' "$*" | tee -a "$LOG"; }
check() {
  if [ "$2" = "$3" ]; then log "  ✅ $1（$2）";
  else log "  ❌ $1（得到 $2，期望 $3）"; rc=1; fi
}

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

# ── 唯一的兜底：再删一遍，然后复核 ────────────────────────────────────
# 持久对象不受进程生死影响，所以"脚本退出了"不代表清干净了。
# 只有真的再删一遍 + 再枚举一遍才知道。
force_clean() {
  log "兜底：再跑一次 purge（持久对象不受脚本退出影响，必须显式删）"
  "$BIN" purge >>"$LOG" 2>&1 || true
}
trap force_clean EXIT INT TERM

step "0/5 准备"
log "日志文件  : $(pwd)/$LOG"
cargo build -p aegis-wfp --example persist_probe >>"$LOG" 2>&1 \
  || { log "❌ 编译失败，看 $LOG"; exit 1; }
TARGET_DIR="$(python -c "
import json,subprocess
print(json.loads(subprocess.check_output(['cargo','metadata','--format-version','1','--no-deps']))['target_directory'])
" 2>/dev/null)"
BIN="$TARGET_DIR/debug/examples/persist_probe.exe"
log "探针      : $BIN"

step "1/5 基线"
# ⚠ 顺序不能反：**先清再测基线**。上一轮（哪怕是被中断的那一轮）可能留下了
# 持久规则，而持久规则不受任何进程生死影响——不先清，基线直接就是"断"，
# 后面每一步的对照全部失效。
subkeys() { reg query "$1" 2>/dev/null | grep -c '^HKEY' || true; }
# ⚠ 持久**过滤器**不是子键，而是 `Persistent\Filter` 下的 REG_BINARY **值**，
#   名字就是过滤器 GUID（本机实测：能看到 Windows 防火墙自己的那一堆）。
#   所以数的是"缩进的 { 开头"的行，不是 HKEY 开头的行——数错了会得到恒 1。
values() { reg query "$1" 2>/dev/null | grep -cE '^ +\{' || true; }
REGKEY='HKLM\SYSTEM\CurrentControlSet\Services\BFE\Parameters\Policy\Persistent'
"$BIN" purge >>"$LOG" 2>&1 || true
sleep 1

before="$(probe)"
log "百度 = $before   （期望：通）"
if [ "$before" != "通" ]; then
  log "❌ 基线不通（上一轮的持久规则没清掉）。再清一次后再判一次。"
  "$BIN" purge >>"$LOG" 2>&1 || true
  sleep 1
  before="$(probe)"
  log "   再清一次后 = $before"
  [ "$before" = "通" ] || { log "❌ 仍不通，对照失去意义。中止。"; exit 1; }
fi

# 数一下 BFE 持久存储里已经有几条 filter（子键数）。后面 arm 完再数一次，
# 两个数对比才能证明"真的写进持久存储了"——只看"键存在"证明不了什么。
REG0="$(values "$REGKEY\\Filter")"
log "持久存储里已有 filter 条目 = $REG0（基线，含 Windows 防火墙自己的）"

step "2/5 arm —— 装一条**持久化**阻断规则"
"$BIN" arm 2>&1 | tee -a "$LOG"

step "3/5 check —— **另一个进程**里看它还在不在"
# ⚠ 必须是另一个进程：同一个进程里装完再看，什么都证明不了
"$BIN" check 2>&1 | tee -a "$LOG"
after="$(probe)"
log "百度 = $after   （期望：断 —— 规则**跨进程**还在）"

step "4/5 持久存储到底落在哪（离线逃生舱的前提）"
if reg query "$REGKEY" >/dev/null 2>&1; then
  REG1="$(values "$REGKEY\\Filter")"
  PROV1="$(values "$REGKEY\\Provider")"
  log "✅ 持久存储键存在（本机实测）："
  log "     $REGKEY"
  log "   子键：$(reg query "$REGKEY" 2>/dev/null | grep '^HKEY' | sed 's|.*Persistent.||' | tr '\n' ' ')"
  log "   filter 条目：基线 $REG0 → 装后 $REG1   （期望：+1 —— 真的写进持久存储了）"
  log "   provider 条目 = $PROV1"
  REG_OK=1
  REG_DELTA=$((REG1 - REG0))
else
  log "⚠ 注册表键不存在或不可读：$REGKEY"
  log "   离线逃生舱（挂 SYSTEM hive 删这个键）**在本机未确认**，不能写进手册"
  REG_OK=0
  REG_DELTA=-1
fi

step "5/5 purge —— 先删 filter 再删 Provider，然后复核"
"$BIN" purge 2>&1 | tee -a "$LOG"
sleep 1
final="$(probe)"
log "百度 = $final   （期望：通 —— 删干净了）"
# ⚠ 不能写成 `check | grep -c`：**进程崩了也会得到 0**，看起来像"清干净了"。
# 必须先看退出码，退出码不对就如实报"崩了"，而不是当成 0 条。
CHK_OUT="$("$BIN" check 2>&1)"
CHK_RC=$?
if [ "$CHK_RC" -ne 0 ]; then
  LEFT="崩溃(rc=$CHK_RC)"
else
  LEFT="$(printf '%s\n' "$CHK_OUT" | grep -oE '过滤器 = [0-9]+ 条' | grep -oE '[0-9]+' | head -1)"
fi

step "结论"
check "装之前通"                  "$before" "通"
check "跨进程后仍断（真持久化）"  "$after"  "断"
check "删除后恢复"                "$final"  "通"
check "删完没有残留"              "$LEFT"   "0"
if [ "$REG_OK" = "1" ]; then
  check "持久存储确实被写入（子键 +1）" "$REG_DELTA" "1"
else
  log "  ⏭ 持久存储位置**未确认**，离线逃生舱暂不写进手册"
fi

echo
if [ "$rc" -eq 0 ]; then
  log "✅ 持久化路径跑通：装得上、跨进程还在、删得掉。"
  log "   「死了也不放开」在原语层面成立，可以进入 P1。"
else
  log "❌ 有一项没过。"
  log "   ⚠ 如果百度现在还是断的，说明有持久规则没删掉："
  log "      1) $BIN purge"
  log "      2) netsh wfp show filters → 找「持久化探针」按 id 删"
  log "      3) 重启（持久规则会在 BFE 启动时重新加载，删不掉才走这条）"
fi
echo
log "完整日志：$REPO/$LOG"
exit "$rc"
