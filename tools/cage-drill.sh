#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Aegis 绝缘笼全流程演练 —— **自动恢复**，不需要人在场配合
#
#   bash tools/cage-drill.sh
#
# 它装一次整副绝缘笼，自动观察，然后**什么都不做**，让 10 秒倒计时
# 自己把规则撤销，最后复核网络回来了。断网时长约 12 秒。
#
# ---------------------------------------------------------------------------
# 为什么必须做成脚本（而不是人在终端里敲）
#
# 装上去的那一刻网络就没了。人在这时候能做的事非常有限，而且容易慌；
# 更糟的是"我（AI）也没法在对面断网的时候跟你配合"。所以整套动作必须
# 事先写死在脚本里，靠**时间**而不是靠**人**来恢复。
#
# ---------------------------------------------------------------------------
# 四层恢复兜底（任何一层生效，网络就回来）
#
#   第 0 层  10 秒倒计时      aegisd 自己撤（本次演练就靠这一层）
#   第 1 层  脚本 trap        脚本无论怎么退出都会 kill aegisd
#   第 2 层  aegisd 时限      --serve-secs 45，到点自己退出（**不依赖任何东西**）
#   第 3 层  一键脚本         tools/aegis-restore.sh
#   第 4 层  手动             结束 aegisd 进程 / 重启（见 EMERGENCY-TEARDOWN.md）
#
# 第 2 层是真正的安全网：即使脚本被杀、终端被关、机器卡住，
# 45 秒后 aegisd 一定退出，而动态会话随之清空。**最坏情况有硬上界。**
# ---------------------------------------------------------------------------

set -u
cd "$(dirname "$0")/.." || exit 1
REPO="$(pwd)"

# ── 配置 ────────────────────────────────────────────────────────────────
SERVE_SECS=45          # aegisd 硬时限：到点一定退出（第 2 层兜底）
CONFIRM_WINDOW=10      # 与 CONFIRM_WINDOW_MS 一致
PROBE_HOST="183.2.172.177"   # www.baidu.com 的一个 IP
PROBE_PORT=443
TIMEOUT=3

LOG_DIR=".aegis-run"
mkdir -p "$LOG_DIR"
LOG="$LOG_DIR/drill-$(date +%Y%m%d-%H%M%S).log"
DAEMON_LOG="$LOG_DIR/drill-daemon.log"

export RUSTUP_HOME="${RUSTUP_HOME:-D:\\Dev\\Rust\\.rustup}"
export CARGO_HOME="${CARGO_HOME:-D:\\Dev\\Rust\\.cargo}"
export PATH="/d/Dev/Rust/.cargo/bin:/d/Dev/msys64/mingw64/bin:$PATH"
unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy 2>/dev/null

DAEMON_PID=""

# ── 日志（每一步都记，事后能复盘）──────────────────────────────────────
log()  { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*" | tee -a "$LOG"; }
step() { printf '\n=== %s ===\n' "$*" | tee -a "$LOG"; }

# ── 恢复（第 1 层：无论怎么退出都执行）───────────────────────────────────
restore() {
  log "恢复动作：结束 aegisd（动态会话随之清空，规则全部消失）"
  if [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
    kill "$DAEMON_PID" 2>/dev/null && log "  已 kill $DAEMON_PID"
    sleep 1
    kill -0 "$DAEMON_PID" 2>/dev/null && kill -9 "$DAEMON_PID" 2>/dev/null
  fi
  pkill -f 'aegisd.exe' 2>/dev/null && log "  已清掉残留的 aegisd 进程"
}
trap restore EXIT INT TERM

# ── 连通性探测：TCP 握手，不用 ping ─────────────────────────────────────
# WFP 的 ALE 层不管 ICMP，ping 在装了阻断规则之后照样通，会给出假的"没生效"。
probe() {
  python -c "
import socket,sys
try:
    socket.create_connection(('$PROBE_HOST', $PROBE_PORT), $TIMEOUT).close()
    print('通')
except OSError as e:
    print('断')
" 2>/dev/null
}

step "0/6 准备"
log "仓库      : $REPO"
log "日志文件  : $(pwd)/$LOG"
{ echo "--- aegisd 输出 ---"; } >> "$DAEMON_LOG"

log "编译 aegisd / aegisctl"
cargo build -p aegisd -p aegisctl >>"$LOG" 2>&1 || { log "❌ 编译失败，看 $LOG"; exit 1; }

TARGET_DIR="$(python -c "
import json,subprocess
print(json.loads(subprocess.check_output(['cargo','metadata','--format-version','1','--no-deps']))['target_directory'])
" 2>/dev/null)"
log "target 目录: $TARGET_DIR"

# 上一轮留下的审计日志会让 aegisd 以 exit 5 退出（create_new 不覆盖）
rm -rf .aegis-run/ipc.token .aegis-run/audit-*.binlog 2>/dev/null

step "1/6 启动 aegisd（硬时限 ${SERVE_SECS}s）"
"$TARGET_DIR/debug/aegisd.exe" \
  --config config/config.example.toml \
  --data-dir .aegis-run \
  --serve-secs "$SERVE_SECS" >>"$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!
log "aegisd 已启动，pid=$DAEMON_PID"

for _ in $(seq 1 20); do
  [ -f .aegis-run/ipc.token ] && break
  sleep 0.5
done
[ -f .aegis-run/ipc.token ] || { log "❌ 没等到 token 文件"; exit 1; }
log "token 已就绪"

CTL=("$TARGET_DIR/debug/aegisctl.exe" --token-file .aegis-run/ipc.token)

step "2/6 基线（装之前）"
before="$(probe)"
log "外网 $PROBE_HOST:$PROBE_PORT = $before   （期望：通）"
"${CTL[@]}" status >>"$LOG" 2>&1 && log "IPC status 通" || log "⚠ IPC status 失败"

step "3/6 下发整副绝缘笼（**不 confirm**）"
APPLY_OUT="$("${CTL[@]}" apply 2>&1)"
echo "$APPLY_OUT" >>"$LOG"
echo "$APPLY_OUT"
log "⏳ 倒计时 ${CONFIRM_WINDOW}s 开始 —— 我不 confirm，让它自动撤销"

step "4/6 装之后的观察"
after="$(probe)"
log "外网 $PROBE_HOST:$PROBE_PORT = $after   （期望：断）"
# 关键一条：**网断了 IPC 还得活着**，否则"没网怎么拆笼子"就是空话
if "${CTL[@]}" status >>"$LOG" 2>&1; then
  log "IPC status 通 —— **网断了本地 IPC 仍然活着**（这就是能强拆的根据）"
  IPC_ALIVE=1
else
  log "⚠ IPC 也断了"
  IPC_ALIVE=0
fi

step "5/6 等倒计时自动撤销（${CONFIRM_WINDOW}s + 余量）"
sleep $((CONFIRM_WINDOW + 3))
after2="$(probe)"
log "外网 $PROBE_HOST:$PROBE_PORT = $after2   （期望：通）"

step "6/6 复核与收尾"
restore
sleep 1
final="$(probe)"
log "收尾后外网 = $final   （期望：通）"

# ── 判定 ────────────────────────────────────────────────────────────────
step "结论"
rc=0
check() { if [ "$2" = "$3" ]; then log "  ✅ $1（$2）"; else log "  ❌ $1（得到 $2，期望 $3）"; rc=1; fi; }
check "装之前外网通"      "$before" "通"
check "装之后外网断"      "$after"  "断"
check "断网期间 IPC 仍活" "$IPC_ALIVE" "1"
check "倒计时后自动恢复"  "$after2" "通"
check "收尾后外网通"      "$final"  "通"

echo
if [ "$rc" -eq 0 ]; then
  log "✅ 演练通过：绝缘笼真的拦住了外网，10 秒倒计时自动撤销，网络恢复。"
else
  log "❌ 演练没全过。网络**现在应该是通的**（第 1/2 层兜底已执行）。"
  log "   如果还是不通，按下面的顺序来："
  log "   1) bash $(pwd)/tools/aegis-restore.sh"
  log "   2) 任务管理器结束 aegisd.exe（动态会话随之清空）"
  log "   3) 重启（本版不装 Boot 层规则，重启一定是干净的）"
fi
echo
log "完整日志：$REPO/$LOG"
log "守护进程输出：$REPO/$DAEMON_LOG"
exit "$rc"
