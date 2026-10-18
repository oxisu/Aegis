#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Aegis 一键恢复 —— 网络被笼子困住时，跑这一个就够了
#
#   bash tools/aegis-restore.sh
#
# 它按"从优雅到粗暴"的顺序做四件事，每做完一件就立刻验证一次网络：
#
#   1. aegisctl rollback   走本地 IPC 强拆（**不需要网络**）
#   2. 结束 aegisd 进程    动态会话随之清空
#   3. 报告状态            还是不通就给出手动步骤
#
# 全程记日志，事后能复盘。
# ---------------------------------------------------------------------------

set -u
cd "$(dirname "$0")/.." || exit 1
REPO="$(pwd)"

PROBE_HOST="${AEGIS_PROBE_HOST:-183.2.172.177}"
PROBE_PORT="${AEGIS_PROBE_PORT:-443}"
TIMEOUT=3

LOG_DIR=".aegis-run"
mkdir -p "$LOG_DIR"
LOG="$LOG_DIR/restore-$(date +%Y%m%d-%H%M%S).log"

export RUSTUP_HOME="${RUSTUP_HOME:-D:\\Dev\\Rust\\.rustup}"
export CARGO_HOME="${CARGO_HOME:-D:\\Dev\\Rust\\.cargo}"
export PATH="/d/Dev/Rust/.cargo/bin:/d/Dev/msys64/mingw64/bin:$PATH"
unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy 2>/dev/null

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*" | tee -a "$LOG"; }

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

log "Aegis 一键恢复"
log "仓库    : $REPO"
log "日志    : $REPO/$LOG"
log "探测目标: $PROBE_HOST:$PROBE_PORT （TCP 握手，不用 ping——ALE 层不管 ICMP）"
echo

if [ "$(probe)" = "通" ]; then
  log "当前外网已经是通的。仍然继续走一遍，确保没有残留规则。"
fi

# ── 第 1 步：走本地 IPC 强拆（优先，因为它最精确且不需要网络）──────────
echo "--- 第 1 步：aegisctl rollback（本机 IPC，不经过网卡）---" | tee -a "$LOG"
if [ -f .aegis-run/ipc.token ]; then
  TARGET_DIR="$(python -c "
import json,subprocess
print(json.loads(subprocess.check_output(['cargo','metadata','--format-version','1','--no-deps']))['target_directory'])
" 2>/dev/null)"
  OUT="$("$TARGET_DIR/debug/aegisctl.exe" --token-file .aegis-run/ipc.token rollback 2>&1)"
  echo "$OUT" | tee -a "$LOG"
  sleep 1
  log "现在外网 = $(probe)"
else
  log "没有 .aegis-run/ipc.token —— aegisd 多半已经不在了，跳到第 2 步。"
fi

# ── 第 2 步：结束 aegisd（动态会话随之清空，这条**一定**有效）──────────
echo "--- 第 2 步：结束 aegisd（动态会话随之清空）---" | tee -a "$LOG"
pkill -f 'aegisd.exe' 2>/dev/null && log "已发出结束信号" || log "没有在跑的 aegisd"
sleep 2
log "现在外网 = $(probe)"

# ── 第 3 步：判定 ───────────────────────────────────────────────────────
echo
if [ "$(probe)" = "通" ]; then
  log "✅ 网络已恢复。"
  exit 0
fi

log "❌ 脚本没能恢复网络。按下面的顺序手动来（逐条往下，通了就停）："
log ""
log "  1) 任务管理器 → 详细信息 → 找到 aegisd.exe → 结束任务"
log "     它的所有规则都在**动态会话**里，进程一死内核就清空，这条一定有效。"
log ""
log "  2) 还是不通："
log "       netsh wfp show filters > C:\\wfp-filters.txt"
log "       在输出里搜 aegis- ，确认有没有残留"
log ""
log "  3) 重启。本版**不装** Boot 层（引导时间）规则——"
log "     preflight 见到 Tier::Boot 就直接拒绝下发——所以重启一定是干净的。"
log ""
log "  详细手册：docs/EMERGENCY-TEARDOWN.md"
log "  本次日志：$REPO/$LOG"
exit 1
