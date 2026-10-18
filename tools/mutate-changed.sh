#!/usr/bin/env bash
# 只对"我刚改的文件"跑变异测试 —— 日常开发用这个，别跑全量。
#
# 用法：
#   tools/mutate-changed.sh              # 对比 HEAD（未提交的改动）
#   tools/mutate-changed.sh HEAD~3       # 对比任意基线
#   tools/mutate-changed.sh origin/master
#
# 为什么不全量跑：变异测试的成本 = 变异体数 ×（一次编译 + 一次跑测试）。
# 全工作区 572 个变异体，单机要一个多小时；只跑刚改的几个文件通常几分钟。
#
# ⚠ 两个踩过的坑，改这个脚本时别退回去：
#   1. 不能用 `--file`。配置里的 `examine_globs` 会把它覆盖掉，
#      传了跟没传一样（实测 193 → 193，毫无效果）。要用 `-F` 正则。
#   2. 必须带 `--profile mutants`（关掉调试信息，单次编译 7s → 3s）。
#      它写在配置文件里会被静默忽略，只能走命令行。
#   3. 不要加 `-j`。cargo 对 target 目录是独占锁，实测 -j 4 比 -j 1 还慢。

set -euo pipefail

BASE="${1:-HEAD}"

cd "$(dirname "$0")/.."

# 只关心被测源码；示例、集成测试、构建脚本本来就被 examine_globs 排除了
mapfile -t FILES < <(git diff --name-only "$BASE" -- 'crates/*/src/*.rs')

if [ "${#FILES[@]}" -eq 0 ]; then
  echo "相对于 $BASE 没有任何 crates/*/src/*.rs 的改动，无需跑变异测试。"
  exit 0
fi

# 拼成文件名的正则：plan.rs|state.rs|...
RE=""
for f in "${FILES[@]}"; do
  name="$(basename "$f")"
  # 文件名里的点要转义，否则会匹配到别的东西
  esc="$(printf '%s' "$name" | sed 's/\./\\./g')"
  if [ -z "$RE" ]; then RE="$esc"; else RE="$RE|$esc"; fi
done

echo "改动的文件："
printf '  %s\n' "${FILES[@]}"
echo
echo "变异范围正则：-F '$RE'"
echo

export RUSTUP_HOME="${RUSTUP_HOME:-D:\\Dev\\Rust\\.rustup}"
export CARGO_HOME="${CARGO_HOME:-D:\\Dev\\Rust\\.cargo}"
export PATH="/d/Dev/msys64/mingw64/bin:/d/Dev/Rust/.cargo/bin:$PATH"
export CARGO_NET_OFFLINE=true

cargo mutants -v --profile mutants --no-shuffle -t 120 \
  --output mutants.out \
  -F "$RE"
