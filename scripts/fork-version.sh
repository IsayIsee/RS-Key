#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

# The fork's accounting for the one `check.sh` row this fork keeps red on
# purpose: `bcd bump + CHANGELOG`. The row and its gate stay upstream's,
# untouched; this is the fork-side bookkeeping (rule, white list and tag
# convention: FORK-VERSIONING.md, a working-machine document).
#
#   rc 0  the value sits on upstream's line, and every problem the gate printed
#         is a known one
#   rc 1  a value off its anchor, a new red, or something that could not run
#
# Unknown is not green, so both a row that prints nothing (the Windows Store
# `python` exits 49 in silence) and a checkout with no upstream ref to compare
# against are rc 1. Point FORK_PYTHON at a real 3.11+ interpreter.
set -euo pipefail
cd "$(dirname "$0")/.."

MAIN=firmware/src/main.rs
PY="${FORK_PYTHON:-python}"

# On Windows a gate must go through the shim, or it reports a false red rather
# than crashing: `str(pathlib.Path)` is backslash-separated there while every
# gate reads forward slashes ("no commit in this history ever changed the
# counter"). FORK_SHIM overrides; point it at /dev/null to force a direct call.
SHIM="${FORK_SHIM:-$HOME/rs-key-gate-shims/run_gate.py}"
if [ -f "$SHIM" ]; then
  gate=("$PY" "$SHIM" "$PWD" scripts/bcd_gate.py)
  gate_where="经 shim $SHIM"
else
  gate=("$PY" scripts/bcd_gate.py)
  gate_where="直调 $PY(Windows 上会是假红)"
fi

#: The two problem shapes this fork accepts, as `bcd_gate.py` spells them. The
#: decrease line is expected because the value may come *down* onto a lower
#: upstream anchor — what catches a bad one is the anchor check below, not this
#: list: a drop that does not land on the anchor is a NEW red there.
GOES_UP='the counter is 0x[0-9A-Fa-f]+ and was 0x[0-9A-Fa-f]+: it only goes up'
REACHED='changed since [0-9a-f]+ bumped the counter: '

#: The binding at a rev, comments excluded — a `//` line quoting it must not
#: read as the value, the same reason `bcd_gate.py` strips comments first.
value_at() {
  git show "$1:$MAIN" 2>/dev/null |
    sed -n 's/^[[:space:]]*let device_release: u16 = \(0x[0-9A-Fa-f]\{1,\}\).*/\1/p' |
    head -1 | tr 'A-F' 'a-f'
}

#: The same, in the working tree.
value_here() {
  sed -n 's/^[[:space:]]*let device_release: u16 = \(0x[0-9A-Fa-f]\{1,\}\).*/\1/p' "$MAIN" |
    head -1 | tr 'A-F' 'a-f'
}

merging=""
if [ -f "$(git rev-parse --git-path MERGE_HEAD)" ]; then
  merging=$(cat "$(git rev-parse --git-path MERGE_HEAD)")
fi

# First ref that exists, in the fork's own order of preference. Nothing is
# fetched here: a check that changes the repo is not a check, so a stale ref is
# named as stale rather than quietly trusted.
up_ref=""
for ref in upstream/develop upstream/main origin/develop origin/main; do
  if git rev-parse --verify --quiet "$ref^{commit}" >/dev/null 2>&1; then
    up_ref=$ref
    break
  fi
done
if [ -z "$up_ref" ]; then
  echo "FAIL: 本地没有任何上游 ref — 先 git fetch upstream,锚定无法判定" >&2
  exit 1
fi
up_value=$(value_at "$up_ref")

# The anchor is upstream's value at the point HEAD has merged upstream: the
# newest commit the two share. A merge in progress whose other side IS upstream
# (or a descendant of it) takes that side — the merge is what moves the value.
if [ -n "$merging" ] && git merge-base --is-ancestor "$merging" "$up_ref" 2>/dev/null; then
  anchor_where="MERGE_HEAD ${merging:0:8}(上游侧)"
  anchor=$(value_at "$merging")
else
  shared=$(git merge-base HEAD "$up_ref" 2>/dev/null || true)
  anchor_where="与 $up_ref 的共有提交 ${shared:0:8}"
  anchor=$(value_at "${shared:-HEAD}")
fi
if [ -z "$anchor" ]; then
  echo "FAIL: 锚点($anchor_where)读不到 bcdDevice 绑定" >&2
  exit 1
fi

tree=$(value_here)
if [ -z "$tree" ]; then
  echo "FAIL: $MAIN binds no \`let device_release: u16 = 0x…\`" >&2
  exit 1
fi

echo "fork-version: 值 $tree,锚值 $anchor($anchor_where)"
echo "  build: $(git describe --tags --always --dirty 2>/dev/null || echo '?')"
echo "  上游 ref(本地,未 fetch,可能过期):$up_ref=$up_value"
echo "  gate: $gate_where"
last_merge=$(git log --format=%H --merges -1)
if [ -n "$last_merge" ]; then
  since=$(git rev-list --count "$last_merge..HEAD" 2>/dev/null || echo '?')
  echo "  tag 说明写: bcd $tree(锚定 $anchor_where);自 ${last_merge:0:8} 起 $since 个 fork 提交"
fi

new=0
if [ "$tree" != "$anchor" ]; then
  echo "NEW: 值 $tree 离开锚值 $anchor($anchor_where)——fork 不自增、也不自降 bcd" >&2
  new=$((new + 1))
fi

out=$(mktemp "${TMPDIR:-/tmp}/fork-version.XXXXXX")
trap 'rm -f "$out"' EXIT
gate_rc=0
PYTHONUTF8=1 "${gate[@]}" >"$out" 2>&1 || gate_rc=$?
if [ ! -s "$out" ]; then
  echo "FAIL: scripts/bcd_gate.py 没有任何输出(rc=$gate_rc)——解释器不可用?设 FORK_PYTHON" >&2
  exit 1
fi

# A problem is printed two spaces in, under a `bcd-gate:` header; the advice
# block that follows it starts at column 0, so the indent is what tells them
# apart.
known=0
while IFS= read -r line; do
  case $line in
  '  '*) ;;
  *) continue ;;
  esac
  body=${line:2}
  if [[ $body =~ $REACHED || $body =~ $GOES_UP ]]; then
    known=$((known + 1))
    continue
  fi
  echo "NEW: 不在白名单: $body" >&2
  new=$((new + 1))
done <<<"$(grep -E '^  [^ ]' "$out" || true)"

if [ "$new" -gt 0 ]; then
  echo "fork-version: rc 1 —— $new 条新红,预期红 $known 条" >&2
  exit 1
fi
echo "fork-version: ok —— 锚定成立,预期红 $known 条(白名单与规则: FORK-VERSIONING.md)"
