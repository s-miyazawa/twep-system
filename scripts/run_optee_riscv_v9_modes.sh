#!/usr/bin/env bash
# Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
set -Eeuo pipefail

if [[ $# -lt 2 ]]; then
	echo "usage: $0 LABEL MODE [MODE ...]" >&2
	exit 2
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RISCV_OPTEE_ROOT="${RISCV_OPTEE_ROOT:-$(cd "$REPO_ROOT/../riscv-optee" && pwd)}"
OUT_DIR="${RISCV_OPTEE_OUT:-$REPO_ROOT/build/riscv-optee-v9}"
LABEL="$1"
shift
RUN_DAEMON="${TWEP_RISCV_MODES_RUN_DAEMON:-1}"
SESSION="riscv-optee-qemu"
LOG="$OUT_DIR/qemu-${LABEL}.log"

[[ "$LABEL" =~ ^[a-z0-9-]+$ ]] || { echo "invalid RISC-V suite label: $LABEL" >&2; exit 2; }
[[ "$RUN_DAEMON" == "0" || "$RUN_DAEMON" == "1" ]] || { echo "TWEP_RISCV_MODES_RUN_DAEMON must be 0 or 1" >&2; exit 2; }
for mode in "$@"; do
	[[ "$mode" =~ ^[a-z0-9-]+$ ]] || { echo "invalid RISC-V smoke mode: $mode" >&2; exit 2; }
done
command -v expect >/dev/null 2>&1 || { echo "expect is required" >&2; exit 2; }
[[ -x "$RISCV_OPTEE_ROOT/scripts/start-qemu.sh" ]] || { echo "v9 QEMU launcher is missing" >&2; exit 2; }
if tmux has-session -t "$SESSION" 2>/dev/null; then
	echo "managed QEMU session is already active: $SESSION" >&2
	exit 2
fi

stop_qemu() {
	tmux kill-session -t "$SESSION" 2>/dev/null || true
}
trap stop_qemu EXIT

mkdir -p -- "$OUT_DIR"
: >"$LOG"
"$RISCV_OPTEE_ROOT/scripts/start-qemu.sh"
timeout --signal=TERM --kill-after=15s 7200s \
	expect "$REPO_ROOT/scripts/run_optee_riscv_v9_modes.exp" "$LOG" "$RUN_DAEMON" "$@"
marker="$(printf '%s' "$LABEL" | tr '[:lower:]-' '[:upper:]_')"
echo "TWEP_RISCV_OPTEE_V9_${marker}_PASS" | tee -a "$LOG"
echo "TWEP RISC-V OP-TEE v9 $LABEL log: $LOG"
