#!/usr/bin/env bash
# Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
set -Eeuo pipefail

if [[ $# -ne 2 ]]; then
	echo "usage: $0 MODE ATTESTAM_URL" >&2
	exit 2
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RISCV_OPTEE_ROOT="${RISCV_OPTEE_ROOT:-$(cd "$REPO_ROOT/../riscv-optee" && pwd)}"
OUT_DIR="${RISCV_OPTEE_OUT:-$REPO_ROOT/build/riscv-optee-v9}"
MODE="$1"
ATTESTAM_URL="$2"
SESSION="riscv-optee-qemu"
LOG="$OUT_DIR/qemu-${MODE}.log"

command -v expect >/dev/null 2>&1 || { echo "expect is required" >&2; exit 2; }
[[ -n "$ATTESTAM_URL" ]] || { echo "ATTESTAM_URL is required" >&2; exit 2; }
[[ -x "$RISCV_OPTEE_ROOT/scripts/start-qemu.sh" ]] || { echo "v9 QEMU launcher is missing" >&2; exit 2; }
if tmux has-session -t "$SESSION" 2>/dev/null; then
	echo "managed QEMU session is already active: $SESSION" >&2
	exit 2
fi

stop_qemu() {
	tmux kill-session -t "$SESSION" 2>/dev/null || true
}
trap stop_qemu EXIT

"$RISCV_OPTEE_ROOT/scripts/start-qemu.sh"
timeout --signal=TERM --kill-after=15s 1200s \
	expect "$REPO_ROOT/scripts/run_optee_riscv_v9_phase.exp" \
	"$LOG" "$MODE" "$ATTESTAM_URL"
echo "TWEP_RISCV_OPTEE_V9_${MODE^^}_PASS" | tr '-' '_' | tee -a "$LOG"
echo "TWEP RISC-V OP-TEE v9 live phase log: $LOG"
