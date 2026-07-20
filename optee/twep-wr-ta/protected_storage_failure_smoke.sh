#!/bin/sh
# Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
set -eu

PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
STATE_DIR="/tmp/twep-trustzone-diagnose-state"
TMP_DIR="/tmp/twep-trustzone-failure-smoke"
APP=optee_example_twep_wr_ta

expect_fail() {
	label=$1
	shift
	out="${TMP_DIR}/${label}.out"
	err="${TMP_DIR}/${label}.err"

	set +e
	"$@" >"${out}" 2>"${err}"
	status=$?
	set -e
	if [ "${status}" -eq 0 ]; then
		echo "${label} unexpectedly succeeded"
		cat "${out}"
		exit 1
	fi
	echo "${label} failed as expected with status ${status}"
	cat "${err}"
}

rm -rf "${TMP_DIR}"
mkdir -p "${TMP_DIR}"

expect_fail missing-read "${APP}" read "missing-object-for-failure-smoke"
grep -q "SECURE_STORAGE_GET failed" "${TMP_DIR}/missing-read.err"

: >"${TMP_DIR}/empty.bin"
expect_fail empty-provision "${APP}" provision "empty-object-for-failure-smoke" "${TMP_DIR}/empty.bin"
grep -q "refusing to provision empty object" "${TMP_DIR}/empty-provision.err"

printf 'short-buffer-value' >"${TMP_DIR}/short-buffer.bin"
"${APP}" provision "short-buffer-object-for-failure-smoke" "${TMP_DIR}/short-buffer.bin"
expect_fail short-buffer-read "${APP}" read-small "short-buffer-object-for-failure-smoke"
grep -q "SECURE_STORAGE_GET failed" "${TMP_DIR}/short-buffer-read.err"

"${PROJECT_DIR}/diagnose_verified_trustzone.sh"
grep -q "protected-credential-store-load=absent" "${STATE_DIR}/diagnose.txt"
grep -q "platform-issuer-allowlist-load=absent" "${STATE_DIR}/diagnose.txt"
grep -q "platform-store-freshness-load=absent" "${STATE_DIR}/diagnose.txt"
grep -q "platform-revocation-state-load=absent" "${STATE_DIR}/diagnose.txt"
grep -q "trust-anchor-bound=false" "${STATE_DIR}/diagnose.txt"
grep -q "final-verified=false" "${STATE_DIR}/diagnose.txt"
grep -q "protected-credential-store-load=absent" "${STATE_DIR}/diagnose.json"
grep -q "final-verified=false" "${STATE_DIR}/diagnose.json"

echo "TrustZone protected storage failure smoke ok"
