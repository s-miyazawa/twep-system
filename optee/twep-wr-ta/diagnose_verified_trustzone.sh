#!/bin/sh
# Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
set -eu

PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
GUEST_DIR="${PROJECT_DIR}/guest"
STATE_DIR="/tmp/twep-trustzone-diagnose-state"
SOCKET="${STATE_DIR}/twepd.sock"
TWEP_WR_LIB="${GUEST_DIR}/build/libtwep_wr.so"

dump_logs() {
	status=$?
	if [ "${status}" -ne 0 ] && [ -d "${STATE_DIR}" ]; then
		echo "TrustZone verified diagnose smoke failed with status ${status}"
		for log in twepd.log twep-cli.out twep-cli.err diagnose.txt diagnose.json; do
			if [ -f "${STATE_DIR}/${log}" ]; then
				echo "== ${log} =="
				cat "${STATE_DIR}/${log}"
			fi
		done
	fi
}
trap dump_logs EXIT

test -x "${GUEST_DIR}/bin/twepd"
test -x "${GUEST_DIR}/bin/twep-cli"
test -f "${GUEST_DIR}/build/teep-agent.wasm"
test -f "${TWEP_WR_LIB}"

rm -rf "${STATE_DIR}"
mkdir -p "${STATE_DIR}/teep-agent"
cp "${GUEST_DIR}/build/teep-agent.wasm" "${STATE_DIR}/teep-agent/teep-agent.wasm"
printf '\241\160fixture_verified\365' >"${STATE_DIR}/teep-agent/verified-dry-run-state.cbor"
if [ "${TWEP_TRUSTZONE_VERIFIED_INPUT:-0}" = "1" ]; then
	cp "${GUEST_DIR}/fixtures/verified-input.cose" "${STATE_DIR}/teep-agent/verified-input.cose"
	cp "${GUEST_DIR}/fixtures/verified-expected-token.bin" "${STATE_DIR}/teep-agent/verified-expected-token.bin"
fi
sync

cd "${GUEST_DIR}"

for attempt in 1 2 3; do
	rm -f "${SOCKET}" \
		"${STATE_DIR}/twepd.log" \
		"${STATE_DIR}/twep-cli.out" \
		"${STATE_DIR}/twep-cli.err" \
		"${STATE_DIR}/diagnose.txt" \
		"${STATE_DIR}/diagnose.json" \
		"${STATE_DIR}/teep-agent/verified-state.txt" \
		"${STATE_DIR}/teep-agent/credential-status.txt" \
		"${STATE_DIR}/teep-agent/platform-status.txt" \
		"${STATE_DIR}/teep-agent/evidence-status.txt" \
		"${STATE_DIR}/teep-agent/agent-identity-status.txt" \
		"${STATE_DIR}/teep-agent/suit-auth-status.txt"

	LD_LIBRARY_PATH="${GUEST_DIR}/build${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}" \
		./bin/twepd \
		--socket "${SOCKET}" \
		--state-dir "${STATE_DIR}" \
		--resolver-mode=attestam-verified \
		--attestam-url=http://127.0.0.1:1/tam \
		--once >"${STATE_DIR}/twepd.log" 2>&1 &
	pid=$!

	for _ in $(seq 1 50); do
		if [ -S "${SOCKET}" ]; then
			break
		fi
		sleep 0.1
	done

	set +e
	./bin/twep-cli --socket "${SOCKET}" remotehello >"${STATE_DIR}/twep-cli.out" 2>"${STATE_DIR}/twep-cli.err"
	cli_status=$?
	wait "${pid}"
	daemon_status=$?
	set -e

	if [ "${daemon_status}" -ne 0 ]; then
		echo "twepd exited with status ${daemon_status}"
		exit "${daemon_status}"
	fi

	if [ "${cli_status}" -eq 0 ]; then
		echo "twep-cli unexpectedly succeeded in attestam-verified mode"
		cat "${STATE_DIR}/twep-cli.out"
		exit 1
	fi
	grep -q "teep.verified_required" "${STATE_DIR}/twep-cli.err"

	./bin/twep-cli diagnose verified --state-dir "${STATE_DIR}" >"${STATE_DIR}/diagnose.txt"
	./bin/twep-cli diagnose verified --state-dir "${STATE_DIR}" --output-format json >"${STATE_DIR}/diagnose.json"

	if grep -q "platform-backend=trustzone" "${STATE_DIR}/diagnose.txt"; then
		break
	fi
	if [ "${attempt}" -eq 3 ]; then
		echo "diagnose artifacts missing after ${attempt} attempts"
		exit 1
	fi
done

grep -q "sealed-storage-security=tee-ree-fs-secure-storage" "${STATE_DIR}/diagnose.txt"
grep -q "sealed-storage-rollback-protected=false" "${STATE_DIR}/diagnose.txt"
grep -q "runtime-location=trustzone-ta" "${STATE_DIR}/diagnose.txt"
grep -q "teep-agent-location=trustzone-ta" "${STATE_DIR}/diagnose.txt"
grep -q "catalog-resolution-location=trustzone-ta" "${STATE_DIR}/diagnose.txt"
# D038 keeps rollback protection as diagnostic (`false` on REE FS) while
# source-aligned policy/identity/evidence signals may be `bound`/`true`.
grep -q "agent-identity-source=platform-status-ta-local" "${STATE_DIR}/diagnose.txt"
grep -q "agent-identity-observed=true" "${STATE_DIR}/diagnose.txt"
grep -Eq "agent-identity-binding=(unbound|matched-unbound|bound)" "${STATE_DIR}/diagnose.txt"
grep -Eq "agent-identity-bound=(false|true)" "${STATE_DIR}/diagnose.txt"
grep -q "protected-storage-binding=tee-ree-fs-secure-storage" "${STATE_DIR}/diagnose.txt"
grep -Eq "evidence-result-load=(absent|loaded-unbound)" "${STATE_DIR}/diagnose.txt"
grep -Eq "evidence-verifier-result=(none|affirming)" "${STATE_DIR}/diagnose.txt"
grep -Eq "evidence-binding=(unbound|matched-unbound|bound)" "${STATE_DIR}/diagnose.txt"
grep -Eq "evidence-affirming=(false|true)" "${STATE_DIR}/diagnose.txt"
# This smoke starts from an unverified COSE/SUIT fixture state; final
# verification stays false because fixture trust inputs are missing.
grep -q "trust-anchor-bound=false" "${STATE_DIR}/diagnose.txt"
grep -q "final-verified=false" "${STATE_DIR}/diagnose.txt"
grep -q '"schema_version": 1' "${STATE_DIR}/diagnose.json"
grep -q '"target": "verified"' "${STATE_DIR}/diagnose.json"
grep -q '"summary": {' "${STATE_DIR}/diagnose.json"
grep -q '"fixture_verified": false' "${STATE_DIR}/diagnose.json"
grep -q '"final_verified": false' "${STATE_DIR}/diagnose.json"
grep -q '"missing_step": "teep.cose_outer_unverified"' "${STATE_DIR}/diagnose.json"
grep -q '"final_missing_step": "teep.cose_outer_unverified"' "${STATE_DIR}/diagnose.json"
grep -q '"final_blockers": \[' "${STATE_DIR}/diagnose.json"
grep -q '"teep.cose_outer_unverified"' "${STATE_DIR}/diagnose.json"
grep -q '"matched_unbound": \[' "${STATE_DIR}/diagnose.json"
grep -q '"label": "platform-status"' "${STATE_DIR}/diagnose.json"
grep -q '"label": "evidence-status"' "${STATE_DIR}/diagnose.json"
grep -q '"label": "agent-identity-status"' "${STATE_DIR}/diagnose.json"
grep -q '"label": "credential-status"' "${STATE_DIR}/diagnose.json"
grep -q "platform-backend=trustzone" "${STATE_DIR}/diagnose.json"
grep -q "sealed-storage-security=tee-ree-fs-secure-storage" "${STATE_DIR}/diagnose.json"
grep -q "sealed-storage-rollback-protected=false" "${STATE_DIR}/diagnose.json"
grep -q "runtime-location=trustzone-ta" "${STATE_DIR}/diagnose.json"
grep -q "teep-agent-location=trustzone-ta" "${STATE_DIR}/diagnose.json"
grep -q "catalog-resolution-location=trustzone-ta" "${STATE_DIR}/diagnose.json"
# D038 keeps rollback protection as diagnostic (`false` on REE FS) while
# source-aligned policy/identity/evidence signals may be `bound`/`true`.
grep -q "agent-identity-source=platform-status-ta-local" "${STATE_DIR}/diagnose.json"
grep -q "agent-identity-observed=true" "${STATE_DIR}/diagnose.json"
grep -Eq "agent-identity-binding=(unbound|matched-unbound|bound)" "${STATE_DIR}/diagnose.json"
grep -Eq "agent-identity-bound=(false|true)" "${STATE_DIR}/diagnose.json"
grep -q "protected-storage-binding=tee-ree-fs-secure-storage" "${STATE_DIR}/diagnose.json"
grep -Eq "evidence-result-load=(absent|loaded-unbound)" "${STATE_DIR}/diagnose.json"
grep -Eq "evidence-verifier-result=(none|affirming)" "${STATE_DIR}/diagnose.json"
grep -Eq "evidence-binding=(unbound|matched-unbound|bound)" "${STATE_DIR}/diagnose.json"
grep -Eq "evidence-affirming=(false|true)" "${STATE_DIR}/diagnose.json"
# This smoke starts from an unverified COSE/SUIT fixture state; final
# verification stays false because fixture trust inputs are missing.
grep -q "final-verified=false" "${STATE_DIR}/diagnose.json"

echo "TrustZone verified diagnose smoke ok"
cat "${STATE_DIR}/diagnose.txt"
cat "${STATE_DIR}/diagnose.json"
