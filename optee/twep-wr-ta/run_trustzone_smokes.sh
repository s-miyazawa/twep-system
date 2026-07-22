#!/bin/sh
# Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
set -eu

PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
APP=optee_example_twep_wr_ta

usage() {
	echo "usage: $0 [default|diagnose|provision|failures|abi-vectors|execute-abi-negative|execute-helloworld|execute-calcadd|execute-negaposi|execute-hostcall-negative|execute-cleanup-negative|execute-catalog-resource-negative|teep-agent-resolve|teep-agent-resolve-hash-negative|teep-agent-resolve-catalog-negative|teep-agent-resolve-wrapped-error-negative|public-abi-wrapped-error-negative|public-abi-app-hash-negative|public-abi-resource-limit-negative|public-abi-execute-helloworld|public-abi-execute-calcadd|public-abi-execute-negaposi|attestam-live|attestam-verified-acceptance|attestam-verified-catalog|attestam-verified-app|host-io-resume|host-io-resume-negative|sha256-boundary-negative|teep-agent-hostcall-http|teep-agent-hostcall-evidence|teep-agent-transcript-limits|teep-agent-hostcall-bridge|teep-agent-acceptance|teep-agent-acceptance-faults|teep-agent-two-session-generation|teep-agent-hostcall-object-negative|wamr-spike|wamr-spike-linked|wamr-spike-linked-negative|wamr-spike-input-negative|wamr-spike-output-negative|wamr-spike-cleanup-negative|wamr-spike-negatives|all]" >&2
}

reset_guest_secure_storage() {
	if [ "${TWEP_TRUSTZONE_RESET_STORAGE:-0}" = "1" ] && [ -d /var/lib/tee ] && [ -e /dev/tee0 ]; then
		rm -rf /var/lib/tee/*
		sync
	fi
}

run_default_smoke() {
	"${APP}" >"/tmp/twep-trustzone-default-smoke.log"
	grep -q "TA ping ok" "/tmp/twep-trustzone-default-smoke.log"
	grep -q "secure storage readback ok" "/tmp/twep-trustzone-default-smoke.log"
	grep -q "random smoke ok" "/tmp/twep-trustzone-default-smoke.log"
	grep -q "time smoke ok" "/tmp/twep-trustzone-default-smoke.log"
	grep -q "CBOR dry-run ok" "/tmp/twep-trustzone-default-smoke.log"
	grep -q "platform-backend=trustzone" "/tmp/twep-trustzone-default-smoke.log"
	grep -q "sealed-storage-security=tee-ree-fs-secure-storage" "/tmp/twep-trustzone-default-smoke.log"
	grep -q "sealed-storage-rollback-protected=false" "/tmp/twep-trustzone-default-smoke.log"
	# Default smoke does not execute the verified TEEP/COSE/SUIT path; final
	# verification remains false for missing trust inputs, not for rollback.
	grep -q "final-verified=false" "/tmp/twep-trustzone-default-smoke.log"
	cat "/tmp/twep-trustzone-default-smoke.log"
	echo "TrustZone default smoke ok"
}

run_diagnose_smoke() {
	"${PROJECT_DIR}/diagnose_verified_trustzone.sh"
}

run_provision_smoke() {
	"${PROJECT_DIR}/provision_and_diagnose_trustzone.sh"
}

run_failure_smoke() {
	"${PROJECT_DIR}/protected_storage_failure_smoke.sh"
}

run_execute_abi_negative() {
	"${APP}" execute-abi-negative >"/tmp/twep-trustzone-execute-abi-negative.log"
	grep -q "TA production init envelope parsed" "/tmp/twep-trustzone-execute-abi-negative.log"
	grep -q "TA production execute envelope parsed" "/tmp/twep-trustzone-execute-abi-negative.log"
	grep -q "TA production resume-host-io rejected without pending request" "/tmp/twep-trustzone-execute-abi-negative.log"
	grep -q "TA production rejected D043 private test command" "/tmp/twep-trustzone-execute-abi-negative.log"
	grep -q "TA production init rejected short output buffer" "/tmp/twep-trustzone-execute-abi-negative.log"
	grep -q "TA production execute rejected malformed envelope" "/tmp/twep-trustzone-execute-abi-negative.log"
	grep -q "TA unsupported command rejected" "/tmp/twep-trustzone-execute-abi-negative.log"
	cat "/tmp/twep-trustzone-execute-abi-negative.log"
	echo "TrustZone TA execute ABI negative ok"
}

run_abi_vectors() {
	"${APP}" abi-vectors "${PROJECT_DIR}/guest/fixtures/abi-vectors.hex" \
		>"/tmp/twep-trustzone-abi-vectors.log"
	grep -q "TA production canonical vector execute envelope parsed" \
		"/tmp/twep-trustzone-abi-vectors.log"
	grep -q "TA canonical ABI vectors parsed from shared bytes ok" \
		"/tmp/twep-trustzone-abi-vectors.log"
	cat "/tmp/twep-trustzone-abi-vectors.log"
	echo "TrustZone canonical ABI vectors ok"
}

run_execute_helloworld() {
	"${APP}" execute-helloworld "${PROJECT_DIR}/guest/build/helloworld.wasm" >"/tmp/twep-trustzone-execute-helloworld.log"
	grep -q "TA production execute helloworld ok" "/tmp/twep-trustzone-execute-helloworld.log"
	cat "/tmp/twep-trustzone-execute-helloworld.log"
	echo "TrustZone TA execute helloworld ok"
}

run_execute_calcadd() {
	"${APP}" execute-calcadd "${PROJECT_DIR}/guest/build/calcadd.wasm" >"/tmp/twep-trustzone-execute-calcadd.log"
	grep -q "TA production execute calcadd ok" "/tmp/twep-trustzone-execute-calcadd.log"
	cat "/tmp/twep-trustzone-execute-calcadd.log"
	echo "TrustZone TA execute calcadd ok"
}

run_execute_negaposi() {
	"${APP}" execute-negaposi "${PROJECT_DIR}/guest/build/negaposi.wasm" "${PROJECT_DIR}/guest/fixtures/input.jpg" >"/tmp/twep-trustzone-execute-negaposi.log"
	grep -q "TA production execute negaposi ok" "/tmp/twep-trustzone-execute-negaposi.log"
	cat "/tmp/twep-trustzone-execute-negaposi.log"
	echo "TrustZone TA execute negaposi ok"
}

run_execute_hostcall_negative() {
	"${APP}" execute-hostcall-negative "${PROJECT_DIR}/guest/build/unsupported-import.wasm" "${PROJECT_DIR}/guest/build/teep-env-import.wasm" >"/tmp/twep-trustzone-execute-hostcall-negative.log"
	grep -q "TA production execute rejected env.* import" "/tmp/twep-trustzone-execute-hostcall-negative.log"
	grep -q "TA production execute rejected twep_teep_env.* import" "/tmp/twep-trustzone-execute-hostcall-negative.log"
	grep -q "TrustZone TA execute general app hostcall rejection ok" "/tmp/twep-trustzone-execute-hostcall-negative.log"
	cat "/tmp/twep-trustzone-execute-hostcall-negative.log"
	echo "TrustZone TA execute hostcall negative ok"
}

run_execute_cleanup_negative() {
	"${APP}" execute-cleanup-negative \
		"${PROJECT_DIR}/guest/build/helloworld.wasm" \
		"${PROJECT_DIR}/guest/build/production-nonzero-status.wasm" \
		"${PROJECT_DIR}/guest/build/production-trap.wasm" \
		"${PROJECT_DIR}/guest/build/production-oversized-output.wasm" \
		>"/tmp/twep-trustzone-execute-cleanup-negative.log"
	grep -q "TA production execute rejected short output buffer" "/tmp/twep-trustzone-execute-cleanup-negative.log"
	grep -q "TA production execute rejected nonzero app status" "/tmp/twep-trustzone-execute-cleanup-negative.log"
	grep -q "TA production execute rejected oversized app output" "/tmp/twep-trustzone-execute-cleanup-negative.log"
	grep -q "TA production execute rejected trap app" "/tmp/twep-trustzone-execute-cleanup-negative.log"
	grep -q "TA production execute helloworld ok" "/tmp/twep-trustzone-execute-cleanup-negative.log"
	grep -q "TA production execute cleanup after failures ok" "/tmp/twep-trustzone-execute-cleanup-negative.log"
	cat "/tmp/twep-trustzone-execute-cleanup-negative.log"
	echo "TrustZone TA execute cleanup negative ok"
}

run_execute_catalog_resource_negative() {
	"${APP}" execute-catalog-resource-negative \
		"${PROJECT_DIR}/guest/build/teep-agent.wasm" \
		"${PROJECT_DIR}/guest/build/catalog.dev.cbor" \
		"${PROJECT_DIR}/guest/build/negaposi.wasm" \
		"${PROJECT_DIR}/guest/fixtures/input.jpg" \
		>"/tmp/twep-trustzone-execute-catalog-resource-negative.log"
	grep -q "TA production execute wrapped app.resource_limit ok" "/tmp/twep-trustzone-execute-catalog-resource-negative.log"
	grep -q "TrustZone TA execute catalog resource limit negative ok" "/tmp/twep-trustzone-execute-catalog-resource-negative.log"
	cat "/tmp/twep-trustzone-execute-catalog-resource-negative.log"
	echo "TrustZone TA execute catalog resource negative ok"
}

run_teep_agent_resolve() {
	"${APP}" teep-agent-resolve "${PROJECT_DIR}/guest/build/teep-agent.wasm" "${PROJECT_DIR}/guest/build/catalog.dev.cbor" "${PROJECT_DIR}/guest/build/helloworld.wasm" >"/tmp/twep-trustzone-teep-agent-resolve.log"
	grep -q "TA production teep-agent resolve executed ok" "/tmp/twep-trustzone-teep-agent-resolve.log"
	cat "/tmp/twep-trustzone-teep-agent-resolve.log"
	echo "TrustZone TA teep-agent resolve executed ok"
}

run_teep_agent_resolve_hash_negative() {
	"${APP}" teep-agent-resolve-hash-negative "${PROJECT_DIR}/guest/build/teep-agent.wasm" "${PROJECT_DIR}/guest/build/catalog.dev.cbor" "${PROJECT_DIR}/guest/build/helloworld.wasm" >"/tmp/twep-trustzone-teep-agent-resolve-hash-negative.log"
	grep -q "TA production teep-agent resolve rejected app.hash_mismatch ok" "/tmp/twep-trustzone-teep-agent-resolve-hash-negative.log"
	cat "/tmp/twep-trustzone-teep-agent-resolve-hash-negative.log"
	echo "TrustZone TA teep-agent resolve hash negative ok"
}

run_teep_agent_resolve_catalog_negative() {
	"${APP}" teep-agent-resolve-catalog-negative "${PROJECT_DIR}/guest/build/teep-agent.wasm" "${PROJECT_DIR}/guest/build/catalog.dev.cbor" "${PROJECT_DIR}/guest/build/helloworld.wasm" >"/tmp/twep-trustzone-teep-agent-resolve-catalog-negative.log"
	grep -q "TA production teep-agent resolve rejected catalog.invalid ok" "/tmp/twep-trustzone-teep-agent-resolve-catalog-negative.log"
	grep -q "TA production teep-agent resolve rejected catalog.not_found ok" "/tmp/twep-trustzone-teep-agent-resolve-catalog-negative.log"
	grep -q "TA production teep-agent resolve catalog negatives ok" "/tmp/twep-trustzone-teep-agent-resolve-catalog-negative.log"
	cat "/tmp/twep-trustzone-teep-agent-resolve-catalog-negative.log"
	echo "TrustZone TA teep-agent resolve catalog negatives ok"
}

run_teep_agent_resolve_wrapped_error_negative() {
	"${APP}" teep-agent-resolve-wrapped-error-negative "${PROJECT_DIR}/guest/build/teep-agent.wasm" "${PROJECT_DIR}/guest/build/catalog.dev.cbor" "${PROJECT_DIR}/guest/build/helloworld.wasm" >"/tmp/twep-trustzone-teep-agent-resolve-wrapped-error-negative.log"
	grep -q "TA production teep-agent wrapped error mapped catalog.invalid ok" "/tmp/twep-trustzone-teep-agent-resolve-wrapped-error-negative.log"
	grep -q "TA production teep-agent wrapped error mapped catalog.not_found ok" "/tmp/twep-trustzone-teep-agent-resolve-wrapped-error-negative.log"
	grep -q "TA production teep-agent wrapped error mapped app.hash_mismatch ok" "/tmp/twep-trustzone-teep-agent-resolve-wrapped-error-negative.log"
	grep -q "TrustZone execute transport returned wrapped twep_wr_execute error catalog.invalid ok" "/tmp/twep-trustzone-teep-agent-resolve-wrapped-error-negative.log"
	grep -q "TrustZone execute transport returned wrapped twep_wr_execute error catalog.not_found ok" "/tmp/twep-trustzone-teep-agent-resolve-wrapped-error-negative.log"
	grep -q "TrustZone execute transport returned wrapped twep_wr_execute error app.hash_mismatch ok" "/tmp/twep-trustzone-teep-agent-resolve-wrapped-error-negative.log"
	grep -q "TA production teep-agent wrapped error mapping negatives ok" "/tmp/twep-trustzone-teep-agent-resolve-wrapped-error-negative.log"
	cat "/tmp/twep-trustzone-teep-agent-resolve-wrapped-error-negative.log"
	echo "TrustZone TA teep-agent wrapped error mapping negatives ok"
}

run_public_abi_wrapped_error_negative() {
	rm -rf "/tmp/twep-public-abi-state"
	(cd "${PROJECT_DIR}/guest" && twep_wr_public_abi_smoke "/tmp/twep-public-abi-state" wrapped-error) >"/tmp/twep-trustzone-public-abi-wrapped-error-negative.log"
	grep -q "public C ABI TrustZone execute wrapped error catalog.not_found ok" "/tmp/twep-trustzone-public-abi-wrapped-error-negative.log"
	cat "/tmp/twep-trustzone-public-abi-wrapped-error-negative.log"
	echo "TrustZone public C ABI wrapped error negative ok"
}

run_public_abi_app_hash_negative() {
	rm -rf "/tmp/twep-public-abi-state"
	(cd "${PROJECT_DIR}/guest" && twep_wr_public_abi_smoke "/tmp/twep-public-abi-state" app-hash-negative) >"/tmp/twep-trustzone-public-abi-app-hash-negative.log"
	grep -q "public C ABI TrustZone execute app.hash_mismatch wrapped error ok" "/tmp/twep-trustzone-public-abi-app-hash-negative.log"
	cat "/tmp/twep-trustzone-public-abi-app-hash-negative.log"
	echo "TrustZone public C ABI app hash negative ok"
}

run_public_abi_resource_limit_negative() {
	rm -rf "/tmp/twep-public-abi-state"
	(cd "${PROJECT_DIR}/guest" && twep_wr_public_abi_smoke "/tmp/twep-public-abi-state" resource-limit-negative "fixtures/input.jpg") >"/tmp/twep-trustzone-public-abi-resource-limit-negative.log"
	grep -q "public C ABI TrustZone execute app.resource_limit wrapped error ok" "/tmp/twep-trustzone-public-abi-resource-limit-negative.log"
	cat "/tmp/twep-trustzone-public-abi-resource-limit-negative.log"
	echo "TrustZone public C ABI resource limit negative ok"
}

run_public_abi_execute_helloworld() {
	rm -rf "/tmp/twep-public-abi-state"
	(cd "${PROJECT_DIR}/guest" && twep_wr_public_abi_smoke "/tmp/twep-public-abi-state" helloworld) >"/tmp/twep-trustzone-public-abi-execute-helloworld.log"
	grep -q "public C ABI TrustZone execute helloworld ok" "/tmp/twep-trustzone-public-abi-execute-helloworld.log"
	cat "/tmp/twep-trustzone-public-abi-execute-helloworld.log"
	echo "TrustZone public C ABI execute helloworld ok"
}

run_public_abi_execute_calcadd() {
	rm -rf "/tmp/twep-public-abi-state"
	(cd "${PROJECT_DIR}/guest" && twep_wr_public_abi_smoke "/tmp/twep-public-abi-state" calcadd) >"/tmp/twep-trustzone-public-abi-execute-calcadd.log"
	grep -q "public C ABI TrustZone execute calcadd ok" "/tmp/twep-trustzone-public-abi-execute-calcadd.log"
	cat "/tmp/twep-trustzone-public-abi-execute-calcadd.log"
	echo "TrustZone public C ABI execute calcadd ok"
}

run_public_abi_execute_negaposi() {
	rm -rf "/tmp/twep-public-abi-state" "/tmp/twep-public-abi-output.jpg"
	(cd "${PROJECT_DIR}/guest" && twep_wr_public_abi_smoke "/tmp/twep-public-abi-state" negaposi "fixtures/input.jpg" "/tmp/twep-public-abi-output.jpg") >"/tmp/twep-trustzone-public-abi-execute-negaposi.log"
	grep -q "public C ABI TrustZone execute negaposi ok" "/tmp/twep-trustzone-public-abi-execute-negaposi.log"
	test -s "/tmp/twep-public-abi-output.jpg"
	cat "/tmp/twep-trustzone-public-abi-execute-negaposi.log"
	echo "TrustZone public C ABI execute negaposi ok"
}

run_attestam_live() {
	state="/tmp/twep-trustzone-attestam-live-state"
	sock="${state}/run/twepd.sock"
	log="${state}/twepd.log"
	attestam_url="${ATTESTAM_URL:-http://10.0.2.2:8080/tam}"

	rm -rf "${state}"
	mkdir -p "${state}/run"
	(cd "${PROJECT_DIR}/guest" && twepd \
		--socket "${sock}" \
		--state-dir "${state}" \
		--resolver-mode attestam-insecure \
		--attestam-url "${attestam_url}" \
		--insecure-demo-mode \
		--insecure-demo-agent-key alternate \
		--once >"${log}" 2>&1) &
	pid=$!
	i=0
	while [ "${i}" -lt 50 ] && [ ! -S "${sock}" ]; do
		sleep 0.1
		i=$((i + 1))
	done
	if [ ! -S "${sock}" ]; then
		cat "${log}" || true
		kill "${pid}" 2>/dev/null || true
		wait "${pid}" 2>/dev/null || true
		echo "twepd socket not ready" >&2
		exit 1
	fi
	if ! (cd "${PROJECT_DIR}/guest" && twep-cli --socket "${sock}" helloworld) >"${state}/twep-cli.out" 2>"${state}/twep-cli.err"; then
		cat "${state}/twep-cli.err" || true
		cat "${log}" || true
		wait "${pid}" 2>/dev/null || true
		exit 1
	fi
	wait "${pid}"
	cat "${state}/twep-cli.out"
	grep -q "Hello, World!!" "${state}/twep-cli.out"
	mkdir -p "${state}/teep-agent"
	cat >"${state}/teep-agent/platform-status.txt" <<'EOF_STATUS'
platform-backend=trustzone
runtime-location=trustzone-ta
teep-agent-location=trustzone-ta
catalog-resolution-location=trustzone-ta
sealed-storage-security=tee-ree-fs-secure-storage
sealed-storage-rollback-protected=false
final-verified=false
EOF_STATUS
	twep-cli diagnose verified --state-dir "${state}" >"${state}/diagnose.txt"
	twep-cli diagnose verified --state-dir "${state}" --output-format json >"${state}/diagnose.json"
	grep -q "runtime-location=trustzone-ta" "${state}/diagnose.txt"
	grep -q "teep-agent-location=trustzone-ta" "${state}/diagnose.txt"
	grep -q "catalog-resolution-location=trustzone-ta" "${state}/diagnose.txt"
	# AttesTAM live smoke checks bridge placement only. The synthetic state above
	# intentionally omits final verified artifacts, so rollback=false is
	# diagnostic and final verification must stay false.
	grep -q "final-verified=false" "${state}/diagnose.txt"
	cat "${state}/twep-cli.out"
	cat "${state}/diagnose.txt"
	echo "TrustZone AttesTAM live smoke ok"
}

run_attestam_verified_acceptance() {
	state="/tmp/twep-trustzone-attestam-verified-acceptance-state"
	sock="${state}/run/twepd.sock"
	log="${state}/twepd.log"
	attestam_url="${ATTESTAM_URL:-http://10.0.2.2:8080/tam}"

	rm -rf "${state}"
	mkdir -p "${state}/run"
	for object_name in \
		protected-credential-store.cbor \
		protected-issuer-allowlist.cbor \
		protected-store-freshness.cbor \
		protected-revocation-state.cbor \
		protected-agent-identity.cbor
	do
		"${APP}" provision "${object_name}" "${PROJECT_DIR}/guest/fixtures/${object_name}"
	done

	(cd "${PROJECT_DIR}/guest" && twepd \
		--socket "${sock}" \
		--state-dir "${state}" \
		--resolver-mode attestam-verified \
		--attestam-url "${attestam_url}" \
		--insecure-demo-agent-key alternate \
		--once >"${log}" 2>&1) &
	pid=$!
	i=0
	while [ "${i}" -lt 50 ] && [ ! -S "${sock}" ]; do
		sleep 0.1
		i=$((i + 1))
	done
	if [ ! -S "${sock}" ]; then
		cat "${log}" || true
		kill "${pid}" 2>/dev/null || true
		wait "${pid}" 2>/dev/null || true
		echo "twepd socket not ready" >&2
		exit 1
	fi

	set +e
	(cd "${PROJECT_DIR}/guest" && twep-cli --socket "${sock}" helloworld) >"${state}/twep-cli.out" 2>"${state}/twep-cli.err"
	cli_status=$?
	wait "${pid}"
	daemon_status=$?
	set -e
	if [ "${daemon_status}" -ne 0 ]; then
		cat "${log}" || true
		exit "${daemon_status}"
	fi
	if [ "${cli_status}" -eq 0 ]; then
		echo "twep-cli unexpectedly succeeded in attestam-verified acceptance mode" >&2
		exit 1
	fi
	if ! grep -q "teep.verified_required" "${state}/twep-cli.err"; then
		cat "${state}/twep-cli.out" || true
		cat "${state}/twep-cli.err" || true
		cat "${log}" || true
		twep-cli diagnose verified --state-dir "${state}" >"${state}/diagnose-failure.txt" 2>&1 || true
		cat "${state}/diagnose-failure.txt" || true
		for diagnostic in \
			"${state}/teep-agent/verification-state.txt" \
			"${state}/teep-agent/suit-auth-status.txt" \
			"${state}/teep-agent/agent-identity-status.txt" \
			"${state}/teep-agent/protected-credential-status.txt"
		do
			if [ -f "${diagnostic}" ]; then
				echo "--- ${diagnostic}"
				cat "${diagnostic}"
			fi
		done
		echo "verified acceptance did not reach the expected terminal result" >&2
		exit 1
	fi
	if grep -q "Hello, World!!" "${state}/twep-cli.out"; then
		echo "verified acceptance unexpectedly executed application code" >&2
		exit 1
	fi
	for forbidden in \
		"${state}/catalog/catalog.cbor" \
		"${state}/apps/helloworld.wasm" \
		"${state}/tmp/update-payload-0.bin" \
		"${state}/teep-agent/success.cose"
	do
		if [ -e "${forbidden}" ]; then
			echo "verified acceptance unexpectedly created ${forbidden}" >&2
			exit 1
		fi
	done

	twep-cli diagnose verified --state-dir "${state}" >"${state}/diagnose.txt"
	twep-cli diagnose verified --state-dir "${state}" --output-format json >"${state}/diagnose.json"
	cat "${state}/twep-cli.err"
	cat "${state}/diagnose.txt"
	for expected in \
		evidence-decision-source=attestam-signed-update \
		evidence-tam-response-verified=true \
		evidence-challenge-response-bound=true \
		evidence-acceptance-generation-current=true \
		evidence-binding=bound \
		final-verified=false
	do
		if ! grep -q "${expected}" "${state}/diagnose.txt"; then
			echo "verified acceptance diagnosis is missing ${expected}" >&2
			exit 1
		fi
	done
	echo "TrustZone AttesTAM verified acceptance smoke ok"
}

run_attestam_verified_catalog() {
	state="/tmp/twep-trustzone-attestam-verified-catalog-state"
	sock="${state}/run/twepd.sock"
	log="${state}/twepd.log"
	attestam_url="${ATTESTAM_URL:-http://10.0.2.2:8080/tam}"

	rm -rf "${state}"
	mkdir -p "${state}/run"
	for object_name in \
		protected-credential-store.cbor \
		protected-issuer-allowlist.cbor \
		protected-store-freshness.cbor \
		protected-revocation-state.cbor \
		protected-agent-identity.cbor
	do
		"${APP}" provision "${object_name}" "${PROJECT_DIR}/guest/fixtures/${object_name}"
	done

	(cd "${PROJECT_DIR}/guest" && twepd \
		--socket "${sock}" \
		--state-dir "${state}" \
		--resolver-mode attestam-verified \
		--attestam-url "${attestam_url}" \
		--insecure-demo-agent-key alternate \
		--once >"${log}" 2>&1) &
	pid=$!
	i=0
	while [ "${i}" -lt 50 ] && [ ! -S "${sock}" ]; do
		sleep 0.1
		i=$((i + 1))
	done
	if [ ! -S "${sock}" ]; then
		cat "${log}" || true
		kill "${pid}" 2>/dev/null || true
		wait "${pid}" 2>/dev/null || true
		echo "twepd socket not ready" >&2
		exit 1
	fi

	set +e
	(cd "${PROJECT_DIR}/guest" && twep-cli --socket "${sock}" helloworld) >"${state}/twep-cli.out" 2>"${state}/twep-cli.err"
	cli_status=$?
	wait "${pid}"
	daemon_status=$?
	set -e
	if [ "${daemon_status}" -ne 0 ]; then
		cat "${log}" || true
		exit "${daemon_status}"
	fi
	if [ "${cli_status}" -eq 0 ]; then
		echo "twep-cli unexpectedly succeeded after verified Catalog commit" >&2
		exit 1
	fi
	if ! grep -q "teep.verified_required" "${state}/twep-cli.err"; then
		cat "${state}/twep-cli.out" || true
		cat "${state}/twep-cli.err" || true
		cat "${log}" || true
		echo "verified Catalog session did not reach its expected terminal result" >&2
		exit 1
	fi
	if grep -q "Hello, World!!" "${state}/twep-cli.out"; then
		echo "verified Catalog session unexpectedly executed application code" >&2
		exit 1
	fi
	# In the TrustZone backend, Wasm write_file observations are TA-local
	# transient objects and are not exported into the REE state directory.
	# The verified-required terminal result is reached only after the signed
	# Success POST receives the AttesTAM NoContent response.
	echo "Catalog Success acknowledged"

	for forbidden in \
		"${state}/catalog/catalog.cbor" \
		"${state}/apps/helloworld.wasm" \
		"${state}/tmp/update-payload-0.bin" \
		"${state}/tmp/update-staging-metadata.cbor" \
		"${state}/components/install-metadata.cbor"
	do
		if [ -e "${forbidden}" ]; then
			echo "verified Catalog session unexpectedly created ${forbidden}" >&2
			exit 1
		fi
	done

	# A new host process and TA session must be able to select the protected
	# Catalog committed by the live session. The second command exercises the
	# deterministic inactive-slot, replay, publication-fault, and non-Catalog
	# preservation matrix after live readback has been established.
	"${APP}" d047-catalog-live-readback >"${state}/catalog-live-readback.log"
	grep -q "TA D047 live Catalog restart readback ok" "${state}/catalog-live-readback.log"
	cat "${state}/catalog-live-readback.log"
	"${APP}" d047-catalog-transactions >"${state}/catalog-transactions.log"
	for expected in \
		"TA D047 Catalog initial commit and restart readback ok" \
		"TA D047 Catalog inactive-slot update and readback ok" \
		"TA D047 equal-sequence rejection preserved prior Catalog ok" \
		"TA D047 replay rejection preserved prior Catalog ok" \
		"TA D047 Catalog staging fault matrix preserved prior Catalog ok" \
		"TA D047 D043 publication fault preserved prior Catalog ok" \
		"TA D047 later non-Catalog acceptance preserved Catalog visibility ok"
	do
		grep -q "${expected}" "${state}/catalog-transactions.log"
	done
	cat "${state}/catalog-transactions.log"

	twep-cli diagnose verified --state-dir "${state}" >"${state}/diagnose.txt"
	twep-cli diagnose verified --state-dir "${state}" --output-format json >"${state}/diagnose.json"
	cat "${state}/twep-cli.err"
	cat "${state}/diagnose.txt"
	for expected in \
		evidence-acceptance-generation-current=true \
		final-verified=false
	do
		if ! grep -q "${expected}" "${state}/diagnose.txt"; then
			echo "verified Catalog diagnosis is missing ${expected}" >&2
			exit 1
		fi
	done
	echo "TrustZone AttesTAM verified Catalog smoke ok"
}

run_verified_app_once() {
	phase="$1"
	url="$2"
	sock="${verified_app_state}/run/twepd.sock"
	log="${verified_app_state}/twepd-${phase}.log"
	rm -f "${sock}"
	(cd "${PROJECT_DIR}/guest" && twepd \
		--socket "${sock}" \
		--state-dir "${verified_app_state}" \
		--resolver-mode attestam-verified \
		--attestam-url "${url}" \
		--insecure-demo-agent-key alternate \
		--once >"${log}" 2>&1) &
	pid=$!
	i=0
	while [ "${i}" -lt 50 ] && [ ! -S "${sock}" ]; do
		sleep 0.1
		i=$((i + 1))
	done
	if [ ! -S "${sock}" ]; then
		cat "${log}" || true
		kill "${pid}" 2>/dev/null || true
		wait "${pid}" 2>/dev/null || true
		echo "twepd socket not ready during ${phase}" >&2
		exit 1
	fi
	set +e
	(cd "${PROJECT_DIR}/guest" && twep-cli --socket "${sock}" helloworld) \
		>"${verified_app_state}/twep-cli-${phase}.out" \
		2>"${verified_app_state}/twep-cli-${phase}.err"
	verified_app_cli_status=$?
	wait "${pid}"
	verified_app_daemon_status=$?
	set -e
	if [ "${verified_app_daemon_status}" -ne 0 ]; then
		cat "${log}" || true
		exit "${verified_app_daemon_status}"
	fi
}

run_attestam_verified_app() {
	verified_app_state="/tmp/twep-trustzone-attestam-verified-app-state"
	attestam_url="${ATTESTAM_URL:-http://10.0.2.2:8080/tam}"

	rm -rf "${verified_app_state}"
	mkdir -p "${verified_app_state}/run"
	for object_name in \
		protected-credential-store.cbor \
		protected-issuer-allowlist.cbor \
		protected-store-freshness.cbor \
		protected-revocation-state.cbor \
		protected-agent-identity.cbor
	do
		"${APP}" provision "${object_name}" \
			"${PROJECT_DIR}/guest/fixtures/${object_name}"
	done

	# The first request installs only the independent default Catalog TC.
	run_verified_app_once catalog "${attestam_url}"
	if [ "${verified_app_cli_status}" -eq 0 ] ||
	   ! grep -q "teep.verified_required" \
		"${verified_app_state}/twep-cli-catalog.err"; then
		cat "${verified_app_state}/twep-cli-catalog.out" || true
		cat "${verified_app_state}/twep-cli-catalog.err" || true
		cat "${verified_app_state}/twepd-catalog.log" || true
		echo "verified Catalog phase did not request the app TC" >&2
		exit 1
	fi
	echo "Verified Catalog committed"

	# The next request obtains the app TC, commits it, and executes it only
	# after the protected Catalog command/digest check succeeds.
	run_verified_app_once install "${attestam_url}"
	if [ "${verified_app_cli_status}" -ne 0 ] ||
	   ! grep -q "Hello, World!!" \
		"${verified_app_state}/twep-cli-install.out"; then
		cat "${verified_app_state}/twep-cli-install.out" || true
		cat "${verified_app_state}/twep-cli-install.err" || true
		cat "${verified_app_state}/twepd-install.log" || true
		echo "verified app was not installed and executed" >&2
		exit 1
	fi
	echo "Verified app installed and executed"

	# A fresh process/session must resolve and execute protected state without
	# contacting AttesTAM. The URL is deliberately unreachable.
	run_verified_app_once restart "http://127.0.0.1:1/tam"
	if [ "${verified_app_cli_status}" -ne 0 ] ||
	   ! grep -q "Hello, World!!" \
		"${verified_app_state}/twep-cli-restart.out"; then
		cat "${verified_app_state}/twep-cli-restart.out" || true
		cat "${verified_app_state}/twep-cli-restart.err" || true
		cat "${verified_app_state}/twepd-restart.log" || true
		echo "protected app did not survive restart/offline execution" >&2
		exit 1
	fi
	echo "Protected app restart and offline execution ok"

	for forbidden in \
		"${verified_app_state}/catalog/catalog.cbor" \
		"${verified_app_state}/apps/helloworld.wasm"
	do
		if [ -e "${forbidden}" ]; then
			echo "verified app escaped protected storage: ${forbidden}" >&2
			exit 1
		fi
	done
	twep-cli diagnose verified --state-dir "${verified_app_state}" \
		>"${verified_app_state}/diagnose.txt"
	cat "${verified_app_state}/twep-cli-install.out"
	cat "${verified_app_state}/twep-cli-restart.out"
	cat "${verified_app_state}/diagnose.txt"
	grep -q "final-verified=false" "${verified_app_state}/diagnose.txt"
	echo "TrustZone AttesTAM verified app smoke ok"
}

run_host_io_resume() {
	"${APP}" host-io-resume >"/tmp/twep-trustzone-host-io-resume.log"
	grep -q "TA production host io requested ok" "/tmp/twep-trustzone-host-io-resume.log"
	grep -q "TA production host io resumed ok" "/tmp/twep-trustzone-host-io-resume.log"
	cat "/tmp/twep-trustzone-host-io-resume.log"
	echo "TrustZone TA host io resume ok"
}

run_host_io_resume_negative() {
	"${APP}" host-io-resume-negative >"/tmp/twep-trustzone-host-io-resume-negative.log"
	grep -q "TA production host io rejected missing pending request" "/tmp/twep-trustzone-host-io-resume-negative.log"
	grep -q "TA production host io rejected request_id mismatch" "/tmp/twep-trustzone-host-io-resume-negative.log"
	grep -q "TA production host io rejected io_id mismatch" "/tmp/twep-trustzone-host-io-resume-negative.log"
	grep -q "TA production host io rejected kind mismatch" "/tmp/twep-trustzone-host-io-resume-negative.log"
	grep -q "TA production host io rejected nonzero status" "/tmp/twep-trustzone-host-io-resume-negative.log"
	grep -q "TA production host io rejected sequence mismatch" "/tmp/twep-trustzone-host-io-resume-negative.log"
	grep -q "TA production host io rejected request body digest mismatch" "/tmp/twep-trustzone-host-io-resume-negative.log"
	grep -q "TA production host io rejected normalized input digest mismatch" "/tmp/twep-trustzone-host-io-resume-negative.log"
	grep -q "TA production host io rejected cross-session resume" "/tmp/twep-trustzone-host-io-resume-negative.log"
	grep -q "TA production host io rejected closed-session resume" "/tmp/twep-trustzone-host-io-resume-negative.log"
	grep -q "TA production host io resume negatives ok" "/tmp/twep-trustzone-host-io-resume-negative.log"
	cat "/tmp/twep-trustzone-host-io-resume-negative.log"
	echo "TrustZone TA host io resume negatives ok"
}

run_sha256_boundary_negative() {
	log="/tmp/twep-trustzone-sha256-boundary-negative.log"
	host_io_source="${PROJECT_DIR}/ta/ta_host_io_continuation.c"
	: >"${log}"
	grep -q "request_body_sha256" "${host_io_source}"
	grep -q "normalized_input_sha256" "${host_io_source}"
	# Catalog commit digests bind the protected D047 transaction; they do not
	# authorize Catalog or app content. Trust hashes remain TEEP Agent-owned.
	if grep -nE "payload_sha256|payload hash|app.hash|SUIT payload" \
		"${PROJECT_DIR}"/ta/ta_production_runtime.c \
		"${PROJECT_DIR}"/ta/ta_runtime_cbor.c \
		"${PROJECT_DIR}"/ta/ta_host_io_continuation.c \
		"${PROJECT_DIR}"/ta/ta_app_runtime.c \
		"${PROJECT_DIR}"/ta/ta_teep_hostcalls.c \
		"${PROJECT_DIR}"/ta/ta_teep_runtime.c >>"${log}"; then
		cat "${log}"
		echo "TA C SHA-256 boundary violation: Catalog/app authorization hash found"
		exit 1
	fi
	echo "TA C SHA-256 boundary kept to transport and protected-commit binding" | tee -a "${log}"
	echo "TrustZone TA SHA-256 boundary negative ok" | tee -a "${log}"
}

run_teep_agent_hostcall_http() {
	"${APP}" teep-agent-hostcall-http >"/tmp/twep-trustzone-teep-agent-hostcall-http.log"
	grep -q "TA production teep-agent http hostcall requested ok" "/tmp/twep-trustzone-teep-agent-hostcall-http.log"
	grep -q "TA production teep-agent http hostcall resumed ok" "/tmp/twep-trustzone-teep-agent-hostcall-http.log"
	cat "/tmp/twep-trustzone-teep-agent-hostcall-http.log"
	echo "TrustZone TA teep-agent hostcall http ok"
}

run_teep_agent_hostcall_evidence() {
	"${APP}" teep-agent-hostcall-evidence >"/tmp/twep-trustzone-teep-agent-hostcall-evidence.log"
	grep -q "TA production teep-agent evidence hostcall requested ok" "/tmp/twep-trustzone-teep-agent-hostcall-evidence.log"
	grep -q "TA production teep-agent evidence hostcall resumed ok" "/tmp/twep-trustzone-teep-agent-hostcall-evidence.log"
	cat "/tmp/twep-trustzone-teep-agent-hostcall-evidence.log"
	echo "TrustZone TA teep-agent hostcall evidence ok"
}

run_teep_agent_transcript_limits() {
	log="/tmp/twep-trustzone-teep-agent-transcript-limits.log"
	if ! "${APP}" teep-agent-transcript-limits >"${log}" 2>&1; then
		cat "${log}" >&2
		return 1
	fi
	grep -q "TA D043 transcript 32768-byte and 65536-byte aggregate boundary accepted" "${log}"
	grep -q "TA D043 third pending HTTP transcript rejected with resource limit" "${log}"
	grep -q "TA D043 create_evidence excluded from HTTP transcript quota" "${log}"
	grep -q "TA D043 32769-byte replacement rejected and old transcript invalidated" "${log}"
	grep -q "TA D043 accepted terminal failure released transcript quota" "${log}"
	grep -q "TA D043 session close released transcript quota" "${log}"
	grep -q "TA D043 accepted resume released transcript quota" "${log}"
	grep -q "TA D043 transcript resource limits ok" "${log}"
	cat "${log}"
	echo "TrustZone TA D043 transcript resource limits ok"
}

run_teep_agent_hostcall_bridge() {
	"${APP}" teep-agent-hostcall-http-wasm "${PROJECT_DIR}/guest/build/teep-agent.wasm" >"/tmp/twep-trustzone-teep-agent-hostcall-bridge.log"
	"${APP}" teep-agent-hostcall-evidence-wasm "${PROJECT_DIR}/guest/build/teep-agent.wasm" >>"/tmp/twep-trustzone-teep-agent-hostcall-bridge.log"
	grep -q "TA production teep-agent wasm http hostcall requested ok" "/tmp/twep-trustzone-teep-agent-hostcall-bridge.log"
	grep -q "TA production teep-agent wasm http hostcall resumed ok" "/tmp/twep-trustzone-teep-agent-hostcall-bridge.log"
	grep -q "TA production teep-agent wasm evidence hostcall requested ok" "/tmp/twep-trustzone-teep-agent-hostcall-bridge.log"
	grep -q "TA production teep-agent wasm evidence hostcall resumed ok" "/tmp/twep-trustzone-teep-agent-hostcall-bridge.log"
	cat "/tmp/twep-trustzone-teep-agent-hostcall-bridge.log"
	echo "TrustZone TA teep-agent wasm hostcall bridge ok"
}

run_teep_agent_acceptance() {
	log="/tmp/twep-trustzone-teep-agent-acceptance.log"
	if ! "${APP}" teep-agent-acceptance-probe \
		"${PROJECT_DIR}/guest/build/teep-agent.wasm" >"${log}" 2>&1; then
		cat "${log}" >&2
		return 1
	fi
	grep -q "TA production acceptance generation 1 committed ok" "${log}"
	grep -q "TA production acceptance generation 2 committed ok" "${log}"
	grep -q "TA production acceptance state two-slot persistence ok" "${log}"
	grep -q "TA acceptance transcript mismatch rejected with state unchanged" "${log}"
	grep -q "TA acceptance replay rejected with state unchanged" "${log}"
	grep -q "TA acceptance stale generation rejected with state unchanged" "${log}"
	grep -q "TA acceptance cross-session resume rejected with state unchanged" "${log}"
	grep -q "TA acceptance restart without pending rejected with state unchanged" "${log}"
	grep -q "TA production teep-agent verified result secure storage mirror ok" "${log}"
	cat "${log}"
	echo "TrustZone TA TEEP synthetic acceptance commit ok"
	echo "TrustZone TA TEEP acceptance persistence and negatives ok"
}

run_teep_agent_acceptance_faults() {
	log="/tmp/twep-trustzone-teep-agent-acceptance-faults.log"
	if ! "${APP}" teep-agent-acceptance-faults \
		"${PROJECT_DIR}/guest/build/teep-agent.wasm" >"${log}" 2>&1; then
		cat "${log}" >&2
		return 1
	fi
	grep -q "TA D043 protected-storage fault matrix ok" "${log}"
	cat "${log}"
	echo "TrustZone TA D043 protected-storage fault matrix ok"
}

run_teep_agent_two_session_generation() {
	log="/tmp/twep-trustzone-teep-agent-two-session-generation.log"
	if ! "${APP}" teep-agent-two-session-generation \
		"${PROJECT_DIR}/guest/build/teep-agent.wasm" >"${log}" 2>&1; then
		cat "${log}" >&2
		return 1
	fi
	grep -q "TA D043 synchronized two-session generation ok" "${log}"
	cat "${log}"
	echo "TrustZone TA D043 synchronized two-session generation ok"
}

run_teep_agent_hostcall_object_negative() {
	"${APP}" teep-agent-hostcall-object-negative "${PROJECT_DIR}/guest/build/teep-agent.wasm" >"/tmp/twep-trustzone-teep-agent-hostcall-object-negative.log"
	grep -q "TA ordinary build rejected D043 test probe ok" "/tmp/twep-trustzone-teep-agent-hostcall-object-negative.log"
	grep -q "TA production teep-agent rejected bad read object id ok" "/tmp/twep-trustzone-teep-agent-hostcall-object-negative.log"
	grep -q "TA production teep-agent rejected bad write object id ok" "/tmp/twep-trustzone-teep-agent-hostcall-object-negative.log"
	grep -q "TA production teep-agent rejected bad protected-result write object id ok" "/tmp/twep-trustzone-teep-agent-hostcall-object-negative.log"
	grep -q "TA REE generic acceptance-state writes rejected ok" "/tmp/twep-trustzone-teep-agent-hostcall-object-negative.log"
	grep -q "TA REE generic catalog-state reads and writes rejected ok" "/tmp/twep-trustzone-teep-agent-hostcall-object-negative.log"
	grep -q "TA production teep-agent hostcall object negative ok" "/tmp/twep-trustzone-teep-agent-hostcall-object-negative.log"
	cat "/tmp/twep-trustzone-teep-agent-hostcall-object-negative.log"
	echo "TrustZone TA teep-agent hostcall object negative ok"
}

run_wamr_spike() {
	"${APP}" wamr-spike "${PROJECT_DIR}/guest/build/helloworld.wasm" >"/tmp/twep-trustzone-wamr-spike.log"
	grep -q "WAMR spike blocker: TA command shape reached" "/tmp/twep-trustzone-wamr-spike.log"
	grep -q "TA_TWEP_WR_CMD_WAMR_SPIKE_EXEC returned TEEC_ERROR_NOT_SUPPORTED" "/tmp/twep-trustzone-wamr-spike.log"
	cat "/tmp/twep-trustzone-wamr-spike.log"
	echo "TrustZone WAMR spike blocker captured"
}

run_wamr_spike_linked() {
	"${APP}" wamr-spike "${PROJECT_DIR}/guest/build/helloworld.wasm" >"/tmp/twep-trustzone-wamr-spike-linked.log"
	grep -q "WAMR spike executed helloworld inside TA" "/tmp/twep-trustzone-wamr-spike-linked.log"
	cat "/tmp/twep-trustzone-wamr-spike-linked.log"
	echo "TrustZone WAMR spike linked execution ok"
}

run_wamr_spike_linked_negative() {
	"${APP}" wamr-spike-expect-reject "${PROJECT_DIR}/guest/build/unsupported-import.wasm" >"/tmp/twep-trustzone-wamr-spike-linked-negative.log"
	grep -q "WAMR spike rejected unsupported import inside TA" "/tmp/twep-trustzone-wamr-spike-linked-negative.log"
	cat "/tmp/twep-trustzone-wamr-spike-linked-negative.log"
	echo "TrustZone WAMR spike linked negative ok"
}

run_wamr_spike_input_negative() {
	"${APP}" wamr-spike-input-negative "${PROJECT_DIR}/guest/build/helloworld.wasm" >"/tmp/twep-trustzone-wamr-spike-input-negative.log"
	grep -q "WAMR spike rejected empty app input inside TA" "/tmp/twep-trustzone-wamr-spike-input-negative.log"
	grep -q "WAMR spike rejected malformed app input inside TA" "/tmp/twep-trustzone-wamr-spike-input-negative.log"
	grep -q "WAMR spike rejected oversized app input inside TA" "/tmp/twep-trustzone-wamr-spike-input-negative.log"
	grep -q "WAMR spike input boundary rejection ok" "/tmp/twep-trustzone-wamr-spike-input-negative.log"
	cat "/tmp/twep-trustzone-wamr-spike-input-negative.log"
	echo "TrustZone WAMR spike input negative ok"
}

run_wamr_spike_output_negative() {
	"${APP}" wamr-spike-output-negative "${PROJECT_DIR}/guest/build/helloworld.wasm" "${PROJECT_DIR}/guest/build/oversized-output.wasm" >"/tmp/twep-trustzone-wamr-spike-output-negative.log"
	grep -q "WAMR spike rejected short output buffer inside TA" "/tmp/twep-trustzone-wamr-spike-output-negative.log"
	grep -q "WAMR spike rejected oversized app output inside TA" "/tmp/twep-trustzone-wamr-spike-output-negative.log"
	grep -q "WAMR spike output boundary rejection ok" "/tmp/twep-trustzone-wamr-spike-output-negative.log"
	cat "/tmp/twep-trustzone-wamr-spike-output-negative.log"
	echo "TrustZone WAMR spike output negative ok"
}

run_wamr_spike_cleanup_negative() {
	"${APP}" wamr-spike-cleanup-negative "${PROJECT_DIR}/guest/build/helloworld.wasm" "${PROJECT_DIR}/guest/build/nonzero-status.wasm" "${PROJECT_DIR}/guest/build/trap.wasm" >"/tmp/twep-trustzone-wamr-spike-cleanup-negative.log"
	grep -q "WAMR spike rejected nonzero app status inside TA" "/tmp/twep-trustzone-wamr-spike-cleanup-negative.log"
	grep -q "WAMR spike rejected trap app inside TA" "/tmp/twep-trustzone-wamr-spike-cleanup-negative.log"
	grep -q "WAMR spike executed helloworld inside TA" "/tmp/twep-trustzone-wamr-spike-cleanup-negative.log"
	grep -q "WAMR spike cleanup after failures ok" "/tmp/twep-trustzone-wamr-spike-cleanup-negative.log"
	cat "/tmp/twep-trustzone-wamr-spike-cleanup-negative.log"
	echo "TrustZone WAMR spike cleanup negative ok"
}

run_wamr_spike_negatives() {
	run_wamr_spike_linked_negative
	run_wamr_spike_input_negative
	run_wamr_spike_output_negative
	run_wamr_spike_cleanup_negative
	echo "TrustZone WAMR spike negatives ok"
}

mode=${1:-all}
reset_guest_secure_storage

case "${mode}" in
default)
	run_default_smoke
	;;
diagnose)
	run_diagnose_smoke
	;;
provision)
	run_provision_smoke
	;;
failures)
	run_failure_smoke
	;;
abi-vectors)
	run_abi_vectors
	;;
execute-abi-negative)
	run_execute_abi_negative
	;;
execute-helloworld)
	run_execute_helloworld
	;;
execute-calcadd)
	run_execute_calcadd
	;;
execute-negaposi)
	run_execute_negaposi
	;;
execute-hostcall-negative)
	run_execute_hostcall_negative
	;;
execute-cleanup-negative)
	run_execute_cleanup_negative
	;;
execute-catalog-resource-negative)
	run_execute_catalog_resource_negative
	;;
teep-agent-resolve)
	run_teep_agent_resolve
	;;
teep-agent-resolve-hash-negative)
	run_teep_agent_resolve_hash_negative
	;;
teep-agent-resolve-catalog-negative)
	run_teep_agent_resolve_catalog_negative
	;;
teep-agent-resolve-wrapped-error-negative)
	run_teep_agent_resolve_wrapped_error_negative
	;;
public-abi-wrapped-error-negative)
	run_public_abi_wrapped_error_negative
	;;
public-abi-app-hash-negative)
	run_public_abi_app_hash_negative
	;;
public-abi-resource-limit-negative)
	run_public_abi_resource_limit_negative
	;;
public-abi-execute-helloworld)
	run_public_abi_execute_helloworld
	;;
public-abi-execute-calcadd)
	run_public_abi_execute_calcadd
	;;
public-abi-execute-negaposi)
	run_public_abi_execute_negaposi
	;;
attestam-live)
	run_attestam_live
	;;
attestam-verified-acceptance)
	run_attestam_verified_acceptance
	;;
attestam-verified-catalog)
	run_attestam_verified_catalog
	;;
attestam-verified-app)
	run_attestam_verified_app
	;;
host-io-resume)
	run_host_io_resume
	;;
host-io-resume-negative)
	run_host_io_resume_negative
	;;
sha256-boundary-negative)
	run_sha256_boundary_negative
	;;
teep-agent-hostcall-http)
	run_teep_agent_hostcall_http
	;;
teep-agent-hostcall-evidence)
	run_teep_agent_hostcall_evidence
	;;
teep-agent-transcript-limits)
	run_teep_agent_transcript_limits
	;;
teep-agent-hostcall-bridge)
	run_teep_agent_hostcall_bridge
	;;
teep-agent-acceptance)
	run_teep_agent_acceptance
	;;
teep-agent-acceptance-faults)
	run_teep_agent_acceptance_faults
	;;
teep-agent-two-session-generation)
	run_teep_agent_two_session_generation
	;;
teep-agent-hostcall-object-negative)
	run_teep_agent_hostcall_object_negative
	;;
wamr-spike)
	run_wamr_spike
	;;
wamr-spike-linked)
	run_wamr_spike_linked
	;;
wamr-spike-linked-negative)
	run_wamr_spike_linked_negative
	;;
wamr-spike-input-negative)
	run_wamr_spike_input_negative
	;;
wamr-spike-output-negative)
	run_wamr_spike_output_negative
	;;
wamr-spike-cleanup-negative)
	run_wamr_spike_cleanup_negative
	;;
wamr-spike-negatives)
	run_wamr_spike_negatives
	;;
all)
	run_default_smoke
	run_diagnose_smoke
	run_provision_smoke
	echo "TrustZone smoke suite ok"
	;;
*)
	usage
	exit 2
	;;
esac
