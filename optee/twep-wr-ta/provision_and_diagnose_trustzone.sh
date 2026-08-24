#!/bin/sh
# Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
set -eu

PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
GUEST_DIR="${PROJECT_DIR}/guest"
FIXTURES_DIR="${GUEST_DIR}/fixtures"
STATE_DIR="/tmp/twep-trustzone-diagnose-state"
APP=optee_example_twep_wr_ta

provision_object() {
	object_name=$1
	fixture="${2:-${FIXTURES_DIR}/${object_name}}"
	readback="/tmp/${object_name}.readback"

	test -f "${fixture}"
	"${APP}" provision "${object_name}" "${fixture}"
	"${APP}" read "${object_name}" >"${readback}"
	cmp "${fixture}" "${readback}"
}

diagnose_allow_failure() {
	rm -f "${STATE_DIR}/diagnose.txt" "${STATE_DIR}/diagnose.json"
	if TWEP_TRUSTZONE_VERIFIED_INPUT=1 "${PROJECT_DIR}/diagnose_verified_trustzone.sh"; then
		return 0
	else
		status=$?
		printf 'diagnose_verified_trustzone.sh failed with exit status %s\n' "${status}" >&2
	fi
	return 0
}

provision_object protected-credential-store.cbor
provision_object protected-issuer-allowlist.cbor
provision_object protected-store-freshness.cbor
provision_object protected-revocation-state.cbor
provision_object protected-agent-identity.cbor

"${PROJECT_DIR}/diagnose_verified_trustzone.sh"

grep -q "protected-credential-store-load=loaded-unbound" "${STATE_DIR}/diagnose.txt"
grep -q "protected-credential-store-attestam-message-verification-keys=1" "${STATE_DIR}/diagnose.txt"
grep -q "protected-credential-store-suit-content-verification-keys=1" "${STATE_DIR}/diagnose.txt"
grep -q "platform-issuer-allowlist-load=loaded-unbound" "${STATE_DIR}/diagnose.txt"
grep -q "platform-store-freshness-load=loaded-unbound" "${STATE_DIR}/diagnose.txt"
grep -q "platform-revocation-state-load=loaded-unbound" "${STATE_DIR}/diagnose.txt"
grep -q "protected-storage-binding=tee-ree-fs-secure-storage" "${STATE_DIR}/diagnose.txt"
grep -q "protected-credential-store-issuer-allowlist-match=true" "${STATE_DIR}/diagnose.txt"
grep -q "protected-store-freshness-epoch-match=true" "${STATE_DIR}/diagnose.txt"
grep -q "protected-revocation-state-match=true" "${STATE_DIR}/diagnose.txt"
grep -Eq "protected-credential-store-rotation-policy=(matched-unbound|bound)" "${STATE_DIR}/diagnose.txt"
grep -Eq "protected-credential-store-revocation-status=(matched-unbound|bound)" "${STATE_DIR}/diagnose.txt"
grep -Eq "protected-credential-store-freshness=(matched-unbound|bound)" "${STATE_DIR}/diagnose.txt"
grep -q "protected-agent-identity-load=loaded-unbound" "${STATE_DIR}/diagnose.txt"
grep -q "protected-agent-identity-backend-match=true" "${STATE_DIR}/diagnose.txt"
grep -q "protected-agent-identity-runtime-match=true" "${STATE_DIR}/diagnose.txt"
grep -q "protected-agent-identity-teep-agent-match=true" "${STATE_DIR}/diagnose.txt"
grep -q "protected-agent-identity-measurement=matched" "${STATE_DIR}/diagnose.txt"
grep -q "evidence-result-load=absent" "${STATE_DIR}/diagnose.txt"
grep -q "evidence-binding=unbound" "${STATE_DIR}/diagnose.txt"
grep -q "evidence-affirming=false" "${STATE_DIR}/diagnose.txt"
# D038 allows REE FS secure storage diagnostics to become `bound` after
# source/test alignment while keeping rollback protection diagnostic-only.
grep -q "agent-identity-binding=bound" "${STATE_DIR}/diagnose.txt"
grep -q "agent-identity-bound=true" "${STATE_DIR}/diagnose.txt"
grep -q "protected-credential-store-bound=false" "${STATE_DIR}/diagnose.txt"
grep -q "issuer-allowlist-bound=false" "${STATE_DIR}/diagnose.txt"
grep -Eq "store-freshness-bound=(false|true)" "${STATE_DIR}/diagnose.txt"
grep -Eq "revocation-state-bound=(false|true)" "${STATE_DIR}/diagnose.txt"
grep -q "trust-anchor-bound=false" "${STATE_DIR}/diagnose.txt"
grep -q "final-verified=false" "${STATE_DIR}/diagnose.txt"
grep -q "protected-credential-store-load=loaded-unbound" "${STATE_DIR}/diagnose.json"
grep -q "protected-credential-store-attestam-message-verification-keys=1" "${STATE_DIR}/diagnose.json"
grep -q "protected-credential-store-suit-content-verification-keys=1" "${STATE_DIR}/diagnose.json"
grep -q "platform-issuer-allowlist-load=loaded-unbound" "${STATE_DIR}/diagnose.json"
grep -q "platform-store-freshness-load=loaded-unbound" "${STATE_DIR}/diagnose.json"
grep -q "platform-revocation-state-load=loaded-unbound" "${STATE_DIR}/diagnose.json"
grep -q "protected-storage-binding=tee-ree-fs-secure-storage" "${STATE_DIR}/diagnose.json"
grep -q "protected-credential-store-issuer-allowlist-match=true" "${STATE_DIR}/diagnose.json"
grep -q "protected-store-freshness-epoch-match=true" "${STATE_DIR}/diagnose.json"
grep -q "protected-revocation-state-match=true" "${STATE_DIR}/diagnose.json"
grep -Eq "protected-credential-store-rotation-policy=(matched-unbound|bound)" "${STATE_DIR}/diagnose.json"
grep -Eq "protected-credential-store-revocation-status=(matched-unbound|bound)" "${STATE_DIR}/diagnose.json"
grep -Eq "protected-credential-store-freshness=(matched-unbound|bound)" "${STATE_DIR}/diagnose.json"
grep -q "protected-agent-identity-load=loaded-unbound" "${STATE_DIR}/diagnose.json"
grep -q "protected-agent-identity-backend-match=true" "${STATE_DIR}/diagnose.json"
grep -q "protected-agent-identity-runtime-match=true" "${STATE_DIR}/diagnose.json"
grep -q "protected-agent-identity-teep-agent-match=true" "${STATE_DIR}/diagnose.json"
grep -q "protected-agent-identity-measurement=matched" "${STATE_DIR}/diagnose.json"
grep -q "evidence-result-load=absent" "${STATE_DIR}/diagnose.json"
grep -q "evidence-binding=unbound" "${STATE_DIR}/diagnose.json"
grep -q "evidence-affirming=false" "${STATE_DIR}/diagnose.json"
grep -q "agent-identity-binding=bound" "${STATE_DIR}/diagnose.json"
grep -Eq '"teep.credential_rotation_matched_unbound"|"teep.store_freshness_bound"' "${STATE_DIR}/diagnose.json"
grep -Eq '"teep.revocation_state_matched_unbound"|"teep.revocation_state_bound"' "${STATE_DIR}/diagnose.json"
grep -Eq '"teep.store_freshness_matched_unbound"|"teep.store_freshness_bound"' "${STATE_DIR}/diagnose.json"
grep -q '"teep.agent_identity_bound"' "${STATE_DIR}/diagnose.json"
grep -q "agent-identity-bound=true" "${STATE_DIR}/diagnose.json"
grep -q "protected-credential-store-bound=false" "${STATE_DIR}/diagnose.json"
grep -q "issuer-allowlist-bound=false" "${STATE_DIR}/diagnose.json"
grep -Eq "store-freshness-bound=(false|true)" "${STATE_DIR}/diagnose.json"
grep -Eq "revocation-state-bound=(false|true)" "${STATE_DIR}/diagnose.json"
grep -q "trust-anchor-bound=false" "${STATE_DIR}/diagnose.json"
grep -q "final-verified=false" "${STATE_DIR}/diagnose.json"

"${APP}" provision protected-issuer-allowlist.cbor "${FIXTURES_DIR}/protected-issuer-allowlist-mismatch.cbor"
"${APP}" read protected-issuer-allowlist.cbor >"/tmp/protected-issuer-allowlist-mismatch.cbor.readback"
cmp "${FIXTURES_DIR}/protected-issuer-allowlist-mismatch.cbor" "/tmp/protected-issuer-allowlist-mismatch.cbor.readback"

TWEP_TRUSTZONE_VERIFIED_INPUT=1 "${PROJECT_DIR}/diagnose_verified_trustzone.sh"

grep -q "protected-credential-store-attestam-key-binding=observed-kid-entry-protected-storage-bound" "${STATE_DIR}/diagnose.txt"
grep -q "platform-issuer-allowlist-load=loaded-unbound" "${STATE_DIR}/diagnose.txt"
grep -q "protected-credential-store-issuer-allowlist-match=false" "${STATE_DIR}/diagnose.txt"
grep -q "protected-store-freshness-epoch-match=true" "${STATE_DIR}/diagnose.txt"
grep -q "protected-revocation-state-match=true" "${STATE_DIR}/diagnose.txt"
grep -Eq "protected-credential-store-rotation-policy=(matched-unbound|bound)" "${STATE_DIR}/diagnose.txt"
grep -Eq "protected-credential-store-revocation-status=(matched-unbound|bound)" "${STATE_DIR}/diagnose.txt"
grep -Eq "protected-credential-store-freshness=(matched-unbound|bound)" "${STATE_DIR}/diagnose.txt"
grep -q "protected-credential-store-bound=true" "${STATE_DIR}/diagnose.txt"
grep -q "issuer-allowlist-bound=false" "${STATE_DIR}/diagnose.txt"
grep -Eq "store-freshness-bound=(false|true)" "${STATE_DIR}/diagnose.txt"
grep -Eq "revocation-state-bound=(false|true)" "${STATE_DIR}/diagnose.txt"
grep -q "trust-anchor-bound=false" "${STATE_DIR}/diagnose.txt"
grep -q "final-verified=false" "${STATE_DIR}/diagnose.txt"
grep -q "protected-credential-store-attestam-key-binding=observed-kid-entry-protected-storage-bound" "${STATE_DIR}/diagnose.json"
grep -q "platform-issuer-allowlist-load=loaded-unbound" "${STATE_DIR}/diagnose.json"
grep -q "protected-credential-store-issuer-allowlist-match=false" "${STATE_DIR}/diagnose.json"
grep -q "protected-store-freshness-epoch-match=true" "${STATE_DIR}/diagnose.json"
grep -q "protected-revocation-state-match=true" "${STATE_DIR}/diagnose.json"
grep -Eq "protected-credential-store-rotation-policy=(matched-unbound|bound)" "${STATE_DIR}/diagnose.json"
grep -Eq "protected-credential-store-revocation-status=(matched-unbound|bound)" "${STATE_DIR}/diagnose.json"
grep -Eq "protected-credential-store-freshness=(matched-unbound|bound)" "${STATE_DIR}/diagnose.json"
grep -q "protected-credential-store-bound=true" "${STATE_DIR}/diagnose.json"
grep -q "issuer-allowlist-bound=false" "${STATE_DIR}/diagnose.json"
grep -Eq "store-freshness-bound=(false|true)" "${STATE_DIR}/diagnose.json"
grep -Eq "revocation-state-bound=(false|true)" "${STATE_DIR}/diagnose.json"
grep -q '"teep.protected_credential_store_bound"' "${STATE_DIR}/diagnose.json"
grep -q "trust-anchor-bound=false" "${STATE_DIR}/diagnose.json"
grep -q "final-verified=false" "${STATE_DIR}/diagnose.json"

"${APP}" provision protected-issuer-allowlist.cbor "${FIXTURES_DIR}/protected-issuer-allowlist.cbor"
"${APP}" read protected-issuer-allowlist.cbor >"/tmp/protected-issuer-allowlist.cbor.readback"
cmp "${FIXTURES_DIR}/protected-issuer-allowlist.cbor" "/tmp/protected-issuer-allowlist.cbor.readback"

TWEP_TRUSTZONE_VERIFIED_INPUT=1 "${PROJECT_DIR}/diagnose_verified_trustzone.sh"

grep -q "observed-attestam-kid=" "${STATE_DIR}/diagnose.txt"
grep -q "protected-credential-store-attestam-key-binding=observed-kid-entry-protected-storage-bound" "${STATE_DIR}/diagnose.txt"
grep -q "protected-credential-store-issuer-allowlist-match=true" "${STATE_DIR}/diagnose.txt"
grep -q "protected-store-freshness-epoch-match=true" "${STATE_DIR}/diagnose.txt"
grep -q "protected-revocation-state-match=true" "${STATE_DIR}/diagnose.txt"
grep -Eq "protected-credential-store-rotation-policy=(matched-unbound|bound)" "${STATE_DIR}/diagnose.txt"
grep -Eq "protected-credential-store-revocation-status=(matched-unbound|bound)" "${STATE_DIR}/diagnose.txt"
grep -Eq "protected-credential-store-freshness=(matched-unbound|bound)" "${STATE_DIR}/diagnose.txt"
grep -q "protected-credential-store-bound=true" "${STATE_DIR}/diagnose.txt"
grep -q "issuer-allowlist-bound=true" "${STATE_DIR}/diagnose.txt"
grep -Eq "store-freshness-bound=(false|true)" "${STATE_DIR}/diagnose.txt"
grep -Eq "revocation-state-bound=(false|true)" "${STATE_DIR}/diagnose.txt"
grep -q "trust-anchor-bound=false" "${STATE_DIR}/diagnose.txt"
grep -q "fixture-verified=false" "${STATE_DIR}/diagnose.txt"
grep -q "evidence-affirming=false" "${STATE_DIR}/diagnose.txt"
grep -q "agent-identity-bound=true" "${STATE_DIR}/diagnose.txt"
grep -q "missing-step=teep.cose_outer_unverified" "${STATE_DIR}/diagnose.txt"
grep -q "final-verified=false" "${STATE_DIR}/diagnose.txt"
grep -q "protected-credential-store-attestam-key-binding=observed-kid-entry-protected-storage-bound" "${STATE_DIR}/diagnose.json"
grep -q "protected-credential-store-issuer-allowlist-match=true" "${STATE_DIR}/diagnose.json"
grep -q "protected-store-freshness-epoch-match=true" "${STATE_DIR}/diagnose.json"
grep -q "protected-revocation-state-match=true" "${STATE_DIR}/diagnose.json"
grep -Eq "protected-credential-store-rotation-policy=(matched-unbound|bound)" "${STATE_DIR}/diagnose.json"
grep -Eq "protected-credential-store-revocation-status=(matched-unbound|bound)" "${STATE_DIR}/diagnose.json"
grep -Eq "protected-credential-store-freshness=(matched-unbound|bound)" "${STATE_DIR}/diagnose.json"
grep -q "protected-credential-store-bound=true" "${STATE_DIR}/diagnose.json"
grep -q "issuer-allowlist-bound=true" "${STATE_DIR}/diagnose.json"
grep -Eq "store-freshness-bound=(false|true)" "${STATE_DIR}/diagnose.json"
grep -Eq "revocation-state-bound=(false|true)" "${STATE_DIR}/diagnose.json"
grep -q '"teep.protected_credential_store_bound"' "${STATE_DIR}/diagnose.json"
grep -q '"teep.issuer_allowlist_bound"' "${STATE_DIR}/diagnose.json"
grep -q "trust-anchor-bound=false" "${STATE_DIR}/diagnose.json"
grep -q "fixture-verified=false" "${STATE_DIR}/diagnose.json"
grep -q "evidence-affirming=false" "${STATE_DIR}/diagnose.json"
grep -q "agent-identity-bound=true" "${STATE_DIR}/diagnose.json"
grep -q "missing-step=teep.cose_outer_unverified" "${STATE_DIR}/diagnose.json"
grep -q "final-verified=false" "${STATE_DIR}/diagnose.json"

# D043 positive-result and two-slot objects are deliberately not injectable
# through the generic REE provisioning command. Their malformed/current/stale
# persistence cases belong to the dedicated M9.1H test-only fault interface.

provision_object protected-agent-identity.cbor "${FIXTURES_DIR}/protected-agent-identity-mismatch.cbor"
diagnose_allow_failure
grep -q "protected-agent-identity-load=loaded-unbound" "${STATE_DIR}/diagnose.txt"
grep -q "protected-agent-identity-measurement=mismatch" "${STATE_DIR}/diagnose.txt"
grep -q "protected-agent-identity-measurement-source=optee-ta-measure-wasm" "${STATE_DIR}/diagnose.txt"
grep -q "agent-identity-binding=matched-unbound" "${STATE_DIR}/diagnose.txt"
grep -q "agent-identity-bound=false" "${STATE_DIR}/diagnose.txt"
grep -q "protected-agent-identity-load=loaded-unbound" "${STATE_DIR}/diagnose.json"
grep -q "protected-agent-identity-measurement=mismatch" "${STATE_DIR}/diagnose.json"
grep -q "protected-agent-identity-measurement-source=optee-ta-measure-wasm" "${STATE_DIR}/diagnose.json"
grep -q "agent-identity-binding=matched-unbound" "${STATE_DIR}/diagnose.json"
grep -q "agent-identity-bound=false" "${STATE_DIR}/diagnose.json"
provision_object protected-agent-identity.cbor

provision_object protected-agent-identity.cbor "${FIXTURES_DIR}/protected-agent-identity-optional-missing.cbor"
diagnose_allow_failure
grep -q "protected-agent-identity-load=loaded-unbound" "${STATE_DIR}/diagnose.txt"
grep -q "protected-agent-identity-backend-match=true" "${STATE_DIR}/diagnose.txt"
grep -q "protected-agent-identity-runtime-match=false" "${STATE_DIR}/diagnose.txt"
grep -q "protected-agent-identity-teep-agent-match=false" "${STATE_DIR}/diagnose.txt"
grep -q "protected-agent-identity-measurement=absent" "${STATE_DIR}/diagnose.txt"
grep -q "protected-agent-identity-measurement-source=none" "${STATE_DIR}/diagnose.txt"
grep -q "agent-identity-binding=unbound" "${STATE_DIR}/diagnose.txt"
grep -q "agent-identity-bound=false" "${STATE_DIR}/diagnose.txt"
grep -q "protected-agent-identity-load=loaded-unbound" "${STATE_DIR}/diagnose.json"
grep -q "protected-agent-identity-backend-match=true" "${STATE_DIR}/diagnose.json"
grep -q "protected-agent-identity-runtime-match=false" "${STATE_DIR}/diagnose.json"
grep -q "protected-agent-identity-teep-agent-match=false" "${STATE_DIR}/diagnose.json"
grep -q "protected-agent-identity-measurement=absent" "${STATE_DIR}/diagnose.json"
grep -q "protected-agent-identity-measurement-source=none" "${STATE_DIR}/diagnose.json"
grep -q "agent-identity-binding=unbound" "${STATE_DIR}/diagnose.json"
grep -q "agent-identity-bound=false" "${STATE_DIR}/diagnose.json"
provision_object protected-agent-identity.cbor

provision_object protected-credential-store.cbor "${FIXTURES_DIR}/protected-credential-store-malformed.cbor"
diagnose_allow_failure
grep -q "protected-credential-store-load=malformed" "${STATE_DIR}/diagnose.txt"
grep -q "protected-credential-store-bound=false" "${STATE_DIR}/diagnose.txt"
grep -q "protected-credential-store-load=malformed" "${STATE_DIR}/diagnose.json"
grep -q "protected-credential-store-bound=false" "${STATE_DIR}/diagnose.json"
provision_object protected-credential-store.cbor

provision_object protected-store-freshness.cbor "${FIXTURES_DIR}/protected-store-freshness-stale.cbor"
diagnose_allow_failure
grep -q "protected-store-freshness-epoch-match=false" "${STATE_DIR}/diagnose.txt"
grep -q "store-freshness-bound=false" "${STATE_DIR}/diagnose.txt"
grep -q "protected-store-freshness-epoch-match=false" "${STATE_DIR}/diagnose.json"
grep -q "store-freshness-bound=false" "${STATE_DIR}/diagnose.json"
provision_object protected-store-freshness.cbor

provision_object protected-revocation-state.cbor "${FIXTURES_DIR}/protected-revocation-state-revoked.cbor"
diagnose_allow_failure
grep -q "protected-revocation-state-match=false" "${STATE_DIR}/diagnose.txt"
grep -q "revocation-state-bound=false" "${STATE_DIR}/diagnose.txt"
grep -q "protected-revocation-state-match=false" "${STATE_DIR}/diagnose.json"
grep -q "revocation-state-bound=false" "${STATE_DIR}/diagnose.json"
provision_object protected-revocation-state.cbor

echo "TrustZone issuer allowlist negative smoke ok"
echo "TrustZone provisioning diagnose smoke ok"
