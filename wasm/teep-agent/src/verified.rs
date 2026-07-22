// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause
use alloc::vec::Vec;
use ciborium::value::Value;
use coset::{CborSerializable, CoseSign1, TaggedCborSerializable};

use crate::cose::{
    cose_sign1_detached_payload_verified_with, outer_teep_cose_sign1_key_id,
    outer_teep_cose_sign1_payload_verified_with, verify_demo_tam_esp256_signature,
    verify_esp256_signature_with_coordinates, CoseSign1VerificationError,
};
use crate::credential_management;
use crate::evidence::VERIFIED_EVIDENCE_RESULT_PATH;
use crate::host_io;
use crate::session::{dev_sequence_is_fresh, write_update_candidate_observation};
#[cfg(not(feature = "m9-1-acceptance-only-smoke"))]
use crate::suit::success_response_payload;
#[cfg(any(not(feature = "m9-1-acceptance-only-smoke"), test))]
use crate::suit::twep_catalog_component_id;
use crate::suit::{
    suit_manifest_digest_raw, teep_update_candidate, teep_update_candidate_any, ComponentKind,
    TeepUpdateCandidate,
};
use crate::teep::{teep_message_type, TEEP_TYPE_UPDATE};
use crate::{cbor, error_output, sha256, write_output};

const LAST_TEEP_VERIFIED_STATE_PATH: &[u8] = b"teep-agent/verified-state.txt";
const LAST_TEEP_CREDENTIAL_STATUS_PATH: &[u8] = b"teep-agent/credential-status.txt";
const LAST_TEEP_PLATFORM_STATUS_PATH: &[u8] = b"teep-agent/platform-status.txt";
const LAST_TEEP_EVIDENCE_STATUS_PATH: &[u8] = b"teep-agent/evidence-status.txt";
const LAST_TEEP_AGENT_IDENTITY_STATUS_PATH: &[u8] = b"teep-agent/agent-identity-status.txt";
const VERIFIED_DRY_RUN_STATE_PATH: &[u8] = b"teep-agent/verified-dry-run-state.cbor";
const VERIFIED_INPUT_COSE_PATH: &[u8] = b"teep-agent/verified-input.cose";
const VERIFIED_INPUT_PAYLOAD_PATH: &[u8] = b"teep-agent/verified-input-payload.cbor";
const VERIFIED_EXPECTED_TOKEN_PATH: &[u8] = b"teep-agent/verified-expected-token.bin";
const LAST_TEEP_SUIT_AUTH_STATUS_PATH: &[u8] = b"teep-agent/suit-auth-status.txt";
const LAST_TEEP_UPDATE_COMPONENT_STATUS_PATH: &[u8] = b"teep-agent/update-component-status.txt";
const DEV_TRUST_ANCHORS_PATH: &[u8] = b"teep-agent/dev-trust-anchors.cbor";
const PROTECTED_CREDENTIAL_STORE_PATH: &[u8] = b"teep-agent/protected-credential-store.cbor";
const PROTECTED_CREDENTIAL_STORE_OBJECT: &[u8] = b"protected-credential-store.cbor";
const PROTECTED_ISSUER_ALLOWLIST_OBJECT: &[u8] = b"protected-issuer-allowlist.cbor";
const PROTECTED_STORE_FRESHNESS_OBJECT: &[u8] = b"protected-store-freshness.cbor";
const PROTECTED_REVOCATION_STATE_OBJECT: &[u8] = b"protected-revocation-state.cbor";
const PROTECTED_AGENT_IDENTITY_OBJECT: &[u8] = b"protected-agent-identity.cbor";
const PROTECTED_VERIFIED_EVIDENCE_RESULT_OBJECT: &[u8] = b"verified-evidence-result.cbor";

mod agent_identity;
mod credentials;
mod diagnostics;
mod dry_run;
mod evidence_status;
mod live_acceptance;
mod state;

use agent_identity::*;
use credentials::{
    read_attestam_message_verification_key, read_dev_trust_anchor_status,
    read_platform_credential_policy_status, read_protected_credential_store_bytes,
    read_protected_credential_store_status,
};
pub(crate) use diagnostics::verification_state_text;
use dry_run::{
    line_value_equals, platform_status_text, protected_storage_binding_from_platform_status,
};
pub(crate) use dry_run::{run_verified_dry_run, trustzone_live_poc_acceptance_supported};
use evidence_status::*;
pub(crate) use evidence_status::{
    protected_attestam_acceptance_is_current, protected_evidence_result_is_stale,
};
pub(crate) use live_acceptance::accept_live_attestam_update_cose;
use live_acceptance::*;
pub use state::VerificationState;
#[cfg(test)]
pub use state::VerificationStep;

pub(crate) enum LiveUpdateAcceptance {
    #[cfg(feature = "m9-1-acceptance-only-smoke")]
    AcceptanceCommitted,
    #[cfg(not(feature = "m9-1-acceptance-only-smoke"))]
    CatalogCommitted { success_payload: Vec<u8> },
    #[cfg(not(feature = "m9-1-acceptance-only-smoke"))]
    AppCommitted { success_payload: Vec<u8> },
}

pub(crate) fn verified_dry_run_state(input: &[u8]) -> Option<VerificationState> {
    let pairs = match cbor::value(input)? {
        Value::Map(pairs) => pairs,
        _ => return None,
    };
    let mut state = VerificationState::default();
    for (key, value) in pairs {
        let key = match key {
            Value::Text(key) => key,
            _ => return None,
        };
        let key = key.as_bytes();
        let value = match key {
            b"fixture_verified"
            | b"cose_outer_verified"
            | b"session_token_bound"
            | b"suit_auth_verified"
            | b"sequence_fresh"
            | b"evidence_affirming"
            | b"agent_identity_bound" => match value {
                Value::Bool(value) => value,
                _ => return None,
            },
            _ => continue,
        };
        if !value {
            continue;
        }
        match key {
            b"fixture_verified" => {
                state.mark_cose_outer_verified();
                state.mark_session_token_bound();
                state.mark_suit_auth_verified();
                state.mark_sequence_fresh();
            }
            b"cose_outer_verified" => state.mark_cose_outer_verified(),
            b"session_token_bound" => state.mark_session_token_bound(),
            b"suit_auth_verified" => state.mark_suit_auth_verified(),
            b"sequence_fresh" => state.mark_sequence_fresh(),
            b"evidence_affirming" => state.mark_evidence_affirming(),
            b"agent_identity_bound" => state.mark_agent_identity_bound(),
            _ => {}
        }
    }
    Some(state)
}

fn final_trust_anchor_ready(
    state: &VerificationState,
    binding_status: credential_management::TrustAnchorBindingStatus,
) -> bool {
    state.fixture_verified()
        && state.evidence_affirming
        && state.agent_identity_bound
        && binding_status.bound()
}

fn protected_final_storage_binding(platform_status: &[u8]) -> bool {
    line_value_equals(platform_status, b"platform-backend", b"trustzone")
        && (line_value_equals(
            platform_status,
            b"sealed-storage-security",
            b"tee-protected",
        ) || line_value_equals(
            platform_status,
            b"sealed-storage-security",
            b"tee-ree-fs-secure-storage",
        ))
}

fn read_verified_dry_run_state() -> Option<VerificationState> {
    let bytes = host_io::read_file_alloc(VERIFIED_DRY_RUN_STATE_PATH, 512)?;
    verified_dry_run_state(&bytes)
}

fn read_verified_input_cose_state(
    state: &mut VerificationState,
    requested_component_id: &[u8],
    attestam_verification_key: Option<&credential_management::AttestamMessageVerificationKey>,
) -> Option<Vec<u8>> {
    if state.cose_outer_verified() {
        return None;
    }
    let bytes = host_io::read_file_alloc(VERIFIED_INPUT_COSE_PATH, 4096)?;
    let payload = outer_teep_cose_sign1_payload_verified_with(&bytes, state, |signature, tbs| {
        verify_attestam_response_signature(attestam_verification_key, signature, tbs)
    })
    .ok()?;
    if !host_io::write_file(VERIFIED_INPUT_PAYLOAD_PATH, &payload) {
        return None;
    }
    if teep_message_type(&payload) == Some(TEEP_TYPE_UPDATE) {
        if let Ok(candidate) = verified_update_candidate(&payload, requested_component_id) {
            let suit_auth_status = mark_verified_update_candidate_state(
                state,
                &candidate,
                verified_expected_token_matches(candidate.update_token),
                dev_sequence_is_fresh(&candidate.info),
            );
            let _ = host_io::write_file(LAST_TEEP_SUIT_AUTH_STATUS_PATH, suit_auth_status);
            if !write_update_candidate_observation(&candidate) {
                return None;
            }
            if !write_verified_update_component_status(&candidate) {
                return None;
            }
        }
    }
    Some(payload)
}

fn read_verified_input_cose_key_id() -> Option<Vec<u8>> {
    let bytes = host_io::read_file_alloc(VERIFIED_INPUT_COSE_PATH, 4096)?;
    outer_teep_cose_sign1_key_id(&bytes).ok().flatten()
}

fn mark_verified_update_candidate_state(
    state: &mut VerificationState,
    candidate: &TeepUpdateCandidate<'_>,
    token_bound: bool,
    sequence_fresh: bool,
) -> &'static [u8] {
    let suit_auth_status = suit_auth_status(candidate);
    mark_verified_update_candidate_state_with_suit_status(
        state,
        token_bound,
        sequence_fresh,
        suit_auth_status,
    )
}

fn mark_live_verified_update_candidate_state(
    state: &mut VerificationState,
    candidate: &TeepUpdateCandidate<'_>,
    token_bound: bool,
    sequence_fresh: bool,
) -> &'static [u8] {
    let suit_auth_status = live_suit_auth_status(candidate);
    mark_verified_update_candidate_state_with_suit_status(
        state,
        token_bound,
        sequence_fresh,
        suit_auth_status,
    )
}

fn mark_verified_update_candidate_state_with_suit_status(
    state: &mut VerificationState,
    token_bound: bool,
    sequence_fresh: bool,
    suit_auth_status: &'static [u8],
) -> &'static [u8] {
    if token_bound {
        state.mark_session_token_bound();
    }
    if suit_auth_status == b"suit-auth=ok\n" {
        state.mark_suit_auth_verified();
    }
    if sequence_fresh {
        state.mark_sequence_fresh();
    }
    suit_auth_status
}

fn live_suit_auth_status(candidate: &TeepUpdateCandidate<'_>) -> &'static [u8] {
    let Some(protected_credential_store) = read_protected_credential_store_bytes() else {
        return b"suit-auth=signature-mismatch\n";
    };
    live_suit_auth_status_with_protected_store(candidate, &protected_credential_store)
}

fn live_suit_auth_status_with_protected_store(
    candidate: &TeepUpdateCandidate<'_>,
    protected_credential_store: &[u8],
) -> &'static [u8] {
    let Some(manifest_digest) = suit_manifest_digest_raw(candidate.info.manifest_body) else {
        return b"suit-auth=digest-error\n";
    };
    if manifest_digest.as_slice() != candidate.info.manifest_digest {
        return b"suit-auth=digest-mismatch\n";
    }
    let Some(kid) = detached_cose_sign1_key_id(candidate.info.suit_auth_block) else {
        return b"suit-auth=signature-mismatch\n";
    };
    let Some(key) =
        credential_management::suit_content_verification_key(protected_credential_store, &kid)
    else {
        return b"suit-auth=signature-mismatch\n";
    };
    if cose_sign1_detached_payload_verified_with(
        candidate.info.suit_auth_block,
        candidate.info.manifest_digest,
        |signature, tbs| verify_esp256_signature_with_coordinates(&key.x, &key.y, signature, tbs),
    )
    .is_ok()
    {
        b"suit-auth=ok\n"
    } else {
        b"suit-auth=signature-mismatch\n"
    }
}

fn detached_cose_sign1_key_id(input: &[u8]) -> Option<Vec<u8>> {
    let sign1 = CoseSign1::from_slice(input)
        .or_else(|_| CoseSign1::from_tagged_slice(input))
        .ok()?;
    let protected_kid = sign1.protected.header.key_id;
    let unprotected_kid = sign1.unprotected.key_id;
    match (protected_kid.is_empty(), unprotected_kid.is_empty()) {
        (false, true) => Some(protected_kid),
        (true, false) => Some(unprotected_kid),
        _ => None,
    }
}

fn suit_auth_status(candidate: &TeepUpdateCandidate<'_>) -> &'static [u8] {
    let Some(manifest_digest) = suit_manifest_digest_raw(candidate.info.manifest_body) else {
        return b"suit-auth=digest-error\n";
    };
    if manifest_digest.as_slice() != candidate.info.manifest_digest {
        return b"suit-auth=digest-mismatch\n";
    }
    if cose_sign1_detached_payload_verified_with(
        candidate.info.suit_auth_block,
        candidate.info.manifest_digest,
        verify_demo_tam_esp256_signature,
    )
    .is_ok()
    {
        b"suit-auth=ok\n"
    } else {
        b"suit-auth=signature-mismatch\n"
    }
}

fn verified_expected_token_matches(update_token: &[u8]) -> bool {
    if update_token.is_empty() || update_token.len() > 128 {
        return false;
    }
    let Some(bytes) = host_io::read_file_alloc(VERIFIED_EXPECTED_TOKEN_PATH, 128) else {
        return false;
    };
    bytes == update_token
}

fn live_attestam_tokens_bound(prior_session_token: &[u8], update_token: &[u8]) -> bool {
    !prior_session_token.is_empty()
        && prior_session_token.len() <= 128
        && !update_token.is_empty()
        && update_token.len() <= 128
}

fn append_bool_text(out: &mut Vec<u8>, value: bool) {
    if value {
        out.extend_from_slice(b"true");
    } else {
        out.extend_from_slice(b"false");
    }
}

fn append_i32_text(out: &mut Vec<u8>, value: i32) {
    if value < 0 {
        out.push(b'-');
        append_u32_text(out, value.unsigned_abs());
    } else {
        append_u32_text(out, value as u32);
    }
}

fn append_u32_text(out: &mut Vec<u8>, mut value: u32) {
    if value == 0 {
        out.push(b'0');
        return;
    }
    let mut digits = [0u8; 10];
    let mut len = 0;
    while value != 0 {
        digits[len] = b'0' + (value % 10) as u8;
        value /= 10;
        len += 1;
    }
    while len != 0 {
        len -= 1;
        out.push(digits[len]);
    }
}

#[cfg(test)]
mod tests;
