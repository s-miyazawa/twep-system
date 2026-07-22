// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause

use super::*;

pub(crate) fn accept_live_attestam_update_cose(
    input_cose: &[u8],
    requested_component_id: &[u8],
    evidence_query_response: &[u8],
    prior_session_token: &[u8],
) -> Result<LiveUpdateAcceptance, &'static [u8]> {
    if evidence_query_response.is_empty() || prior_session_token.is_empty() {
        return Err(b"verified PoC session binding input is missing");
    }
    let kid = outer_teep_cose_sign1_key_id(input_cose)
        .map_err(|_| b"verified PoC Update COSE is malformed".as_slice())?
        .ok_or(b"verified PoC Update has no readable COSE kid".as_slice())?;
    let attestam_verification_key = read_attestam_message_verification_key(&kid)
        .ok_or(b"verified PoC Update COSE kid has no matching development key".as_slice())?;
    let mut state = VerificationState::default();
    let Some(payload) =
        verified_attestam_update_payload(input_cose, Some(&attestam_verification_key), &mut state)
    else {
        return Err(b"verified PoC Update COSE signature or message type was rejected");
    };
    if !host_io::write_file(VERIFIED_INPUT_COSE_PATH, input_cose)
        || !host_io::write_file(VERIFIED_INPUT_PAYLOAD_PATH, &payload)
    {
        return Err(b"verified PoC Update observation could not be persisted");
    }
    let Ok(candidate) = verified_update_candidate(&payload, requested_component_id) else {
        return Err(b"verified PoC Update candidate was rejected");
    };
    let suit_auth_status = mark_live_verified_update_candidate_state(
        &mut state,
        &candidate,
        live_attestam_tokens_bound(prior_session_token, candidate.update_token),
        dev_sequence_is_fresh(&candidate.info),
    );
    let _ = host_io::write_file(LAST_TEEP_SUIT_AUTH_STATUS_PATH, suit_auth_status);
    if suit_auth_status != b"suit-auth=ok\n" {
        return Err(b"verified PoC SUIT authentication was rejected");
    }
    if !write_update_candidate_observation(&candidate)
        || !write_verified_update_component_status(&candidate)
    {
        return Err(b"verified PoC Update candidate observation could not be persisted");
    }
    let (binding_status, agent_identity_status, platform_status) =
        attestam_live_acceptance_context(Some(&kid));
    if !state.fixture_verified() {
        return Err(b"verified PoC Update protocol verification is incomplete");
    }
    if candidate.manifest_count != 1 || candidate.info.sequence_number == 0 {
        return Err(b"verified PoC Update manifest is not commit eligible");
    }
    if !binding_status.bound() {
        return Err(b"verified PoC development trust anchors are not bound");
    }
    if !agent_identity_status.bound_ready(&platform_status) {
        return Err(b"verified PoC TEEP Agent identity is not bound");
    }
    if !protected_final_storage_binding(&platform_status) {
        return Err(b"verified PoC protected storage is not commit capable");
    }
    match candidate.info.component_kind {
        ComponentKind::Catalog => {
            #[cfg(feature = "m9-1-acceptance-only-smoke")]
            return Err(b"M9.1 acceptance-only smoke rejects Catalog candidates");
            #[cfg(not(feature = "m9-1-acceptance-only-smoke"))]
            {
                let exact_component_id = twep_catalog_component_id(b"default").ok_or(
                    b"verified PoC default Catalog component could not be encoded".as_slice(),
                )?;
                if candidate.info.catalog_name != Some(b"default")
                    || candidate.info.component_id != exact_component_id.as_slice()
                {
                    return Err(b"verified PoC Update is not the exact default Catalog component");
                }
                if !crate::catalog_validator::validate_authoritative_catalog(candidate.info.payload)
                {
                    return Err(b"verified PoC Catalog payload is not a valid canonical Catalog");
                }
                let success_payload =
                    success_response_payload(&candidate.info, candidate.update_token)
                        .ok_or(b"verified PoC Catalog Success could not be encoded".as_slice())?;
                if !commit_attestam_catalog_evidence_result(
                    &state,
                    &candidate,
                    evidence_query_response,
                    Some(&kid),
                ) {
                    return Err(b"verified PoC Catalog failed protected commit/readback gates");
                }
                Ok(LiveUpdateAcceptance::CatalogCommitted { success_payload })
            }
        }
        ComponentKind::App => {
            #[cfg(feature = "m9-1-acceptance-only-smoke")]
            {
                if !commit_attestam_acceptance_evidence_result(
                    &state,
                    &candidate,
                    evidence_query_response,
                    Some(&kid),
                ) {
                    return Err(b"M9.1 app acceptance failed protected D043 commit/readback gates");
                }
                Ok(LiveUpdateAcceptance::AcceptanceCommitted)
            }
            #[cfg(not(feature = "m9-1-acceptance-only-smoke"))]
            {
                let command = candidate
                    .info
                    .app_command
                    .ok_or(b"verified PoC app component has no command".as_slice())?;
                let catalog = host_io::read_file_alloc(b"catalog/catalog.cbor", 65_536)
                    .ok_or(b"verified PoC app requires an active protected Catalog".as_slice())?;
                if !crate::catalog_validator::validate_authoritative_catalog(&catalog)
                    || !crate::catalog::authorizes_app_payload(
                        &catalog,
                        command,
                        &candidate.payload_sha256,
                    )
                {
                    return Err(b"verified PoC app is not authorized by the protected Catalog");
                }
                let success_payload =
                    success_response_payload(&candidate.info, candidate.update_token)
                        .ok_or(b"verified PoC app Success could not be encoded".as_slice())?;
                if !commit_attestam_app_evidence_result(
                    &state,
                    &candidate,
                    evidence_query_response,
                    Some(&kid),
                ) {
                    return Err(b"verified PoC app failed protected commit/readback gates");
                }
                Ok(LiveUpdateAcceptance::AppCommitted { success_payload })
            }
        }
        ComponentKind::Unsupported => Err(b"verified PoC Update component is unsupported"),
    }
}

#[cfg(feature = "m9-1-acceptance-only-smoke")]
fn commit_attestam_acceptance_evidence_result(
    state: &VerificationState,
    candidate: &TeepUpdateCandidate<'_>,
    evidence_query_response: &[u8],
    observed_attestam_kid: Option<&[u8]>,
) -> bool {
    let (binding_status, agent_identity_status, platform_status) =
        attestam_live_acceptance_context(observed_attestam_kid);
    commit_attestam_acceptance_evidence_result_cbor_with(
        state,
        candidate,
        evidence_query_response,
        binding_status,
        &agent_identity_status,
        &platform_status,
        host_io::acceptance_generation,
        host_io::commit_acceptance,
    )
    .is_some()
}

pub(super) fn verified_attestam_update_payload(
    input_cose: &[u8],
    attestam_verification_key: Option<&credential_management::AttestamMessageVerificationKey>,
    state: &mut VerificationState,
) -> Option<Vec<u8>> {
    let payload =
        match outer_teep_cose_sign1_payload_verified_with(input_cose, state, |signature, tbs| {
            verify_attestam_response_signature(attestam_verification_key, signature, tbs)
        }) {
            Ok(payload) => payload,
            Err(error) => {
                log_verified_update_error(match error {
                    CoseSign1VerificationError::Malformed => {
                        b"verified PoC Update COSE is malformed"
                    }
                    CoseSign1VerificationError::MissingPayload => {
                        b"verified PoC Update COSE payload is missing"
                    }
                    CoseSign1VerificationError::SignatureRejected => {
                        b"verified PoC Update COSE signature was rejected"
                    }
                    CoseSign1VerificationError::SignatureUnverified => {
                        b"verified PoC Update COSE verification state is invalid"
                    }
                    CoseSign1VerificationError::UnsupportedAlgorithm => {
                        b"verified PoC Update COSE algorithm is unsupported"
                    }
                });
                return None;
            }
        };
    if teep_message_type(&payload) == Some(TEEP_TYPE_UPDATE) {
        Some(payload)
    } else {
        None
    }
}

pub(super) fn log_verified_update_error(message: &[u8]) {
    #[cfg(not(test))]
    host_io::log(3, message);
    #[cfg(test)]
    let _ = message;
}

pub(super) fn attestam_signed_update_evidence_result_cbor(
    acceptance_generation: u64,
) -> Option<Vec<u8>> {
    if acceptance_generation == 0 {
        return None;
    }
    let mut out = Vec::new();
    if cbor::write_map(&mut out, 5).is_none()
        || cbor::write_text(&mut out, b"schema_version").is_none()
        || cbor::write_uint(&mut out, 2).is_none()
        || cbor::write_text(&mut out, b"decision_source").is_none()
        || cbor::write_text(&mut out, b"attestam-signed-update").is_none()
        || cbor::write_text(&mut out, b"tam_response_verified").is_none()
        || cbor::write_bool(&mut out, true).is_none()
        || cbor::write_text(&mut out, b"challenge_response_bound").is_none()
        || cbor::write_bool(&mut out, true).is_none()
        || cbor::write_text(&mut out, b"acceptance_generation").is_none()
        || cbor::write_uint64(&mut out, acceptance_generation).is_none()
    {
        return None;
    }
    Some(out)
}

pub(super) fn attestam_live_acceptance_context(
    observed_attestam_kid: Option<&[u8]>,
) -> (
    credential_management::TrustAnchorBindingStatus,
    AgentIdentityStatus,
    Vec<u8>,
) {
    let protected_store_status = read_protected_credential_store_status(observed_attestam_kid);
    let platform_policy_status = read_platform_credential_policy_status();
    let platform_status = platform_status_text();
    let protected_storage_binding =
        protected_storage_binding_from_platform_status(&platform_status);
    let binding_status = credential_management::trust_anchor_binding_status(
        protected_store_status,
        platform_policy_status,
        protected_storage_binding,
    );
    let agent_identity_status = protected_agent_identity_status(&platform_status);
    (binding_status, agent_identity_status, platform_status)
}

#[cfg(not(feature = "m9-1-acceptance-only-smoke"))]
pub(super) fn commit_attestam_catalog_evidence_result(
    state: &VerificationState,
    candidate: &TeepUpdateCandidate<'_>,
    evidence_query_response: &[u8],
    observed_attestam_kid: Option<&[u8]>,
) -> bool {
    let (binding_status, agent_identity_status, platform_status) =
        attestam_live_acceptance_context(observed_attestam_kid);
    commit_attestam_catalog_with(
        state,
        candidate,
        evidence_query_response,
        binding_status,
        &agent_identity_status,
        &platform_status,
        host_io::acceptance_generation,
        |digest, component_id, sequence, expected_generation, catalog, catalog_sha256| {
            host_io::commit_catalog(
                digest,
                component_id,
                sequence,
                expected_generation,
                catalog,
                catalog_sha256,
            )
        },
    )
    .is_some()
}

#[cfg(not(feature = "m9-1-acceptance-only-smoke"))]
fn commit_attestam_app_evidence_result(
    state: &VerificationState,
    candidate: &TeepUpdateCandidate<'_>,
    evidence_query_response: &[u8],
    observed_attestam_kid: Option<&[u8]>,
) -> bool {
    let (binding_status, agent_identity_status, platform_status) =
        attestam_live_acceptance_context(observed_attestam_kid);
    commit_attestam_app_with(
        state,
        candidate,
        evidence_query_response,
        binding_status,
        &agent_identity_status,
        &platform_status,
        host_io::acceptance_generation,
        |digest, component_id, sequence, expected_generation, wasm, wasm_sha256| {
            host_io::commit_app(
                digest,
                component_id,
                sequence,
                expected_generation,
                wasm,
                wasm_sha256,
            )
        },
    )
    .is_some()
}

pub(super) fn attestam_acceptance_commit_ready(
    state: &VerificationState,
    candidate: &TeepUpdateCandidate<'_>,
    evidence_query_response: &[u8],
    binding_status: credential_management::TrustAnchorBindingStatus,
    agent_identity_status: &AgentIdentityStatus,
    platform_status: &[u8],
) -> bool {
    !evidence_query_response.is_empty()
        && state.fixture_verified()
        && candidate.manifest_count == 1
        && candidate.info.sequence_number != 0
        && binding_status.bound()
        && agent_identity_status.bound_ready(platform_status)
        && protected_final_storage_binding(platform_status)
}

pub(super) fn attestam_acceptance_commit_input<'a>(
    state: &VerificationState,
    candidate: &'a TeepUpdateCandidate<'a>,
    evidence_query_response: &'a [u8],
    binding_status: credential_management::TrustAnchorBindingStatus,
    agent_identity_status: &AgentIdentityStatus,
    platform_status: &[u8],
) -> Option<([u8; 32], &'a [u8], u64)> {
    if !attestam_acceptance_commit_ready(
        state,
        candidate,
        evidence_query_response,
        binding_status,
        agent_identity_status,
        platform_status,
    ) {
        return None;
    }
    Some((
        sha256(evidence_query_response),
        candidate.info.component_id,
        candidate.info.sequence_number as u64,
    ))
}

#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
pub(super) fn commit_attestam_acceptance_evidence_result_cbor_with<F, G>(
    state: &VerificationState,
    candidate: &TeepUpdateCandidate<'_>,
    evidence_query_response: &[u8],
    binding_status: credential_management::TrustAnchorBindingStatus,
    agent_identity_status: &AgentIdentityStatus,
    platform_status: &[u8],
    current_generation: F,
    commit_acceptance: G,
) -> Option<Vec<u8>>
where
    F: FnOnce() -> Result<u64, i32>,
    G: FnOnce(&[u8; 32], &[u8], u64, u64) -> Result<u64, i32>,
{
    let (digest, component_id, sequence) = attestam_acceptance_commit_input(
        state,
        candidate,
        evidence_query_response,
        binding_status,
        agent_identity_status,
        platform_status,
    )?;
    let expected_generation = current_generation().ok()?;
    let required_generation = expected_generation.checked_add(1)?;
    let new_generation =
        commit_acceptance(&digest, component_id, sequence, expected_generation).ok()?;
    if new_generation != required_generation {
        return None;
    }
    attestam_signed_update_evidence_result_cbor(new_generation)
}

#[allow(clippy::too_many_arguments)]
#[cfg(any(not(feature = "m9-1-acceptance-only-smoke"), test))]
pub(super) fn commit_attestam_catalog_with<F, G>(
    state: &VerificationState,
    candidate: &TeepUpdateCandidate<'_>,
    evidence_query_response: &[u8],
    binding_status: credential_management::TrustAnchorBindingStatus,
    agent_identity_status: &AgentIdentityStatus,
    platform_status: &[u8],
    current_generation: F,
    commit_catalog: G,
) -> Option<u64>
where
    F: FnOnce() -> Result<u64, i32>,
    G: FnOnce(&[u8; 32], &[u8], u64, u64, &[u8], &[u8; 32]) -> Result<u64, i32>,
{
    if candidate.info.component_kind != ComponentKind::Catalog
        || candidate.info.catalog_name != Some(b"default")
        || !crate::catalog_validator::validate_authoritative_catalog(candidate.info.payload)
    {
        return None;
    }
    let exact_component_id = twep_catalog_component_id(b"default")?;
    if candidate.info.component_id != exact_component_id.as_slice() {
        return None;
    }
    let (digest, component_id, sequence) = attestam_acceptance_commit_input(
        state,
        candidate,
        evidence_query_response,
        binding_status,
        agent_identity_status,
        platform_status,
    )?;
    let expected_generation = current_generation().ok()?;
    let required_generation = expected_generation.checked_add(1)?;
    let new_generation = commit_catalog(
        &digest,
        component_id,
        sequence,
        expected_generation,
        candidate.info.payload,
        &candidate.payload_sha256,
    )
    .ok()?;
    if new_generation != required_generation {
        return None;
    }
    Some(new_generation)
}

#[allow(clippy::too_many_arguments)]
#[cfg(any(not(feature = "m9-1-acceptance-only-smoke"), test))]
pub(super) fn commit_attestam_app_with<F, G>(
    state: &VerificationState,
    candidate: &TeepUpdateCandidate<'_>,
    evidence_query_response: &[u8],
    binding_status: credential_management::TrustAnchorBindingStatus,
    agent_identity_status: &AgentIdentityStatus,
    platform_status: &[u8],
    current_generation: F,
    commit_app: G,
) -> Option<u64>
where
    F: FnOnce() -> Result<u64, i32>,
    G: FnOnce(&[u8; 32], &[u8], u64, u64, &[u8], &[u8; 32]) -> Result<u64, i32>,
{
    if candidate.info.component_kind != ComponentKind::App
        || candidate.info.app_command.is_none()
        || candidate.info.payload.is_empty()
    {
        return None;
    }
    let (digest, component_id, sequence) = attestam_acceptance_commit_input(
        state,
        candidate,
        evidence_query_response,
        binding_status,
        agent_identity_status,
        platform_status,
    )?;
    let expected_generation = current_generation().ok()?;
    let required_generation = expected_generation.checked_add(1)?;
    let new_generation = commit_app(
        &digest,
        component_id,
        sequence,
        expected_generation,
        candidate.info.payload,
        &candidate.payload_sha256,
    )
    .ok()?;
    if new_generation != required_generation {
        return None;
    }
    Some(new_generation)
}

pub(super) fn verify_attestam_response_signature(
    key: Option<&credential_management::AttestamMessageVerificationKey>,
    signature: &[u8],
    tbs: &[u8],
) -> bool {
    if let Some(key) = key {
        verify_esp256_signature_with_coordinates(&key.x, &key.y, signature, tbs)
    } else {
        verify_demo_tam_esp256_signature(signature, tbs)
    }
}

pub(super) fn write_verified_update_component_status(candidate: &TeepUpdateCandidate<'_>) -> bool {
    let (kind, name) = match candidate.info.component_kind {
        ComponentKind::App => (b"twep-app-v1".as_slice(), candidate.info.app_command),
        ComponentKind::Catalog => (b"twep-catalog-v1".as_slice(), candidate.info.catalog_name),
        ComponentKind::Unsupported => return false,
    };
    let Some(name) = name else {
        return false;
    };
    let mut status = Vec::new();
    status.extend_from_slice(b"component-kind=");
    status.extend_from_slice(kind);
    status.extend_from_slice(b"\ncomponent-name=");
    status.extend_from_slice(name);
    status.extend_from_slice(b"\npromotion=blocked-final-verified\n");
    host_io::write_file(LAST_TEEP_UPDATE_COMPONENT_STATUS_PATH, &status)
}

pub(super) fn verified_update_candidate<'a>(
    payload: &'a [u8],
    requested_component_id: &[u8],
) -> Result<TeepUpdateCandidate<'a>, ()> {
    if let Ok(candidate) = teep_update_candidate(payload, requested_component_id) {
        return Ok(candidate);
    }
    let candidate = teep_update_candidate_any(payload).map_err(|_| ())?;
    if candidate.info.component_kind == ComponentKind::Catalog {
        return Ok(candidate);
    }
    Err(())
}
