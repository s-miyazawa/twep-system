// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause

use super::*;

#[test]
fn live_attestam_update_payload_requires_tam_signature() {
    let payload = b"\x82\x03\xa0";
    let valid = crate::cose::sign_test_update(payload, crate::cose::TestCoseSigner::Tam)
        .expect("signed update");
    let mut valid_state = VerificationState::default();

    assert_eq!(
        verified_attestam_update_payload(&valid, None, &mut valid_state)
            .expect("verified update payload"),
        payload
    );
    assert!(valid_state.cose_outer_verified());

    let signed_by_agent =
        crate::cose::sign_test_update(payload, crate::cose::TestCoseSigner::Agent)
            .expect("signed update");
    let mut state = VerificationState::default();
    assert!(verified_attestam_update_payload(&signed_by_agent, None, &mut state).is_none());
    assert!(!state.cose_outer_verified());
}

#[test]
fn live_attestam_signed_update_commits_positive_v2_result_after_tam_signature() {
    let query_response = b"tagged evidence query response";
    let update_token = b"\x01\x02\x03";
    let app_payload = b"wasm bytes";
    let (update_payload, component_id, _payload_sha256) =
        crate::suit::fixture_test_update_payload_with_suit_auth(
            b"remotehello",
            app_payload,
            app_payload,
            update_token,
        );
    let signed_update =
        crate::cose::sign_test_update(&update_payload, crate::cose::TestCoseSigner::Tam)
            .expect("signed update");
    let mut state = VerificationState::default();

    let verified_payload = verified_attestam_update_payload(&signed_update, None, &mut state)
        .expect("verified update payload");
    let candidate =
        verified_update_candidate(&verified_payload, &component_id).expect("verified candidate");
    assert_eq!(
        mark_verified_update_candidate_state(&mut state, &candidate, true, true),
        b"suit-auth=ok\n"
    );
    assert!(state.fixture_verified());

    let binding_status = bound_trust_anchor_status();
    let agent_identity_status = bound_agent_identity_status();
    let platform_status =
        b"platform-backend=trustzone\nsealed-storage-security=tee-ree-fs-secure-storage\nruntime-location=trustzone-ta\nteep-agent-location=trustzone-ta\n";
    let mut committed = false;
    let result = commit_attestam_acceptance_evidence_result_cbor_with(
        &state,
        &candidate,
        query_response,
        binding_status,
        &agent_identity_status,
        platform_status,
        || Ok(41),
        |digest, got_component_id, sequence, expected_generation| {
            committed = true;
            assert_eq!(*digest, sha256(query_response));
            assert_eq!(got_component_id, component_id.as_slice());
            assert_eq!(sequence, 1);
            assert_eq!(expected_generation, 41);
            Ok(42)
        },
    )
    .expect("positive v2 evidence result");
    assert!(committed);

    let status = evidence_status_from_cbor_with_generation(
        &result,
        EvidenceSource::ProtectedObject,
        Some(42),
    );
    assert_eq!(
        status.decision_source,
        EvidenceDecisionSource::AttestamSignedUpdate
    );
    assert!(status.tam_response_verified);
    assert!(status.challenge_response_bound);
    assert_eq!(
        result,
        attestam_signed_update_evidence_result_cbor(42).expect("expected result")
    );
    assert!(status.acceptance_generation_current);
    assert!(status.affirming_ready(platform_status));
}

#[test]
fn live_catalog_commit_uses_exact_payload_and_dedicated_generation_gate() {
    let mut state = VerificationState::default();
    state.mark_cose_outer_verified();
    state.mark_session_token_bound();
    state.mark_suit_auth_verified();
    state.mark_sequence_fresh();

    let catalog = authoritative_test_catalog();
    let component_id = twep_catalog_component_id(b"default").expect("component id");
    let candidate = catalog_commit_candidate(&component_id, &catalog);
    let query_response = b"tagged evidence query response";
    let platform_status =
        b"platform-backend=trustzone\nsealed-storage-security=tee-ree-fs-secure-storage\nruntime-location=trustzone-ta\nteep-agent-location=trustzone-ta\n";
    let mut committed = false;
    let generation = commit_attestam_catalog_with(
        &state,
        &candidate,
        query_response,
        bound_trust_anchor_status(),
        &bound_agent_identity_status(),
        platform_status,
        || Ok(8),
        |digest, got_component_id, sequence, generation, payload, payload_sha256| {
            committed = true;
            assert_eq!(*digest, sha256(query_response));
            assert_eq!(got_component_id, component_id);
            assert_eq!(sequence, 1);
            assert_eq!(generation, 8);
            assert_eq!(payload, catalog);
            assert_eq!(*payload_sha256, sha256(&catalog));
            Ok(9)
        },
    )
    .expect("Catalog commit generation");
    assert!(committed);
    assert_eq!(generation, 9);

    let app_candidate = attestam_commit_candidate(b"app", 1, 1);
    assert!(commit_attestam_catalog_with(
        &state,
        &app_candidate,
        query_response,
        bound_trust_anchor_status(),
        &bound_agent_identity_status(),
        platform_status,
        || panic!("generation must not be read for an app candidate"),
        |_, _, _, _, _, _| panic!("Catalog commit must not run for an app candidate"),
    )
    .is_none());
}

#[test]
fn live_attestam_accepts_bounded_rolling_tokens() {
    assert!(live_attestam_tokens_bound(
        b"query-request-token",
        b"update-token"
    ));
    assert!(live_attestam_tokens_bound(b"same-token", b"same-token"));
    assert!(!live_attestam_tokens_bound(b"", b"update-token"));
    assert!(!live_attestam_tokens_bound(b"query-request-token", b""));
    assert!(!live_attestam_tokens_bound(&[0u8; 129], b"update-token"));
    assert!(!live_attestam_tokens_bound(
        b"query-request-token",
        &[0u8; 129]
    ));
}

#[test]
fn attestam_acceptance_commit_input_requires_final_capable_bindings() {
    let mut state = VerificationState::default();
    state.mark_cose_outer_verified();
    state.mark_session_token_bound();
    state.mark_suit_auth_verified();
    state.mark_sequence_fresh();

    let component_id = b"\x82\x4btwep-app-v1\x4bremotehello";
    let candidate = attestam_commit_candidate(component_id, 7, 1);
    let binding_status = bound_trust_anchor_status();
    let agent_identity_status = bound_agent_identity_status();
    let trustzone_platform =
        b"platform-backend=trustzone\nsealed-storage-security=tee-ree-fs-secure-storage\nruntime-location=trustzone-ta\nteep-agent-location=trustzone-ta\n";
    let query_response = b"tagged evidence query response";

    let (digest, got_component_id, sequence) = attestam_acceptance_commit_input(
        &state,
        &candidate,
        query_response,
        binding_status,
        &agent_identity_status,
        trustzone_platform,
    )
    .expect("acceptance input");
    assert_eq!(digest, sha256(query_response));
    assert_eq!(got_component_id, component_id);
    assert_eq!(sequence, 7);

    let linux_platform = b"platform-backend=linux\nsealed-storage-security=observation-only\n";
    assert!(attestam_acceptance_commit_input(
        &state,
        &candidate,
        query_response,
        binding_status,
        &agent_identity_status,
        linux_platform,
    )
    .is_none());

    let mut missing_session_state = VerificationState::default();
    missing_session_state.mark_cose_outer_verified();
    missing_session_state.mark_suit_auth_verified();
    missing_session_state.mark_sequence_fresh();
    assert!(attestam_acceptance_commit_input(
        &missing_session_state,
        &candidate,
        query_response,
        binding_status,
        &agent_identity_status,
        trustzone_platform,
    )
    .is_none());

    let zero_sequence = attestam_commit_candidate(component_id, 0, 1);
    assert!(attestam_acceptance_commit_input(
        &state,
        &zero_sequence,
        query_response,
        binding_status,
        &agent_identity_status,
        trustzone_platform,
    )
    .is_none());

    let multi_manifest = attestam_commit_candidate(component_id, 7, 2);
    assert!(attestam_acceptance_commit_input(
        &state,
        &multi_manifest,
        query_response,
        binding_status,
        &agent_identity_status,
        trustzone_platform,
    )
    .is_none());
}

#[test]
fn attestam_acceptance_commit_result_does_not_probe_storage_before_ready() {
    let mut state = VerificationState::default();
    state.mark_cose_outer_verified();
    state.mark_session_token_bound();
    state.mark_suit_auth_verified();
    state.mark_sequence_fresh();

    let component_id = b"\x82\x4btwep-app-v1\x4bremotehello";
    let candidate = attestam_commit_candidate(component_id, 7, 1);
    let binding_status = bound_trust_anchor_status();
    let agent_identity_status = bound_agent_identity_status();
    let platform_status =
        b"platform-backend=trustzone\nsealed-storage-security=tee-ree-fs-secure-storage\nruntime-location=trustzone-ta\nteep-agent-location=trustzone-ta\n";
    let query_response = b"tagged evidence query response";

    let mut missing_sequence_state = VerificationState::default();
    missing_sequence_state.mark_cose_outer_verified();
    missing_sequence_state.mark_session_token_bound();
    missing_sequence_state.mark_suit_auth_verified();
    assert_acceptance_commit_not_ready(
        &missing_sequence_state,
        &candidate,
        query_response,
        binding_status,
        &agent_identity_status,
        platform_status,
    );

    assert_acceptance_commit_not_ready(
        &state,
        &candidate,
        b"",
        binding_status,
        &agent_identity_status,
        platform_status,
    );

    let unbound_trust_anchor = credential_management::TrustAnchorBindingStatus {
        protected_store_bound: false,
        ..binding_status
    };
    assert_acceptance_commit_not_ready(
        &state,
        &candidate,
        query_response,
        unbound_trust_anchor,
        &agent_identity_status,
        platform_status,
    );

    let unbound_agent_identity = AgentIdentityStatus {
        measurement_status: AgentIdentityMeasurementStatus::Mismatch,
        ..bound_agent_identity_status()
    };
    assert_acceptance_commit_not_ready(
        &state,
        &candidate,
        query_response,
        binding_status,
        &unbound_agent_identity,
        platform_status,
    );
}

#[test]
fn attestam_acceptance_commit_result_uses_committed_generation() {
    let mut state = VerificationState::default();
    state.mark_cose_outer_verified();
    state.mark_session_token_bound();
    state.mark_suit_auth_verified();
    state.mark_sequence_fresh();

    let component_id = b"\x82\x4btwep-app-v1\x4bremotehello";
    let candidate = attestam_commit_candidate(component_id, 7, 1);
    let binding_status = bound_trust_anchor_status();
    let agent_identity_status = bound_agent_identity_status();
    let platform_status =
        b"platform-backend=trustzone\nsealed-storage-security=tee-ree-fs-secure-storage\nruntime-location=trustzone-ta\nteep-agent-location=trustzone-ta\n";
    let query_response = b"tagged evidence query response";

    let result = commit_attestam_acceptance_evidence_result_cbor_with(
        &state,
        &candidate,
        query_response,
        binding_status,
        &agent_identity_status,
        platform_status,
        || Ok(12),
        |digest, got_component_id, sequence, expected_generation| {
            assert_eq!(*digest, sha256(query_response));
            assert_eq!(got_component_id, component_id);
            assert_eq!(sequence, 7);
            assert_eq!(expected_generation, 12);
            Ok(13)
        },
    )
    .expect("committed evidence result");

    let status = evidence_status_from_cbor_with_generation(
        &result,
        EvidenceSource::ProtectedObject,
        Some(13),
    );
    assert_eq!(
        status.decision_source,
        EvidenceDecisionSource::AttestamSignedUpdate
    );
    assert!(status.acceptance_generation_current);
    assert!(status.affirming_ready(platform_status));
}

#[test]
fn attestam_acceptance_commit_result_fails_closed_on_commit_error() {
    let mut state = VerificationState::default();
    state.mark_cose_outer_verified();
    state.mark_session_token_bound();
    state.mark_suit_auth_verified();
    state.mark_sequence_fresh();

    let component_id = b"\x82\x4btwep-app-v1\x4bremotehello";
    let candidate = attestam_commit_candidate(component_id, 7, 1);
    let binding_status = bound_trust_anchor_status();
    let agent_identity_status = bound_agent_identity_status();
    let platform_status =
        b"platform-backend=trustzone\nsealed-storage-security=tee-ree-fs-secure-storage\nruntime-location=trustzone-ta\nteep-agent-location=trustzone-ta\n";

    assert!(commit_attestam_acceptance_evidence_result_cbor_with(
        &state,
        &candidate,
        b"tagged evidence query response",
        binding_status,
        &agent_identity_status,
        platform_status,
        || Ok(12),
        |_digest, _component_id, _sequence, _expected_generation| Err(9),
    )
    .is_none());
}

#[test]
fn attestam_acceptance_commit_result_requires_single_generation_advance() {
    let mut state = VerificationState::default();
    state.mark_cose_outer_verified();
    state.mark_session_token_bound();
    state.mark_suit_auth_verified();
    state.mark_sequence_fresh();

    let component_id = b"\x82\x4btwep-app-v1\x4bremotehello";
    let candidate = attestam_commit_candidate(component_id, 7, 1);
    let binding_status = bound_trust_anchor_status();
    let agent_identity_status = bound_agent_identity_status();
    let platform_status =
        b"platform-backend=trustzone\nsealed-storage-security=tee-ree-fs-secure-storage\nruntime-location=trustzone-ta\nteep-agent-location=trustzone-ta\n";

    assert!(commit_attestam_acceptance_evidence_result_cbor_with(
        &state,
        &candidate,
        b"tagged evidence query response",
        binding_status,
        &agent_identity_status,
        platform_status,
        || Ok(12),
        |_digest, _component_id, _sequence, _expected_generation| Ok(14),
    )
    .is_none());
}

#[test]
fn attestam_acceptance_commit_result_fails_closed_when_generation_unsupported() {
    let mut state = VerificationState::default();
    state.mark_cose_outer_verified();
    state.mark_session_token_bound();
    state.mark_suit_auth_verified();
    state.mark_sequence_fresh();

    let component_id = b"\x82\x4btwep-app-v1\x4bremotehello";
    let candidate = attestam_commit_candidate(component_id, 7, 1);
    let binding_status = bound_trust_anchor_status();
    let agent_identity_status = bound_agent_identity_status();
    let platform_status =
        b"platform-backend=trustzone\nsealed-storage-security=tee-ree-fs-secure-storage\nruntime-location=trustzone-ta\nteep-agent-location=trustzone-ta\n";

    assert!(commit_attestam_acceptance_evidence_result_cbor_with(
        &state,
        &candidate,
        b"tagged evidence query response",
        binding_status,
        &agent_identity_status,
        platform_status,
        || Err(8),
        |_digest, _component_id, _sequence, _expected_generation| {
            panic!("commit_acceptance must not run without a current acceptance generation")
        },
    )
    .is_none());
}
