// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause

use super::*;

#[test]
fn agent_identity_status_stays_unbound_without_measurement_match() {
    let status = AgentIdentityStatus {
        load_status: AgentIdentityLoadStatus::LoadedUnbound,
        backend_match: true,
        runtime_seen: true,
        runtime_match: true,
        teep_agent_seen: true,
        teep_agent_match: true,
        measurement_status: AgentIdentityMeasurementStatus::Mismatch,
    };
    let bound_ree_fs_platform =
        b"platform-backend=trustzone\nsealed-storage-security=tee-ree-fs-secure-storage\nsealed-storage-rollback-protected=false\n";
    assert_eq!(
        status.binding_text(bound_ree_fs_platform),
        b"matched-unbound"
    );
    assert!(!status.bound_ready(bound_ree_fs_platform));

    let bound_platform =
        b"platform-backend=trustzone\nsealed-storage-security=tee-protected\nsealed-storage-rollback-protected=true\n";
    assert_eq!(status.binding_text(bound_platform), b"matched-unbound");
    assert!(!status.bound_ready(bound_platform));
}

#[test]
fn final_trust_anchor_requires_fixture_evidence_identity_and_credentials() {
    let mut state = VerificationState::default();
    let binding_status = credential_management::TrustAnchorBindingStatus {
        protected_store_bound: true,
        issuer_allowlist_bound: true,
        store_freshness_bound: true,
        revocation_state_bound: true,
        protected_storage_binding: credential_management::ProtectedStorageBinding::TeeProtected,
    };

    assert!(!final_trust_anchor_ready(&state, binding_status));

    state.mark_cose_outer_verified();
    state.mark_session_token_bound();
    state.mark_suit_auth_verified();
    state.mark_sequence_fresh();
    assert!(state.fixture_verified());
    assert!(!final_trust_anchor_ready(&state, binding_status));

    state.mark_evidence_affirming();
    assert!(!final_trust_anchor_ready(&state, binding_status));

    state.mark_agent_identity_bound();
    assert!(final_trust_anchor_ready(&state, binding_status));

    let unbound_revocation = credential_management::TrustAnchorBindingStatus {
        revocation_state_bound: false,
        ..binding_status
    };
    assert!(!final_trust_anchor_ready(&state, unbound_revocation));
}

#[test]
fn agent_identity_status_requires_locations_and_measurement_for_bound() {
    let status = AgentIdentityStatus {
        load_status: AgentIdentityLoadStatus::LoadedUnbound,
        backend_match: true,
        runtime_seen: true,
        runtime_match: true,
        teep_agent_seen: true,
        teep_agent_match: true,
        measurement_status: AgentIdentityMeasurementStatus::Matched,
    };
    let platform_status =
        b"platform-backend=trustzone\nruntime-location=trustzone-ta\nteep-agent-location=trustzone-ta\nsealed-storage-security=tee-ree-fs-secure-storage\nsealed-storage-rollback-protected=false\n";
    assert_eq!(status.binding_text(platform_status), b"bound".as_slice());
    assert!(status.bound_ready(platform_status));

    let backend_only = AgentIdentityStatus {
        runtime_seen: false,
        runtime_match: false,
        teep_agent_seen: false,
        teep_agent_match: false,
        ..status
    };
    assert_eq!(
        backend_only.binding_text(platform_status),
        b"matched-unbound".as_slice()
    );
    assert!(!backend_only.bound_ready(platform_status));

    let missing_measurement = AgentIdentityStatus {
        measurement_status: AgentIdentityMeasurementStatus::Absent,
        ..status
    };
    assert_eq!(
        missing_measurement.binding_text(platform_status),
        b"matched-unbound".as_slice()
    );
    assert!(!missing_measurement.bound_ready(platform_status));

    let runtime_mismatch = AgentIdentityStatus {
        runtime_match: false,
        ..status
    };
    assert_eq!(
        runtime_mismatch.binding_text(platform_status),
        b"unbound".as_slice()
    );
    assert!(!runtime_mismatch.bound_ready(platform_status));
}

#[test]
fn agent_identity_status_binds_only_with_measurement_match() {
    let status = AgentIdentityStatus {
        load_status: AgentIdentityLoadStatus::LoadedUnbound,
        backend_match: true,
        runtime_seen: true,
        runtime_match: true,
        teep_agent_seen: true,
        teep_agent_match: true,
        measurement_status: AgentIdentityMeasurementStatus::Matched,
    };
    let trustzone_platform =
        b"platform-backend=trustzone\nruntime-location=trustzone-ta\nteep-agent-location=trustzone-ta\nsealed-storage-security=tee-ree-fs-secure-storage\nsealed-storage-rollback-protected=false\n";
    assert_eq!(status.binding_text(trustzone_platform), b"bound");
    assert!(status.bound_ready(trustzone_platform));

    let linux_platform =
        b"platform-backend=linux\nsealed-storage-security=observation-only\nsealed-storage-rollback-protected=false\n";
    assert_eq!(status.binding_text(linux_platform), b"matched-unbound");
    assert!(!status.bound_ready(linux_platform));

    let unavailable = AgentIdentityStatus {
        measurement_status: AgentIdentityMeasurementStatus::Unavailable,
        ..status
    };
    assert_eq!(
        unavailable.binding_text(trustzone_platform),
        b"matched-unbound"
    );
    assert!(!unavailable.bound_ready(trustzone_platform));
}

#[test]
fn protected_agent_identity_runtime_and_location_omission_never_bind() {
    let mut input = Vec::new();
    cbor::write_map(&mut input, 3).unwrap();
    cbor::write_text(&mut input, b"schema_version").unwrap();
    cbor::write_uint(&mut input, 1).unwrap();
    cbor::write_text(&mut input, b"platform_backend").unwrap();
    cbor::write_text(&mut input, b"trustzone").unwrap();
    cbor::write_text(&mut input, b"measurement_sha256").unwrap();
    cbor::write_bytes(&mut input, &[0x42; 32]).unwrap();

    let platform_status = b"platform-backend=trustzone\nruntime-location=trustzone-ta\nteep-agent-location=trustzone-ta\nsealed-storage-security=tee-ree-fs-secure-storage\nsealed-storage-rollback-protected=false\n";
    let status =
        protected_agent_identity_status_from_cbor(&input, platform_status, Some([0x42; 32]));
    assert_eq!(status.binding_text(platform_status), b"matched-unbound");
    assert!(!status.bound_ready(platform_status));
}

#[test]
fn protected_agent_identity_measurement_equality_controls_binding() {
    let mut input = Vec::new();
    cbor::write_map(&mut input, 5).unwrap();
    cbor::write_text(&mut input, b"schema_version").unwrap();
    cbor::write_uint(&mut input, 1).unwrap();
    cbor::write_text(&mut input, b"platform_backend").unwrap();
    cbor::write_text(&mut input, b"trustzone").unwrap();
    cbor::write_text(&mut input, b"runtime_location").unwrap();
    cbor::write_text(&mut input, b"trustzone-ta").unwrap();
    cbor::write_text(&mut input, b"teep_agent_location").unwrap();
    cbor::write_text(&mut input, b"trustzone-ta").unwrap();
    cbor::write_text(&mut input, b"measurement_sha256").unwrap();
    cbor::write_bytes(&mut input, &[0x42; 32]).unwrap();

    let platform_status = b"platform-backend=trustzone\nruntime-location=trustzone-ta\nteep-agent-location=trustzone-ta\nsealed-storage-security=tee-ree-fs-secure-storage\nsealed-storage-rollback-protected=false\n";
    let matched =
        protected_agent_identity_status_from_cbor(&input, platform_status, Some([0x42; 32]));
    assert_eq!(
        matched.measurement_status,
        AgentIdentityMeasurementStatus::Matched
    );
    assert_eq!(matched.binding_text(platform_status), b"bound");
    assert!(matched.bound_ready(platform_status));

    let mismatch =
        protected_agent_identity_status_from_cbor(&input, platform_status, Some([0x24; 32]));
    assert_eq!(
        mismatch.measurement_status,
        AgentIdentityMeasurementStatus::Mismatch
    );
    assert_eq!(mismatch.binding_text(platform_status), b"matched-unbound");
    assert!(!mismatch.bound_ready(platform_status));

    let unavailable = protected_agent_identity_status_from_cbor(&input, platform_status, None);
    assert_eq!(
        unavailable.measurement_status,
        AgentIdentityMeasurementStatus::Unavailable
    );
    assert_eq!(
        unavailable.binding_text(platform_status),
        b"matched-unbound"
    );
    assert!(!unavailable.bound_ready(platform_status));
}

#[test]
fn protected_agent_identity_rejects_unknown_backend() {
    let mut input = Vec::new();
    cbor::write_map(&mut input, 2).unwrap();
    cbor::write_text(&mut input, b"schema_version").unwrap();
    cbor::write_uint(&mut input, 1).unwrap();
    cbor::write_text(&mut input, b"platform_backend").unwrap();
    cbor::write_text(&mut input, b"unknown-backend").unwrap();

    let platform_status = b"platform-backend=arm-optee\n";
    let status = protected_agent_identity_status_from_cbor(&input, platform_status, None);
    assert!(!status.backend_match);
    assert!(!status.bound_ready(platform_status));
}

fn protected_identity(profile: &[u8], location: &[u8]) -> Vec<u8> {
    let mut input = Vec::new();
    cbor::write_map(&mut input, 5).unwrap();
    cbor::write_text(&mut input, b"schema_version").unwrap();
    cbor::write_uint(&mut input, 1).unwrap();
    cbor::write_text(&mut input, b"platform_backend").unwrap();
    cbor::write_text(&mut input, profile).unwrap();
    cbor::write_text(&mut input, b"runtime_location").unwrap();
    cbor::write_text(&mut input, location).unwrap();
    cbor::write_text(&mut input, b"teep_agent_location").unwrap();
    cbor::write_text(&mut input, location).unwrap();
    cbor::write_text(&mut input, b"measurement_sha256").unwrap();
    cbor::write_bytes(&mut input, &[0x42; 32]).unwrap();
    input
}

#[test]
fn optee_profiles_bind_only_to_the_selected_platform() {
    let arm = b"platform-backend=arm-optee\nruntime-location=optee-ta\nteep-agent-location=optee-ta\nsealed-storage-security=tee-ree-fs-secure-storage\n";
    let riscv = b"platform-backend=riscv-optee\nruntime-location=optee-ta\nteep-agent-location=optee-ta\nsealed-storage-security=tee-ree-fs-secure-storage\n";

    let arm_identity = protected_identity(b"arm-optee", b"optee-ta");
    let arm_match = protected_agent_identity_status_from_cbor(&arm_identity, arm, Some([0x42; 32]));
    assert!(arm_match.bound_ready(arm));
    let arm_on_riscv =
        protected_agent_identity_status_from_cbor(&arm_identity, riscv, Some([0x42; 32]));
    assert!(!arm_on_riscv.backend_match);
    assert!(!arm_on_riscv.bound_ready(riscv));

    let riscv_identity = protected_identity(b"riscv-optee", b"optee-ta");
    let riscv_match =
        protected_agent_identity_status_from_cbor(&riscv_identity, riscv, Some([0x42; 32]));
    assert!(riscv_match.bound_ready(riscv));
}

#[test]
fn optee_profiles_reject_mixed_legacy_and_new_locations() {
    let mixed = b"platform-backend=arm-optee\nruntime-location=trustzone-ta\nteep-agent-location=optee-ta\nsealed-storage-security=tee-ree-fs-secure-storage\n";
    let identity = protected_identity(b"arm-optee", b"optee-ta");
    let status = protected_agent_identity_status_from_cbor(&identity, mixed, Some([0x42; 32]));
    assert!(!status.bound_ready(mixed));
    assert!(optee_profile(mixed).is_none());
    assert!(!protected_final_storage_binding(mixed));
}
