// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause

use super::*;

#[test]
fn evidence_status_keeps_legacy_results_matched_unbound() {
    let file_status = EvidenceStatus {
        load_status: EvidenceLoadStatus::LoadedUnbound,
        source: EvidenceSource::ReeStateFile,
        decision_source: EvidenceDecisionSource::LegacyDirectResult,
        verifier_result: b"affirming",
        nonce_match: true,
        cnf_key_match: true,
        platform_match: true,
        tam_response_verified: false,
        challenge_response_bound: false,
        acceptance_generation_current: false,
    };
    let bound_ree_fs_platform =
        b"platform-backend=trustzone\nsealed-storage-security=tee-ree-fs-secure-storage\nsealed-storage-rollback-protected=false\n";
    assert_eq!(
        file_status.binding_text(bound_ree_fs_platform),
        b"matched-unbound"
    );
    assert!(!file_status.affirming_ready(bound_ree_fs_platform));

    let protected_status = EvidenceStatus {
        source: EvidenceSource::ProtectedObject,
        ..file_status
    };
    assert_eq!(
        protected_status.binding_text(bound_ree_fs_platform),
        b"matched-unbound"
    );
    assert!(!protected_status.affirming_ready(bound_ree_fs_platform));

    let bound_platform =
        b"platform-backend=trustzone\nsealed-storage-security=tee-protected\nsealed-storage-rollback-protected=true\n";
    assert_eq!(file_status.binding_text(bound_platform), b"matched-unbound");
    assert!(!file_status.affirming_ready(bound_platform));
    assert_eq!(
        protected_status.binding_text(bound_platform),
        b"matched-unbound"
    );
    assert!(!protected_status.affirming_ready(bound_platform));
}

#[test]
fn evidence_status_reports_legacy_matches_unbound_when_partial() {
    let status = EvidenceStatus {
        load_status: EvidenceLoadStatus::LoadedUnbound,
        source: EvidenceSource::ReeStateFile,
        decision_source: EvidenceDecisionSource::LegacyDirectResult,
        verifier_result: b"affirming",
        nonce_match: true,
        cnf_key_match: true,
        platform_match: true,
        tam_response_verified: false,
        challenge_response_bound: false,
        acceptance_generation_current: false,
    };
    let platform_status =
        b"platform-backend=trustzone\nsealed-storage-security=tee-ree-fs-secure-storage\nsealed-storage-rollback-protected=false\n";
    assert_eq!(
        status.binding_text(platform_status),
        b"matched-unbound".as_slice()
    );
    assert!(!status.affirming_ready(platform_status));

    let missing_platform = EvidenceStatus {
        platform_match: false,
        ..status
    };
    assert_eq!(
        missing_platform.binding_text(platform_status),
        b"unbound".as_slice()
    );
    assert!(!missing_platform.affirming_ready(platform_status));
}

#[test]
fn evidence_status_from_cbor_keeps_legacy_result_non_final() {
    let mut input = Vec::new();
    cbor::write_map(&mut input, 5).unwrap();
    cbor::write_text(&mut input, b"schema_version").unwrap();
    cbor::write_uint(&mut input, 1).unwrap();
    cbor::write_text(&mut input, b"verifier_result").unwrap();
    cbor::write_text(&mut input, b"affirming").unwrap();
    cbor::write_text(&mut input, b"nonce_match").unwrap();
    cbor::write_bool(&mut input, true).unwrap();
    cbor::write_text(&mut input, b"cnf_key_match").unwrap();
    cbor::write_bool(&mut input, true).unwrap();
    cbor::write_text(&mut input, b"platform_match").unwrap();
    cbor::write_bool(&mut input, true).unwrap();

    let platform_status =
        b"platform-backend=trustzone\nsealed-storage-security=tee-ree-fs-secure-storage\nsealed-storage-rollback-protected=false\n";

    let file_status = evidence_status_from_cbor(&input, EvidenceSource::ReeStateFile);
    assert_eq!(
        file_status.binding_text(platform_status),
        b"matched-unbound"
    );
    assert!(!file_status.affirming_ready(platform_status));

    let protected_status = evidence_status_from_cbor(&input, EvidenceSource::ProtectedObject);
    assert_eq!(
        protected_status.binding_text(platform_status),
        b"matched-unbound"
    );
    assert!(!protected_status.affirming_ready(platform_status));
}

#[test]
fn attestam_evidence_result_v2_requires_verified_response_and_transcript() {
    let platform_status =
        b"platform-backend=trustzone\nsealed-storage-security=tee-ree-fs-secure-storage\nsealed-storage-rollback-protected=false\n";
    let mut input = Vec::new();
    cbor::write_map(&mut input, 5).unwrap();
    cbor::write_text(&mut input, b"schema_version").unwrap();
    cbor::write_uint(&mut input, 2).unwrap();
    cbor::write_text(&mut input, b"decision_source").unwrap();
    cbor::write_text(&mut input, b"attestam-signed-update").unwrap();
    cbor::write_text(&mut input, b"tam_response_verified").unwrap();
    cbor::write_bool(&mut input, true).unwrap();
    cbor::write_text(&mut input, b"challenge_response_bound").unwrap();
    cbor::write_bool(&mut input, false).unwrap();
    cbor::write_text(&mut input, b"acceptance_generation").unwrap();
    cbor::write_uint(&mut input, 7).unwrap();

    let unbound =
        evidence_status_from_cbor_with_generation(&input, EvidenceSource::ProtectedObject, Some(6));
    assert_eq!(unbound.binding_text(platform_status), b"unbound");
    assert!(!unbound.affirming_ready(platform_status));

    let stale = EvidenceStatus {
        challenge_response_bound: true,
        ..unbound
    };
    assert_eq!(stale.binding_text(platform_status), b"unbound");
    assert!(!stale.affirming_ready(platform_status));

    let bound = EvidenceStatus {
        challenge_response_bound: true,
        ..evidence_status_from_cbor_with_generation(
            &input,
            EvidenceSource::ProtectedObject,
            Some(7),
        )
    };
    assert_eq!(bound.binding_text(platform_status), b"bound");
    assert!(bound.affirming_ready(platform_status));
}

#[test]
fn attestam_evidence_result_binds_only_current_commit_generation() {
    let generation = 0x1_0000_0001;
    let input = attestam_signed_update_evidence_result_cbor(generation).expect("evidence cbor");
    let platform_status =
        b"platform-backend=trustzone\nsealed-storage-security=tee-ree-fs-secure-storage\nsealed-storage-rollback-protected=false\n";

    let current = evidence_status_from_cbor_with_generation(
        &input,
        EvidenceSource::ProtectedObject,
        Some(generation),
    );
    assert_eq!(
        current.decision_source,
        EvidenceDecisionSource::AttestamSignedUpdate
    );
    assert!(current.acceptance_generation_current);
    assert_eq!(current.binding_text(platform_status), b"bound");
    assert!(current.affirming_ready(platform_status));

    let stale = evidence_status_from_cbor_with_generation(
        &input,
        EvidenceSource::ProtectedObject,
        Some(generation + 1),
    );
    assert!(!stale.acceptance_generation_current);
    assert_eq!(stale.binding_text(platform_status), b"unbound");
    assert!(!stale.affirming_ready(platform_status));
}

#[test]
fn attestam_signed_update_generation_zero_is_not_a_positive_result() {
    let platform_status =
        b"platform-backend=trustzone\nsealed-storage-security=tee-ree-fs-secure-storage\nsealed-storage-rollback-protected=false\n";
    assert!(attestam_signed_update_evidence_result_cbor(0).is_none());

    let mut input = Vec::new();
    cbor::write_map(&mut input, 5).unwrap();
    cbor::write_text(&mut input, b"schema_version").unwrap();
    cbor::write_uint(&mut input, 2).unwrap();
    cbor::write_text(&mut input, b"decision_source").unwrap();
    cbor::write_text(&mut input, b"attestam-signed-update").unwrap();
    cbor::write_text(&mut input, b"tam_response_verified").unwrap();
    cbor::write_bool(&mut input, true).unwrap();
    cbor::write_text(&mut input, b"challenge_response_bound").unwrap();
    cbor::write_bool(&mut input, true).unwrap();
    cbor::write_text(&mut input, b"acceptance_generation").unwrap();
    cbor::write_uint64(&mut input, 0).unwrap();

    let file_status = evidence_status_from_cbor(&input, EvidenceSource::ReeStateFile);
    assert_eq!(file_status.load_status, EvidenceLoadStatus::Unsupported);
    assert!(!file_status.acceptance_generation_current);
    assert_eq!(file_status.binding_text(platform_status), b"unbound");
    assert!(!file_status.affirming_ready(platform_status));

    let protected_status =
        evidence_status_from_cbor_with_generation(&input, EvidenceSource::ProtectedObject, Some(0));
    assert_eq!(
        protected_status.load_status,
        EvidenceLoadStatus::Unsupported
    );
    assert!(!protected_status.acceptance_generation_current);
    assert_eq!(protected_status.binding_text(platform_status), b"unbound");
    assert!(!protected_status.affirming_ready(platform_status));
}

#[test]
fn direct_verifier_evidence_result_v2_is_not_final_capable() {
    let platform_status =
        b"platform-backend=trustzone\nsealed-storage-security=tee-ree-fs-secure-storage\nsealed-storage-rollback-protected=false\n";
    let mut input = Vec::new();
    cbor::write_map(&mut input, 6).unwrap();
    cbor::write_text(&mut input, b"schema_version").unwrap();
    cbor::write_uint(&mut input, 2).unwrap();
    cbor::write_text(&mut input, b"decision_source").unwrap();
    cbor::write_text(&mut input, b"direct-verifier").unwrap();
    cbor::write_text(&mut input, b"verifier_result").unwrap();
    cbor::write_text(&mut input, b"affirming").unwrap();
    cbor::write_text(&mut input, b"nonce_match").unwrap();
    cbor::write_bool(&mut input, true).unwrap();
    cbor::write_text(&mut input, b"cnf_key_match").unwrap();
    cbor::write_bool(&mut input, true).unwrap();
    cbor::write_text(&mut input, b"platform_match").unwrap();
    cbor::write_bool(&mut input, true).unwrap();

    let status = evidence_status_from_cbor(&input, EvidenceSource::ProtectedObject);
    assert_eq!(status.binding_text(platform_status), b"matched-unbound");
    assert!(!status.affirming_ready(platform_status));
}

#[test]
fn attestam_evidence_result_v2_requires_acceptance_generation() {
    let mut input = Vec::new();
    cbor::write_map(&mut input, 2).unwrap();
    cbor::write_text(&mut input, b"schema_version").unwrap();
    cbor::write_uint(&mut input, 2).unwrap();
    cbor::write_text(&mut input, b"decision_source").unwrap();
    cbor::write_text(&mut input, b"attestam-signed-update").unwrap();

    let status =
        evidence_status_from_cbor_with_generation(&input, EvidenceSource::ProtectedObject, Some(0));
    assert_eq!(status.load_status, EvidenceLoadStatus::Unsupported);
}

#[test]
fn direct_verifier_evidence_result_v2_rejects_acceptance_generation() {
    let mut input = Vec::new();
    cbor::write_map(&mut input, 3).unwrap();
    cbor::write_text(&mut input, b"schema_version").unwrap();
    cbor::write_uint(&mut input, 2).unwrap();
    cbor::write_text(&mut input, b"decision_source").unwrap();
    cbor::write_text(&mut input, b"direct-verifier").unwrap();
    cbor::write_text(&mut input, b"acceptance_generation").unwrap();
    cbor::write_uint(&mut input, 1).unwrap();

    let status =
        evidence_status_from_cbor_with_generation(&input, EvidenceSource::ProtectedObject, Some(1));
    assert_eq!(status.load_status, EvidenceLoadStatus::Unsupported);
}
