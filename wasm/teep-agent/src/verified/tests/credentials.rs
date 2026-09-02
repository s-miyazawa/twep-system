// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause

use super::*;

#[test]
fn selected_protected_tam_key_does_not_fallback_to_demo_key() {
    let payload = b"\x82\x03\xa0";
    let signed =
        crate::cose::sign_agent_esp256_cose_sign1(payload, crate::cose::DemoAgentSigner::Alternate)
            .expect("signed TAM response");
    let wrong_key = credential_management::AttestamMessageVerificationKey {
        x: [8u8; 32],
        y: [8u8; 32],
    };
    let mut state = VerificationState::default();

    assert!(
        outer_teep_cose_sign1_payload_verified_with(&signed, &mut state, |signature, tbs| {
            verify_attestam_response_signature(Some(&wrong_key), signature, tbs)
        })
        .is_err()
    );
    assert!(!state.cose_outer_verified());
}

#[test]
fn live_suit_auth_uses_unique_kid_selected_protected_content_key() {
    let manifest_body = b"manifest-body";
    let manifest_digest = suit_manifest_digest_raw(manifest_body).expect("manifest digest");
    let kid = b"fixed-dev-suit-key";
    let (auth_block, x, y) = signed_test_suit_auth(&manifest_digest, Some(kid), None);
    let protected_store = test_protected_credential_store(kid, &x, &y, false);
    let candidate = test_suit_auth_candidate(manifest_body, &manifest_digest, &auth_block);

    assert_eq!(
        live_suit_auth_status_with_protected_store(&candidate, &protected_store),
        b"suit-auth=ok\n"
    );

    let missing_store = test_protected_credential_store(b"different-kid", &x, &y, false);
    assert_eq!(
        live_suit_auth_status_with_protected_store(&candidate, &missing_store),
        b"suit-auth=signature-mismatch\n"
    );

    let duplicate_store = test_protected_credential_store(kid, &x, &y, true);
    assert_eq!(
        live_suit_auth_status_with_protected_store(&candidate, &duplicate_store),
        b"suit-auth=signature-mismatch\n"
    );
}

#[test]
fn live_suit_auth_rejects_absent_or_ambiguous_detached_cose_kid() {
    let manifest_body = b"manifest-body";
    let manifest_digest = suit_manifest_digest_raw(manifest_body).expect("manifest digest");
    let kid = b"fixed-dev-suit-key";
    let (without_kid, x, y) = signed_test_suit_auth(&manifest_digest, None, None);
    let protected_store = test_protected_credential_store(kid, &x, &y, false);
    let candidate = test_suit_auth_candidate(manifest_body, &manifest_digest, &without_kid);
    assert_eq!(
        live_suit_auth_status_with_protected_store(&candidate, &protected_store),
        b"suit-auth=signature-mismatch\n"
    );

    let (ambiguous, _, _) =
        signed_test_suit_auth(&manifest_digest, Some(kid), Some(b"second-header-kid"));
    let candidate = test_suit_auth_candidate(manifest_body, &manifest_digest, &ambiguous);
    assert_eq!(
        live_suit_auth_status_with_protected_store(&candidate, &protected_store),
        b"suit-auth=signature-mismatch\n"
    );
}
