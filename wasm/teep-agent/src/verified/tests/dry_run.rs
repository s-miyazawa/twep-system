// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause

use super::*;

#[test]
fn verified_dry_run_state_reads_step_flags() {
    let mut input = Vec::new();
    cbor::write_map(&mut input, 6).unwrap();
    cbor::write_text(&mut input, b"cose_outer_verified").unwrap();
    cbor::write_bool(&mut input, true).unwrap();
    cbor::write_text(&mut input, b"session_token_bound").unwrap();
    cbor::write_bool(&mut input, true).unwrap();
    cbor::write_text(&mut input, b"suit_auth_verified").unwrap();
    cbor::write_bool(&mut input, false).unwrap();
    cbor::write_text(&mut input, b"sequence_fresh").unwrap();
    cbor::write_bool(&mut input, true).unwrap();
    cbor::write_text(&mut input, b"evidence_affirming").unwrap();
    cbor::write_bool(&mut input, true).unwrap();
    cbor::write_text(&mut input, b"agent_identity_bound").unwrap();
    cbor::write_bool(&mut input, true).unwrap();

    let state = verified_dry_run_state(&input).expect("dry-run state");
    assert_eq!(state.first_missing_step(), Some(VerificationStep::SuitAuth));
    assert!(!state.fixture_verified());
    assert!(!state.final_verified());
    assert!(state.evidence_affirming);
    assert!(state.agent_identity_bound);
}

#[test]
fn verified_dry_run_state_accepts_fixture_verified_shortcut() {
    let mut input = Vec::new();
    cbor::write_map(&mut input, 2).unwrap();
    cbor::write_text(&mut input, b"fixture_verified").unwrap();
    cbor::write_bool(&mut input, true).unwrap();
    cbor::write_text(&mut input, b"trust_anchor_bound").unwrap();
    cbor::write_bool(&mut input, true).unwrap();

    let state = verified_dry_run_state(&input).expect("dry-run state");
    assert_eq!(state.first_missing_step(), None);
    assert_eq!(
        state.first_missing_final_step(),
        Some(VerificationStep::TrustAnchor)
    );
    assert!(state.fixture_verified());
    assert!(!state.final_verified());
}
