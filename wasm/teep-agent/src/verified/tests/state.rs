// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause

use super::*;

#[test]
fn verification_state_reports_first_missing_step() {
    let mut state = VerificationState::default();
    assert_eq!(
        state.first_missing_step(),
        Some(VerificationStep::CoseOuter)
    );
    assert_eq!(
        state.first_missing_step().map(VerificationStep::code),
        Some(b"teep.cose_outer_unverified".as_slice())
    );
    assert!(!state.fixture_verified());
    assert!(!state.final_verified());

    state.mark_cose_outer_verified();
    assert_eq!(
        state.first_missing_step(),
        Some(VerificationStep::SessionToken)
    );
    assert_eq!(
        state.first_missing_step().map(VerificationStep::code),
        Some(b"teep.session_unbound".as_slice())
    );

    state.mark_session_token_bound();
    assert_eq!(state.first_missing_step(), Some(VerificationStep::SuitAuth));
    assert_eq!(
        state.first_missing_step().map(VerificationStep::code),
        Some(b"teep.suit_auth_unverified".as_slice())
    );

    state.mark_suit_auth_verified();
    assert_eq!(
        state.first_missing_step(),
        Some(VerificationStep::SequenceFreshness)
    );
    assert_eq!(
        state.first_missing_step().map(VerificationStep::code),
        Some(b"teep.sequence_unverified".as_slice())
    );

    state.mark_sequence_fresh();
    assert_eq!(state.first_missing_step(), None);
    assert_eq!(
        state.first_missing_final_step(),
        Some(VerificationStep::TrustAnchor)
    );
    assert_eq!(
        state.first_missing_final_step().map(VerificationStep::code),
        Some(b"teep.trust_anchor_unbound".as_slice())
    );
    assert!(state.fixture_verified());
    assert!(!state.final_verified());

    state.mark_trust_anchor_bound();
    assert_eq!(
        state.first_missing_final_step(),
        Some(VerificationStep::Evidence)
    );
    state.mark_evidence_affirming();
    assert_eq!(
        state.first_missing_final_step(),
        Some(VerificationStep::AgentIdentity)
    );
}

#[test]
fn verification_state_text_reports_fixture_and_final_state() {
    let state = VerificationState::default();
    assert_eq!(
        verification_state_text(&state).expect("state text"),
        b"cose-outer-verified=false\nsession-token-bound=false\nsuit-auth-verified=false\nsequence-fresh=false\nevidence-affirming=false\nagent-identity-bound=false\nfixture-verified=false\ntrust-anchor-bound=false\nfinal-verified=false\nmissing-step=teep.cose_outer_unverified\nfinal-missing-step=teep.cose_outer_unverified\n"
            .to_vec()
    );

    let mut complete = VerificationState::default();
    complete.mark_cose_outer_verified();
    complete.mark_session_token_bound();
    complete.mark_suit_auth_verified();
    complete.mark_sequence_fresh();
    assert_eq!(
        verification_state_text(&complete).expect("state text"),
        b"cose-outer-verified=true\nsession-token-bound=true\nsuit-auth-verified=true\nsequence-fresh=true\nevidence-affirming=false\nagent-identity-bound=false\nfixture-verified=true\ntrust-anchor-bound=false\nfinal-verified=false\nmissing-step=none\nfinal-missing-step=teep.trust_anchor_unbound\n".to_vec()
    );
}
