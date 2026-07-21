// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause

//! Stable diagnostic rendering for verified-mode state.

use alloc::vec::Vec;

use super::VerificationState;

fn append_bool_text(out: &mut Vec<u8>, value: bool) {
    out.extend_from_slice(if value { b"true" } else { b"false" });
}

pub(crate) fn verification_state_text(state: &VerificationState) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(b"cose-outer-verified=");
    append_bool_text(&mut out, state.cose_outer_verified);
    out.extend_from_slice(b"\nsession-token-bound=");
    append_bool_text(&mut out, state.session_token_bound);
    out.extend_from_slice(b"\nsuit-auth-verified=");
    append_bool_text(&mut out, state.suit_auth_verified);
    out.extend_from_slice(b"\nsequence-fresh=");
    append_bool_text(&mut out, state.sequence_fresh);
    out.extend_from_slice(b"\nevidence-affirming=");
    append_bool_text(&mut out, state.evidence_affirming);
    out.extend_from_slice(b"\nagent-identity-bound=");
    append_bool_text(&mut out, state.agent_identity_bound);
    out.extend_from_slice(b"\nfixture-verified=");
    append_bool_text(&mut out, state.fixture_verified());
    out.extend_from_slice(b"\ntrust-anchor-bound=");
    append_bool_text(&mut out, state.trust_anchor_bound);
    out.extend_from_slice(b"\nfinal-verified=");
    append_bool_text(&mut out, state.final_verified());
    out.extend_from_slice(b"\nmissing-step=");
    match state.first_missing_step() {
        Some(step) => out.extend_from_slice(step.code()),
        None => out.extend_from_slice(b"none"),
    }
    out.extend_from_slice(b"\nfinal-missing-step=");
    match state.first_missing_final_step() {
        Some(step) => out.extend_from_slice(step.code()),
        None => out.extend_from_slice(b"none"),
    }
    out.push(b'\n');
    Some(out)
}
