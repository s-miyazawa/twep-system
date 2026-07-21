// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause

//! Ordered verification state shared by dry-run and live acceptance flows.

use crate::credential_management;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerificationStep {
    CoseOuter,
    SessionToken,
    SuitAuth,
    SequenceFreshness,
    TrustAnchor,
    Evidence,
    AgentIdentity,
}

impl VerificationStep {
    pub fn code(self) -> &'static [u8] {
        match self {
            VerificationStep::CoseOuter => b"teep.cose_outer_unverified",
            VerificationStep::SessionToken => b"teep.session_unbound",
            VerificationStep::SuitAuth => b"teep.suit_auth_unverified",
            VerificationStep::SequenceFreshness => b"teep.sequence_unverified",
            VerificationStep::TrustAnchor => b"teep.trust_anchor_unbound",
            VerificationStep::Evidence => b"teep.evidence_unaffirmed",
            VerificationStep::AgentIdentity => b"teep.agent_identity_unbound",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VerificationState {
    pub(crate) cose_outer_verified: bool,
    pub(crate) session_token_bound: bool,
    pub(crate) suit_auth_verified: bool,
    pub(crate) sequence_fresh: bool,
    pub(crate) trust_anchor_bound: bool,
    pub(crate) evidence_affirming: bool,
    pub(crate) agent_identity_bound: bool,
}

impl VerificationState {
    pub fn mark_cose_outer_verified(&mut self) {
        self.cose_outer_verified = true;
    }
    pub fn cose_outer_verified(&self) -> bool {
        self.cose_outer_verified
    }
    pub fn mark_session_token_bound(&mut self) {
        self.session_token_bound = true;
    }
    pub fn mark_suit_auth_verified(&mut self) {
        self.suit_auth_verified = true;
    }
    pub fn mark_sequence_fresh(&mut self) {
        self.sequence_fresh = true;
    }
    pub fn mark_trust_anchor_bound(&mut self) {
        self.trust_anchor_bound = true;
    }
    pub fn mark_evidence_affirming(&mut self) {
        self.evidence_affirming = true;
    }
    pub fn set_evidence_affirming(&mut self, value: bool) {
        self.evidence_affirming = value;
    }
    pub fn mark_agent_identity_bound(&mut self) {
        self.agent_identity_bound = true;
    }
    pub fn set_agent_identity_bound(&mut self, value: bool) {
        self.agent_identity_bound = value;
    }

    pub fn first_missing_step(&self) -> Option<VerificationStep> {
        if !self.cose_outer_verified {
            Some(VerificationStep::CoseOuter)
        } else if !self.session_token_bound {
            Some(VerificationStep::SessionToken)
        } else if !self.suit_auth_verified {
            Some(VerificationStep::SuitAuth)
        } else if !self.sequence_fresh {
            Some(VerificationStep::SequenceFreshness)
        } else {
            None
        }
    }

    pub fn fixture_verified(&self) -> bool {
        self.first_missing_step().is_none()
    }

    pub fn final_verified(&self) -> bool {
        self.fixture_verified()
            && self.trust_anchor_bound
            && self.evidence_affirming
            && self.agent_identity_bound
            && credential_management::credential_model_ready()
    }

    pub fn first_missing_final_step(&self) -> Option<VerificationStep> {
        self.first_missing_step().or(if !self.trust_anchor_bound {
            Some(VerificationStep::TrustAnchor)
        } else if !self.evidence_affirming {
            Some(VerificationStep::Evidence)
        } else if !self.agent_identity_bound {
            Some(VerificationStep::AgentIdentity)
        } else {
            None
        })
    }
}
