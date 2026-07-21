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
use crate::suit::{
    success_response_payload, suit_manifest_digest_raw, teep_update_candidate,
    teep_update_candidate_any, twep_catalog_component_id, ComponentKind, TeepUpdateCandidate,
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

mod credentials;
mod diagnostics;
mod dry_run;
mod live_acceptance;
mod state;

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
pub(crate) use live_acceptance::accept_live_attestam_update_cose;
use live_acceptance::*;
pub use state::VerificationState;
#[cfg(test)]
pub use state::VerificationStep;

pub(crate) enum LiveUpdateAcceptance {
    CatalogCommitted { success_payload: Vec<u8> },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EvidenceLoadStatus {
    Absent,
    LoadedUnbound,
    Malformed,
    Unsupported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EvidenceSource {
    None,
    ReeStateFile,
    ProtectedObject,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EvidenceDecisionSource {
    None,
    LegacyDirectResult,
    DirectVerifier,
    AttestamSignedUpdate,
}

struct EvidenceStatus {
    load_status: EvidenceLoadStatus,
    source: EvidenceSource,
    decision_source: EvidenceDecisionSource,
    verifier_result: &'static [u8],
    nonce_match: bool,
    cnf_key_match: bool,
    platform_match: bool,
    tam_response_verified: bool,
    challenge_response_bound: bool,
    acceptance_generation_current: bool,
}

impl EvidenceStatus {
    fn binding_text(&self, platform_status: &[u8]) -> &'static [u8] {
        if self.affirming_ready(platform_status) {
            b"bound"
        } else if self.legacy_match_ready() {
            b"matched-unbound"
        } else {
            b"unbound"
        }
    }

    fn affirming_ready(&self, platform_status: &[u8]) -> bool {
        self.load_status == EvidenceLoadStatus::LoadedUnbound
            && self.source == EvidenceSource::ProtectedObject
            && self.attestam_acceptance_ready()
            && protected_final_storage_binding(platform_status)
    }

    fn legacy_match_ready(&self) -> bool {
        self.load_status == EvidenceLoadStatus::LoadedUnbound
            && matches!(
                self.decision_source,
                EvidenceDecisionSource::LegacyDirectResult | EvidenceDecisionSource::DirectVerifier
            )
            && self.verifier_result == b"affirming"
            && self.nonce_match
            && self.cnf_key_match
            && self.platform_match
    }

    fn attestam_acceptance_ready(&self) -> bool {
        self.decision_source == EvidenceDecisionSource::AttestamSignedUpdate
            && self.tam_response_verified
            && self.challenge_response_bound
            && self.acceptance_generation_current
    }
}

fn evidence_status_text(platform_status: &[u8], status: &EvidenceStatus) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"evidence-model-ready=true\nevidence-source=");
    if status.load_status == EvidenceLoadStatus::LoadedUnbound {
        out.extend_from_slice(b"verified-evidence-result");
    } else {
        out.extend_from_slice(b"none");
    }
    out.extend_from_slice(b"\nevidence-result-load=");
    out.extend_from_slice(match status.load_status {
        EvidenceLoadStatus::Absent => b"absent",
        EvidenceLoadStatus::LoadedUnbound => b"loaded-unbound",
        EvidenceLoadStatus::Malformed => b"malformed",
        EvidenceLoadStatus::Unsupported => b"unsupported",
    });
    out.extend_from_slice(b"\nevidence-verifier-result=");
    out.extend_from_slice(status.verifier_result);
    out.extend_from_slice(b"\nevidence-decision-source=");
    out.extend_from_slice(match status.decision_source {
        EvidenceDecisionSource::None => b"none",
        EvidenceDecisionSource::LegacyDirectResult => b"legacy-direct-result",
        EvidenceDecisionSource::DirectVerifier => b"direct-verifier",
        EvidenceDecisionSource::AttestamSignedUpdate => b"attestam-signed-update",
    });
    out.extend_from_slice(b"\nevidence-nonce-match=");
    append_bool_text(&mut out, status.nonce_match);
    out.extend_from_slice(b"\nevidence-cnf-key-match=");
    append_bool_text(&mut out, status.cnf_key_match);
    out.extend_from_slice(b"\nevidence-platform-match=");
    append_bool_text(&mut out, status.platform_match);
    out.extend_from_slice(b"\nevidence-tam-response-verified=");
    append_bool_text(&mut out, status.tam_response_verified);
    out.extend_from_slice(b"\nevidence-challenge-response-bound=");
    append_bool_text(&mut out, status.challenge_response_bound);
    out.extend_from_slice(b"\nevidence-acceptance-generation-current=");
    append_bool_text(&mut out, status.acceptance_generation_current);
    out.extend_from_slice(b"\nevidence-binding=");
    out.extend_from_slice(status.binding_text(platform_status));
    out.extend_from_slice(b"\nevidence-affirming=");
    append_bool_text(&mut out, status.affirming_ready(platform_status));
    out.push(b'\n');
    out
}

fn read_evidence_status() -> EvidenceStatus {
    let protected_status = read_evidence_status_from_protected();
    if protected_status.load_status != EvidenceLoadStatus::Absent {
        return protected_status;
    }
    read_evidence_status_from_file()
}

fn read_evidence_status_from_protected() -> EvidenceStatus {
    let Some(out_len) =
        (match host_io::read_protected_len(PROTECTED_VERIFIED_EVIDENCE_RESULT_OBJECT) {
            Ok(value) => value,
            Err(_) => return malformed_evidence_status(EvidenceSource::ProtectedObject),
        })
    else {
        return absent_evidence_status();
    };
    if out_len > 4096 {
        return malformed_evidence_status(EvidenceSource::ProtectedObject);
    }
    if out_len == 0 {
        return unsupported_evidence_status(EvidenceSource::ProtectedObject);
    }
    let Some(bytes) =
        host_io::read_protected_alloc(PROTECTED_VERIFIED_EVIDENCE_RESULT_OBJECT, 4096)
    else {
        return malformed_evidence_status(EvidenceSource::ProtectedObject);
    };
    let current_generation = host_io::acceptance_generation().ok();
    evidence_status_from_cbor_with_generation(
        &bytes,
        EvidenceSource::ProtectedObject,
        current_generation,
    )
}

pub(crate) fn protected_evidence_result_is_stale() -> bool {
    let status = read_evidence_status_from_protected();
    host_io::acceptance_generation().is_ok()
        && status.load_status == EvidenceLoadStatus::LoadedUnbound
        && status.decision_source == EvidenceDecisionSource::AttestamSignedUpdate
        && !status.acceptance_generation_current
}

fn read_evidence_status_from_file() -> EvidenceStatus {
    let Some(out_len) = (match host_io::read_file_len(VERIFIED_EVIDENCE_RESULT_PATH) {
        Ok(value) => value,
        Err(_) => return malformed_evidence_status(EvidenceSource::ReeStateFile),
    }) else {
        return absent_evidence_status();
    };
    if out_len > 4096 {
        return malformed_evidence_status(EvidenceSource::ReeStateFile);
    }
    if out_len == 0 {
        return unsupported_evidence_status(EvidenceSource::ReeStateFile);
    }
    let Some(bytes) = host_io::read_file_alloc(VERIFIED_EVIDENCE_RESULT_PATH, 4096) else {
        return malformed_evidence_status(EvidenceSource::ReeStateFile);
    };
    evidence_status_from_cbor(&bytes, EvidenceSource::ReeStateFile)
}

fn evidence_status_from_cbor(input: &[u8], source: EvidenceSource) -> EvidenceStatus {
    evidence_status_from_cbor_with_generation(input, source, None)
}

fn evidence_status_from_cbor_with_generation(
    input: &[u8],
    source: EvidenceSource,
    current_generation: Option<u64>,
) -> EvidenceStatus {
    let pairs = match cbor::value(input) {
        Some(Value::Map(pairs)) => pairs,
        _ => return malformed_evidence_status(source),
    };
    let mut schema_version = 0u8;
    let mut decision_source = EvidenceDecisionSource::None;
    let mut verifier_result: &'static [u8] = b"none";
    let mut nonce_match = false;
    let mut cnf_key_match = false;
    let mut platform_match = false;
    let mut tam_response_verified = false;
    let mut challenge_response_bound = false;
    let mut acceptance_generation = None;

    for (key, value) in pairs {
        let key = match key {
            Value::Text(key) => key,
            _ => return unsupported_evidence_status(source),
        };
        match key.as_str() {
            "schema_version" => match value {
                Value::Integer(value) if value == 1.into() => schema_version = 1,
                Value::Integer(value) if value == 2.into() => schema_version = 2,
                _ => return unsupported_evidence_status(source),
            },
            "decision_source" => match value {
                Value::Text(value) => {
                    decision_source = match value.as_str() {
                        "direct-verifier" => EvidenceDecisionSource::DirectVerifier,
                        "attestam-signed-update" => EvidenceDecisionSource::AttestamSignedUpdate,
                        _ => return unsupported_evidence_status(source),
                    };
                }
                _ => return unsupported_evidence_status(source),
            },
            "verifier_result" => match value {
                Value::Text(value) => {
                    verifier_result = match value.as_str() {
                        "affirming" => b"affirming",
                        "contraindicated" => b"contraindicated",
                        "warning" => b"warning",
                        "none" => b"none",
                        _ => return unsupported_evidence_status(source),
                    };
                }
                _ => return unsupported_evidence_status(source),
            },
            "nonce_match" => match value {
                Value::Bool(value) => nonce_match = value,
                _ => return unsupported_evidence_status(source),
            },
            "cnf_key_match" => match value {
                Value::Bool(value) => cnf_key_match = value,
                _ => return unsupported_evidence_status(source),
            },
            "platform_match" => match value {
                Value::Bool(value) => platform_match = value,
                _ => return unsupported_evidence_status(source),
            },
            "tam_response_verified" => match value {
                Value::Bool(value) => tam_response_verified = value,
                _ => return unsupported_evidence_status(source),
            },
            "challenge_response_bound" => match value {
                Value::Bool(value) => challenge_response_bound = value,
                _ => return unsupported_evidence_status(source),
            },
            "acceptance_generation" => match value {
                Value::Integer(value) => match u64::try_from(value) {
                    Ok(value) => acceptance_generation = Some(value),
                    Err(_) => return unsupported_evidence_status(source),
                },
                _ => return unsupported_evidence_status(source),
            },
            _ => {}
        }
    }
    if schema_version == 0
        || (schema_version == 1 && decision_source != EvidenceDecisionSource::None)
        || (schema_version == 2 && decision_source == EvidenceDecisionSource::None)
    {
        return unsupported_evidence_status(source);
    }
    if schema_version == 1 {
        decision_source = EvidenceDecisionSource::LegacyDirectResult;
    }
    if (decision_source == EvidenceDecisionSource::AttestamSignedUpdate
        && !matches!(acceptance_generation, Some(generation) if generation != 0))
        || (decision_source == EvidenceDecisionSource::DirectVerifier
            && acceptance_generation.is_some())
        || (decision_source == EvidenceDecisionSource::LegacyDirectResult
            && acceptance_generation.is_some())
    {
        return unsupported_evidence_status(source);
    }
    let acceptance_generation_current = acceptance_generation
        .zip(current_generation)
        .map(|(result, current)| result == current)
        .unwrap_or(false);
    EvidenceStatus {
        load_status: EvidenceLoadStatus::LoadedUnbound,
        source,
        decision_source,
        verifier_result,
        nonce_match,
        cnf_key_match,
        platform_match,
        tam_response_verified,
        challenge_response_bound,
        acceptance_generation_current,
    }
}

fn absent_evidence_status() -> EvidenceStatus {
    EvidenceStatus {
        load_status: EvidenceLoadStatus::Absent,
        source: EvidenceSource::None,
        decision_source: EvidenceDecisionSource::None,
        verifier_result: b"none",
        nonce_match: false,
        cnf_key_match: false,
        platform_match: false,
        tam_response_verified: false,
        challenge_response_bound: false,
        acceptance_generation_current: false,
    }
}

fn malformed_evidence_status(source: EvidenceSource) -> EvidenceStatus {
    EvidenceStatus {
        load_status: EvidenceLoadStatus::Malformed,
        source,
        ..absent_evidence_status()
    }
}

fn unsupported_evidence_status(source: EvidenceSource) -> EvidenceStatus {
    EvidenceStatus {
        load_status: EvidenceLoadStatus::Unsupported,
        source,
        ..absent_evidence_status()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AgentIdentityLoadStatus {
    Absent,
    LoadedUnbound,
    Malformed,
    Unsupported,
}

struct AgentIdentityStatus {
    load_status: AgentIdentityLoadStatus,
    backend_match: bool,
    runtime_seen: bool,
    runtime_match: bool,
    teep_agent_seen: bool,
    teep_agent_match: bool,
    measurement_status: AgentIdentityMeasurementStatus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AgentIdentityMeasurementStatus {
    Absent,
    Unavailable,
    Mismatch,
    Matched,
}

impl AgentIdentityStatus {
    fn binding_text(&self, platform_status: &[u8]) -> &'static [u8] {
        if self.bound_ready(platform_status) {
            b"bound"
        } else if self.load_status == AgentIdentityLoadStatus::LoadedUnbound
            && self.backend_match
            && (!self.runtime_seen || self.runtime_match)
            && (!self.teep_agent_seen || self.teep_agent_match)
        {
            b"matched-unbound"
        } else {
            b"unbound"
        }
    }

    fn bound_ready(&self, platform_status: &[u8]) -> bool {
        self.load_status == AgentIdentityLoadStatus::LoadedUnbound
            && self.backend_match
            && self.runtime_seen
            && self.runtime_match
            && self.teep_agent_seen
            && self.teep_agent_match
            && self.measurement_match_ready()
            && protected_final_storage_binding(platform_status)
    }

    fn measurement_match_ready(&self) -> bool {
        self.measurement_status == AgentIdentityMeasurementStatus::Matched
    }
}

fn agent_identity_status_text(
    platform_status: &[u8],
    protected_agent_identity: &AgentIdentityStatus,
) -> Vec<u8> {
    let is_trustzone = line_value_equals(platform_status, b"platform-backend", b"trustzone");
    let is_linux = line_value_equals(platform_status, b"platform-backend", b"linux");
    let ta_runtime = line_value_equals(platform_status, b"runtime-location", b"trustzone-ta");
    let ta_agent = line_value_equals(platform_status, b"teep-agent-location", b"trustzone-ta");
    let rollback_false = line_value_equals(
        platform_status,
        b"sealed-storage-rollback-protected",
        b"false",
    );
    let rollback_true = line_value_equals(
        platform_status,
        b"sealed-storage-rollback-protected",
        b"true",
    );
    let agent_observed = is_linux || (is_trustzone && ta_runtime && ta_agent);

    let mut out = Vec::new();
    out.extend_from_slice(b"agent-identity-model-ready=true\nplatform-backend=");
    if is_trustzone {
        out.extend_from_slice(b"trustzone");
    } else if is_linux {
        out.extend_from_slice(b"linux");
    } else {
        out.extend_from_slice(b"unknown");
    }
    out.extend_from_slice(b"\nruntime-location=");
    if ta_runtime {
        out.extend_from_slice(b"trustzone-ta");
    } else {
        out.extend_from_slice(b"unknown");
    }
    out.extend_from_slice(b"\nteep-agent-location=");
    if ta_agent {
        out.extend_from_slice(b"trustzone-ta");
    } else {
        out.extend_from_slice(b"unknown");
    }
    out.extend_from_slice(b"\nsealed-storage-rollback-protected=");
    if rollback_true {
        out.extend_from_slice(b"true");
    } else if rollback_false {
        out.extend_from_slice(b"false");
    } else {
        out.extend_from_slice(b"unknown");
    }
    out.extend_from_slice(b"\nagent-identity-source=");
    if is_trustzone && ta_runtime && ta_agent {
        out.extend_from_slice(b"platform-status-ta-local");
    } else if is_linux {
        out.extend_from_slice(b"platform-status-linux");
    } else {
        out.extend_from_slice(b"none");
    }
    out.extend_from_slice(b"\nagent-identity-observed=");
    append_bool_text(&mut out, agent_observed);
    out.extend_from_slice(b"\nprotected-agent-identity-load=");
    out.extend_from_slice(match protected_agent_identity.load_status {
        AgentIdentityLoadStatus::Absent => b"absent",
        AgentIdentityLoadStatus::LoadedUnbound => b"loaded-unbound",
        AgentIdentityLoadStatus::Malformed => b"malformed",
        AgentIdentityLoadStatus::Unsupported => b"unsupported",
    });
    out.extend_from_slice(b"\nprotected-agent-identity-backend-match=");
    append_bool_text(&mut out, protected_agent_identity.backend_match);
    out.extend_from_slice(b"\nprotected-agent-identity-runtime-match=");
    append_bool_text(&mut out, protected_agent_identity.runtime_match);
    out.extend_from_slice(b"\nprotected-agent-identity-teep-agent-match=");
    append_bool_text(&mut out, protected_agent_identity.teep_agent_match);
    out.extend_from_slice(b"\nprotected-agent-identity-measurement=");
    out.extend_from_slice(match protected_agent_identity.measurement_status {
        AgentIdentityMeasurementStatus::Absent => b"absent",
        AgentIdentityMeasurementStatus::Unavailable => b"unavailable",
        AgentIdentityMeasurementStatus::Mismatch => b"mismatch",
        AgentIdentityMeasurementStatus::Matched => b"matched",
    });
    out.extend_from_slice(b"\nagent-identity-binding=");
    out.extend_from_slice(protected_agent_identity.binding_text(platform_status));
    out.extend_from_slice(b"\nagent-identity-bound=");
    append_bool_text(
        &mut out,
        protected_agent_identity.bound_ready(platform_status),
    );
    out.push(b'\n');
    out
}

fn protected_agent_identity_status(platform_status: &[u8]) -> AgentIdentityStatus {
    let Some(out_len) = (match host_io::read_protected_len(PROTECTED_AGENT_IDENTITY_OBJECT) {
        Ok(value) => value,
        Err(_) => return malformed_agent_identity_status(),
    }) else {
        return absent_agent_identity_status();
    };
    if out_len > 4096 {
        return malformed_agent_identity_status();
    }
    if out_len == 0 {
        return unsupported_agent_identity_status();
    }
    let Some(bytes) = host_io::read_protected_alloc(PROTECTED_AGENT_IDENTITY_OBJECT, 4096) else {
        return malformed_agent_identity_status();
    };
    let actual_measurement = host_io::teep_agent_measurement_sha256().ok().flatten();
    protected_agent_identity_status_from_cbor(&bytes, platform_status, actual_measurement)
}

fn protected_agent_identity_status_from_cbor(
    input: &[u8],
    platform_status: &[u8],
    actual_measurement: Option<[u8; 32]>,
) -> AgentIdentityStatus {
    let pairs = match cbor::value(input) {
        Some(Value::Map(pairs)) => pairs,
        _ => return malformed_agent_identity_status(),
    };
    let mut schema_ok = false;
    let mut backend_match = false;
    let mut runtime_seen = false;
    let mut runtime_match = false;
    let mut teep_agent_seen = false;
    let mut teep_agent_match = false;
    let mut expected_measurement: Option<[u8; 32]> = None;
    let mut backend_seen = false;

    for (key, value) in pairs {
        let key = match key {
            Value::Text(key) => key,
            _ => return unsupported_agent_identity_status(),
        };
        match key.as_str() {
            "schema_version" => match value {
                Value::Integer(value) if value == 1.into() => schema_ok = true,
                _ => return unsupported_agent_identity_status(),
            },
            "platform_backend" => match value {
                Value::Text(value) => {
                    backend_seen = true;
                    backend_match =
                        line_value_equals(platform_status, b"platform-backend", value.as_bytes());
                }
                _ => return unsupported_agent_identity_status(),
            },
            "runtime_location" => match value {
                Value::Text(value) => {
                    runtime_seen = true;
                    runtime_match =
                        line_value_equals(platform_status, b"runtime-location", value.as_bytes());
                }
                _ => return unsupported_agent_identity_status(),
            },
            "teep_agent_location" => match value {
                Value::Text(value) => {
                    teep_agent_seen = true;
                    teep_agent_match = line_value_equals(
                        platform_status,
                        b"teep-agent-location",
                        value.as_bytes(),
                    );
                }
                _ => return unsupported_agent_identity_status(),
            },
            "measurement_sha256" => match value {
                Value::Bytes(bytes) if bytes.len() == 32 => {
                    let mut measurement = [0u8; 32];
                    measurement.copy_from_slice(bytes.as_slice());
                    expected_measurement = Some(measurement);
                }
                _ => return unsupported_agent_identity_status(),
            },
            _ => {}
        }
    }

    if !schema_ok || !backend_seen {
        return unsupported_agent_identity_status();
    }
    AgentIdentityStatus {
        load_status: AgentIdentityLoadStatus::LoadedUnbound,
        backend_match,
        runtime_seen,
        runtime_match,
        teep_agent_seen,
        teep_agent_match,
        measurement_status: agent_identity_measurement_status(
            expected_measurement,
            actual_measurement,
        ),
    }
}

fn agent_identity_measurement_status(
    expected: Option<[u8; 32]>,
    actual: Option<[u8; 32]>,
) -> AgentIdentityMeasurementStatus {
    match (expected, actual) {
        (None, _) => AgentIdentityMeasurementStatus::Absent,
        (Some(_), None) => AgentIdentityMeasurementStatus::Unavailable,
        (Some(expected), Some(actual)) if expected == actual => {
            AgentIdentityMeasurementStatus::Matched
        }
        (Some(_), Some(_)) => AgentIdentityMeasurementStatus::Mismatch,
    }
}

fn absent_agent_identity_status() -> AgentIdentityStatus {
    AgentIdentityStatus {
        load_status: AgentIdentityLoadStatus::Absent,
        backend_match: false,
        runtime_seen: false,
        runtime_match: false,
        teep_agent_seen: false,
        teep_agent_match: false,
        measurement_status: AgentIdentityMeasurementStatus::Absent,
    }
}

fn malformed_agent_identity_status() -> AgentIdentityStatus {
    AgentIdentityStatus {
        load_status: AgentIdentityLoadStatus::Malformed,
        ..absent_agent_identity_status()
    }
}

fn unsupported_agent_identity_status() -> AgentIdentityStatus {
    AgentIdentityStatus {
        load_status: AgentIdentityLoadStatus::Unsupported,
        ..absent_agent_identity_status()
    }
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
mod tests {
    use super::*;
    use coset::{iana, CoseSign1Builder, HeaderBuilder};
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};

    #[test]
    fn selected_protected_tam_key_does_not_fallback_to_demo_key() {
        let payload = b"\x82\x03\xa0";
        let signed = crate::cose::sign_demo_agent_esp256_cose_sign1(
            payload,
            crate::cose::DemoAgentSigner::Alternate,
        )
        .expect("signed TAM response");
        let wrong_key = credential_management::AttestamMessageVerificationKey {
            x: [8u8; 32],
            y: [8u8; 32],
        };
        let mut state = VerificationState::default();

        assert!(outer_teep_cose_sign1_payload_verified_with(
            &signed,
            &mut state,
            |signature, tbs| {
                verify_attestam_response_signature(Some(&wrong_key), signature, tbs)
            }
        )
        .is_err());
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

        let unbound = evidence_status_from_cbor_with_generation(
            &input,
            EvidenceSource::ProtectedObject,
            Some(6),
        );
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
        let candidate = verified_update_candidate(&verified_payload, &component_id)
            .expect("verified candidate");
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

        let protected_status = evidence_status_from_cbor_with_generation(
            &input,
            EvidenceSource::ProtectedObject,
            Some(0),
        );
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

        let status = evidence_status_from_cbor_with_generation(
            &input,
            EvidenceSource::ProtectedObject,
            Some(0),
        );
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

        let status = evidence_status_from_cbor_with_generation(
            &input,
            EvidenceSource::ProtectedObject,
            Some(1),
        );
        assert_eq!(status.load_status, EvidenceLoadStatus::Unsupported);
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
            b"platform-backend=trustzone\nsealed-storage-security=tee-ree-fs-secure-storage\nsealed-storage-rollback-protected=false\n";
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

    fn signed_test_suit_auth(
        detached_payload: &[u8],
        unprotected_kid: Option<&[u8]>,
        protected_kid: Option<&[u8]>,
    ) -> (Vec<u8>, [u8; 32], [u8; 32]) {
        let signing_key = SigningKey::from_slice(&[3u8; 32]).expect("test signing key");
        let point = signing_key.verifying_key().to_encoded_point(false);
        let mut x = [0u8; 32];
        x.copy_from_slice(point.x().expect("test public x"));
        let mut y = [0u8; 32];
        y.copy_from_slice(point.y().expect("test public y"));
        let mut protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::ESP256)
            .build();
        if let Some(kid) = protected_kid {
            protected.key_id = kid.to_vec();
        }
        let mut unprotected = HeaderBuilder::new().build();
        if let Some(kid) = unprotected_kid {
            unprotected.key_id = kid.to_vec();
        }
        let auth_block = CoseSign1Builder::new()
            .protected(protected)
            .unprotected(unprotected)
            .try_create_detached_signature(detached_payload, &[], |tbs| {
                let signature: Signature = signing_key.sign(tbs);
                Ok::<_, ()>(signature.to_bytes().to_vec())
            })
            .expect("test SUIT auth signature")
            .build()
            .to_vec()
            .expect("test SUIT auth CBOR");
        (auth_block, x, y)
    }

    fn test_protected_credential_store(
        kid: &[u8],
        x: &[u8; 32],
        y: &[u8; 32],
        duplicate: bool,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        cbor::write_map(&mut out, 4).unwrap();
        cbor::write_text(&mut out, b"schema_version").unwrap();
        cbor::write_uint(&mut out, 1).unwrap();
        cbor::write_text(&mut out, b"store_epoch").unwrap();
        cbor::write_uint(&mut out, 1).unwrap();
        cbor::write_text(&mut out, b"attestam_message_verification_keys").unwrap();
        cbor::write_array(&mut out, 0).unwrap();
        cbor::write_text(&mut out, b"suit_content_verification_keys").unwrap();
        cbor::write_array(&mut out, if duplicate { 2 } else { 1 }).unwrap();
        write_test_suit_content_key(&mut out, b"suit-entry", kid, x, y);
        if duplicate {
            write_test_suit_content_key(&mut out, b"duplicate-suit-entry", kid, x, y);
        }
        out
    }

    fn write_test_suit_content_key(
        out: &mut Vec<u8>,
        entry_id: &[u8],
        kid: &[u8],
        x: &[u8; 32],
        y: &[u8; 32],
    ) {
        cbor::write_map(out, 11).unwrap();
        cbor::write_text(out, b"entry_id").unwrap();
        cbor::write_bytes(out, entry_id).unwrap();
        cbor::write_text(out, b"issuer_id").unwrap();
        cbor::write_bytes(out, b"test-issuer").unwrap();
        cbor::write_text(out, b"kid").unwrap();
        cbor::write_bytes(out, kid).unwrap();
        cbor::write_text(out, b"purpose").unwrap();
        cbor::write_text(out, b"suit-content-verification").unwrap();
        cbor::write_text(out, b"alg").unwrap();
        cbor::write_text(out, b"ESP256").unwrap();
        cbor::write_text(out, b"crv").unwrap();
        cbor::write_text(out, b"P-256").unwrap();
        cbor::write_text(out, b"x").unwrap();
        cbor::write_bytes(out, x).unwrap();
        cbor::write_text(out, b"y").unwrap();
        cbor::write_bytes(out, y).unwrap();
        cbor::write_text(out, b"not_before").unwrap();
        cbor::write_uint(out, 1).unwrap();
        cbor::write_text(out, b"not_after").unwrap();
        cbor::write_uint(out, 2).unwrap();
        cbor::write_text(out, b"provisioning_epoch").unwrap();
        cbor::write_uint(out, 1).unwrap();
    }

    fn test_suit_auth_candidate<'a>(
        manifest_body: &'a [u8],
        manifest_digest: &'a [u8],
        auth_block: &'a [u8],
    ) -> TeepUpdateCandidate<'a> {
        TeepUpdateCandidate {
            manifest: b"manifest-envelope",
            manifest_count: 1,
            update_token: b"update-token",
            info: crate::suit::SuitManifestInfo {
                component_id: b"component-id",
                component_kind: ComponentKind::App,
                sequence_number: 1,
                manifest_body,
                manifest_digest,
                suit_auth_block: auth_block,
                payload_digest: b"payload-digest",
                payload_digest_sha256: b"payload-digest-sha256",
                payload_uri: b"#payload",
                payload: b"payload",
                app_command: Some(b"remotehello"),
                catalog_name: None,
            },
            payload_sha256: [0u8; 32],
        }
    }

    fn attestam_commit_candidate<'a>(
        component_id: &'a [u8],
        sequence_number: usize,
        manifest_count: usize,
    ) -> TeepUpdateCandidate<'a> {
        TeepUpdateCandidate {
            manifest: b"manifest",
            manifest_count,
            update_token: b"token",
            info: crate::suit::SuitManifestInfo {
                component_id,
                component_kind: ComponentKind::App,
                sequence_number,
                manifest_body: b"manifest-body",
                manifest_digest: b"manifest-digest",
                suit_auth_block: b"auth-block",
                payload_digest: b"payload-digest",
                payload_digest_sha256: b"payload-digest-sha256",
                payload_uri: b"#payload",
                payload: b"payload",
                app_command: Some(b"remotehello"),
                catalog_name: None,
            },
            payload_sha256: [0u8; 32],
        }
    }

    fn authoritative_test_catalog() -> Vec<u8> {
        let mut catalog = Vec::new();
        cbor::write_map(&mut catalog, 4).unwrap();
        cbor::write_text(&mut catalog, b"apps").unwrap();
        cbor::write_map(&mut catalog, 0).unwrap();
        cbor::write_text(&mut catalog, b"source").unwrap();
        cbor::write_text(&mut catalog, b"test").unwrap();
        cbor::write_text(&mut catalog, b"generated_at").unwrap();
        cbor::write_text(&mut catalog, b"2026-07-11T00:00:00Z").unwrap();
        cbor::write_text(&mut catalog, b"schema_version").unwrap();
        cbor::write_uint(&mut catalog, 1).unwrap();
        catalog
    }

    fn catalog_commit_candidate<'a>(
        component_id: &'a [u8],
        payload: &'a [u8],
    ) -> TeepUpdateCandidate<'a> {
        TeepUpdateCandidate {
            manifest: b"manifest",
            manifest_count: 1,
            update_token: b"token",
            info: crate::suit::SuitManifestInfo {
                component_id,
                component_kind: ComponentKind::Catalog,
                sequence_number: 1,
                manifest_body: b"manifest-body",
                manifest_digest: b"manifest-digest",
                suit_auth_block: b"auth-block",
                payload_digest: b"payload-digest",
                payload_digest_sha256: b"payload-digest-sha256",
                payload_uri: b"#catalog.cbor",
                payload,
                app_command: None,
                catalog_name: Some(b"default"),
            },
            payload_sha256: sha256(payload),
        }
    }

    fn bound_agent_identity_status() -> AgentIdentityStatus {
        AgentIdentityStatus {
            load_status: AgentIdentityLoadStatus::LoadedUnbound,
            backend_match: true,
            runtime_seen: true,
            runtime_match: true,
            teep_agent_seen: true,
            teep_agent_match: true,
            measurement_status: AgentIdentityMeasurementStatus::Matched,
        }
    }

    fn bound_trust_anchor_status() -> credential_management::TrustAnchorBindingStatus {
        credential_management::TrustAnchorBindingStatus {
            protected_store_bound: true,
            issuer_allowlist_bound: true,
            store_freshness_bound: true,
            revocation_state_bound: true,
            protected_storage_binding:
                credential_management::ProtectedStorageBinding::TeeReeFsSecureStorage,
        }
    }

    fn assert_acceptance_commit_not_ready(
        state: &VerificationState,
        candidate: &TeepUpdateCandidate<'_>,
        evidence_query_response: &[u8],
        binding_status: credential_management::TrustAnchorBindingStatus,
        agent_identity_status: &AgentIdentityStatus,
        platform_status: &[u8],
    ) {
        assert!(commit_attestam_acceptance_evidence_result_cbor_with(
            state,
            candidate,
            evidence_query_response,
            binding_status,
            agent_identity_status,
            platform_status,
            || panic!("acceptance_generation must not run before all acceptance gates are ready"),
            |_digest, _component_id, _sequence, _expected_generation| {
                panic!("commit_acceptance must not run before all acceptance gates are ready")
            },
        )
        .is_none());
    }
}
