// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum EvidenceLoadStatus {
    Absent,
    LoadedUnbound,
    Malformed,
    Unsupported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum EvidenceSource {
    None,
    ReeStateFile,
    ProtectedObject,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum EvidenceDecisionSource {
    None,
    LegacyDirectResult,
    DirectVerifier,
    AttestamSignedUpdate,
}

pub(super) struct EvidenceStatus {
    pub(super) load_status: EvidenceLoadStatus,
    pub(super) source: EvidenceSource,
    pub(super) decision_source: EvidenceDecisionSource,
    pub(super) verifier_result: &'static [u8],
    pub(super) nonce_match: bool,
    pub(super) cnf_key_match: bool,
    pub(super) platform_match: bool,
    pub(super) tam_response_verified: bool,
    pub(super) challenge_response_bound: bool,
    pub(super) acceptance_generation_current: bool,
}

impl EvidenceStatus {
    pub(super) fn binding_text(&self, platform_status: &[u8]) -> &'static [u8] {
        if self.affirming_ready(platform_status) {
            b"bound"
        } else if self.legacy_match_ready() {
            b"matched-unbound"
        } else {
            b"unbound"
        }
    }

    pub(super) fn affirming_ready(&self, platform_status: &[u8]) -> bool {
        self.load_status == EvidenceLoadStatus::LoadedUnbound
            && self.source == EvidenceSource::ProtectedObject
            && self.attestam_acceptance_ready()
            && protected_final_storage_binding(platform_status)
    }

    pub(super) fn legacy_match_ready(&self) -> bool {
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

    pub(super) fn attestam_acceptance_ready(&self) -> bool {
        self.decision_source == EvidenceDecisionSource::AttestamSignedUpdate
            && self.tam_response_verified
            && self.challenge_response_bound
            && self.acceptance_generation_current
    }
}

pub(super) fn evidence_status_text(platform_status: &[u8], status: &EvidenceStatus) -> Vec<u8> {
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

pub(super) fn read_evidence_status() -> EvidenceStatus {
    let protected_status = read_evidence_status_from_protected();
    if protected_status.load_status != EvidenceLoadStatus::Absent {
        return protected_status;
    }
    read_evidence_status_from_file()
}

pub(super) fn read_evidence_status_from_protected() -> EvidenceStatus {
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

pub(super) fn read_evidence_status_from_file() -> EvidenceStatus {
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

pub(super) fn evidence_status_from_cbor(input: &[u8], source: EvidenceSource) -> EvidenceStatus {
    evidence_status_from_cbor_with_generation(input, source, None)
}

pub(super) fn evidence_status_from_cbor_with_generation(
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

pub(super) fn absent_evidence_status() -> EvidenceStatus {
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

pub(super) fn malformed_evidence_status(source: EvidenceSource) -> EvidenceStatus {
    EvidenceStatus {
        load_status: EvidenceLoadStatus::Malformed,
        source,
        ..absent_evidence_status()
    }
}

pub(super) fn unsupported_evidence_status(source: EvidenceSource) -> EvidenceStatus {
    EvidenceStatus {
        load_status: EvidenceLoadStatus::Unsupported,
        source,
        ..absent_evidence_status()
    }
}
