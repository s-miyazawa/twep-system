// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AgentIdentityLoadStatus {
    Absent,
    LoadedUnbound,
    Malformed,
    Unsupported,
}

pub(super) struct AgentIdentityStatus {
    pub(super) load_status: AgentIdentityLoadStatus,
    pub(super) backend_match: bool,
    pub(super) runtime_seen: bool,
    pub(super) runtime_match: bool,
    pub(super) teep_agent_seen: bool,
    pub(super) teep_agent_match: bool,
    pub(super) measurement_status: AgentIdentityMeasurementStatus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AgentIdentityMeasurementStatus {
    Absent,
    Unavailable,
    Mismatch,
    Matched,
}

impl AgentIdentityStatus {
    pub(super) fn binding_text(&self, platform_status: &[u8]) -> &'static [u8] {
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

    pub(super) fn bound_ready(&self, platform_status: &[u8]) -> bool {
        self.load_status == AgentIdentityLoadStatus::LoadedUnbound
            && self.backend_match
            && self.runtime_seen
            && self.runtime_match
            && self.teep_agent_seen
            && self.teep_agent_match
            && self.measurement_match_ready()
            && protected_final_storage_binding(platform_status)
    }

    pub(super) fn measurement_match_ready(&self) -> bool {
        self.measurement_status == AgentIdentityMeasurementStatus::Matched
    }
}

pub(super) fn agent_identity_status_text(
    platform_status: &[u8],
    protected_agent_identity: &AgentIdentityStatus,
) -> Vec<u8> {
    let optee = optee_profile(platform_status);
    let optee_backend = optee_backend_name(platform_status);
    let is_linux = line_value_equals(platform_status, b"platform-backend", b"linux");
    let ta_runtime = optee.is_some();
    let ta_agent = optee.is_some();
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
    let agent_observed = is_linux || optee.is_some();

    let mut out = Vec::new();
    out.extend_from_slice(b"agent-identity-model-ready=true\nplatform-backend=");
    if let Some(backend) = optee_backend {
        out.extend_from_slice(backend);
    } else if is_linux {
        out.extend_from_slice(b"linux");
    } else {
        out.extend_from_slice(b"unknown");
    }
    out.extend_from_slice(b"\nruntime-location=");
    if ta_runtime {
        out.extend_from_slice(optee.unwrap().1);
    } else {
        out.extend_from_slice(b"unknown");
    }
    out.extend_from_slice(b"\nteep-agent-location=");
    if ta_agent {
        out.extend_from_slice(optee.unwrap().1);
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
    if optee.is_some() {
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

pub(super) fn protected_agent_identity_status(platform_status: &[u8]) -> AgentIdentityStatus {
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

pub(super) fn protected_agent_identity_status_from_cbor(
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

pub(super) fn agent_identity_measurement_status(
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

pub(super) fn absent_agent_identity_status() -> AgentIdentityStatus {
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

pub(super) fn malformed_agent_identity_status() -> AgentIdentityStatus {
    AgentIdentityStatus {
        load_status: AgentIdentityLoadStatus::Malformed,
        ..absent_agent_identity_status()
    }
}

pub(super) fn unsupported_agent_identity_status() -> AgentIdentityStatus {
    AgentIdentityStatus {
        load_status: AgentIdentityLoadStatus::Unsupported,
        ..absent_agent_identity_status()
    }
}
