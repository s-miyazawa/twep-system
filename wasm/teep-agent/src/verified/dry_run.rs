// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause

use super::*;

pub(crate) fn run_verified_dry_run(out_desc_ptr: u32, requested_component_id: &[u8]) -> i32 {
    let mut state = read_verified_dry_run_state().unwrap_or_default();
    let observed_attestam_kid = read_verified_input_cose_key_id();
    let trust_anchor_status = read_dev_trust_anchor_status(observed_attestam_kid.as_deref());
    let protected_store_status =
        read_protected_credential_store_status(observed_attestam_kid.as_deref());
    let attestam_verification_key = read_attestam_message_verification_key(
        observed_attestam_kid.as_deref().unwrap_or_default(),
    );
    let platform_policy_status = read_platform_credential_policy_status();
    let platform_status = platform_status_text();
    let protected_storage_binding =
        protected_storage_binding_from_platform_status(&platform_status);
    let agent_identity_status = protected_agent_identity_status(&platform_status);
    let agent_identity_status_bytes =
        agent_identity_status_text(&platform_status, &agent_identity_status);
    let binding_status = credential_management::trust_anchor_binding_status(
        protected_store_status,
        platform_policy_status,
        protected_storage_binding,
    );
    let _payload = read_verified_input_cose_state(
        &mut state,
        requested_component_id,
        attestam_verification_key.as_ref(),
    );
    let evidence_status = read_evidence_status();
    let evidence_status_bytes = evidence_status_text(&platform_status, &evidence_status);
    state.set_evidence_affirming(evidence_status.affirming_ready(&platform_status));
    state.set_agent_identity_bound(agent_identity_status.bound_ready(&platform_status));
    if final_trust_anchor_ready(&state, binding_status) {
        state.mark_trust_anchor_bound();
    }
    let Some(state_text) = verification_state_text(&state) else {
        return 4;
    };
    if !host_io::write_file(LAST_TEEP_VERIFIED_STATE_PATH, &state_text) {
        return 127;
    }
    let credential_status = credential_management::credential_status_text(
        observed_attestam_kid.as_deref(),
        trust_anchor_status,
        protected_store_status,
        platform_policy_status,
        binding_status,
    );
    if !host_io::write_file(LAST_TEEP_CREDENTIAL_STATUS_PATH, &credential_status) {
        return 127;
    }
    if !host_io::write_file(LAST_TEEP_PLATFORM_STATUS_PATH, &platform_status) {
        return 127;
    }
    if !host_io::write_file(LAST_TEEP_EVIDENCE_STATUS_PATH, &evidence_status_bytes) {
        return 127;
    }
    if !host_io::write_file(
        LAST_TEEP_AGENT_IDENTITY_STATUS_PATH,
        &agent_identity_status_bytes,
    ) {
        return 127;
    }
    write_output(
        out_desc_ptr,
        &error_output(
            b"teep.verified_required",
            b"verified TEEP/COSE/SUIT is not implemented",
        ),
    )
}

pub(super) fn protected_storage_binding_from_platform_status(
    platform_status: &[u8],
) -> credential_management::ProtectedStorageBinding {
    if line_value_equals(
        platform_status,
        b"sealed-storage-security",
        b"tee-protected",
    ) {
        credential_management::ProtectedStorageBinding::TeeProtected
    } else if line_value_equals(
        platform_status,
        b"sealed-storage-security",
        b"tee-secure-storage-smoke",
    ) {
        credential_management::ProtectedStorageBinding::TeeSecureStorageSmoke
    } else if line_value_equals(
        platform_status,
        b"sealed-storage-security",
        b"tee-ree-fs-secure-storage",
    ) {
        credential_management::ProtectedStorageBinding::TeeReeFsSecureStorage
    } else if line_value_equals(
        platform_status,
        b"sealed-storage-security",
        b"observation-only",
    ) {
        credential_management::ProtectedStorageBinding::ObservationOnly
    } else {
        credential_management::ProtectedStorageBinding::Unsupported
    }
}

pub(super) fn line_value_equals(input: &[u8], key: &[u8], value: &[u8]) -> bool {
    let mut start = 0;
    while start <= input.len() {
        let end = input[start..]
            .iter()
            .position(|b| *b == b'\n')
            .map(|pos| start + pos)
            .unwrap_or(input.len());
        let line = &input[start..end];
        if line.len() == key.len() + 1 + value.len()
            && &line[..key.len()] == key
            && line[key.len()] == b'='
            && &line[key.len() + 1..] == value
        {
            return true;
        }
        if end == input.len() {
            break;
        }
        start = end + 1;
    }
    false
}

pub(super) fn platform_status_text() -> Vec<u8> {
    let mut buf = [0u8; 256];
    match host_io::platform_status(&mut buf) {
        Ok(len) => buf[..len].to_vec(),
        Err(status) => {
            let mut out = Vec::new();
            out.extend_from_slice(b"platform-status=unavailable\nplatform-status-error=");
            append_i32_text(&mut out, status);
            out.push(b'\n');
            out
        }
    }
}

pub(crate) fn trustzone_live_poc_acceptance_supported() -> bool {
    let platform_status = platform_status_text();
    line_value_equals(&platform_status, b"platform-backend", b"trustzone")
        && line_value_equals(&platform_status, b"runtime-location", b"trustzone-ta")
        && line_value_equals(&platform_status, b"teep-agent-location", b"trustzone-ta")
}
