// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause

use super::*;
use crate::suit::success_response_payload;

pub(super) fn process_update_payload(
    out_desc_ptr: u32,
    attestam_url: &[u8],
    requested_component_id: &[u8],
    body_payload: &[u8],
) -> Result<bool, i32> {
    observation::observe_manifest_summary(body_payload)?;
    let candidate = match teep_update_candidate(body_payload, requested_component_id) {
        Ok(value) => value,
        Err(TeepUpdateCandidateError::PayloadHashMismatch) => {
            let _ = host_io::write_file(
                LAST_TEEP_UPDATE_PAYLOAD_HASH_STATUS_PATH,
                b"payload-hash=mismatch\n",
            );
            return Err(write_output(
                out_desc_ptr,
                &error_output(
                    b"teep.protocol",
                    TeepUpdateCandidateError::PayloadHashMismatch.message(),
                ),
            ));
        }
        Err(err) => {
            return Err(write_output(
                out_desc_ptr,
                &error_output(b"teep.protocol", err.message()),
            ));
        }
    };
    observation::write_update_candidate_checked(&candidate)?;
    verify_app_payload_signature_or_error(out_desc_ptr, &candidate)?;
    stage_update_or_127(&candidate)?;
    post_success(out_desc_ptr, attestam_url, &candidate)
}

fn verify_app_payload_signature_or_error(
    out_desc_ptr: u32,
    candidate: &TeepUpdateCandidate<'_>,
) -> Result<(), i32> {
    if candidate.info.component_kind != ComponentKind::App {
        return Ok(());
    }
    match wasm_signature::verify_app_signature(candidate.info.payload) {
        Ok(()) => Ok(()),
        Err(_) => Err(write_output(
            out_desc_ptr,
            &error_output(
                b"teep.protocol",
                b"AttesTAM Wasm app code signature verification failed",
            ),
        )),
    }
}

fn stage_update_or_127(candidate: &TeepUpdateCandidate<'_>) -> Result<(), i32> {
    let manifest_info = candidate.info;
    if !host_io::write_file(STAGING_UPDATE_PAYLOAD0_PATH, manifest_info.payload) {
        return Err(127);
    }
    let Some(staging_metadata) = update_metadata(
        &manifest_info,
        &candidate.payload_sha256,
        STAGING_UPDATE_PAYLOAD0_PATH,
    ) else {
        return Err(4);
    };
    if !host_io::write_file(STAGING_UPDATE_METADATA_PATH, &staging_metadata)
        || !host_io::write_file(STAGING_UPDATE_STATUS_PATH, b"staging=ready\n")
    {
        return Err(127);
    }
    Ok(())
}

fn post_success(
    out_desc_ptr: u32,
    attestam_url: &[u8],
    candidate: &TeepUpdateCandidate<'_>,
) -> Result<bool, i32> {
    let manifest_info = candidate.info;
    let Some(success_payload) = success_response_payload(&manifest_info, candidate.update_token)
    else {
        return Err(4);
    };
    if !host_io::write_file(LAST_TEEP_SUCCESS_PAYLOAD_PATH, &success_payload) {
        return Err(127);
    }
    if !dev_sequence_is_fresh(&manifest_info) {
        return Err(write_output(
            out_desc_ptr,
            &error_output(b"teep.protocol", b"AttesTAM SUIT sequence is not fresh"),
        ));
    }
    let success_cose =
        match sign_demo_agent_esp256_cose_sign1(&success_payload, demo_agent_signer()) {
            Ok(signed) => signed,
            Err(_) => {
                return Err(write_output(
                    out_desc_ptr,
                    &error_output(b"teep.protocol", b"AttesTAM Success signing failed"),
                ));
            }
        };
    if !host_io::write_file(LAST_TEEP_SUCCESS_COSE_PATH, &success_cose) {
        return Err(127);
    }
    let mut success_http_buf = [0u8; 2048];
    let (success_status, success_out_len) =
        host_io::http_post(attestam_url, &success_cose, &mut success_http_buf);
    if success_status != 0 && success_status != 2 && success_status != 5 {
        return Err(127);
    }
    if success_status == 5 {
        return Err(write_output(
            out_desc_ptr,
            &error_output(b"teep.network", b"AttesTAM Success POST failed"),
        ));
    }
    if !host_io::write_file(
        LAST_TEEP_SUCCESS_STATUS_PATH,
        http_status_text(success_status),
    ) {
        return Err(127);
    }
    if success_status == 0 && success_out_len == 0 {
        if !host_io::write_file(
            LAST_TEEP_SESSION_RESULT_PATH,
            b"session-result=no-content\n",
        ) {
            return Err(127);
        }
        if !write_dev_sequence_freshness(&manifest_info) {
            return Err(127);
        }
        install_payload(&manifest_info, &candidate.payload_sha256)
    } else if success_status == 0 {
        let success_body_len = core::cmp::min(success_out_len as usize, success_http_buf.len());
        let success_body = &success_http_buf[..success_body_len];
        if !host_io::write_file(LAST_TEEP_SUCCESS_BODY_PATH, success_body) {
            return Err(127);
        }
        Ok(false)
    } else {
        Ok(false)
    }
}

fn install_payload(
    manifest_info: &SuitManifestInfo<'_>,
    payload_hash: &[u8; 32],
) -> Result<bool, i32> {
    let Some(installed_payload_path) = installed_payload_path(manifest_info) else {
        return Err(4);
    };
    if !host_io::write_file(&installed_payload_path, manifest_info.payload) {
        return Err(127);
    }
    let Some(install_metadata) =
        update_metadata(manifest_info, payload_hash, &installed_payload_path)
    else {
        return Err(4);
    };
    if !host_io::write_file(INSTALLED_TC_METADATA_PATH, &install_metadata)
        || !host_io::write_file(INSTALLED_TC_STATUS_PATH, b"install=ready\n")
    {
        return Err(127);
    }
    match manifest_info.component_kind {
        ComponentKind::App => {
            write_promoted_app_catalog(manifest_info, payload_hash)?;
            Ok(true)
        }
        ComponentKind::Catalog => Ok(true),
        ComponentKind::Unsupported => Ok(false),
    }
}

fn write_promoted_app_catalog(
    manifest_info: &SuitManifestInfo<'_>,
    payload_hash: &[u8; 32],
) -> Result<(), i32> {
    let Some(catalog) = promoted_app_catalog(manifest_info, payload_hash) else {
        return Err(4);
    };
    if !host_io::write_file(CATALOG_PATH, &catalog) {
        return Err(127);
    }
    Ok(())
}

fn promoted_app_catalog(
    manifest_info: &SuitManifestInfo<'_>,
    payload_hash: &[u8; 32],
) -> Option<Vec<u8>> {
    let command = manifest_info.app_command?;
    let mut wasm_file = Vec::new();
    wasm_file.extend_from_slice(command);
    wasm_file.extend_from_slice(b".wasm");

    let mut component_id = Vec::new();
    component_id.extend_from_slice(b"twep-app-v1:");
    component_id.extend_from_slice(command);

    let mut out = Vec::new();
    cbor::write_map(&mut out, 3)?;
    cbor::write_text(&mut out, b"schema_version")?;
    cbor::write_uint(&mut out, 1)?;
    cbor::write_text(&mut out, b"source")?;
    cbor::write_text(&mut out, b"attestam-insecure")?;
    cbor::write_text(&mut out, b"apps")?;
    cbor::write_map(&mut out, 1)?;
    cbor::write_text(&mut out, command)?;
    cbor::write_map(&mut out, 5)?;
    cbor::write_text(&mut out, b"component_id")?;
    cbor::write_text(&mut out, &component_id)?;
    cbor::write_text(&mut out, b"version")?;
    cbor::write_text(&mut out, b"0.1.0")?;
    cbor::write_text(&mut out, b"abi")?;
    cbor::write_text(&mut out, b"twep-app-v1")?;
    cbor::write_text(&mut out, b"wasm_file")?;
    cbor::write_text(&mut out, &wasm_file)?;
    cbor::write_text(&mut out, b"sha256")?;
    cbor::write_bytes(&mut out, payload_hash)?;
    Some(out)
}

pub(crate) fn dev_sequence_is_fresh(info: &SuitManifestInfo<'_>) -> bool {
    match read_protected_sequence_freshness_object() {
        Ok(Some(bytes)) => {
            return dev_sequence_is_fresh_bytes(
                Some(&bytes),
                info.component_id,
                info.sequence_number,
            )
            .unwrap_or(false);
        }
        Ok(None) => {}
        Err(()) => return false,
    }
    match read_dev_sequence_freshness_file() {
        Ok(bytes) => {
            dev_sequence_is_fresh_bytes(bytes.as_deref(), info.component_id, info.sequence_number)
                .unwrap_or(false)
        }
        Err(()) => false,
    }
}

fn read_protected_sequence_freshness_object() -> Result<Option<Vec<u8>>, ()> {
    let out_len = match host_io::read_protected_len(PROTECTED_SEQUENCE_FRESHNESS_OBJECT) {
        Ok(value) => value,
        Err(_) => return Err(()),
    };
    let Some(out_len) = out_len else {
        return Ok(None);
    };
    if out_len > 4096 {
        return Err(());
    }
    if out_len == 0 {
        return Ok(Some(Vec::new()));
    }
    match host_io::read_protected_alloc(PROTECTED_SEQUENCE_FRESHNESS_OBJECT, 4096) {
        Some(bytes) => Ok(Some(bytes)),
        None => Err(()),
    }
}

fn write_dev_sequence_freshness(info: &SuitManifestInfo<'_>) -> bool {
    let bytes = match read_dev_sequence_freshness_file() {
        Ok(value) => value,
        Err(()) => return false,
    };
    let updated = match dev_sequence_freshness_update(
        bytes.as_deref(),
        info.component_id,
        info.sequence_number,
    ) {
        Some(value) => value,
        None => return false,
    };
    host_io::write_file(DEV_SEQUENCE_FRESHNESS_PATH, &updated)
}

fn read_dev_sequence_freshness_file() -> Result<Option<Vec<u8>>, ()> {
    let out_len = match host_io::read_file_len(DEV_SEQUENCE_FRESHNESS_PATH) {
        Ok(value) => value,
        Err(_) => return Err(()),
    };
    let Some(out_len) = out_len else {
        return Ok(None);
    };
    if out_len > 4096 {
        return Err(());
    }
    if out_len == 0 {
        return Ok(Some(Vec::new()));
    }
    host_io::read_file_alloc(DEV_SEQUENCE_FRESHNESS_PATH, 4096)
        .map(Some)
        .ok_or(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn promoted_app_catalog_contains_installed_app_entry() {
        let component_id = [
            0x82, 0x4b, b's', b'e', b'c', b'm', b'-', b'a', b'p', b'p', b'-', b'v', b'1', 0x4b,
            b'r', b'e', b'm', b'o', b't', b'e', b'h', b'e', b'l', b'l', b'o',
        ];
        let payload = b"wasm";
        let sha = [0x5a; 32];
        let info = SuitManifestInfo {
            component_id: &component_id,
            component_kind: ComponentKind::App,
            sequence_number: 1,
            manifest_body: b"",
            manifest_digest: b"",
            suit_auth_block: b"",
            payload_digest: b"",
            payload_digest_sha256: &sha,
            payload_uri: b"#remotehello.wasm",
            payload,
            app_command: Some(b"remotehello"),
            catalog_name: None,
        };

        let catalog = promoted_app_catalog(&info, &sha).expect("catalog");

        assert!(catalog
            .windows(b"remotehello".len())
            .any(|v| v == b"remotehello"));
        assert!(catalog
            .windows(b"remotehello.wasm".len())
            .any(|v| v == b"remotehello.wasm"));
        assert!(catalog
            .windows(b"twep-app-v1".len())
            .any(|v| v == b"twep-app-v1"));
        assert!(catalog.windows(sha.len()).any(|v| v == sha));
    }
}
