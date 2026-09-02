// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause
use alloc::vec::Vec;

use crate::catalog::resolve_from_catalog;
use crate::cbor;
use crate::cose::{
    demo_agent_public_cose_key, outer_teep_cose_sign1_payload_unverified,
    sign_agent_esp256_cose_sign1, DemoAgentSigner,
};
use crate::evidence;
use crate::freshness::{dev_sequence_freshness_update, dev_sequence_is_fresh_bytes};
use crate::host_io;
use crate::suit::{
    installed_payload_path, teep_update_candidate, update_metadata, ComponentKind,
    SuitManifestInfo, TeepUpdateCandidate, TeepUpdateCandidateError,
};
use crate::teep::{
    query_response_payload, teep_message_token, teep_message_type, TEEP_TYPE_QUERY_REQUEST,
    TEEP_TYPE_UPDATE,
};
use crate::verified::{self, VerificationState};
use crate::wasm_signature;
use crate::{error_output, write_output};

const LAST_TEEP_RESPONSE_PATH: &[u8] = b"teep-agent/last-teep-response.cose";
const LAST_TEEP_PAYLOAD_PATH: &[u8] = b"teep-agent/last-teep-payload.cbor";
const LAST_TEEP_MESSAGE_TYPE_PATH: &[u8] = b"teep-agent/last-teep-message-type.txt";
const LAST_TEEP_QUERY_RESPONSE_PATH: &[u8] = b"teep-agent/last-query-response.cose";
const LAST_TEEP_QUERY_RESPONSE_STATUS_PATH: &[u8] = b"teep-agent/last-query-response-status.txt";
const LAST_TEEP_QUERY_RESPONSE_BODY_PATH: &[u8] = b"teep-agent/last-query-response-body.cose";
const LAST_TEEP_QUERY_RESPONSE_BODY_PAYLOAD_PATH: &[u8] =
    b"teep-agent/last-query-response-body-payload.cbor";
const LAST_TEEP_QUERY_RESPONSE_BODY_TYPE_PATH: &[u8] =
    b"teep-agent/last-query-response-body-message-type.txt";
const LAST_TEEP_ATTESTATION_RESPONSE_PATH: &[u8] =
    b"teep-agent/last-attestation-query-response.cose";
const LAST_TEEP_ATTESTATION_RESPONSE_STATUS_PATH: &[u8] =
    b"teep-agent/last-attestation-query-response-status.txt";
const LAST_TEEP_ATTESTATION_RESPONSE_BODY_PATH: &[u8] =
    b"teep-agent/last-attestation-query-response-body.cose";
const VERIFIED_EVIDENCE_QUERY_RESPONSE_PATH: &[u8] =
    b"teep-agent/verified-evidence-query-response.cose";
const LAST_TEEP_UPDATE_PAYLOAD_HASH_STATUS_PATH: &[u8] =
    b"teep-agent/update-payload-hash-status.txt";
const STAGING_UPDATE_PAYLOAD0_PATH: &[u8] = b"tmp/update-payload-0.bin";
const STAGING_UPDATE_METADATA_PATH: &[u8] = b"tmp/update-staging-metadata.cbor";
const STAGING_UPDATE_STATUS_PATH: &[u8] = b"tmp/update-staging-status.txt";
const INSTALLED_TC_METADATA_PATH: &[u8] = b"components/install-metadata.cbor";
const INSTALLED_TC_STATUS_PATH: &[u8] = b"components/install-status.txt";
const LAST_TEEP_SUCCESS_PAYLOAD_PATH: &[u8] = b"teep-agent/success-payload.cbor";
const LAST_TEEP_SUCCESS_COSE_PATH: &[u8] = b"teep-agent/success.cose";
const LAST_TEEP_SUCCESS_STATUS_PATH: &[u8] = b"teep-agent/success-status.txt";
const LAST_TEEP_SUCCESS_BODY_PATH: &[u8] = b"teep-agent/success-body.cose";
const LAST_TEEP_SESSION_RESULT_PATH: &[u8] = b"teep-agent/last-session-result.txt";
const CATALOG_PATH: &[u8] = b"catalog/catalog.cbor";
const DEV_SEQUENCE_FRESHNESS_PATH: &[u8] = b"teep-agent/dev-sequence-freshness.cbor";
const PROTECTED_SEQUENCE_FRESHNESS_OBJECT: &[u8] = b"protected-sequence-freshness.cbor";
const MAX_VERIFIED_INBOUND_RESPONSE: usize = 131_072;

mod exchange;
mod insecure_install;
mod live;
mod observation;

use exchange::{demo_agent_signer, sign_query_response};
pub(crate) use insecure_install::dev_sequence_is_fresh;
use insecure_install::process_update_payload;
use live::run_attestam_session;
pub(crate) use observation::write_update_candidate as write_update_candidate_observation;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SessionPolicy {
    InsecureInstall,
    VerifiedPocAcceptanceOnly,
}

#[derive(Clone, Copy)]
struct SessionContext<'a> {
    out_desc_ptr: u32,
    attestam_url: &'a [u8],
    requested_component_id: &'a [u8],
    policy: SessionPolicy,
    session_token: Option<&'a [u8]>,
    signer: DemoAgentSigner,
}

pub(crate) fn run_resolve_app(
    out_desc_ptr: u32,
    target_command: &[u8],
    requested_component_id: &[u8],
    attestam_url: &[u8],
) -> i32 {
    let catalog_path = b"catalog/catalog.cbor";
    let probe_path = b"tmp/teep-agent-probe";
    let mut probe = [0u8; 64];
    let prefix = b"target_command=";
    if prefix.len() + target_command.len() + 1 > probe.len() {
        return 2;
    }
    probe[..prefix.len()].copy_from_slice(prefix);
    probe[prefix.len()..prefix.len() + target_command.len()].copy_from_slice(target_command);
    let probe_len = prefix.len() + target_command.len() + 1;
    probe[probe_len - 1] = b'\n';

    let mut random_probe = [0u8; 8];
    if !host_io::random(&mut random_probe) {
        return 127;
    }
    let _now = host_io::unix_time_ms();

    if !attestam_url.is_empty() {
        match run_attestam_session(
            out_desc_ptr,
            attestam_url,
            requested_component_id,
            SessionPolicy::InsecureInstall,
        ) {
            Ok(Some(true)) => {
                return resolve_catalog(
                    out_desc_ptr,
                    catalog_path,
                    target_command,
                    probe_path,
                    &probe[..probe_len],
                )
            }
            Ok(Some(false)) => {
                return write_output(
                    out_desc_ptr,
                    &error_output(
                        b"teep.protocol",
                        b"AttesTAM TC is not a twep-app-v1 Wasm app",
                    ),
                );
            }
            Ok(None) => {}
            Err(code) => return code,
        }
    }

    resolve_catalog(
        out_desc_ptr,
        catalog_path,
        target_command,
        probe_path,
        &probe[..probe_len],
    )
}

pub(crate) fn run_verified_poc_resolve(
    out_desc_ptr: u32,
    target_command: &[u8],
    attestam_url: &[u8],
    app_component_id: &[u8],
) -> i32 {
    #[cfg(not(feature = "m9-1-acceptance-only-smoke"))]
    let catalog = host_io::read_file_alloc(CATALOG_PATH, 65_536);
    #[cfg(not(feature = "m9-1-acceptance-only-smoke"))]
    if let Some(catalog) = catalog.as_deref() {
        if !crate::catalog_validator::validate_authoritative_catalog(catalog) {
            return write_output(
                out_desc_ptr,
                &error_output(b"catalog.invalid", b"protected Catalog is invalid"),
            );
        }
        if !crate::catalog::authorizes_command(catalog, target_command) {
            return write_output(
                out_desc_ptr,
                &error_output(b"catalog.not_found", b"target command not found"),
            );
        }
        if crate::catalog::protected_app_is_ready(catalog, target_command) {
            return resolve_catalog(
                out_desc_ptr,
                CATALOG_PATH,
                target_command,
                b"tmp/teep-agent-probe",
                b"verified-protected-app\n",
            );
        }
    }
    #[cfg(feature = "m9-1-acceptance-only-smoke")]
    let requested_component_id = app_component_id;
    #[cfg(not(feature = "m9-1-acceptance-only-smoke"))]
    let requested_component_id = if catalog.is_some() {
        app_component_id.to_vec()
    } else {
        match crate::suit::twep_catalog_component_id(b"default") {
            Some(value) => value,
            None => return 4,
        }
    };
    match run_attestam_session(
        out_desc_ptr,
        attestam_url,
        requested_component_id.as_ref(),
        SessionPolicy::VerifiedPocAcceptanceOnly,
    ) {
        #[cfg(feature = "m9-1-acceptance-only-smoke")]
        Ok(Some(true)) => write_output(
            out_desc_ptr,
            &error_output(
                b"teep.verified_required",
                b"M9.1 acceptance committed; installation remains blocked",
            ),
        ),
        #[cfg(not(feature = "m9-1-acceptance-only-smoke"))]
        Ok(Some(true)) => {
            if catalog.is_some() {
                resolve_catalog(
                    out_desc_ptr,
                    CATALOG_PATH,
                    target_command,
                    b"tmp/teep-agent-probe",
                    b"verified-protected-app\n",
                )
            } else {
                if !host_io::write_file(
                    LAST_TEEP_SESSION_RESULT_PATH,
                    b"session-result=teep.verified_required\n",
                ) {
                    return 127;
                }
                write_output(
                    out_desc_ptr,
                    &error_output(
                        b"teep.verified_required",
                        b"protected Catalog committed; rerun to install and execute app",
                    ),
                )
            }
        }
        Ok(_) => write_output(
            out_desc_ptr,
            &error_output(
                b"teep.protocol",
                b"verified PoC requires an immediate Update after Evidence",
            ),
        ),
        Err(code) => code,
    }
}

fn cose_payload_or_error(out_desc_ptr: u32, body: &[u8], message: &[u8]) -> Result<Vec<u8>, i32> {
    let cose_state = VerificationState::default();
    outer_teep_cose_sign1_payload_unverified(body, &cose_state)
        .map_err(|_| write_output(out_desc_ptr, &error_output(b"teep.protocol", message)))
}

fn resolve_catalog(
    out_desc_ptr: u32,
    catalog_path: &[u8],
    target_command: &[u8],
    probe_path: &[u8],
    probe: &[u8],
) -> i32 {
    let out_len = match host_io::read_file_len(catalog_path) {
        Ok(Some(value)) => value,
        Ok(None) | Err(_) => return 127,
    };
    if out_len == 0 {
        return write_output(
            out_desc_ptr,
            &error_output(b"catalog.invalid", b"catalog is empty"),
        );
    }
    let Some(catalog) = host_io::read_file_alloc(catalog_path, out_len) else {
        return 127;
    };
    resolve_from_catalog(out_desc_ptr, &catalog, target_command, probe_path, probe)
}

fn http_status_text(status: i32) -> &'static [u8] {
    match status {
        0 => b"host-status=ok\n",
        2 => b"host-status=response-too-large\n",
        4 => b"host-status=denied\n",
        5 => b"host-status=network\n",
        7 => b"host-status=http-error\n",
        _ => b"host-status=unexpected\n",
    }
}
