// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause
use alloc::vec::Vec;

use crate::catalog::resolve_from_catalog;
use crate::cbor;
use crate::cose::{
    outer_teep_cose_sign1_payload_unverified, sign_demo_agent_esp256_cose_sign1, DemoAgentSigner,
};
use crate::evidence;
use crate::freshness::{dev_sequence_freshness_update, dev_sequence_is_fresh_bytes};
use crate::host_io;
use crate::suit::{
    installed_payload_path, success_response_payload, teep_update_candidate, update_metadata,
    ComponentKind, SuitManifestInfo, TeepUpdateCandidate, TeepUpdateCandidateError,
};
use crate::teep::{
    query_response_payload, query_response_payload_with_attestation, teep_message_token,
    teep_message_type, QueryResponsePayloadError, TEEP_TYPE_QUERY_REQUEST, TEEP_TYPE_UPDATE,
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
const DEV_AGENT_PUBLIC_KEY_PATH: &[u8] = b"teep-agent/dev-agent-public-key.cbor";
const DEV_SEQUENCE_FRESHNESS_PATH: &[u8] = b"teep-agent/dev-sequence-freshness.cbor";
const PROTECTED_SEQUENCE_FRESHNESS_OBJECT: &[u8] = b"protected-sequence-freshness.cbor";
const MAX_VERIFIED_INBOUND_RESPONSE: usize = 131_072;
const DEMO_AGENT_PUBLIC_COSE_KEY: &[u8] = &[
    0xa5, 0x01, 0x02, 0x03, 0x28, 0x20, 0x01, 0x21, 0x58, 0x20, 0xbe, 0x7c, 0x56, 0x99, 0x3f, 0x71,
    0x11, 0x45, 0x34, 0xc2, 0xf4, 0xa4, 0xf4, 0xe4, 0x60, 0x67, 0x84, 0xfa, 0x9d, 0x96, 0x35, 0xe1,
    0x22, 0xbc, 0x8a, 0x49, 0x0b, 0x2e, 0x11, 0xfe, 0xb9, 0x32, 0x22, 0x58, 0x20, 0x81, 0x69, 0x6b,
    0x42, 0xc3, 0xbe, 0x1b, 0x24, 0x4c, 0xc0, 0x3b, 0xca, 0x97, 0xf0, 0xce, 0x75, 0xe2, 0xd9, 0x3a,
    0xda, 0x1c, 0xe5, 0x56, 0x62, 0x92, 0x27, 0xf1, 0x0a, 0x8c, 0x2c, 0x5b, 0x29,
];

mod observation;

pub(crate) use observation::write_update_candidate as write_update_candidate_observation;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BuildQueryResponseError {
    AttestationUnsupported,
    MissingToken,
    EncodeFailed,
    PendingHostIo,
}

struct SignedQueryResponse {
    cose: Vec<u8>,
    evidence_bearing: bool,
}

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

pub(crate) fn run_verified_poc_acceptance(
    out_desc_ptr: u32,
    attestam_url: &[u8],
    requested_component_id: &[u8],
) -> i32 {
    match run_attestam_session(
        out_desc_ptr,
        attestam_url,
        requested_component_id,
        SessionPolicy::VerifiedPocAcceptanceOnly,
    ) {
        Ok(Some(true)) => write_output(
            out_desc_ptr,
            &error_output(
                b"teep.verified_required",
                b"insecure PoC Catalog committed; app installation remains blocked",
            ),
        ),
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

fn run_attestam_session(
    out_desc_ptr: u32,
    attestam_url: &[u8],
    requested_component_id: &[u8],
    policy: SessionPolicy,
) -> Result<Option<bool>, i32> {
    let mut http_buf = alloc::vec![
        0u8;
        if policy == SessionPolicy::VerifiedPocAcceptanceOnly {
            MAX_VERIFIED_INBOUND_RESPONSE
        } else {
            2048
        }
    ];
    let empty_body: [u8; 0] = [];
    let (http_status, http_out_len) = host_io::http_post(attestam_url, &empty_body, &mut http_buf);
    if policy == SessionPolicy::VerifiedPocAcceptanceOnly && http_status == 2 {
        return Err(write_output(
            out_desc_ptr,
            &error_output(b"teep.protocol", b"AttesTAM response exceeds 128 KiB"),
        ));
    }
    if http_status != 0 && http_status != 2 && http_status != 5 {
        return Err(127);
    }
    if http_status == 5 {
        return Err(write_output(
            out_desc_ptr,
            &error_output(b"teep.network", b"AttesTAM HTTP request failed"),
        ));
    }
    if http_status != 0 || http_out_len == 0 {
        return Ok(None);
    }

    let response_len = core::cmp::min(http_out_len as usize, http_buf.len());
    let response = &http_buf[..response_len];
    let payload = cose_payload_or_error(
        out_desc_ptr,
        response,
        b"AttesTAM response is not COSE_Sign1",
    )?;
    if !host_io::write_file(LAST_TEEP_RESPONSE_PATH, response) {
        return Err(127);
    }
    if teep_message_type(&payload) != Some(TEEP_TYPE_QUERY_REQUEST) {
        return Err(write_output(
            out_desc_ptr,
            &error_output(
                b"teep.protocol",
                b"AttesTAM TEEP message type is not QueryRequest",
            ),
        ));
    }
    if !host_io::write_file(LAST_TEEP_PAYLOAD_PATH, &payload)
        || !host_io::write_file(LAST_TEEP_MESSAGE_TYPE_PATH, b"query-request\n")
    {
        return Err(127);
    }

    let session_token = teep_message_token(&payload).map(|token| token.to_vec());

    let query_response = sign_query_response(out_desc_ptr, &payload, requested_component_id)?;
    if !host_io::write_file(LAST_TEEP_QUERY_RESPONSE_PATH, &query_response.cose) {
        return Err(127);
    }
    if query_response.evidence_bearing
        && !host_io::write_file(VERIFIED_EVIDENCE_QUERY_RESPONSE_PATH, &query_response.cose)
    {
        return Err(127);
    }
    let (second_status, second_out_len) =
        host_io::http_post(attestam_url, &query_response.cose, &mut http_buf);
    if policy == SessionPolicy::VerifiedPocAcceptanceOnly && second_status == 2 {
        return Err(write_output(
            out_desc_ptr,
            &error_output(b"teep.protocol", b"AttesTAM response exceeds 128 KiB"),
        ));
    }
    if second_status != 0 && second_status != 2 && second_status != 5 {
        return Err(127);
    }
    if second_status == 5 {
        return Err(write_output(
            out_desc_ptr,
            &error_output(b"teep.network", b"AttesTAM QueryResponse POST failed"),
        ));
    }
    if !host_io::write_file(
        LAST_TEEP_QUERY_RESPONSE_STATUS_PATH,
        http_status_text(second_status),
    ) {
        return Err(127);
    }
    let context = SessionContext {
        out_desc_ptr,
        attestam_url,
        requested_component_id,
        policy,
        session_token: session_token.as_deref(),
    };
    handle_session_response(
        &context,
        second_status,
        second_out_len,
        &mut http_buf,
        false,
        if query_response.evidence_bearing {
            Some(query_response.cose.as_slice())
        } else {
            None
        },
    )
    .map(Some)
}

fn handle_session_response(
    context: &SessionContext<'_>,
    status: i32,
    out_len: u32,
    http_buf: &mut [u8],
    attestation_response: bool,
    evidence_query_response: Option<&[u8]>,
) -> Result<bool, i32> {
    if status == 0 && out_len == 0 {
        if !host_io::write_file(
            LAST_TEEP_SESSION_RESULT_PATH,
            b"session-result=no-content\n",
        ) {
            return Err(127);
        }
        return Ok(false);
    }
    if status != 0 {
        return Ok(false);
    }

    let body_len = core::cmp::min(out_len as usize, http_buf.len());
    let body = &http_buf[..body_len];
    let body_path = if attestation_response {
        LAST_TEEP_ATTESTATION_RESPONSE_BODY_PATH
    } else {
        LAST_TEEP_QUERY_RESPONSE_BODY_PATH
    };
    if !host_io::write_file(body_path, body) {
        return Err(127);
    }
    let body_payload = cose_payload_or_error(
        context.out_desc_ptr,
        body,
        if attestation_response {
            b"AttesTAM attestation response is not COSE_Sign1"
        } else {
            b"AttesTAM second response is not COSE_Sign1"
        },
    )?;
    if !attestation_response
        && !host_io::write_file(LAST_TEEP_QUERY_RESPONSE_BODY_PAYLOAD_PATH, &body_payload)
    {
        return Err(127);
    }
    let Some(body_type) = teep_message_type(&body_payload) else {
        return Err(write_output(
            context.out_desc_ptr,
            &error_output(
                b"teep.protocol",
                if attestation_response {
                    b"AttesTAM attestation payload is not TEEP message"
                } else {
                    b"AttesTAM second payload is not TEEP message"
                },
            ),
        ));
    };
    if !attestation_response {
        let body_type_text = if body_type == TEEP_TYPE_UPDATE {
            b"update\n".as_slice()
        } else if body_type == TEEP_TYPE_QUERY_REQUEST {
            b"query-request\n".as_slice()
        } else {
            b"unknown\n".as_slice()
        };
        if !host_io::write_file(LAST_TEEP_QUERY_RESPONSE_BODY_TYPE_PATH, body_type_text) {
            return Err(127);
        }
    }

    if body_type == TEEP_TYPE_UPDATE {
        return match context.policy {
            SessionPolicy::InsecureInstall => process_update_payload(
                context.out_desc_ptr,
                context.attestam_url,
                context.requested_component_id,
                &body_payload,
            ),
            SessionPolicy::VerifiedPocAcceptanceOnly => {
                let Some(evidence_query_response) = evidence_query_response else {
                    return Err(write_output(
                        context.out_desc_ptr,
                        &error_output(
                            b"teep.protocol",
                            b"verified PoC Update was not preceded by Evidence",
                        ),
                    ));
                };
                let Some(session_token) = context.session_token else {
                    return Err(write_output(
                        context.out_desc_ptr,
                        &error_output(
                            b"teep.protocol",
                            b"verified PoC session token is unavailable",
                        ),
                    ));
                };
                match verified::accept_live_attestam_update_cose(
                    body,
                    context.requested_component_id,
                    evidence_query_response,
                    session_token,
                ) {
                    Ok(verified::LiveUpdateAcceptance::CatalogCommitted { success_payload }) => {
                        post_verified_catalog_success(
                            context.out_desc_ptr,
                            context.attestam_url,
                            &success_payload,
                        )
                    }
                    Err(message) => Err(write_output(
                        context.out_desc_ptr,
                        &error_output(b"teep.protocol", message),
                    )),
                }
            }
        };
    }
    if body_type != TEEP_TYPE_QUERY_REQUEST || attestation_response {
        return Ok(false);
    }

    let attestation_response_cose = sign_query_response(
        context.out_desc_ptr,
        &body_payload,
        context.requested_component_id,
    )?;
    if !host_io::write_file(
        LAST_TEEP_ATTESTATION_RESPONSE_PATH,
        &attestation_response_cose.cose,
    ) {
        return Err(127);
    }
    if attestation_response_cose.evidence_bearing
        && !host_io::write_file(
            VERIFIED_EVIDENCE_QUERY_RESPONSE_PATH,
            &attestation_response_cose.cose,
        )
    {
        return Err(127);
    }
    let (attestation_status, attestation_out_len) = host_io::http_post(
        context.attestam_url,
        &attestation_response_cose.cose,
        http_buf,
    );
    if context.policy == SessionPolicy::VerifiedPocAcceptanceOnly && attestation_status == 2 {
        return Err(write_output(
            context.out_desc_ptr,
            &error_output(b"teep.protocol", b"AttesTAM response exceeds 128 KiB"),
        ));
    }
    if attestation_status != 0 && attestation_status != 2 && attestation_status != 5 {
        return Err(127);
    }
    if attestation_status == 5 {
        return Err(write_output(
            context.out_desc_ptr,
            &error_output(
                b"teep.network",
                b"AttesTAM attestation QueryResponse POST failed",
            ),
        ));
    }
    if !host_io::write_file(
        LAST_TEEP_ATTESTATION_RESPONSE_STATUS_PATH,
        http_status_text(attestation_status),
    ) {
        return Err(127);
    }
    let next_context = SessionContext {
        session_token: teep_message_token(&body_payload).or(context.session_token),
        ..*context
    };
    handle_session_response(
        &next_context,
        attestation_status,
        attestation_out_len,
        http_buf,
        true,
        if attestation_response_cose.evidence_bearing {
            Some(attestation_response_cose.cose.as_slice())
        } else {
            None
        },
    )
}

fn post_verified_catalog_success(
    out_desc_ptr: u32,
    attestam_url: &[u8],
    success_payload: &[u8],
) -> Result<bool, i32> {
    if !host_io::write_file(LAST_TEEP_SUCCESS_PAYLOAD_PATH, success_payload) {
        return Err(127);
    }
    let success_cose = match sign_demo_agent_esp256_cose_sign1(success_payload, demo_agent_signer())
    {
        Ok(signed) => signed,
        Err(_) => {
            return Err(write_output(
                out_desc_ptr,
                &error_output(b"teep.protocol", b"AttesTAM Catalog Success signing failed"),
            ));
        }
    };
    if !host_io::write_file(LAST_TEEP_SUCCESS_COSE_PATH, &success_cose) {
        return Err(127);
    }
    let mut response = [0u8; 2048];
    let (status, out_len) = host_io::http_post(attestam_url, &success_cose, &mut response);
    if status != 0 && status != 2 && status != 5 {
        return Err(127);
    }
    if status == 5 {
        return Err(write_output(
            out_desc_ptr,
            &error_output(b"teep.network", b"AttesTAM Catalog Success POST failed"),
        ));
    }
    if !host_io::write_file(LAST_TEEP_SUCCESS_STATUS_PATH, http_status_text(status)) {
        return Err(127);
    }
    if status == 0 && out_len == 0 {
        if !host_io::write_file(
            LAST_TEEP_SESSION_RESULT_PATH,
            b"session-result=no-content\n",
        ) {
            return Err(127);
        }
        Ok(true)
    } else if status == 0 {
        let body_len = core::cmp::min(out_len as usize, response.len());
        if !host_io::write_file(LAST_TEEP_SUCCESS_BODY_PATH, &response[..body_len]) {
            return Err(127);
        }
        Ok(false)
    } else {
        Ok(false)
    }
}

fn sign_query_response(
    out_desc_ptr: u32,
    query_request_payload: &[u8],
    requested_component_id: &[u8],
) -> Result<SignedQueryResponse, i32> {
    let mut agent_public_key_buf = [0u8; 256];
    let mut evidence_buf = [0u8; 1024];
    let query_response = match build_query_response_payload(
        query_request_payload,
        requested_component_id,
        &mut agent_public_key_buf,
        &mut evidence_buf,
    ) {
        Ok(value) => value,
        Err(BuildQueryResponseError::PendingHostIo) => return Err(127),
        Err(err) => {
            return Err(write_output(
                out_desc_ptr,
                &build_query_response_error_output(err),
            ))
        }
    };
    match sign_demo_agent_esp256_cose_sign1(&query_response.payload, demo_agent_signer()) {
        Ok(signed) => Ok(SignedQueryResponse {
            cose: signed,
            evidence_bearing: query_response.evidence_bearing,
        }),
        Err(_) => Err(write_output(
            out_desc_ptr,
            &error_output(b"teep.protocol", b"AttesTAM QueryResponse signing failed"),
        )),
    }
}

struct QueryResponsePayload {
    payload: Vec<u8>,
    evidence_bearing: bool,
}

fn build_query_response_payload(
    query_request_payload: &[u8],
    requested_component_id: &[u8],
    agent_public_key_buf: &mut [u8],
    evidence_buf: &mut [u8],
) -> Result<QueryResponsePayload, BuildQueryResponseError> {
    match query_response_payload(query_request_payload, requested_component_id) {
        Ok(value) => Ok(QueryResponsePayload {
            payload: value,
            evidence_bearing: false,
        }),
        Err(QueryResponsePayloadError::AttestationUnsupported) => {
            let challenge = evidence::query_request_challenge(query_request_payload)
                .ok_or(BuildQueryResponseError::EncodeFailed)?;
            let agent_public_key = demo_agent_public_key(agent_public_key_buf);
            let evidence = evidence::create_eat_evidence(
                challenge,
                agent_public_key,
                evidence_buf,
                |challenge, agent_public_key, out| match host_io::create_evidence(
                    challenge,
                    agent_public_key,
                    out,
                ) {
                    Ok(len) => Ok(len),
                    Err((11, _)) => Err(evidence::EvidenceError::Internal),
                    Err((status, len)) => Err(evidence::host_status_to_evidence_error(status, len)),
                },
            )
            .map_err(|err| match err {
                evidence::EvidenceError::Internal => BuildQueryResponseError::PendingHostIo,
                evidence::EvidenceError::Unsupported => {
                    BuildQueryResponseError::AttestationUnsupported
                }
                _ => BuildQueryResponseError::EncodeFailed,
            })?;
            let payload = query_response_payload_with_attestation(requested_component_id, evidence)
                .map_err(|_| BuildQueryResponseError::EncodeFailed)?;
            Ok(QueryResponsePayload {
                payload,
                evidence_bearing: true,
            })
        }
        Err(QueryResponsePayloadError::MissingToken) => Err(BuildQueryResponseError::MissingToken),
        Err(QueryResponsePayloadError::EncodeFailed) => Err(BuildQueryResponseError::EncodeFailed),
    }
}

fn build_query_response_error_output(err: BuildQueryResponseError) -> Vec<u8> {
    match err {
        BuildQueryResponseError::AttestationUnsupported => error_output(
            b"teep.attestation_unsupported",
            b"AttesTAM QueryRequest attestation challenge is not supported",
        ),
        BuildQueryResponseError::MissingToken => error_output(
            b"teep.protocol",
            b"AttesTAM QueryRequest token is not available",
        ),
        BuildQueryResponseError::EncodeFailed => error_output(
            b"teep.protocol",
            b"AttesTAM QueryResponse payload encoding failed",
        ),
        BuildQueryResponseError::PendingHostIo => {
            error_output(b"teep.protocol", b"AttesTAM QueryResponse host I/O pending")
        }
    }
}

fn demo_agent_public_key(buf: &mut [u8]) -> &[u8] {
    match host_io::read_file(DEV_AGENT_PUBLIC_KEY_PATH, buf) {
        Ok(len) => &buf[..len],
        Err(_) => DEMO_AGENT_PUBLIC_COSE_KEY,
    }
}

fn demo_agent_signer() -> DemoAgentSigner {
    let mut buf = [0u8; 256];
    match host_io::read_file(DEV_AGENT_PUBLIC_KEY_PATH, &mut buf) {
        Ok(_) => DemoAgentSigner::Alternate,
        Err(_) => DemoAgentSigner::Default,
    }
}

fn process_update_payload(
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
