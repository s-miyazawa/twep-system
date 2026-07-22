// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause

use super::*;

pub(super) fn run_attestam_session(
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
        query_response.cose.as_slice(),
        query_response.evidence_bearing,
    )
    .map(Some)
}

fn handle_session_response(
    context: &SessionContext<'_>,
    status: i32,
    out_len: u32,
    http_buf: &mut [u8],
    attestation_response: bool,
    preceding_query_response: &[u8],
    fresh_evidence: bool,
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
                if !fresh_evidence && !verified::protected_attestam_acceptance_is_current() {
                    return Err(write_output(
                        context.out_desc_ptr,
                        &error_output(
                            b"teep.protocol",
                            b"verified PoC Update has neither fresh nor current protected Evidence",
                        ),
                    ));
                }
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
                    preceding_query_response,
                    session_token,
                ) {
                    #[cfg(feature = "m9-1-acceptance-only-smoke")]
                    Ok(verified::LiveUpdateAcceptance::AcceptanceCommitted) => Ok(true),
                    #[cfg(not(feature = "m9-1-acceptance-only-smoke"))]
                    Ok(verified::LiveUpdateAcceptance::CatalogCommitted { success_payload })
                    | Ok(verified::LiveUpdateAcceptance::AppCommitted { success_payload }) => {
                        post_verified_component_success(
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
        attestation_response_cose.cose.as_slice(),
        attestation_response_cose.evidence_bearing,
    )
}

#[cfg(not(feature = "m9-1-acceptance-only-smoke"))]
fn post_verified_component_success(
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
                &error_output(b"teep.protocol", b"AttesTAM Success signing failed"),
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
            &error_output(b"teep.network", b"AttesTAM Success POST failed"),
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
