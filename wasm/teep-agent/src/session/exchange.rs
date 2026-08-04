// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause

use super::*;

const DEV_AGENT_PUBLIC_KEY_PATH: &[u8] = b"teep-agent/dev-agent-public-key.cbor";
const DEMO_AGENT_PUBLIC_COSE_KEY: &[u8] = &[
    0xa5, 0x01, 0x02, 0x03, 0x28, 0x20, 0x01, 0x21, 0x58, 0x20, 0xbe, 0x7c, 0x56, 0x99, 0x3f, 0x71,
    0x11, 0x45, 0x34, 0xc2, 0xf4, 0xa4, 0xf4, 0xe4, 0x60, 0x67, 0x84, 0xfa, 0x9d, 0x96, 0x35, 0xe1,
    0x22, 0xbc, 0x8a, 0x49, 0x0b, 0x2e, 0x11, 0xfe, 0xb9, 0x32, 0x22, 0x58, 0x20, 0x81, 0x69, 0x6b,
    0x42, 0xc3, 0xbe, 0x1b, 0x24, 0x4c, 0xc0, 0x3b, 0xca, 0x97, 0xf0, 0xce, 0x75, 0xe2, 0xd9, 0x3a,
    0xda, 0x1c, 0xe5, 0x56, 0x62, 0x92, 0x27, 0xf1, 0x0a, 0x8c, 0x2c, 0x5b, 0x29,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BuildQueryResponseError {
    MissingToken,
    EncodeFailed,
}

pub(super) struct SignedQueryResponse {
    pub(super) cose: Vec<u8>,
    pub(super) evidence_bearing: bool,
}

struct QueryResponsePayload {
    payload: Vec<u8>,
    evidence_bearing: bool,
}

pub(super) fn sign_query_response(
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
            let evidence = evidence::create_eat_evidence(challenge, agent_public_key, evidence_buf)
                .map_err(|_| BuildQueryResponseError::EncodeFailed)?;
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
        BuildQueryResponseError::MissingToken => error_output(
            b"teep.protocol",
            b"AttesTAM QueryRequest token is not available",
        ),
        BuildQueryResponseError::EncodeFailed => error_output(
            b"teep.protocol",
            b"AttesTAM QueryResponse payload encoding failed",
        ),
    }
}

fn demo_agent_public_key(buf: &mut [u8]) -> &[u8] {
    match host_io::read_file(DEV_AGENT_PUBLIC_KEY_PATH, buf) {
        Ok(len) => &buf[..len],
        Err(_) => DEMO_AGENT_PUBLIC_COSE_KEY,
    }
}

pub(super) fn demo_agent_signer() -> DemoAgentSigner {
    let mut buf = [0u8; 256];
    match host_io::read_file(DEV_AGENT_PUBLIC_KEY_PATH, &mut buf) {
        Ok(_) => DemoAgentSigner::Alternate,
        Err(_) => DemoAgentSigner::Default,
    }
}
