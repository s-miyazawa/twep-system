// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause

use super::*;

const MAX_ATTESTAM_REQUEST_BYTES: usize = 32 * 1024;
const DEV_AGENT_PUBLIC_KEY_PATH: &[u8] = b"teep-agent/dev-agent-public-key.cbor";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BuildQueryResponseError {
    AttestationUnsupported,
    EncodeFailed,
    PendingHostIo,
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
    signer: DemoAgentSigner,
) -> Result<SignedQueryResponse, i32> {
    let agent_public_key = demo_agent_public_cose_key(signer).map_err(|_| {
        write_output(
            out_desc_ptr,
            &error_output(b"teep.protocol", b"agent key unavailable"),
        )
    })?;
    let query_response = match build_query_response_payload(
        query_request_payload,
        requested_component_id,
        &agent_public_key,
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
    match sign_agent_esp256_cose_sign1(&query_response.payload, signer) {
        Ok(signed) if query_response_size_allowed(signed.len()) => Ok(SignedQueryResponse {
            cose: signed,
            evidence_bearing: query_response.evidence_bearing,
        }),
        Ok(_) => Err(write_output(
            out_desc_ptr,
            &error_output(
                b"teep.resource_limit",
                b"AttesTAM QueryResponse exceeds 32 KiB",
            ),
        )),
        Err(_) => Err(write_output(
            out_desc_ptr,
            &error_output(b"teep.protocol", b"AttesTAM QueryResponse signing failed"),
        )),
    }
}

fn query_response_size_allowed(len: usize) -> bool {
    len <= MAX_ATTESTAM_REQUEST_BYTES
}

fn build_query_response_payload(
    query_request_payload: &[u8],
    requested_component_id: &[u8],
    agent_public_key: &[u8],
) -> Result<QueryResponsePayload, BuildQueryResponseError> {
    let challenge = evidence::query_request_challenge_result(query_request_payload)
        .map_err(|_| BuildQueryResponseError::EncodeFailed)?;
    let attestation = if let Some(challenge) = challenge {
        let format = platform_attestation_payload_format()?;
        let evidence = if format == evidence::GENERIC_EAT_FORMAT {
            let mut output = [0u8; 1024];
            let payload = evidence::create_eat_evidence(challenge, agent_public_key, &mut output)
                .map_err(|_| BuildQueryResponseError::EncodeFailed)?;
            evidence::AttestationEvidence {
                format,
                payload: payload.to_vec(),
            }
        } else {
            evidence::create_platform_evidence(
                challenge,
                agent_public_key,
                |challenge, agent_public_key, out| match host_io::create_evidence(
                    challenge,
                    agent_public_key,
                    out,
                ) {
                    Ok(len) => Ok(len),
                    Err((11, _)) => Err(evidence::EvidenceError::Internal),
                    Err((status, len)) => Err(evidence::host_status_to_evidence_error(status, len)),
                },
                format,
            )
            .map_err(|err| match err {
                evidence::EvidenceError::Internal => BuildQueryResponseError::PendingHostIo,
                evidence::EvidenceError::Unsupported => {
                    BuildQueryResponseError::AttestationUnsupported
                }
                _ => BuildQueryResponseError::EncodeFailed,
            })?
        };
        Some(evidence)
    } else {
        None
    };
    let payload = query_response_payload(
        query_request_payload,
        requested_component_id,
        attestation.as_ref(),
    )
    .map_err(|_| BuildQueryResponseError::EncodeFailed)?;
    Ok(QueryResponsePayload {
        payload,
        evidence_bearing: attestation.is_some(),
    })
}

fn platform_attestation_payload_format() -> Result<Vec<u8>, BuildQueryResponseError> {
    let required = match host_io::attestation_payload_format(&mut []) {
        Err((2, required)) => required,
        Ok(required) => required,
        _ => return Err(BuildQueryResponseError::AttestationUnsupported),
    };
    if required == 0 || required > evidence::MAX_FORMAT_BYTES {
        return Err(BuildQueryResponseError::EncodeFailed);
    }
    let mut format = alloc::vec![0; required];
    match host_io::attestation_payload_format(&mut format) {
        Ok(written) if written == required => Ok(format),
        _ => Err(BuildQueryResponseError::EncodeFailed),
    }
}

fn build_query_response_error_output(err: BuildQueryResponseError) -> Vec<u8> {
    match err {
        BuildQueryResponseError::AttestationUnsupported => error_output(
            b"teep.attestation_unsupported",
            b"AttesTAM QueryRequest attestation challenge is not supported",
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

pub(super) fn demo_agent_signer() -> DemoAgentSigner {
    let alternate = demo_agent_public_cose_key(DemoAgentSigner::Alternate).ok();
    let mut buf = [0u8; 128];
    match (
        host_io::read_file(DEV_AGENT_PUBLIC_KEY_PATH, &mut buf),
        alternate,
    ) {
        (Ok(len), Some(expected)) => demo_agent_signer_for_selector(&buf[..len], &expected),
        _ => DemoAgentSigner::Default,
    }
}

fn demo_agent_signer_for_selector(selector: &[u8], alternate: &[u8]) -> DemoAgentSigner {
    if selector == alternate {
        DemoAgentSigner::Alternate
    } else {
        DemoAgentSigner::Default
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn final_query_response_enforces_attestam_request_limit() {
        assert!(query_response_size_allowed(MAX_ATTESTAM_REQUEST_BYTES));
        assert!(!query_response_size_allowed(MAX_ATTESTAM_REQUEST_BYTES + 1));
    }

    #[test]
    fn alternate_selector_requires_an_exact_known_public_key() {
        let alternate = demo_agent_public_cose_key(DemoAgentSigner::Alternate).unwrap();
        assert_eq!(
            demo_agent_signer_for_selector(&alternate, &alternate),
            DemoAgentSigner::Alternate
        );
        let mut changed = alternate.clone();
        changed[10] ^= 1;
        assert_eq!(
            demo_agent_signer_for_selector(&changed, &alternate),
            DemoAgentSigner::Default
        );
        let mut extended = alternate.clone();
        extended.push(0);
        assert_eq!(
            demo_agent_signer_for_selector(&extended, &alternate),
            DemoAgentSigner::Default
        );
        assert_eq!(
            demo_agent_signer_for_selector(&alternate[..alternate.len() - 1], &alternate),
            DemoAgentSigner::Default
        );
        assert_eq!(
            demo_agent_signer_for_selector(&[], &alternate),
            DemoAgentSigner::Default
        );
    }
}
