#![cfg_attr(not(test), allow(dead_code))]
// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause

use crate::cbor;

pub(crate) const VERIFIED_EVIDENCE_RESULT_PATH: &[u8] = b"teep-agent/verified-evidence-result.cbor";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EvidenceError {
    InvalidArgument,
    MissingChallenge,
    Unsupported,
    BufferTooSmall(usize),
    Internal,
}

pub(crate) fn query_request_challenge(input: &[u8]) -> Option<&[u8]> {
    let mut off = 0usize;
    let (major, len) = cbor::head(input, &mut off)?;
    if major != 4 || len < 2 {
        return None;
    }
    if !cbor::skip(input, &mut off) {
        return None;
    }
    let (major, pairs) = cbor::head(input, &mut off)?;
    if major != 5 {
        return None;
    }
    for _ in 0..pairs {
        let (key_major, key_value) = cbor::head(input, &mut off)?;
        if key_major == 0 && key_value == 2 {
            return cbor::bytes(input, &mut off);
        }
        if !cbor::skip(input, &mut off) {
            return None;
        }
    }
    None
}

pub(crate) fn create_eat_evidence<'a, F>(
    challenge: &[u8],
    agent_public_key_cose: &[u8],
    out: &'a mut [u8],
    mut platform_create_evidence: F,
) -> Result<&'a [u8], EvidenceError>
where
    F: FnMut(&[u8], &[u8], &mut [u8]) -> Result<usize, EvidenceError>,
{
    if challenge.is_empty() || agent_public_key_cose.is_empty() {
        return Err(EvidenceError::InvalidArgument);
    }
    if challenge.len() < 8 || challenge.len() > 64 {
        return Err(EvidenceError::MissingChallenge);
    }
    let written = platform_create_evidence(challenge, agent_public_key_cose, out)?;
    if written > out.len() {
        return Err(EvidenceError::BufferTooSmall(written));
    }
    Ok(&out[..written])
}

pub(crate) fn host_status_to_evidence_error(status: i32, out_len: usize) -> EvidenceError {
    match status {
        1 => EvidenceError::InvalidArgument,
        2 => EvidenceError::BufferTooSmall(out_len),
        8 => EvidenceError::Unsupported,
        _ => EvidenceError::Internal,
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    #[test]
    fn query_request_challenge_reads_attestation_challenge() {
        let challenge = b"12345678";
        let mut input = Vec::new();
        cbor::write_array(&mut input, 5).unwrap();
        cbor::write_uint(&mut input, 1).unwrap();
        cbor::write_map(&mut input, 1).unwrap();
        cbor::write_uint(&mut input, 2).unwrap();
        cbor::write_bytes(&mut input, challenge).unwrap();
        cbor::write_array(&mut input, 0).unwrap();
        cbor::write_array(&mut input, 0).unwrap();
        cbor::write_uint(&mut input, 1).unwrap();

        assert_eq!(query_request_challenge(&input), Some(challenge.as_slice()));
        assert_eq!(query_request_challenge(b"\x01"), None);
    }

    #[test]
    fn create_eat_evidence_delegates_platform_generation() {
        let mut out = [0u8; 16];
        let evidence = create_eat_evidence(
            b"12345678",
            b"agent-key",
            &mut out,
            |challenge, agent_key, out| {
                assert_eq!(challenge, b"12345678");
                assert_eq!(agent_key, b"agent-key");
                out[..8].copy_from_slice(b"evidence");
                Ok(8)
            },
        )
        .expect("evidence");

        assert_eq!(evidence, b"evidence");
    }

    #[test]
    fn create_eat_evidence_rejects_missing_challenge() {
        let mut out = [0u8; 16];

        assert_eq!(
            create_eat_evidence(b"short", b"agent-key", &mut out, |_, _, _| Ok(0)),
            Err(EvidenceError::MissingChallenge)
        );
        assert_eq!(
            create_eat_evidence(b"12345678", b"", &mut out, |_, _, _| Ok(0)),
            Err(EvidenceError::InvalidArgument)
        );
    }

    #[test]
    fn host_status_maps_to_evidence_errors() {
        assert_eq!(
            host_status_to_evidence_error(2, 32),
            EvidenceError::BufferTooSmall(32)
        );
        assert_eq!(
            host_status_to_evidence_error(8, 0),
            EvidenceError::Unsupported
        );
    }
}
