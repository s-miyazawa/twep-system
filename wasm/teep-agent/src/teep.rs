// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause
use alloc::vec::Vec;

use crate::{cbor, evidence};

pub(crate) const TEEP_TYPE_QUERY_REQUEST: usize = 1;
pub(crate) const TEEP_TYPE_UPDATE: usize = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum QueryResponsePayloadError {
    InvalidEvidence,
    MalformedQueryRequest,
    EncodeFailed,
}

pub(crate) fn teep_message_type(input: &[u8]) -> Option<usize> {
    let value = cbor::value(input)?;
    let items = value.as_array()?;
    if items.len() < 2 {
        return None;
    }
    cbor::uint_value(items.first()?)
}

pub(crate) fn update_manifest_list(input: &[u8]) -> Option<(&[u8], usize)> {
    let mut off = 0usize;
    let (major, len) = cbor::head(input, &mut off)?;
    if major != 4 || len < 2 {
        return None;
    }
    let (type_major, message_type) = cbor::head(input, &mut off)?;
    if type_major != 0 || message_type != TEEP_TYPE_UPDATE {
        return None;
    }
    let (options_major, pairs) = cbor::head(input, &mut off)?;
    if options_major != 5 {
        return None;
    }
    for _ in 0..pairs {
        let (key_major, key_value) = cbor::head(input, &mut off)?;
        if key_major == 0 && key_value == 9 {
            let (list_major, manifest_count) = cbor::head(input, &mut off)?;
            if list_major != 4 || manifest_count == 0 {
                return None;
            }
            let manifest = cbor::bytes(input, &mut off)?;
            return Some((manifest, manifest_count));
        }
        if !cbor::skip(input, &mut off) {
            return None;
        }
    }
    None
}

pub(crate) fn query_response_payload(
    query_request: &[u8],
    component_id: &[u8],
    evidence: Option<&evidence::AttestationEvidence>,
) -> Result<Vec<u8>, QueryResponsePayloadError> {
    if evidence.is_some_and(|value| {
        value.payload.is_empty()
            || value.format.is_empty()
            || core::str::from_utf8(&value.format).is_err()
    }) {
        return Err(QueryResponsePayloadError::InvalidEvidence);
    }
    let token = evidence::query_request_bytes_option(query_request, 19)
        .map_err(|_| QueryResponsePayloadError::MalformedQueryRequest)?;
    if token.is_some_and(|value| value.is_empty() || value.len() > 128)
        || (evidence.is_none() && token.is_none())
    {
        return Err(QueryResponsePayloadError::MalformedQueryRequest);
    }
    let pairs = 2 + usize::from(evidence.is_some()) * 2 + usize::from(token.is_some());
    let mut payload = Vec::new();
    cbor::write_array(&mut payload, 2).ok_or(QueryResponsePayloadError::EncodeFailed)?;
    cbor::write_uint(&mut payload, 2).ok_or(QueryResponsePayloadError::EncodeFailed)?;
    cbor::write_map(&mut payload, pairs).ok_or(QueryResponsePayloadError::EncodeFailed)?;
    cbor::write_uint(&mut payload, 5).ok_or(QueryResponsePayloadError::EncodeFailed)?;
    cbor::write_uint(&mut payload, 0).ok_or(QueryResponsePayloadError::EncodeFailed)?;
    if let Some(evidence) = evidence {
        cbor::write_uint(&mut payload, 6).ok_or(QueryResponsePayloadError::EncodeFailed)?;
        cbor::write_bytes(&mut payload, &evidence.payload)
            .ok_or(QueryResponsePayloadError::EncodeFailed)?;
        cbor::write_uint(&mut payload, 12).ok_or(QueryResponsePayloadError::EncodeFailed)?;
        cbor::write_text(&mut payload, &evidence.format)
            .ok_or(QueryResponsePayloadError::EncodeFailed)?;
    }
    cbor::write_uint(&mut payload, if evidence.is_some() { 13 } else { 7 })
        .ok_or(QueryResponsePayloadError::EncodeFailed)?;
    cbor::write_array(&mut payload, 1).ok_or(QueryResponsePayloadError::EncodeFailed)?;
    cbor::write_map(&mut payload, 1).ok_or(QueryResponsePayloadError::EncodeFailed)?;
    cbor::write_uint(&mut payload, if evidence.is_some() { 15 } else { 0 })
        .ok_or(QueryResponsePayloadError::EncodeFailed)?;
    payload.extend_from_slice(component_id);
    if let Some(token) = token {
        cbor::write_uint(&mut payload, 19).ok_or(QueryResponsePayloadError::EncodeFailed)?;
        cbor::write_bytes(&mut payload, token).ok_or(QueryResponsePayloadError::EncodeFailed)?;
    }
    Ok(payload)
}

pub(crate) fn teep_message_token(input: &[u8]) -> Option<&[u8]> {
    evidence::query_request_bytes_option(input, 19)
        .ok()
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn query_response_requests_target_component_id() {
        let token = b"\xaa\xbb";
        let query_request = vec![0x82, 0x01, 0xa1, 0x13, 0x42, 0xaa, 0xbb];
        let component_id = [&[0x82, 0x4b][..], b"twep-app-v1", &[0x47][..], b"calcadd"].concat();
        let got =
            query_response_payload(&query_request, &component_id, None).expect("query response");
        let mut want = Vec::new();
        cbor::write_array(&mut want, 2).unwrap();
        cbor::write_uint(&mut want, 2).unwrap();
        cbor::write_map(&mut want, 3).unwrap();
        cbor::write_uint(&mut want, 5).unwrap();
        cbor::write_uint(&mut want, 0).unwrap();
        cbor::write_uint(&mut want, 7).unwrap();
        cbor::write_array(&mut want, 1).unwrap();
        cbor::write_map(&mut want, 1).unwrap();
        cbor::write_uint(&mut want, 0).unwrap();
        want.extend_from_slice(&component_id);
        cbor::write_uint(&mut want, 19).unwrap();
        cbor::write_bytes(&mut want, token).unwrap();

        assert_eq!(got, want);
    }

    #[test]
    fn challenge_only_query_response_has_evidence_without_token() {
        let query_request = vec![
            0x85, 0x01, 0xa1, 0x02, 0x50, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x80, 0x80, 0x01,
        ];
        let component_id = [&[0x82, 0x4b][..], b"twep-app-v1", &[0x47][..], b"calcadd"].concat();

        let evidence = evidence::AttestationEvidence {
            format: evidence::GENERIC_EAT_FORMAT.to_vec(),
            payload: b"eat".to_vec(),
        };
        let got = query_response_payload(&query_request, &component_id, Some(&evidence)).unwrap();
        let value = cbor::value(&got).unwrap();
        let options = value.as_array().unwrap()[1].as_map().unwrap();
        assert_eq!(options.len(), 4);
        assert!(options
            .iter()
            .any(|(key, value)| cbor::uint_value(key) == Some(6)
                && value.as_bytes().map(Vec::as_slice) == Some(b"eat")));
        assert!(options
            .iter()
            .any(|(key, value)| cbor::uint_value(key) == Some(12)
                && value.as_text().map(str::as_bytes) == Some(evidence::GENERIC_EAT_FORMAT)));
        assert!(!options
            .iter()
            .any(|(key, _)| cbor::uint_value(key) == Some(19)));
    }

    #[test]
    fn token_only_query_response_requires_non_empty_bounded_token() {
        let query_request = vec![0x82, 0x01, 0xa0];
        let component_id = [&[0x82, 0x4b][..], b"twep-app-v1", &[0x47][..], b"calcadd"].concat();

        assert_eq!(
            query_response_payload(&query_request, &component_id, None),
            Err(QueryResponsePayloadError::MalformedQueryRequest)
        );
        assert_eq!(
            query_response_payload(b"\x82\x01\xa1\x13\x40", &component_id, None),
            Err(QueryResponsePayloadError::MalformedQueryRequest)
        );
    }

    #[test]
    fn query_response_rejects_non_bstr_token_and_invalid_evidence_format() {
        let component_id = b"\x80";
        assert_eq!(
            query_response_payload(b"\x82\x01\xa1\x13\x01", component_id, None),
            Err(QueryResponsePayloadError::MalformedQueryRequest)
        );
        for format in [Vec::new(), vec![0xff]] {
            let evidence = evidence::AttestationEvidence {
                format,
                payload: b"eat".to_vec(),
            };
            assert_eq!(
                query_response_payload(b"\x82\x01\xa0", component_id, Some(&evidence)),
                Err(QueryResponsePayloadError::InvalidEvidence)
            );
        }
    }

    #[test]
    fn query_response_with_evidence_echoes_only_an_actual_token() {
        let evidence = evidence::AttestationEvidence {
            format: evidence::GENERIC_EAT_FORMAT.to_vec(),
            payload: b"eat".to_vec(),
        };
        let got = query_response_payload(
            b"\x82\x01\xa2\x02\x48challeng\x13\x42\xaa\xbb",
            b"\x80",
            Some(&evidence),
        )
        .unwrap();
        let value = cbor::value(&got).unwrap();
        let options = value.as_array().unwrap()[1].as_map().unwrap();
        assert_eq!(options.len(), 5);
        assert!(options.iter().any(|(key, value)| {
            cbor::uint_value(key) == Some(19)
                && value.as_bytes().map(Vec::as_slice) == Some(b"\xaa\xbb")
        }));
    }

    #[test]
    fn query_response_with_attestation_requests_target_component_id() {
        let component_id = [&[0x82, 0x4b][..], b"twep-app-v1", &[0x47][..], b"calcadd"].concat();
        let query_request = vec![0x82, 0x01, 0xa0];
        let evidence = evidence::AttestationEvidence {
            format: evidence::GENERIC_EAT_FORMAT.to_vec(),
            payload: b"evidence".to_vec(),
        };
        let got = query_response_payload(&query_request, &component_id, Some(&evidence))
            .expect("payload");
        let mut want = Vec::new();
        cbor::write_array(&mut want, 2).unwrap();
        cbor::write_uint(&mut want, 2).unwrap();
        cbor::write_map(&mut want, 4).unwrap();
        cbor::write_uint(&mut want, 5).unwrap();
        cbor::write_uint(&mut want, 0).unwrap();
        cbor::write_uint(&mut want, 6).unwrap();
        cbor::write_bytes(&mut want, b"evidence").unwrap();
        cbor::write_uint(&mut want, 12).unwrap();
        cbor::write_text(&mut want, evidence::GENERIC_EAT_FORMAT).unwrap();
        cbor::write_uint(&mut want, 13).unwrap();
        cbor::write_array(&mut want, 1).unwrap();
        cbor::write_map(&mut want, 1).unwrap();
        cbor::write_uint(&mut want, 15).unwrap();
        want.extend_from_slice(&component_id);

        assert_eq!(got, want);
    }

    #[test]
    fn teep_message_type_reads_cbor_array_type() {
        let mut input = Vec::new();
        cbor::write_array(&mut input, 2).unwrap();
        cbor::write_uint(&mut input, TEEP_TYPE_QUERY_REQUEST).unwrap();
        cbor::write_map(&mut input, 0).unwrap();

        assert_eq!(teep_message_type(&input), Some(TEEP_TYPE_QUERY_REQUEST));
        assert_eq!(teep_message_type(b"\x01"), None);
    }
}
