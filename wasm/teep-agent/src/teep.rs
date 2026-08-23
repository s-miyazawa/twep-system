// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause
use alloc::vec::Vec;

use ciborium::value::Value;

use crate::{cbor, evidence};

pub(crate) const TEEP_TYPE_QUERY_REQUEST: usize = 1;
pub(crate) const TEEP_TYPE_UPDATE: usize = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum QueryResponsePayloadError {
    MissingToken,
    AttestationUnsupported,
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
) -> Result<Vec<u8>, QueryResponsePayloadError> {
    if query_request_has_attestation_challenge(query_request) {
        return Err(QueryResponsePayloadError::AttestationUnsupported);
    }
    let token = teep_message_token(query_request).ok_or(QueryResponsePayloadError::MissingToken)?;
    let mut payload = Vec::new();
    cbor::write_array(&mut payload, 2).ok_or(QueryResponsePayloadError::EncodeFailed)?;
    cbor::write_uint(&mut payload, 2).ok_or(QueryResponsePayloadError::EncodeFailed)?;
    cbor::write_map(&mut payload, 3).ok_or(QueryResponsePayloadError::EncodeFailed)?;
    cbor::write_uint(&mut payload, 5).ok_or(QueryResponsePayloadError::EncodeFailed)?;
    cbor::write_uint(&mut payload, 0).ok_or(QueryResponsePayloadError::EncodeFailed)?;
    cbor::write_uint(&mut payload, 7).ok_or(QueryResponsePayloadError::EncodeFailed)?;
    cbor::write_array(&mut payload, 1).ok_or(QueryResponsePayloadError::EncodeFailed)?;
    cbor::write_map(&mut payload, 1).ok_or(QueryResponsePayloadError::EncodeFailed)?;
    cbor::write_uint(&mut payload, 0).ok_or(QueryResponsePayloadError::EncodeFailed)?;
    payload.extend_from_slice(component_id);
    cbor::write_uint(&mut payload, 19).ok_or(QueryResponsePayloadError::EncodeFailed)?;
    cbor::write_bytes(&mut payload, token).ok_or(QueryResponsePayloadError::EncodeFailed)?;
    Ok(payload)
}

pub(crate) fn query_response_payload_with_attestation(
    component_id: &[u8],
    attestation_payload: &[u8],
) -> Result<Vec<u8>, QueryResponsePayloadError> {
    let mut payload = Vec::new();
    cbor::write_array(&mut payload, 2).ok_or(QueryResponsePayloadError::EncodeFailed)?;
    cbor::write_uint(&mut payload, 2).ok_or(QueryResponsePayloadError::EncodeFailed)?;
    cbor::write_map(&mut payload, 4).ok_or(QueryResponsePayloadError::EncodeFailed)?;
    cbor::write_uint(&mut payload, 5).ok_or(QueryResponsePayloadError::EncodeFailed)?;
    cbor::write_uint(&mut payload, 0).ok_or(QueryResponsePayloadError::EncodeFailed)?;
    cbor::write_uint(&mut payload, 6).ok_or(QueryResponsePayloadError::EncodeFailed)?;
    cbor::write_bytes(&mut payload, attestation_payload)
        .ok_or(QueryResponsePayloadError::EncodeFailed)?;
    cbor::write_uint(&mut payload, 12).ok_or(QueryResponsePayloadError::EncodeFailed)?;
    cbor::write_text(
        &mut payload,
        b"application/eat+cwt; eat_profile=\"urn:ietf:rfc:rfc9711\"",
    )
    .ok_or(QueryResponsePayloadError::EncodeFailed)?;
    cbor::write_uint(&mut payload, 13).ok_or(QueryResponsePayloadError::EncodeFailed)?;
    cbor::write_array(&mut payload, 1).ok_or(QueryResponsePayloadError::EncodeFailed)?;
    cbor::write_map(&mut payload, 1).ok_or(QueryResponsePayloadError::EncodeFailed)?;
    cbor::write_uint(&mut payload, 15).ok_or(QueryResponsePayloadError::EncodeFailed)?;
    payload.extend_from_slice(component_id);
    Ok(payload)
}

fn query_request_has_attestation_challenge(input: &[u8]) -> bool {
    if evidence::query_request_challenge(input).is_some() {
        return true;
    }
    let Some(value) = cbor::value(input) else {
        return false;
    };
    let Some(items) = value.as_array() else {
        return false;
    };
    let Some(Value::Map(options)) = items.get(1) else {
        return false;
    };
    options
        .iter()
        .any(|(key, value)| cbor::uint_value(key) == Some(2) && matches!(value, Value::Bytes(_)))
}

pub(crate) fn teep_message_token(input: &[u8]) -> Option<&[u8]> {
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
        if key_major == 0 && key_value == 19 {
            return cbor::bytes(input, &mut off);
        }
        if !cbor::skip(input, &mut off) {
            return None;
        }
    }
    None
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
        let got = query_response_payload(&query_request, &component_id).expect("query response");
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
    fn query_response_rejects_attestation_challenge_until_evidence_supported() {
        let query_request = vec![
            0x85, 0x01, 0xa1, 0x02, 0x50, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x80, 0x80, 0x01,
        ];
        let component_id = [&[0x82, 0x4b][..], b"twep-app-v1", &[0x47][..], b"calcadd"].concat();

        assert_eq!(
            query_response_payload(&query_request, &component_id),
            Err(QueryResponsePayloadError::AttestationUnsupported)
        );
    }

    #[test]
    fn query_request_has_attestation_challenge_accepts_value_parser_path() {
        let query_request = vec![
            0x85, 0x01, 0xa1, 0x02, 0x50, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x80, 0x80, 0x01,
        ];

        assert!(query_request_has_attestation_challenge(&query_request));
    }

    #[test]
    fn query_response_rejects_missing_token() {
        let query_request = vec![0x82, 0x01, 0xa0];
        let component_id = [&[0x82, 0x4b][..], b"twep-app-v1", &[0x47][..], b"calcadd"].concat();

        assert_eq!(
            query_response_payload(&query_request, &component_id),
            Err(QueryResponsePayloadError::MissingToken)
        );
    }

    #[test]
    fn query_response_with_attestation_requests_target_component_id() {
        let component_id = [&[0x82, 0x4b][..], b"twep-app-v1", &[0x47][..], b"calcadd"].concat();
        let got =
            query_response_payload_with_attestation(&component_id, b"evidence").expect("payload");
        let mut want = Vec::new();
        cbor::write_array(&mut want, 2).unwrap();
        cbor::write_uint(&mut want, 2).unwrap();
        cbor::write_map(&mut want, 4).unwrap();
        cbor::write_uint(&mut want, 5).unwrap();
        cbor::write_uint(&mut want, 0).unwrap();
        cbor::write_uint(&mut want, 6).unwrap();
        cbor::write_bytes(&mut want, b"evidence").unwrap();
        cbor::write_uint(&mut want, 12).unwrap();
        cbor::write_text(
            &mut want,
            b"application/eat+cwt; eat_profile=\"urn:ietf:rfc:rfc9711\"",
        )
        .unwrap();
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
