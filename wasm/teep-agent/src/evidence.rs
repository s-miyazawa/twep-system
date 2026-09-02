#![cfg_attr(not(test), allow(dead_code))]
// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause

use alloc::vec::Vec;

use coset::{iana, Algorithm, CborSerializable, CoseKey, KeyType, Label};
use p256::ecdsa::VerifyingKey;

use crate::{cbor, cose::sign_demo_evidence_es256_cose_sign1};

#[cfg(test)]
use ciborium::value::Value;

pub(crate) const GENERIC_EAT_FORMAT: &[u8] =
    b"application/eat+cwt; eat_profile=\"urn:ietf:rfc:rfc9711\"";
pub(crate) const MAX_EVIDENCE_BYTES: usize = 30 * 1024;
pub(crate) const MAX_FORMAT_BYTES: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AttestationEvidence {
    pub(crate) format: Vec<u8>,
    pub(crate) payload: Vec<u8>,
}

pub(crate) const VERIFIED_EVIDENCE_RESULT_PATH: &[u8] = b"teep-agent/verified-evidence-result.cbor";
const DEMO_AGENT_EAT_UEID: &[u8] = &[
    0x01, 0x98, 0xf5, 0x0a, 0x4f, 0xf6, 0xc0, 0x58, 0x61, 0xc8, 0x86, 0x0d, 0x13, 0xa6, 0x38, 0xea,
];
const DEMO_AGENT_EAT_PROFILE: &[u8] = b"urn:ietf:rfc:rfc9711";
const DEMO_AGENT_EAT_MEASUREMENT_DIGEST: &[u8] = &[
    0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
    0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EvidenceError {
    InvalidArgument,
    MissingChallenge,
    Unsupported,
    BufferTooSmall(usize),
    InvalidLength,
    Internal,
}

pub(crate) fn query_request_challenge(input: &[u8]) -> Option<&[u8]> {
    query_request_challenge_result(input).ok().flatten()
}

pub(crate) fn query_request_challenge_result(input: &[u8]) -> Result<Option<&[u8]>, ()> {
    query_request_bytes_option(input, 2)
}

pub(crate) fn query_request_bytes_option(
    input: &[u8],
    wanted_key: usize,
) -> Result<Option<&[u8]>, ()> {
    let mut off = 0usize;
    let (major, len) = cbor::head(input, &mut off).ok_or(())?;
    if major != 4 || len < 2 {
        return Err(());
    }
    if !cbor::skip(input, &mut off) {
        return Err(());
    }
    let (major, pairs) = cbor::head(input, &mut off).ok_or(())?;
    if major != 5 {
        return Err(());
    }
    for _ in 0..pairs {
        let (key_major, key_value) = cbor::head(input, &mut off).ok_or(())?;
        if key_major == 0 && key_value == wanted_key {
            return cbor::bytes(input, &mut off).map(Some).ok_or(());
        }
        if !cbor::skip(input, &mut off) {
            return Err(());
        }
    }
    Ok(None)
}

pub(crate) fn create_eat_evidence<'a>(
    challenge: &[u8],
    agent_public_key_cose: &[u8],
    out: &'a mut [u8],
) -> Result<&'a [u8], EvidenceError> {
    if challenge.is_empty() || agent_public_key_cose.is_empty() {
        return Err(EvidenceError::InvalidArgument);
    }
    if challenge.len() < 8 || challenge.len() > 64 {
        return Err(EvidenceError::MissingChallenge);
    }
    let payload = encode_generic_eat(challenge, agent_public_key_cose)
        .ok_or(EvidenceError::InvalidArgument)?;
    let evidence =
        sign_demo_evidence_es256_cose_sign1(&payload).map_err(|_| EvidenceError::Internal)?;
    if evidence.len() > out.len() {
        return Err(EvidenceError::BufferTooSmall(evidence.len()));
    }
    out[..evidence.len()].copy_from_slice(&evidence);
    Ok(&out[..evidence.len()])
}

pub(crate) fn create_platform_evidence<F>(
    challenge: &[u8],
    agent_public_key_cose: &[u8],
    mut platform_create_evidence: F,
    format: Vec<u8>,
) -> Result<AttestationEvidence, EvidenceError>
where
    F: FnMut(&[u8], &[u8], &mut [u8]) -> Result<usize, EvidenceError>,
{
    if challenge.is_empty() || agent_public_key_cose.is_empty() {
        return Err(EvidenceError::InvalidArgument);
    }
    if challenge.len() < 8 || challenge.len() > 64 {
        return Err(EvidenceError::MissingChallenge);
    }
    let required = match platform_create_evidence(challenge, agent_public_key_cose, &mut []) {
        Err(EvidenceError::BufferTooSmall(required)) => required,
        Ok(required) => required,
        Err(err) => return Err(err),
    };
    if required == 0 || required > MAX_EVIDENCE_BYTES {
        return Err(EvidenceError::InvalidLength);
    }
    let mut payload = alloc::vec![0; required];
    let written = platform_create_evidence(challenge, agent_public_key_cose, &mut payload)?;
    if written != required || written > payload.len() {
        return Err(EvidenceError::InvalidLength);
    }
    if format.is_empty()
        || format.len() > MAX_FORMAT_BYTES
        || core::str::from_utf8(&format).is_err()
    {
        return Err(EvidenceError::InvalidArgument);
    }
    Ok(AttestationEvidence { format, payload })
}

pub(crate) fn host_status_to_evidence_error(status: i32, out_len: usize) -> EvidenceError {
    match status {
        1 => EvidenceError::InvalidArgument,
        2 => EvidenceError::BufferTooSmall(out_len),
        8 => EvidenceError::Unsupported,
        _ => EvidenceError::Internal,
    }
}

fn encode_generic_eat(challenge: &[u8], agent_public_key_cose: &[u8]) -> Option<Vec<u8>> {
    if !valid_agent_public_cose_key(agent_public_key_cose) {
        return None;
    }

    let mut measured_component = Vec::new();
    cbor::write_map(&mut measured_component, 2)?;
    cbor::write_uint(&mut measured_component, 1)?;
    cbor::write_array(&mut measured_component, 2)?;
    cbor::write_text(&mut measured_component, b"TEEP Agent")?;
    cbor::write_array(&mut measured_component, 2)?;
    cbor::write_text(&mut measured_component, b"1.3.4")?;
    cbor::write_uint(&mut measured_component, 1)?;
    cbor::write_uint(&mut measured_component, 2)?;
    cbor::write_array(&mut measured_component, 2)?;
    cbor::write_uint(&mut measured_component, 1)?;
    cbor::write_bytes(&mut measured_component, DEMO_AGENT_EAT_MEASUREMENT_DIGEST)?;

    let mut eat = Vec::new();
    cbor::write_map(&mut eat, 5)?;
    cbor::write_uint(&mut eat, 8)?;
    cbor::write_map(&mut eat, 1)?;
    cbor::write_uint(&mut eat, 1)?;
    eat.extend_from_slice(agent_public_key_cose);
    cbor::write_uint(&mut eat, 10)?;
    cbor::write_bytes(&mut eat, challenge)?;
    cbor::write_uint(&mut eat, 256)?;
    cbor::write_bytes(&mut eat, DEMO_AGENT_EAT_UEID)?;
    cbor::write_uint(&mut eat, 265)?;
    cbor::write_text(&mut eat, DEMO_AGENT_EAT_PROFILE)?;
    cbor::write_uint(&mut eat, 273)?;
    cbor::write_array(&mut eat, 1)?;
    cbor::write_array(&mut eat, 2)?;
    cbor::write_uint(&mut eat, 600)?;
    cbor::write_bytes(&mut eat, &measured_component)?;
    Some(eat)
}

fn valid_agent_public_cose_key(input: &[u8]) -> bool {
    let Ok(key) = CoseKey::from_slice(input) else {
        return false;
    };
    if key.kty != KeyType::Assigned(iana::KeyType::EC2)
        || key.alg != Some(Algorithm::Assigned(iana::Algorithm::ESP256))
    {
        return false;
    }
    let has_p256_curve = key.params.iter().any(|(label, value)| {
        label == &Label::Int(iana::Ec2KeyParameter::Crv as i64)
            && cbor::uint_value(value) == Some(iana::EllipticCurve::P_256 as usize)
    });
    let has_private_key = key
        .params
        .iter()
        .any(|(label, _)| label == &Label::Int(iana::Ec2KeyParameter::D as i64));
    if !has_p256_curve || has_private_key {
        return false;
    }
    let Ok(sec1) = key.to_sec1_octet_string() else {
        return false;
    };
    sec1.len() == 65 && VerifyingKey::from_sec1_bytes(&sec1).is_ok()
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use coset::{CoseKeyBuilder, CoseSign1, TaggedCborSerializable};
    use p256::ecdsa::SigningKey;

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
    fn create_eat_evidence_returns_tagged_cose_sign1() {
        let agent_key = test_agent_public_key(1);
        let mut out = [0u8; 1024];
        let evidence = create_eat_evidence(b"12345678", &agent_key, &mut out).expect("evidence");

        assert_eq!(evidence.first(), Some(&0xd2));
    }

    #[test]
    fn create_eat_evidence_preserves_generic_eat_contract() {
        let challenge = b"12345678";
        let agent_key = test_agent_public_key(1);
        let sign1 = evidence_sign1(challenge, &agent_key);
        let eat = cbor::value(sign1.payload.as_deref().expect("EAT payload")).expect("Generic EAT");

        assert_eq!(map_field(&eat, 10), Some(&Value::Bytes(challenge.to_vec())));
        assert_eq!(
            map_field(&eat, 256),
            Some(&Value::Bytes(DEMO_AGENT_EAT_UEID.to_vec()))
        );
        assert_eq!(
            map_field(&eat, 265),
            Some(&Value::Text(
                core::str::from_utf8(DEMO_AGENT_EAT_PROFILE)
                    .expect("profile text")
                    .into()
            ))
        );

        let cnf = map_field(&eat, 8).expect("cnf");
        assert_eq!(
            map_field(cnf, 1),
            cbor::value(&agent_key).as_ref(),
            "cnf.key must be the QueryResponse signing key"
        );

        let submods = value_array(map_field(&eat, 273).expect("submods"));
        let measurement_entry = value_array(&submods[0]);
        assert_eq!(cbor::uint_value(&measurement_entry[0]), Some(600));
        let measured_component = match &measurement_entry[1] {
            Value::Bytes(value) => cbor::value(value).expect("measured component"),
            other => panic!("unexpected measurement entry: {other:?}"),
        };
        let identity =
            value_array(map_field(&measured_component, 1).expect("measurement identity"));
        assert_eq!(identity[0], Value::Text("TEEP Agent".into()));
        let version = value_array(&identity[1]);
        assert_eq!(version[0], Value::Text("1.3.4".into()));
        assert_eq!(cbor::uint_value(&version[1]), Some(1));
        let digest = value_array(map_field(&measured_component, 2).expect("measurement digest"));
        assert_eq!(cbor::uint_value(&digest[0]), Some(1));
        assert_eq!(
            digest[1],
            Value::Bytes(DEMO_AGENT_EAT_MEASUREMENT_DIGEST.to_vec())
        );
    }

    #[test]
    fn create_eat_evidence_switches_only_cnf_for_alternate_agent_key() {
        let default = evidence_sign1(b"12345678", &test_agent_public_key(1));
        let alternate = evidence_sign1(b"12345678", &test_agent_public_key(2));
        assert_eq!(default.unprotected.key_id, alternate.unprotected.key_id);

        let default_eat =
            cbor::value(default.payload.as_deref().expect("default EAT")).expect("default EAT");
        let alternate_eat = cbor::value(alternate.payload.as_deref().expect("alternate EAT"))
            .expect("alternate EAT");
        assert_ne!(map_field(&default_eat, 8), map_field(&alternate_eat, 8));
        for label in [10, 256, 265, 273] {
            assert_eq!(
                map_field(&default_eat, label),
                map_field(&alternate_eat, label)
            );
        }
    }

    #[test]
    fn create_eat_evidence_rejects_missing_challenge() {
        let agent_key = test_agent_public_key(1);
        let mut out = [0u8; 1024];

        assert_eq!(
            create_eat_evidence(b"short", &agent_key, &mut out),
            Err(EvidenceError::MissingChallenge)
        );
        assert_eq!(
            create_eat_evidence(b"12345678", b"", &mut out),
            Err(EvidenceError::InvalidArgument)
        );
        assert_eq!(
            create_eat_evidence(b"12345678", b"not-cbor", &mut out),
            Err(EvidenceError::InvalidArgument)
        );
        assert_eq!(
            create_eat_evidence(b"12345678", b"\x01", &mut out),
            Err(EvidenceError::InvalidArgument)
        );
        assert!(create_eat_evidence(b"12345678", &agent_key, &mut out).is_ok());
        assert!(create_eat_evidence(&[0x41; 64], &agent_key, &mut out).is_ok());
        assert_eq!(
            create_eat_evidence(&[0x41; 65], &agent_key, &mut out),
            Err(EvidenceError::MissingChallenge)
        );
    }

    #[test]
    fn create_eat_evidence_reports_required_buffer_size() {
        let agent_key = test_agent_public_key(1);
        let mut out = [0u8; 1];
        let out_len = out.len();

        assert!(matches!(
            create_eat_evidence(b"12345678", &agent_key, &mut out),
            Err(EvidenceError::BufferTooSmall(required)) if required > out_len
        ));
    }

    fn evidence_sign1(challenge: &[u8], agent_key: &[u8]) -> CoseSign1 {
        let mut out = [0u8; 1024];
        let evidence =
            create_eat_evidence(challenge, agent_key, &mut out).expect("Generic EAT Evidence");
        CoseSign1::from_tagged_slice(evidence).expect("tagged COSE_Sign1")
    }

    fn map_field(input: &Value, key: usize) -> Option<&Value> {
        let Value::Map(pairs) = input else {
            return None;
        };
        pairs.iter().find_map(|(field_key, value)| {
            if cbor::uint_value(field_key) == Some(key) {
                Some(value)
            } else {
                None
            }
        })
    }

    fn value_array(input: &Value) -> &[Value] {
        let Value::Array(values) = input else {
            panic!("expected array, got {input:?}");
        };
        values
    }

    fn test_agent_public_key(private_scalar: u8) -> Vec<u8> {
        let signing_key =
            SigningKey::from_slice(&[private_scalar; 32]).expect("test agent signing key");
        let point = signing_key.verifying_key().to_encoded_point(false);
        CoseKeyBuilder::new_ec2_pub_key(
            iana::EllipticCurve::P_256,
            point.x().expect("test agent public x").to_vec(),
            point.y().expect("test agent public y").to_vec(),
        )
        .algorithm(iana::Algorithm::ESP256)
        .build()
        .to_vec()
        .expect("test agent public COSE_Key")
    }
}
