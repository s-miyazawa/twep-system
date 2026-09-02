// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause
use alloc::vec::Vec;

use coset::CoseKeyBuilder;
use coset::{
    iana, Algorithm, CborSerializable, CoseSign1, CoseSign1Builder, HeaderBuilder,
    TaggedCborSerializable,
};
use p256::ecdsa::{signature::Signer, SigningKey};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

// SECURITY: The private scalars below are published, intentionally insecure
// fixtures for disposable demos and automated tests. Never use them in
// production, shared validation environments, long-lived deployments, or with
// external services. Real deployments must provision unique protected keys.

#[cfg(test)]
use crate::cbor;
use crate::{sha256, verified::VerificationState};

const DEMO_TAM_PUBLIC_KEY_X: [u8; 32] = [
    0x0e, 0x90, 0x8a, 0xa8, 0xf0, 0x66, 0xdb, 0x1f, 0x08, 0x4e, 0x0c, 0x36, 0x52, 0xc6, 0x39, 0x52,
    0xbd, 0x99, 0xf2, 0xa5, 0xbd, 0xb2, 0x2f, 0x9e, 0x01, 0x36, 0x7a, 0xad, 0x03, 0xab, 0xa6, 0x8b,
];
const DEMO_TAM_PUBLIC_KEY_Y: [u8; 32] = [
    0x77, 0xda, 0x1b, 0xd8, 0xac, 0x4f, 0x0c, 0xb4, 0x90, 0xba, 0x21, 0x06, 0x48, 0xbf, 0x79, 0xab,
    0x16, 0x4d, 0x49, 0xad, 0x35, 0x51, 0xd7, 0x1d, 0x31, 0x4b, 0x27, 0x49, 0xee, 0x42, 0xd2, 0x9a,
];
const DEMO_TAM_PRIVATE_KEY_D: [u8; 32] = [
    0x84, 0x1a, 0xeb, 0xb7, 0xb9, 0xea, 0x6f, 0x02, 0x60, 0xbe, 0x73, 0x55, 0xa2, 0x45, 0x88, 0xb9,
    0x77, 0xd2, 0x3d, 0x2a, 0xc5, 0xbf, 0x2b, 0x6b, 0x2d, 0x83, 0x79, 0x43, 0x2a, 0x1f, 0xea, 0x98,
];
const DEMO_AGENT_PUBLIC_KEY_X: [u8; 32] = [
    0xbe, 0x7c, 0x56, 0x99, 0x3f, 0x71, 0x11, 0x45, 0x34, 0xc2, 0xf4, 0xa4, 0xf4, 0xe4, 0x60, 0x67,
    0x84, 0xfa, 0x9d, 0x96, 0x35, 0xe1, 0x22, 0xbc, 0x8a, 0x49, 0x0b, 0x2e, 0x11, 0xfe, 0xb9, 0x32,
];
const DEMO_AGENT_PUBLIC_KEY_Y: [u8; 32] = [
    0x81, 0x69, 0x6b, 0x42, 0xc3, 0xbe, 0x1b, 0x24, 0x4c, 0xc0, 0x3b, 0xca, 0x97, 0xf0, 0xce, 0x75,
    0xe2, 0xd9, 0x3a, 0xda, 0x1c, 0xe5, 0x56, 0x62, 0x92, 0x27, 0xf1, 0x0a, 0x8c, 0x2c, 0x5b, 0x29,
];
const DEMO_AGENT_PRIVATE_KEY_D: [u8; 32] = [
    0xa1, 0x3d, 0x1c, 0x9f, 0x42, 0x78, 0x04, 0x70, 0x82, 0xc4, 0xa4, 0x06, 0xef, 0x33, 0xa9, 0xae,
    0xd2, 0xda, 0x01, 0x05, 0x87, 0xa3, 0x75, 0x1e, 0xab, 0xaa, 0x0b, 0x6b, 0xa0, 0x12, 0x63, 0xe3,
];
const DEMO_EVIDENCE_PUBLIC_KEY_X: [u8; 32] = [
    0x30, 0xa0, 0x42, 0x4c, 0xd2, 0x1c, 0x29, 0x44, 0x83, 0x8a, 0x2d, 0x75, 0xc9, 0x2b, 0x37, 0xe7,
    0x6e, 0xa2, 0x0d, 0x9f, 0x00, 0x89, 0x3a, 0x3b, 0x4e, 0xee, 0x8a, 0x3c, 0x0a, 0xaf, 0xec, 0x3e,
];
const DEMO_EVIDENCE_PUBLIC_KEY_Y: [u8; 32] = [
    0xe0, 0x4b, 0x65, 0xe9, 0x24, 0x56, 0xd9, 0x88, 0x8b, 0x52, 0xb3, 0x79, 0xbd, 0xfb, 0xd5, 0x1e,
    0xe8, 0x69, 0xef, 0x1f, 0x0f, 0xc6, 0x5b, 0x66, 0x59, 0x69, 0x5b, 0x6c, 0xce, 0x08, 0x17, 0x23,
];
const DEMO_EVIDENCE_PRIVATE_KEY_D: [u8; 32] = [
    0xf3, 0xbd, 0x0c, 0x07, 0xa8, 0x1f, 0xb9, 0x32, 0x78, 0x1e, 0xd5, 0x27, 0x52, 0xf6, 0x0c, 0xc8,
    0x9a, 0x6b, 0xe5, 0xe5, 0x19, 0x34, 0xfe, 0x01, 0x93, 0x8d, 0xdb, 0x55, 0xd8, 0xf7, 0x78, 0x01,
];

#[cfg(test)]
fn cose_sign1_payload(input: &[u8]) -> Option<&[u8]> {
    let mut off = 0usize;
    let (mut major, mut value) = cbor::head(input, &mut off)?;
    if major == 6 {
        if value != 18 {
            return None;
        }
        (major, value) = cbor::head(input, &mut off)?;
    }
    if major != 4 || value != 4 {
        return None;
    }
    let _protected = cbor::bytes(input, &mut off)?;
    if !cbor::skip(input, &mut off) {
        return None;
    }
    let payload = cbor::bytes(input, &mut off)?;
    if !cbor::skip(input, &mut off) || off != input.len() {
        return None;
    }
    Some(payload)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum CoseSign1VerificationError {
    Malformed,
    MissingPayload,
    SignatureRejected,
    SignatureUnverified,
    UnsupportedAlgorithm,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CoseSign1SigningError {
    EncodeFailed,
    KeyRejected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DemoAgentSigner {
    Default,
    Alternate,
}

fn outer_teep_cose_sign1(input: &[u8]) -> Result<CoseSign1, CoseSign1VerificationError> {
    CoseSign1::from_tagged_slice(input).map_err(|_| CoseSign1VerificationError::Malformed)
}

fn cose_sign1(input: &[u8]) -> Result<CoseSign1, CoseSign1VerificationError> {
    CoseSign1::from_slice(input)
        .or_else(|_| CoseSign1::from_tagged_slice(input))
        .map_err(|_| CoseSign1VerificationError::Malformed)
}

fn outer_teep_cose_sign1_uses_esp256(sign1: &CoseSign1) -> bool {
    sign1.protected.header.alg == Some(Algorithm::Assigned(iana::Algorithm::ESP256))
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn verify_demo_tam_esp256_signature(signature: &[u8], tbs: &[u8]) -> bool {
    verify_esp256_signature_with_coordinates(
        &DEMO_TAM_PUBLIC_KEY_X,
        &DEMO_TAM_PUBLIC_KEY_Y,
        signature,
        tbs,
    )
}

pub(crate) fn verify_esp256_signature_with_coordinates(
    x: &[u8; 32],
    y: &[u8; 32],
    signature: &[u8],
    tbs: &[u8],
) -> bool {
    let Ok(signature) = Signature::from_slice(signature) else {
        return false;
    };
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..33].copy_from_slice(x);
    sec1[33..65].copy_from_slice(y);
    let Ok(verifying_key) = VerifyingKey::from_sec1_bytes(&sec1) else {
        return false;
    };
    verifying_key.verify(tbs, &signature).is_ok()
}

pub(crate) fn outer_teep_cose_sign1_payload_unverified(
    input: &[u8],
    state: &VerificationState,
) -> Result<Vec<u8>, CoseSign1VerificationError> {
    if state.cose_outer_verified() {
        return Err(CoseSign1VerificationError::SignatureUnverified);
    }
    let sign1 = outer_teep_cose_sign1(input)?;
    sign1
        .payload
        .ok_or(CoseSign1VerificationError::MissingPayload)
}

pub(crate) fn outer_teep_cose_sign1_key_id(
    input: &[u8],
) -> Result<Option<Vec<u8>>, CoseSign1VerificationError> {
    let sign1 = outer_teep_cose_sign1(input)?;
    if !sign1.protected.header.key_id.is_empty() {
        return Ok(Some(sign1.protected.header.key_id));
    }
    if !sign1.unprotected.key_id.is_empty() {
        return Ok(Some(sign1.unprotected.key_id));
    }
    Ok(None)
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn outer_teep_cose_sign1_payload_verified_with<F>(
    input: &[u8],
    state: &mut VerificationState,
    verifier: F,
) -> Result<Vec<u8>, CoseSign1VerificationError>
where
    F: FnOnce(&[u8], &[u8]) -> bool,
{
    if state.cose_outer_verified() {
        return Err(CoseSign1VerificationError::SignatureUnverified);
    }
    let sign1 = outer_teep_cose_sign1(input)?;
    if !outer_teep_cose_sign1_uses_esp256(&sign1) {
        return Err(CoseSign1VerificationError::UnsupportedAlgorithm);
    }
    sign1.verify_signature(&[], |signature, tbs| {
        if verifier(signature, tbs) {
            Ok(())
        } else {
            Err(CoseSign1VerificationError::SignatureRejected)
        }
    })?;
    let payload = sign1
        .payload
        .ok_or(CoseSign1VerificationError::MissingPayload)?;
    state.mark_cose_outer_verified();
    Ok(payload)
}

pub(crate) fn cose_sign1_detached_payload_verified_with<F>(
    input: &[u8],
    detached_payload: &[u8],
    verifier: F,
) -> Result<(), CoseSign1VerificationError>
where
    F: FnOnce(&[u8], &[u8]) -> bool,
{
    let sign1 = cose_sign1(input)?;
    if sign1.payload.is_some() {
        return Err(CoseSign1VerificationError::SignatureUnverified);
    }
    if !outer_teep_cose_sign1_uses_esp256(&sign1) {
        return Err(CoseSign1VerificationError::UnsupportedAlgorithm);
    }
    sign1.verify_detached_signature(detached_payload, &[], |signature, tbs| {
        if verifier(signature, tbs) {
            Ok(())
        } else {
            Err(CoseSign1VerificationError::SignatureRejected)
        }
    })
}

pub(crate) fn sign_agent_esp256_cose_sign1(
    payload: &[u8],
    signer: DemoAgentSigner,
) -> Result<Vec<u8>, CoseSign1SigningError> {
    let (private_key, _, _) = demo_agent_key_material(signer);
    let signing_key =
        SigningKey::from_slice(&private_key).map_err(|_| CoseSign1SigningError::KeyRejected)?;
    let public_key = demo_agent_public_cose_key(signer)?;
    let kid = agent_key_kid(&public_key)?;
    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::ESP256)
        .build();
    let unprotected = HeaderBuilder::new().key_id(kid.to_vec()).build();
    let sign1 = CoseSign1Builder::new()
        .protected(protected)
        .unprotected(unprotected)
        .payload(payload.to_vec())
        .try_create_signature(&[], |tbs| {
            let signature: Signature = signing_key.sign(tbs);
            Ok::<_, CoseSign1SigningError>(signature.to_bytes().to_vec())
        })
        .map_err(|_| CoseSign1SigningError::KeyRejected)?
        .build();
    sign1
        .to_tagged_vec()
        .map_err(|_| CoseSign1SigningError::EncodeFailed)
}

fn demo_agent_key_material(signer: DemoAgentSigner) -> ([u8; 32], [u8; 32], [u8; 32]) {
    match signer {
        DemoAgentSigner::Default => (
            DEMO_AGENT_PRIVATE_KEY_D,
            DEMO_AGENT_PUBLIC_KEY_X,
            DEMO_AGENT_PUBLIC_KEY_Y,
        ),
        DemoAgentSigner::Alternate => (
            DEMO_TAM_PRIVATE_KEY_D,
            DEMO_TAM_PUBLIC_KEY_X,
            DEMO_TAM_PUBLIC_KEY_Y,
        ),
    }
}

pub(crate) fn demo_agent_public_cose_key(
    signer: DemoAgentSigner,
) -> Result<Vec<u8>, CoseSign1SigningError> {
    let (_, x, y) = demo_agent_key_material(signer);
    CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, x.to_vec(), y.to_vec())
        .algorithm(iana::Algorithm::ESP256)
        .build()
        .to_vec()
        .map_err(|_| CoseSign1SigningError::EncodeFailed)
}

fn agent_key_kid(public_key: &[u8]) -> Result<[u8; 32], CoseSign1SigningError> {
    if public_key.len() != 77
        || public_key[..10] != [0xa5, 0x01, 0x02, 0x03, 0x28, 0x20, 0x01, 0x21, 0x58, 0x20]
        || public_key[42..45] != [0x22, 0x58, 0x20]
    {
        return Err(CoseSign1SigningError::KeyRejected);
    }
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..33].copy_from_slice(&public_key[10..42]);
    sec1[33..].copy_from_slice(&public_key[45..77]);
    VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| CoseSign1SigningError::KeyRejected)?;
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(&public_key[10..42]);
    y.copy_from_slice(&public_key[45..77]);
    cose_key_thumbprint(x, y)
}

pub(crate) fn sign_demo_evidence_es256_cose_sign1(
    payload: &[u8],
) -> Result<Vec<u8>, CoseSign1SigningError> {
    let kid = cose_key_thumbprint(DEMO_EVIDENCE_PUBLIC_KEY_X, DEMO_EVIDENCE_PUBLIC_KEY_Y)?;
    let signing_key = SigningKey::from_slice(&DEMO_EVIDENCE_PRIVATE_KEY_D)
        .map_err(|_| CoseSign1SigningError::KeyRejected)?;
    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::ES256)
        .build();
    let unprotected = HeaderBuilder::new().key_id(kid.to_vec()).build();
    let sign1 = CoseSign1Builder::new()
        .protected(protected)
        .unprotected(unprotected)
        .payload(payload.to_vec())
        .try_create_signature(&[], |tbs| {
            let signature: Signature = signing_key.sign(tbs);
            Ok::<_, CoseSign1SigningError>(signature.to_bytes().to_vec())
        })
        .map_err(|_| CoseSign1SigningError::KeyRejected)?
        .build();
    sign1
        .to_tagged_vec()
        .map_err(|_| CoseSign1SigningError::EncodeFailed)
}

#[cfg(test)]
#[derive(Clone, Copy)]
pub(crate) enum TestCoseSigner {
    Tam,
    Agent,
}

#[cfg(test)]
pub(crate) fn sign_test_update(
    payload: &[u8],
    signer: TestCoseSigner,
) -> Result<Vec<u8>, CoseSign1SigningError> {
    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::ESP256)
        .build();
    let private_key = match signer {
        TestCoseSigner::Tam => DEMO_TAM_PRIVATE_KEY_D,
        TestCoseSigner::Agent => DEMO_AGENT_PRIVATE_KEY_D,
    };
    let signing_key =
        SigningKey::from_slice(&private_key).map_err(|_| CoseSign1SigningError::KeyRejected)?;
    let sign1 = CoseSign1Builder::new()
        .protected(protected)
        .payload(payload.to_vec())
        .try_create_signature(&[], |tbs| {
            let signature: Signature = signing_key.sign(tbs);
            Ok::<_, CoseSign1SigningError>(signature.to_bytes().to_vec())
        })
        .map_err(|_| CoseSign1SigningError::KeyRejected)?
        .build();
    sign1
        .to_tagged_vec()
        .map_err(|_| CoseSign1SigningError::EncodeFailed)
}

#[cfg(test)]
pub(crate) fn sign_test_suit_auth_detached(
    payload: &[u8],
) -> Result<Vec<u8>, CoseSign1SigningError> {
    let signing_key = SigningKey::from_slice(&DEMO_TAM_PRIVATE_KEY_D)
        .map_err(|_| CoseSign1SigningError::KeyRejected)?;
    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::ESP256)
        .build();
    let sign1 = CoseSign1Builder::new()
        .protected(protected)
        .try_create_detached_signature(payload, &[], |tbs| {
            let signature: Signature = signing_key.sign(tbs);
            Ok::<_, CoseSign1SigningError>(signature.to_bytes().to_vec())
        })
        .map_err(|_| CoseSign1SigningError::KeyRejected)?
        .build();
    sign1
        .to_vec()
        .map_err(|_| CoseSign1SigningError::EncodeFailed)
}

fn cose_key_thumbprint(x: [u8; 32], y: [u8; 32]) -> Result<[u8; 32], CoseSign1SigningError> {
    let key = CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, x.to_vec(), y.to_vec())
        .build()
        .to_vec()
        .map_err(|_| CoseSign1SigningError::EncodeFailed)?;
    Ok(sha256(&key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verified::{VerificationState, VerificationStep};
    use p256::ecdsa::{Signature as P256Signature, SigningKey};

    #[test]
    fn outer_teep_cose_payload_extract_does_not_verify_cose_step() {
        let payload = b"\x82\x01\xa0";
        let mut cose = Vec::new();
        cose.push(0xd2);
        cbor::write_array(&mut cose, 4).unwrap();
        cbor::write_bytes(&mut cose, b"\xa0").unwrap();
        cbor::write_map(&mut cose, 0).unwrap();
        cbor::write_bytes(&mut cose, payload).unwrap();
        cbor::write_bytes(&mut cose, b"signature").unwrap();
        let state = VerificationState::default();
        let manual_payload = cose_sign1_payload(&cose).expect("manual COSE payload");
        let coset_payload =
            outer_teep_cose_sign1_payload_unverified(&cose, &state).expect("coset COSE payload");

        assert_eq!(manual_payload, payload.as_slice());
        assert_eq!(coset_payload, payload);
        assert_eq!(
            state.first_missing_step(),
            Some(VerificationStep::CoseOuter)
        );
    }

    #[test]
    fn outer_teep_cose_payload_accepts_attestam_esp256_header() {
        let payload = b"\x82\x01\xa0";
        let mut cose = Vec::new();
        cose.push(0xd2);
        cbor::write_array(&mut cose, 4).unwrap();
        cbor::write_bytes(&mut cose, b"\xa1\x01\x28").unwrap();
        cbor::write_map(&mut cose, 0).unwrap();
        cbor::write_bytes(&mut cose, payload).unwrap();
        cbor::write_bytes(&mut cose, b"signature").unwrap();
        let state = VerificationState::default();

        let got =
            outer_teep_cose_sign1_payload_unverified(&cose, &state).expect("ESP256 COSE payload");

        assert_eq!(got, payload);
        assert_eq!(
            state.first_missing_step(),
            Some(VerificationStep::CoseOuter)
        );
    }

    #[test]
    fn outer_teep_cose_payload_verified_marks_cose_step() {
        let payload = b"\x82\x01\xa0";
        let mut cose = Vec::new();
        cose.push(0xd2);
        cbor::write_array(&mut cose, 4).unwrap();
        cbor::write_bytes(&mut cose, b"\xa1\x01\x28").unwrap();
        cbor::write_map(&mut cose, 0).unwrap();
        cbor::write_bytes(&mut cose, payload).unwrap();
        cbor::write_bytes(&mut cose, b"signature").unwrap();
        let mut state = VerificationState::default();

        let got =
            outer_teep_cose_sign1_payload_verified_with(&cose, &mut state, |signature, tbs| {
                assert_eq!(signature, b"signature");
                assert!(!tbs.is_empty());
                true
            })
            .expect("verified COSE payload");

        assert_eq!(got, payload);
        assert_eq!(
            state.first_missing_step(),
            Some(VerificationStep::SessionToken)
        );
    }

    #[test]
    fn outer_teep_cose_payload_verified_rejects_bad_signature_without_marking() {
        let payload = b"\x82\x01\xa0";
        let mut cose = Vec::new();
        cose.push(0xd2);
        cbor::write_array(&mut cose, 4).unwrap();
        cbor::write_bytes(&mut cose, b"\xa1\x01\x28").unwrap();
        cbor::write_map(&mut cose, 0).unwrap();
        cbor::write_bytes(&mut cose, payload).unwrap();
        cbor::write_bytes(&mut cose, b"bad-signature").unwrap();
        let mut state = VerificationState::default();

        assert_eq!(
            outer_teep_cose_sign1_payload_verified_with(&cose, &mut state, |signature, _tbs| {
                signature == b"signature"
            }),
            Err(CoseSign1VerificationError::SignatureRejected)
        );
        assert_eq!(
            state.first_missing_step(),
            Some(VerificationStep::CoseOuter)
        );
    }

    #[test]
    fn outer_teep_cose_payload_verified_accepts_demo_tam_esp256_signature() {
        let payload = b"\x82\x01\xa0";
        let unsigned = fixture_esp256_cose_sign1(payload, b"");
        let tbs = outer_teep_cose_sign1(&unsigned)
            .expect("unsigned COSE")
            .tbs_data(&[]);
        let signing_key = SigningKey::from_slice(&DEMO_TAM_PRIVATE_KEY_D).expect("demo TAM key");
        let signature: P256Signature = signing_key.sign(&tbs);
        let signature_bytes = signature.to_bytes().to_vec();
        let cose = fixture_esp256_cose_sign1(payload, &signature_bytes);
        let mut state = VerificationState::default();

        let got = outer_teep_cose_sign1_payload_verified_with(
            &cose,
            &mut state,
            verify_demo_tam_esp256_signature,
        )
        .expect("demo TAM verified COSE");

        assert_eq!(got, payload);
        assert_eq!(
            state.first_missing_step(),
            Some(VerificationStep::SessionToken)
        );
    }

    #[test]
    fn outer_teep_cose_key_id_reads_unprotected_kid() {
        let payload = b"\x82\x01\xa0";
        let mut cose = Vec::new();
        cose.push(0xd2);
        cbor::write_array(&mut cose, 4).unwrap();
        cbor::write_bytes(&mut cose, b"\xa1\x01\x28").unwrap();
        cbor::write_map(&mut cose, 1).unwrap();
        cose.push(0x04);
        cbor::write_bytes(&mut cose, b"tam-key").unwrap();
        cbor::write_bytes(&mut cose, payload).unwrap();
        cbor::write_bytes(&mut cose, b"signature").unwrap();

        assert_eq!(
            outer_teep_cose_sign1_key_id(&cose).expect("COSE key id"),
            Some(b"tam-key".to_vec())
        );
    }

    #[test]
    fn sign_demo_agent_cose_sign1_uses_default_agent_key() {
        let payload = b"\x82\x02\xa0";
        let signed =
            sign_agent_esp256_cose_sign1(payload, DemoAgentSigner::Default).expect("signed COSE");
        let sign1 = CoseSign1::from_tagged_slice(&signed).expect("tagged COSE_Sign1");

        assert_eq!(sign1.payload.as_deref(), Some(payload.as_slice()));
        assert!(outer_teep_cose_sign1_uses_esp256(&sign1));
        assert!(sign1.protected.header.key_id.is_empty());
        assert_eq!(sign1.unprotected.key_id.len(), 32);
        assert_eq!(
            sign1.unprotected.key_id,
            cose_key_thumbprint(DEMO_AGENT_PUBLIC_KEY_X, DEMO_AGENT_PUBLIC_KEY_Y)
                .expect("agent key thumbprint")
        );
        sign1
            .verify_signature(&[], |signature, tbs| {
                if verify_with_key(
                    DEMO_AGENT_PUBLIC_KEY_X,
                    DEMO_AGENT_PUBLIC_KEY_Y,
                    signature,
                    tbs,
                ) {
                    Ok(())
                } else {
                    Err(())
                }
            })
            .expect("signature verified with default key");
    }

    #[test]
    fn cose_key_thumbprint_preserves_default_agent_kid() {
        let expected_kid = [
            0xd0, 0x8d, 0x16, 0x02, 0xca, 0xa2, 0xd0, 0xae, 0x0a, 0xde, 0x02, 0x66, 0x62, 0x92,
            0xb1, 0x4c, 0xef, 0xd0, 0xd0, 0x28, 0x2a, 0x15, 0x3f, 0x77, 0x73, 0xac, 0xf6, 0xfd,
            0xd0, 0xc0, 0xd3, 0x78,
        ];

        assert_eq!(
            cose_key_thumbprint(DEMO_AGENT_PUBLIC_KEY_X, DEMO_AGENT_PUBLIC_KEY_Y)
                .expect("agent key thumbprint"),
            expected_kid
        );
    }

    #[test]
    fn platform_agent_key_requires_canonical_valid_ec2_coordinates() {
        let key = CoseKeyBuilder::new_ec2_pub_key(
            iana::EllipticCurve::P_256,
            DEMO_AGENT_PUBLIC_KEY_X.to_vec(),
            DEMO_AGENT_PUBLIC_KEY_Y.to_vec(),
        )
        .algorithm(iana::Algorithm::ESP256)
        .build()
        .to_vec()
        .expect("canonical key");
        assert_eq!(
            agent_key_kid(&key).unwrap(),
            cose_key_thumbprint(DEMO_AGENT_PUBLIC_KEY_X, DEMO_AGENT_PUBLIC_KEY_Y).unwrap()
        );

        let mut noncanonical = key.clone();
        noncanonical.push(0);
        assert_eq!(
            agent_key_kid(&noncanonical),
            Err(CoseSign1SigningError::KeyRejected)
        );

        let mut reversed_x = key;
        reversed_x[10..42].reverse();
        assert_eq!(
            agent_key_kid(&reversed_x),
            Err(CoseSign1SigningError::KeyRejected)
        );
    }

    #[test]
    fn sign_demo_agent_cose_sign1_can_use_alternate_agent_key() {
        let payload = b"\x82\x02\xa0";
        let signed =
            sign_agent_esp256_cose_sign1(payload, DemoAgentSigner::Alternate).expect("signed COSE");
        let sign1 = CoseSign1::from_tagged_slice(&signed).expect("tagged COSE_Sign1");

        assert_eq!(sign1.payload.as_deref(), Some(payload.as_slice()));
        assert_eq!(
            sign1.unprotected.key_id,
            cose_key_thumbprint(DEMO_TAM_PUBLIC_KEY_X, DEMO_TAM_PUBLIC_KEY_Y)
                .expect("TAM key thumbprint")
        );
        sign1
            .verify_signature(&[], |signature, tbs| {
                if verify_with_key(DEMO_TAM_PUBLIC_KEY_X, DEMO_TAM_PUBLIC_KEY_Y, signature, tbs) {
                    Ok(())
                } else {
                    Err(())
                }
            })
            .expect("signature verified with alternate key");
    }

    #[test]
    fn sign_demo_evidence_cose_sign1_uses_fixed_es256_key_and_rejects_tampering() {
        let payload = b"\xa1\x0a\x48\x31\x32\x33\x34\x35\x36\x37\x38";
        let signed =
            sign_demo_evidence_es256_cose_sign1(payload).expect("signed Generic EAT Evidence");
        let mut sign1 = CoseSign1::from_tagged_slice(&signed).expect("tagged COSE_Sign1");

        assert_eq!(sign1.payload.as_deref(), Some(payload.as_slice()));
        assert_eq!(
            sign1.protected.header.alg,
            Some(Algorithm::Assigned(iana::Algorithm::ES256))
        );
        assert_eq!(
            sign1.unprotected.key_id,
            cose_key_thumbprint(DEMO_EVIDENCE_PUBLIC_KEY_X, DEMO_EVIDENCE_PUBLIC_KEY_Y)
                .expect("Evidence key thumbprint")
        );
        sign1
            .verify_signature(&[], |signature, tbs| {
                if verify_with_key(
                    DEMO_EVIDENCE_PUBLIC_KEY_X,
                    DEMO_EVIDENCE_PUBLIC_KEY_Y,
                    signature,
                    tbs,
                ) {
                    Ok(())
                } else {
                    Err(())
                }
            })
            .expect("signature verified with fixed Evidence key");

        sign1.signature[0] ^= 1;
        assert!(sign1
            .verify_signature(&[], |signature, tbs| {
                if verify_with_key(
                    DEMO_EVIDENCE_PUBLIC_KEY_X,
                    DEMO_EVIDENCE_PUBLIC_KEY_Y,
                    signature,
                    tbs,
                ) {
                    Ok(())
                } else {
                    Err(())
                }
            })
            .is_err());
    }

    #[test]
    fn outer_teep_cose_payload_verified_rejects_unallowed_algorithm() {
        let payload = b"\x82\x01\xa0";
        let mut cose = Vec::new();
        cose.push(0xd2);
        cbor::write_array(&mut cose, 4).unwrap();
        cbor::write_bytes(&mut cose, b"\xa0").unwrap();
        cbor::write_map(&mut cose, 0).unwrap();
        cbor::write_bytes(&mut cose, payload).unwrap();
        cbor::write_bytes(&mut cose, b"signature").unwrap();
        let mut state = VerificationState::default();

        assert_eq!(
            outer_teep_cose_sign1_payload_verified_with(&cose, &mut state, |_, _| true),
            Err(CoseSign1VerificationError::UnsupportedAlgorithm)
        );
        assert_eq!(
            state.first_missing_step(),
            Some(VerificationStep::CoseOuter)
        );
    }

    #[test]
    fn outer_teep_cose_payload_rejects_malformed_cose() {
        let state = VerificationState::default();
        assert_eq!(
            outer_teep_cose_sign1_payload_unverified(b"not-cose", &state),
            Err(CoseSign1VerificationError::Malformed)
        );
    }

    fn fixture_esp256_cose_sign1(payload: &[u8], signature: &[u8]) -> Vec<u8> {
        let mut cose = Vec::new();
        cose.push(0xd2);
        cbor::write_array(&mut cose, 4).unwrap();
        cbor::write_bytes(&mut cose, b"\xa1\x01\x28").unwrap();
        cbor::write_map(&mut cose, 0).unwrap();
        cbor::write_bytes(&mut cose, payload).unwrap();
        cbor::write_bytes(&mut cose, signature).unwrap();
        cose
    }

    fn verify_with_key(x: [u8; 32], y: [u8; 32], signature: &[u8], tbs: &[u8]) -> bool {
        let mut sec1 = [0u8; 65];
        sec1[0] = 0x04;
        sec1[1..33].copy_from_slice(&x);
        sec1[33..65].copy_from_slice(&y);
        let Ok(verifying_key) = VerifyingKey::from_sec1_bytes(&sec1) else {
            return false;
        };
        let Ok(signature) = Signature::from_slice(signature) else {
            return false;
        };
        verifying_key.verify(tbs, &signature).is_ok()
    }
}
