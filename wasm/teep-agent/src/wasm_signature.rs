// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause
use crate::cbor;
use crate::cose::verify_esp256_signature_with_coordinates;

const WASM_MAGIC: &[u8; 4] = b"\0asm";
const SIG_SECTION_NAME: &[u8] = b"twep.sig";
const APP_CODE_SIGNING_PUBLIC_KEY_X: [u8; 32] = [
    0xe5, 0xb5, 0x8f, 0xb0, 0x88, 0xd3, 0xa0, 0x75, 0xc3, 0x22, 0xd9, 0xc2, 0xca, 0x0e, 0xf4, 0xd6,
    0xca, 0xdb, 0xcc, 0x5c, 0x30, 0x6a, 0x5e, 0x44, 0x01, 0x2e, 0x65, 0x18, 0xa4, 0xbc, 0x2f, 0x58,
];
const APP_CODE_SIGNING_PUBLIC_KEY_Y: [u8; 32] = [
    0x2a, 0xb7, 0xd2, 0x2f, 0x7c, 0xdb, 0x0f, 0x36, 0xb5, 0x83, 0x8d, 0x39, 0xbd, 0x89, 0xbd, 0x8e,
    0x68, 0xdc, 0x99, 0x8c, 0x1b, 0xf7, 0x5b, 0x41, 0x30, 0xef, 0xd3, 0x67, 0x5c, 0x1b, 0x3d, 0x1c,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WasmSignatureError {
    Malformed,
    Missing,
    RoleMismatch,
    SignatureRejected,
}

#[derive(Default)]
struct SignaturePayload<'a> {
    alg: Option<&'a [u8]>,
    kid: Option<&'a [u8]>,
    role: Option<&'a [u8]>,
    sig: Option<&'a [u8]>,
}

pub(crate) fn verify_app_signature(input: &[u8]) -> Result<(), WasmSignatureError> {
    let (prefix, payload) = signature_payload(input)?;
    if payload.alg != Some(b"ESP256")
        || payload.kid.is_none_or(|kid| kid.is_empty())
        || payload.role != Some(b"app")
    {
        return Err(WasmSignatureError::RoleMismatch);
    }
    let Some(sig) = payload.sig else {
        return Err(WasmSignatureError::Malformed);
    };
    if sig.len() != 64 {
        return Err(WasmSignatureError::Malformed);
    }
    if verify_esp256_signature_with_coordinates(
        &APP_CODE_SIGNING_PUBLIC_KEY_X,
        &APP_CODE_SIGNING_PUBLIC_KEY_Y,
        sig,
        prefix,
    ) {
        Ok(())
    } else {
        Err(WasmSignatureError::SignatureRejected)
    }
}

fn signature_payload(input: &[u8]) -> Result<(&[u8], SignaturePayload<'_>), WasmSignatureError> {
    if input.len() < 8 || &input[..4] != WASM_MAGIC {
        return Err(WasmSignatureError::Malformed);
    }
    let mut off = 8usize;
    while off < input.len() {
        let section_start = off;
        let section_id = *input.get(off).ok_or(WasmSignatureError::Malformed)?;
        off += 1;
        let section_len = read_varuint32(input, &mut off).ok_or(WasmSignatureError::Malformed)?;
        if section_len > input.len().saturating_sub(off) {
            return Err(WasmSignatureError::Malformed);
        }
        let payload_start = off;
        let payload_end = off + section_len;
        if section_id == 0 {
            if let Some((name, name_end)) = custom_section_name(&input[payload_start..payload_end])
            {
                if name == SIG_SECTION_NAME {
                    if payload_end != input.len() {
                        return Err(WasmSignatureError::Malformed);
                    }
                    let payload =
                        parse_signature_payload(&input[payload_start + name_end..payload_end])?;
                    return Ok((&input[..section_start], payload));
                }
            }
        }
        off = payload_end;
    }
    Err(WasmSignatureError::Missing)
}

fn parse_signature_payload(input: &[u8]) -> Result<SignaturePayload<'_>, WasmSignatureError> {
    let mut off = 0usize;
    let Some((major, pairs)) = cbor::head(input, &mut off) else {
        return Err(WasmSignatureError::Malformed);
    };
    if major != 5 {
        return Err(WasmSignatureError::Malformed);
    }
    let mut payload = SignaturePayload::default();
    for _ in 0..pairs {
        let key = cbor::text(input, &mut off).ok_or(WasmSignatureError::Malformed)?;
        if key == b"alg" {
            payload.alg = Some(cbor::text(input, &mut off).ok_or(WasmSignatureError::Malformed)?);
        } else if key == b"kid" {
            payload.kid = Some(cbor::bytes(input, &mut off).ok_or(WasmSignatureError::Malformed)?);
        } else if key == b"role" {
            payload.role = Some(cbor::text(input, &mut off).ok_or(WasmSignatureError::Malformed)?);
        } else if key == b"sig" {
            payload.sig = Some(cbor::bytes(input, &mut off).ok_or(WasmSignatureError::Malformed)?);
        } else if !cbor::skip(input, &mut off) {
            return Err(WasmSignatureError::Malformed);
        }
    }
    if off == input.len() {
        Ok(payload)
    } else {
        Err(WasmSignatureError::Malformed)
    }
}

fn custom_section_name(input: &[u8]) -> Option<(&[u8], usize)> {
    let mut off = 0usize;
    let name_len = read_varuint32(input, &mut off)?;
    if name_len > input.len().saturating_sub(off) {
        return None;
    }
    Some((&input[off..off + name_len], off + name_len))
}

fn read_varuint32(input: &[u8], off: &mut usize) -> Option<usize> {
    let mut value = 0usize;
    let mut shift = 0usize;
    for _ in 0..5 {
        let byte = *input.get(*off)?;
        *off += 1;
        value |= ((byte & 0x7f) as usize) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
        shift += 7;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};

    const APP_CODE_SIGNING_PRIVATE_KEY_D: [u8; 32] = [
        0xc8, 0x38, 0xa4, 0x96, 0x98, 0x0a, 0x3d, 0x0f, 0xb3, 0x9b, 0xaf, 0x40, 0x84, 0xbf, 0x97,
        0x3c, 0xd1, 0x70, 0x3b, 0x92, 0x5d, 0x99, 0x8b, 0xaa, 0xed, 0x38, 0x85, 0x57, 0x89, 0x35,
        0xec, 0xdf,
    ];
    const TEEP_AGENT_CODE_SIGNING_PRIVATE_KEY_D: [u8; 32] = [
        0xa9, 0x3e, 0xcf, 0x9d, 0xc1, 0x37, 0x87, 0xaa, 0x36, 0x80, 0x10, 0xa9, 0xf0, 0x2d, 0x6a,
        0x09, 0xb0, 0x34, 0x74, 0x35, 0xc7, 0xca, 0x3a, 0xc2, 0x5e, 0xd4, 0x1f, 0x5a, 0xa3, 0x50,
        0xff, 0x36,
    ];

    #[test]
    fn verifies_valid_app_signature() {
        let signed = sign_test_wasm(b"app", &APP_CODE_SIGNING_PRIVATE_KEY_D);
        assert_eq!(verify_app_signature(&signed), Ok(()));
    }

    #[test]
    fn rejects_wrong_role() {
        let signed = sign_test_wasm(b"teep-agent", &TEEP_AGENT_CODE_SIGNING_PRIVATE_KEY_D);
        assert_eq!(
            verify_app_signature(&signed),
            Err(WasmSignatureError::RoleMismatch)
        );
    }

    #[test]
    fn rejects_tamper() {
        let mut signed = sign_test_wasm(b"app", &APP_CODE_SIGNING_PRIVATE_KEY_D);
        signed[7] ^= 1;
        assert_eq!(
            verify_app_signature(&signed),
            Err(WasmSignatureError::SignatureRejected)
        );
    }

    #[test]
    fn rejects_missing_or_nonfinal_signature() {
        let wasm = minimal_wasm();
        assert_eq!(
            verify_app_signature(&wasm),
            Err(WasmSignatureError::Missing)
        );
        let mut signed = sign_test_wasm(b"app", &APP_CODE_SIGNING_PRIVATE_KEY_D);
        signed.extend_from_slice(&[0x00, 0x01, 0x00]);
        assert_eq!(
            verify_app_signature(&signed),
            Err(WasmSignatureError::Malformed)
        );
    }

    fn sign_test_wasm(role: &[u8], private_key: &[u8; 32]) -> Vec<u8> {
        let mut wasm = minimal_wasm();
        let key = SigningKey::from_slice(private_key).expect("signing key");
        let sig: Signature = key.sign(&wasm);
        let sig = sig.to_bytes();
        let mut payload = Vec::new();
        cbor::write_map(&mut payload, 4).unwrap();
        cbor::write_text(&mut payload, b"alg").unwrap();
        cbor::write_text(&mut payload, b"ESP256").unwrap();
        cbor::write_text(&mut payload, b"kid").unwrap();
        cbor::write_bytes(&mut payload, b"test").unwrap();
        cbor::write_text(&mut payload, b"sig").unwrap();
        cbor::write_bytes(&mut payload, &sig).unwrap();
        cbor::write_text(&mut payload, b"role").unwrap();
        cbor::write_text(&mut payload, role).unwrap();

        let section_len = SIG_SECTION_NAME.len() + payload.len() + 1;
        wasm.push(0);
        write_varuint32(&mut wasm, section_len);
        write_varuint32(&mut wasm, SIG_SECTION_NAME.len());
        wasm.extend_from_slice(SIG_SECTION_NAME);
        wasm.extend_from_slice(&payload);
        wasm
    }

    fn minimal_wasm() -> Vec<u8> {
        b"\0asm\x01\0\0\0".to_vec()
    }

    fn write_varuint32(out: &mut Vec<u8>, mut value: usize) {
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                out.push(byte);
                return;
            }
            byte |= 0x80;
            out.push(byte);
        }
    }
}
