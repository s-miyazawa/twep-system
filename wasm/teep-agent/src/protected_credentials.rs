// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause
use ciborium::value::Value;

use crate::{cbor, credential_management::TrustAnchorLoadStatus};

const ATTESTAM_MESSAGE_VERIFICATION_KEYS_FIELD: &[u8] = b"attestam_message_verification_keys";
const SUIT_CONTENT_VERIFICATION_KEYS_FIELD: &[u8] = b"suit_content_verification_keys";
const TRUST_ANCHOR_KID_FIELD: &[u8] = b"kid";
const TRUST_ANCHOR_PURPOSE_FIELD: &[u8] = b"purpose";
const TRUST_ANCHOR_ALG_FIELD: &[u8] = b"alg";
const TRUST_ANCHOR_CRV_FIELD: &[u8] = b"crv";
const TRUST_ANCHOR_X_FIELD: &[u8] = b"x";
const TRUST_ANCHOR_Y_FIELD: &[u8] = b"y";
const TRUST_ANCHOR_PUBLIC_X_FIELD: &[u8] = b"public_x";
const TRUST_ANCHOR_PUBLIC_Y_FIELD: &[u8] = b"public_y";
const TRUST_ANCHOR_PURPOSE_ATTESTAM_MESSAGE_VERIFICATION: &[u8] = b"attestam-message-verification";
const TRUST_ANCHOR_PURPOSE_SUIT_CONTENT_VERIFICATION: &[u8] = b"suit-content-verification";
const TRUST_ANCHOR_PURPOSE_WASM_APP_CODE_SIGNATURE_VERIFICATION: &[u8] =
    b"wasm-app-code-signature-verification";
const TRUST_ANCHOR_PURPOSE_EVIDENCE_SIGNING_CPU: &[u8] = b"evidence-signing-cpu";
const TRUST_ANCHOR_PURPOSE_EVIDENCE_SIGNING_TEEP_AGENT: &[u8] = b"evidence-signing-teep-agent";
const TRUST_ANCHOR_ALG_ESP256: &[u8] = b"ESP256";
const TRUST_ANCHOR_ALG_ES256: &[u8] = b"ES256";
const TRUST_ANCHOR_CRV_P256: &[u8] = b"P-256";

const PROTECTED_CREDENTIAL_SCHEMA_VERSION_FIELD: &[u8] = b"schema_version";
const PROTECTED_CREDENTIAL_STORE_EPOCH_FIELD: &[u8] = b"store_epoch";
const PROTECTED_CREDENTIAL_REVOKED_ENTRY_IDS_FIELD: &[u8] = b"revoked_entry_ids";
const PROTECTED_CREDENTIAL_ENTRY_ID_FIELD: &[u8] = b"entry_id";
const PROTECTED_CREDENTIAL_ISSUER_ID_FIELD: &[u8] = b"issuer_id";
const PROTECTED_CREDENTIAL_NOT_BEFORE_FIELD: &[u8] = b"not_before";
const PROTECTED_CREDENTIAL_NOT_AFTER_FIELD: &[u8] = b"not_after";
const PROTECTED_CREDENTIAL_PROVISIONING_EPOCH_FIELD: &[u8] = b"provisioning_epoch";
const PROTECTED_CREDENTIAL_EVIDENCE_SIGNING_KEYS_FIELD: &[u8] = b"evidence_signing_keys";
const PROTECTED_CREDENTIAL_WASM_APP_CODE_SIGNATURE_VERIFICATION_KEYS_FIELD: &[u8] =
    b"wasm_app_code_signature_verification_keys";
const PROTECTED_CREDENTIAL_PRIVATE_KEY_REF_FIELD: &[u8] = b"private_key_ref";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProtectedCredentialStoreStatus {
    pub(crate) load_status: TrustAnchorLoadStatus,
    pub(crate) attestam_message_key_count: usize,
    pub(crate) suit_content_key_count: usize,
    pub(crate) observed_attestam_kid_match: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AttestamMessageVerificationKey {
    pub(crate) x: [u8; 32],
    pub(crate) y: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SuitContentVerificationKey {
    pub(crate) x: [u8; 32],
    pub(crate) y: [u8; 32],
}

pub(crate) fn attestam_message_verification_key(
    input: &[u8],
    observed_kid: &[u8],
) -> Option<AttestamMessageVerificationKey> {
    if observed_kid.is_empty() {
        return None;
    }
    let Value::Map(pairs) = cbor::value(input)? else {
        return None;
    };
    protected_credential_store_map_status(&pairs, Some(observed_kid))?;
    let entries = map_array_field(&pairs, ATTESTAM_MESSAGE_VERIFICATION_KEYS_FIELD)?;
    let mut matched = None;
    for entry in entries {
        let entry_pairs = protected_common_entry_pairs(
            entry,
            TRUST_ANCHOR_PURPOSE_ATTESTAM_MESSAGE_VERIFICATION,
            TRUST_ANCHOR_ALG_ESP256,
        )?;
        if map_bytes_field(entry_pairs, TRUST_ANCHOR_KID_FIELD)? != observed_kid {
            continue;
        }
        if matched.is_some() {
            return None;
        }
        let x: [u8; 32] = map_bytes_field(entry_pairs, TRUST_ANCHOR_X_FIELD)?
            .try_into()
            .ok()?;
        let y: [u8; 32] = map_bytes_field(entry_pairs, TRUST_ANCHOR_Y_FIELD)?
            .try_into()
            .ok()?;
        matched = Some(AttestamMessageVerificationKey { x, y });
    }
    matched
}

pub(crate) fn suit_content_verification_key(
    input: &[u8],
    observed_kid: &[u8],
) -> Option<SuitContentVerificationKey> {
    if observed_kid.is_empty() {
        return None;
    }
    let Value::Map(pairs) = cbor::value(input)? else {
        return None;
    };
    protected_credential_store_map_status(&pairs, None)?;
    let entries = map_array_field(&pairs, SUIT_CONTENT_VERIFICATION_KEYS_FIELD)?;
    let mut matched = None;
    for entry in entries {
        let entry_pairs = protected_common_entry_pairs(
            entry,
            TRUST_ANCHOR_PURPOSE_SUIT_CONTENT_VERIFICATION,
            TRUST_ANCHOR_ALG_ESP256,
        )?;
        if map_bytes_field(entry_pairs, TRUST_ANCHOR_KID_FIELD)? != observed_kid {
            continue;
        }
        if matched.is_some() {
            return None;
        }
        let x: [u8; 32] = map_bytes_field(entry_pairs, TRUST_ANCHOR_X_FIELD)?
            .try_into()
            .ok()?;
        let y: [u8; 32] = map_bytes_field(entry_pairs, TRUST_ANCHOR_Y_FIELD)?
            .try_into()
            .ok()?;
        matched = Some(SuitContentVerificationKey { x, y });
    }
    matched
}

pub(crate) fn protected_credential_store_status(
    input: Option<&[u8]>,
    observed_attestam_kid: Option<&[u8]>,
) -> ProtectedCredentialStoreStatus {
    let Some(input) = input else {
        return unsupported_protected_credential_store_status(TrustAnchorLoadStatus::Absent);
    };
    match cbor::value(input) {
        Some(Value::Map(pairs)) => {
            match protected_credential_store_map_status(&pairs, observed_attestam_kid) {
                Some(status) => status,
                None => unsupported_protected_credential_store_status(
                    TrustAnchorLoadStatus::Unsupported,
                ),
            }
        }
        Some(_) => {
            unsupported_protected_credential_store_status(TrustAnchorLoadStatus::Unsupported)
        }
        None => unsupported_protected_credential_store_status(TrustAnchorLoadStatus::Malformed),
    }
}

fn protected_credential_store_map_status(
    pairs: &[(Value, Value)],
    observed_attestam_kid: Option<&[u8]>,
) -> Option<ProtectedCredentialStoreStatus> {
    if map_uint_field(pairs, PROTECTED_CREDENTIAL_SCHEMA_VERSION_FIELD)? != 1 {
        return None;
    }
    map_uint_field(pairs, PROTECTED_CREDENTIAL_STORE_EPOCH_FIELD)?;
    let attestam_keys = map_array_field(pairs, ATTESTAM_MESSAGE_VERIFICATION_KEYS_FIELD)?;
    let suit_keys = map_array_field(pairs, SUIT_CONTENT_VERIFICATION_KEYS_FIELD)?;

    let observed_attestam_kid_match = protected_public_key_entries_match_observed_kid(
        attestam_keys,
        TRUST_ANCHOR_PURPOSE_ATTESTAM_MESSAGE_VERIFICATION,
        TRUST_ANCHOR_ALG_ESP256,
        observed_attestam_kid,
    )?;
    if !protected_public_key_entries_are_supported(
        suit_keys,
        TRUST_ANCHOR_PURPOSE_SUIT_CONTENT_VERIFICATION,
        TRUST_ANCHOR_ALG_ESP256,
    ) {
        return None;
    }
    if let Some(wasm_app_keys) = map_optional_array_field(
        pairs,
        PROTECTED_CREDENTIAL_WASM_APP_CODE_SIGNATURE_VERIFICATION_KEYS_FIELD,
    )? {
        if !protected_public_key_entries_are_supported(
            wasm_app_keys,
            TRUST_ANCHOR_PURPOSE_WASM_APP_CODE_SIGNATURE_VERIFICATION,
            TRUST_ANCHOR_ALG_ESP256,
        ) {
            return None;
        }
    }
    if let Some(evidence_signing_keys) =
        map_optional_array_field(pairs, PROTECTED_CREDENTIAL_EVIDENCE_SIGNING_KEYS_FIELD)?
    {
        if !evidence_signing_key_entries_are_supported(evidence_signing_keys) {
            return None;
        }
    }
    if let Some(revoked_entry_ids) =
        map_optional_array_field(pairs, PROTECTED_CREDENTIAL_REVOKED_ENTRY_IDS_FIELD)?
    {
        if !all_values_are_bytes(revoked_entry_ids) {
            return None;
        }
    }

    Some(ProtectedCredentialStoreStatus {
        load_status: TrustAnchorLoadStatus::Loaded,
        attestam_message_key_count: attestam_keys.len(),
        suit_content_key_count: suit_keys.len(),
        observed_attestam_kid_match,
    })
}

fn unsupported_protected_credential_store_status(
    load_status: TrustAnchorLoadStatus,
) -> ProtectedCredentialStoreStatus {
    ProtectedCredentialStoreStatus {
        load_status,
        attestam_message_key_count: 0,
        suit_content_key_count: 0,
        observed_attestam_kid_match: false,
    }
}

fn protected_public_key_entries_are_supported(
    entries: &[Value],
    expected_purpose: &[u8],
    expected_alg: &[u8],
) -> bool {
    entries.iter().all(|entry| {
        protected_public_key_entry_kid(entry, expected_purpose, expected_alg).is_some()
    })
}

fn protected_public_key_entries_match_observed_kid(
    entries: &[Value],
    expected_purpose: &[u8],
    expected_alg: &[u8],
    observed_attestam_kid: Option<&[u8]>,
) -> Option<bool> {
    let mut matched = false;
    for entry in entries {
        let kid = protected_public_key_entry_kid(entry, expected_purpose, expected_alg)?;
        if let Some(observed_attestam_kid) = observed_attestam_kid {
            if kid == observed_attestam_kid {
                matched = true;
            }
        }
    }
    Some(matched)
}

fn protected_public_key_entry_kid<'a>(
    entry: &'a Value,
    expected_purpose: &[u8],
    expected_alg: &[u8],
) -> Option<&'a [u8]> {
    let pairs = protected_common_entry_pairs(entry, expected_purpose, expected_alg)?;
    let x = map_bytes_field(pairs, TRUST_ANCHOR_X_FIELD)?;
    let y = map_bytes_field(pairs, TRUST_ANCHOR_Y_FIELD)?;
    if x.len() != 32 || y.len() != 32 {
        return None;
    }
    map_bytes_field(pairs, TRUST_ANCHOR_KID_FIELD)
}

fn evidence_signing_key_entries_are_supported(entries: &[Value]) -> bool {
    entries.iter().all(evidence_signing_key_entry_is_supported)
}

fn evidence_signing_key_entry_is_supported(entry: &Value) -> bool {
    let pairs = match entry {
        Value::Map(pairs) => pairs,
        _ => return false,
    };
    let purpose = map_text_field(pairs, TRUST_ANCHOR_PURPOSE_FIELD);
    let Some(purpose) = purpose else {
        return false;
    };
    if purpose != TRUST_ANCHOR_PURPOSE_EVIDENCE_SIGNING_CPU
        && purpose != TRUST_ANCHOR_PURPOSE_EVIDENCE_SIGNING_TEEP_AGENT
    {
        return false;
    }
    let Some(pairs) = protected_common_entry_pairs(entry, purpose, TRUST_ANCHOR_ALG_ES256) else {
        return false;
    };
    let Some(public_x) = map_bytes_field(pairs, TRUST_ANCHOR_PUBLIC_X_FIELD) else {
        return false;
    };
    let Some(public_y) = map_bytes_field(pairs, TRUST_ANCHOR_PUBLIC_Y_FIELD) else {
        return false;
    };
    let Some(private_key_ref) = map_bytes_field(pairs, PROTECTED_CREDENTIAL_PRIVATE_KEY_REF_FIELD)
    else {
        return false;
    };
    public_x.len() == 32 && public_y.len() == 32 && !private_key_ref.is_empty()
}

fn protected_common_entry_pairs<'a>(
    entry: &'a Value,
    expected_purpose: &[u8],
    expected_alg: &[u8],
) -> Option<&'a [(Value, Value)]> {
    let pairs = match entry {
        Value::Map(pairs) => pairs,
        _ => return None,
    };
    let entry_id = map_bytes_field(pairs, PROTECTED_CREDENTIAL_ENTRY_ID_FIELD)?;
    let issuer_id = map_bytes_field(pairs, PROTECTED_CREDENTIAL_ISSUER_ID_FIELD)?;
    let kid = map_bytes_field(pairs, TRUST_ANCHOR_KID_FIELD)?;
    let purpose = map_text_field(pairs, TRUST_ANCHOR_PURPOSE_FIELD)?;
    let alg = map_text_field(pairs, TRUST_ANCHOR_ALG_FIELD)?;
    let crv = map_text_field(pairs, TRUST_ANCHOR_CRV_FIELD)?;
    let not_before = map_uint_field(pairs, PROTECTED_CREDENTIAL_NOT_BEFORE_FIELD)?;
    let not_after = map_uint_field(pairs, PROTECTED_CREDENTIAL_NOT_AFTER_FIELD)?;
    map_uint_field(pairs, PROTECTED_CREDENTIAL_PROVISIONING_EPOCH_FIELD)?;
    if entry_id.is_empty() || issuer_id.is_empty() || kid.is_empty() {
        return None;
    }
    if purpose != expected_purpose || alg != expected_alg || crv != TRUST_ANCHOR_CRV_P256 {
        return None;
    }
    if not_after < not_before {
        return None;
    }
    Some(pairs)
}

fn map_array_field<'a>(pairs: &'a [(Value, Value)], field: &[u8]) -> Option<&'a [Value]> {
    for (key, value) in pairs {
        if let Value::Text(text) = key {
            if text.as_bytes() == field {
                if let Value::Array(values) = value {
                    return Some(values);
                }
            }
        }
    }
    None
}

fn map_optional_array_field<'a>(
    pairs: &'a [(Value, Value)],
    field: &[u8],
) -> Option<Option<&'a [Value]>> {
    for (key, value) in pairs {
        if let Value::Text(text) = key {
            if text.as_bytes() == field {
                if let Value::Array(values) = value {
                    return Some(Some(values));
                }
                return None;
            }
        }
    }
    Some(None)
}

fn map_bytes_field<'a>(pairs: &'a [(Value, Value)], field: &[u8]) -> Option<&'a [u8]> {
    for (key, value) in pairs {
        if let Value::Text(text) = key {
            if text.as_bytes() == field {
                if let Value::Bytes(bytes) = value {
                    return Some(bytes);
                }
            }
        }
    }
    None
}

fn map_text_field<'a>(pairs: &'a [(Value, Value)], field: &[u8]) -> Option<&'a [u8]> {
    for (key, value) in pairs {
        if let Value::Text(text) = key {
            if text.as_bytes() == field {
                if let Value::Text(value) = value {
                    return Some(value.as_bytes());
                }
            }
        }
    }
    None
}

fn map_uint_field(pairs: &[(Value, Value)], field: &[u8]) -> Option<usize> {
    for (key, value) in pairs {
        if let Value::Text(text) = key {
            if text.as_bytes() == field {
                return cbor::uint_value(value);
            }
        }
    }
    None
}

fn all_values_are_bytes(values: &[Value]) -> bool {
    values.iter().all(|value| matches!(value, Value::Bytes(_)))
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    #[test]
    fn protected_credential_store_status_accepts_minimal_schema_but_remains_unbound() {
        let input = minimal_protected_credential_store();

        assert_eq!(
            protected_credential_store_status(Some(&input), Some(b"tam-key")),
            ProtectedCredentialStoreStatus {
                load_status: TrustAnchorLoadStatus::Loaded,
                attestam_message_key_count: 1,
                suit_content_key_count: 1,
                observed_attestam_kid_match: true,
            }
        );
    }

    #[test]
    fn attestam_message_verification_key_selects_unique_kid() {
        let input = minimal_protected_credential_store();

        assert_eq!(
            attestam_message_verification_key(&input, b"tam-key"),
            Some(AttestamMessageVerificationKey {
                x: [8u8; 32],
                y: [8u8; 32],
            })
        );
        assert_eq!(
            attestam_message_verification_key(&input, b"missing-key"),
            None
        );
    }

    #[test]
    fn attestam_message_verification_key_rejects_duplicate_kid() {
        let mut input = Vec::new();
        cbor::write_map(&mut input, 4).unwrap();
        write_protected_credential_store_header(&mut input);
        cbor::write_text(&mut input, ATTESTAM_MESSAGE_VERIFICATION_KEYS_FIELD).unwrap();
        cbor::write_array(&mut input, 2).unwrap();
        write_protected_public_key_entry(
            &mut input,
            b"tam-entry-1",
            b"tam-key",
            TRUST_ANCHOR_PURPOSE_ATTESTAM_MESSAGE_VERIFICATION,
        );
        write_protected_public_key_entry(
            &mut input,
            b"tam-entry-2",
            b"tam-key",
            TRUST_ANCHOR_PURPOSE_ATTESTAM_MESSAGE_VERIFICATION,
        );
        cbor::write_text(&mut input, SUIT_CONTENT_VERIFICATION_KEYS_FIELD).unwrap();
        cbor::write_array(&mut input, 0).unwrap();

        assert_eq!(attestam_message_verification_key(&input, b"tam-key"), None);
    }

    #[test]
    fn suit_content_verification_key_selects_unique_purpose_specific_kid() {
        let input = minimal_protected_credential_store();

        assert_eq!(
            suit_content_verification_key(&input, b"suit-key"),
            Some(SuitContentVerificationKey {
                x: [8u8; 32],
                y: [8u8; 32],
            })
        );
        assert_eq!(suit_content_verification_key(&input, b"tam-key"), None);
        assert_eq!(suit_content_verification_key(&input, b"missing-key"), None);
        assert_eq!(suit_content_verification_key(&input, b""), None);
    }

    #[test]
    fn suit_content_verification_key_rejects_duplicate_kid() {
        let mut input = Vec::new();
        cbor::write_map(&mut input, 4).unwrap();
        write_protected_credential_store_header(&mut input);
        cbor::write_text(&mut input, ATTESTAM_MESSAGE_VERIFICATION_KEYS_FIELD).unwrap();
        cbor::write_array(&mut input, 0).unwrap();
        cbor::write_text(&mut input, SUIT_CONTENT_VERIFICATION_KEYS_FIELD).unwrap();
        cbor::write_array(&mut input, 2).unwrap();
        write_protected_public_key_entry(
            &mut input,
            b"suit-entry-1",
            b"suit-key",
            TRUST_ANCHOR_PURPOSE_SUIT_CONTENT_VERIFICATION,
        );
        write_protected_public_key_entry(
            &mut input,
            b"suit-entry-2",
            b"suit-key",
            TRUST_ANCHOR_PURPOSE_SUIT_CONTENT_VERIFICATION,
        );

        assert_eq!(suit_content_verification_key(&input, b"suit-key"), None);
    }

    #[test]
    fn suit_content_verification_key_rejects_malformed_store_entry() {
        let mut input = Vec::new();
        cbor::write_map(&mut input, 4).unwrap();
        write_protected_credential_store_header(&mut input);
        cbor::write_text(&mut input, ATTESTAM_MESSAGE_VERIFICATION_KEYS_FIELD).unwrap();
        cbor::write_array(&mut input, 0).unwrap();
        cbor::write_text(&mut input, SUIT_CONTENT_VERIFICATION_KEYS_FIELD).unwrap();
        cbor::write_array(&mut input, 1).unwrap();
        write_protected_public_key_entry(
            &mut input,
            b"suit-entry",
            b"suit-key",
            TRUST_ANCHOR_PURPOSE_ATTESTAM_MESSAGE_VERIFICATION,
        );

        assert_eq!(suit_content_verification_key(&input, b"suit-key"), None);
    }

    #[test]
    fn protected_credential_store_status_rejects_dev_fixture_shape() {
        let input = minimal_dev_trust_anchor_with_attestam_key_entry(b"tam-key");

        assert_eq!(
            protected_credential_store_status(Some(&input), Some(b"tam-key")),
            ProtectedCredentialStoreStatus {
                load_status: TrustAnchorLoadStatus::Unsupported,
                attestam_message_key_count: 0,
                suit_content_key_count: 0,
                observed_attestam_kid_match: false,
            }
        );
    }

    #[test]
    fn protected_credential_store_status_rejects_malformed_or_wrong_version() {
        assert_eq!(
            protected_credential_store_status(None, None).load_status,
            TrustAnchorLoadStatus::Absent
        );
        assert_eq!(
            protected_credential_store_status(Some(b"not-cbor"), None).load_status,
            TrustAnchorLoadStatus::Malformed
        );

        let mut input = Vec::new();
        cbor::write_map(&mut input, 3).unwrap();
        cbor::write_text(&mut input, PROTECTED_CREDENTIAL_SCHEMA_VERSION_FIELD).unwrap();
        cbor::write_uint(&mut input, 2).unwrap();
        cbor::write_text(&mut input, PROTECTED_CREDENTIAL_STORE_EPOCH_FIELD).unwrap();
        cbor::write_uint(&mut input, 1).unwrap();
        cbor::write_text(&mut input, ATTESTAM_MESSAGE_VERIFICATION_KEYS_FIELD).unwrap();
        cbor::write_array(&mut input, 0).unwrap();

        assert_eq!(
            protected_credential_store_status(Some(&input), None).load_status,
            TrustAnchorLoadStatus::Unsupported
        );
    }

    #[test]
    fn protected_credential_store_status_validates_optional_fields() {
        let input = protected_credential_store_with_optional_evidence_key(TRUST_ANCHOR_ALG_ES256);

        assert_eq!(
            protected_credential_store_status(Some(&input), Some(b"missing-key")).load_status,
            TrustAnchorLoadStatus::Loaded
        );

        let input = protected_credential_store_with_optional_evidence_key(TRUST_ANCHOR_ALG_ESP256);

        assert_eq!(
            protected_credential_store_status(Some(&input), None).load_status,
            TrustAnchorLoadStatus::Unsupported
        );
    }

    fn minimal_dev_trust_anchor_with_attestam_key_entry(kid: &[u8]) -> Vec<u8> {
        let mut input = Vec::new();
        let coordinate = [7u8; 32];
        cbor::write_map(&mut input, 2).unwrap();
        cbor::write_text(&mut input, ATTESTAM_MESSAGE_VERIFICATION_KEYS_FIELD).unwrap();
        cbor::write_array(&mut input, 1).unwrap();
        cbor::write_map(&mut input, 6).unwrap();
        cbor::write_text(&mut input, TRUST_ANCHOR_KID_FIELD).unwrap();
        cbor::write_bytes(&mut input, kid).unwrap();
        cbor::write_text(&mut input, TRUST_ANCHOR_PURPOSE_FIELD).unwrap();
        cbor::write_text(
            &mut input,
            TRUST_ANCHOR_PURPOSE_ATTESTAM_MESSAGE_VERIFICATION,
        )
        .unwrap();
        cbor::write_text(&mut input, TRUST_ANCHOR_ALG_FIELD).unwrap();
        cbor::write_text(&mut input, TRUST_ANCHOR_ALG_ESP256).unwrap();
        cbor::write_text(&mut input, TRUST_ANCHOR_CRV_FIELD).unwrap();
        cbor::write_text(&mut input, TRUST_ANCHOR_CRV_P256).unwrap();
        cbor::write_text(&mut input, TRUST_ANCHOR_X_FIELD).unwrap();
        cbor::write_bytes(&mut input, &coordinate).unwrap();
        cbor::write_text(&mut input, TRUST_ANCHOR_Y_FIELD).unwrap();
        cbor::write_bytes(&mut input, &coordinate).unwrap();
        cbor::write_text(&mut input, SUIT_CONTENT_VERIFICATION_KEYS_FIELD).unwrap();
        cbor::write_array(&mut input, 0).unwrap();
        input
    }

    fn minimal_protected_credential_store() -> Vec<u8> {
        let mut input = Vec::new();
        cbor::write_map(&mut input, 4).unwrap();
        write_protected_credential_store_header(&mut input);
        cbor::write_text(&mut input, ATTESTAM_MESSAGE_VERIFICATION_KEYS_FIELD).unwrap();
        cbor::write_array(&mut input, 1).unwrap();
        write_protected_public_key_entry(
            &mut input,
            b"tam-entry",
            b"tam-key",
            TRUST_ANCHOR_PURPOSE_ATTESTAM_MESSAGE_VERIFICATION,
        );
        cbor::write_text(&mut input, SUIT_CONTENT_VERIFICATION_KEYS_FIELD).unwrap();
        cbor::write_array(&mut input, 1).unwrap();
        write_protected_public_key_entry(
            &mut input,
            b"suit-entry",
            b"suit-key",
            TRUST_ANCHOR_PURPOSE_SUIT_CONTENT_VERIFICATION,
        );
        input
    }

    fn protected_credential_store_with_optional_evidence_key(evidence_alg: &[u8]) -> Vec<u8> {
        let mut input = Vec::new();
        cbor::write_map(&mut input, 5).unwrap();
        write_protected_credential_store_header(&mut input);
        cbor::write_text(&mut input, ATTESTAM_MESSAGE_VERIFICATION_KEYS_FIELD).unwrap();
        cbor::write_array(&mut input, 1).unwrap();
        write_protected_public_key_entry(
            &mut input,
            b"tam-entry",
            b"tam-key",
            TRUST_ANCHOR_PURPOSE_ATTESTAM_MESSAGE_VERIFICATION,
        );
        cbor::write_text(&mut input, SUIT_CONTENT_VERIFICATION_KEYS_FIELD).unwrap();
        cbor::write_array(&mut input, 1).unwrap();
        write_protected_public_key_entry(
            &mut input,
            b"suit-entry",
            b"suit-key",
            TRUST_ANCHOR_PURPOSE_SUIT_CONTENT_VERIFICATION,
        );
        cbor::write_text(&mut input, PROTECTED_CREDENTIAL_EVIDENCE_SIGNING_KEYS_FIELD).unwrap();
        cbor::write_array(&mut input, 1).unwrap();
        write_protected_evidence_signing_key_entry(&mut input, evidence_alg);
        input
    }

    fn write_protected_credential_store_header(out: &mut Vec<u8>) {
        cbor::write_text(out, PROTECTED_CREDENTIAL_SCHEMA_VERSION_FIELD).unwrap();
        cbor::write_uint(out, 1).unwrap();
        cbor::write_text(out, PROTECTED_CREDENTIAL_STORE_EPOCH_FIELD).unwrap();
        cbor::write_uint(out, 1).unwrap();
    }

    fn write_protected_public_key_entry(
        out: &mut Vec<u8>,
        entry_id: &[u8],
        kid: &[u8],
        purpose: &[u8],
    ) {
        let coordinate = [8u8; 32];
        cbor::write_map(out, 11).unwrap();
        write_protected_common_entry_fields(out, entry_id, kid, purpose, TRUST_ANCHOR_ALG_ESP256);
        cbor::write_text(out, TRUST_ANCHOR_X_FIELD).unwrap();
        cbor::write_bytes(out, &coordinate).unwrap();
        cbor::write_text(out, TRUST_ANCHOR_Y_FIELD).unwrap();
        cbor::write_bytes(out, &coordinate).unwrap();
    }

    fn write_protected_evidence_signing_key_entry(out: &mut Vec<u8>, alg: &[u8]) {
        let coordinate = [9u8; 32];
        cbor::write_map(out, 12).unwrap();
        write_protected_common_entry_fields(
            out,
            b"evidence-entry",
            b"evidence-key",
            TRUST_ANCHOR_PURPOSE_EVIDENCE_SIGNING_TEEP_AGENT,
            alg,
        );
        cbor::write_text(out, TRUST_ANCHOR_PUBLIC_X_FIELD).unwrap();
        cbor::write_bytes(out, &coordinate).unwrap();
        cbor::write_text(out, TRUST_ANCHOR_PUBLIC_Y_FIELD).unwrap();
        cbor::write_bytes(out, &coordinate).unwrap();
        cbor::write_text(out, PROTECTED_CREDENTIAL_PRIVATE_KEY_REF_FIELD).unwrap();
        cbor::write_bytes(out, b"sealed-key-ref").unwrap();
    }

    fn write_protected_common_entry_fields(
        out: &mut Vec<u8>,
        entry_id: &[u8],
        kid: &[u8],
        purpose: &[u8],
        alg: &[u8],
    ) {
        cbor::write_text(out, PROTECTED_CREDENTIAL_ENTRY_ID_FIELD).unwrap();
        cbor::write_bytes(out, entry_id).unwrap();
        cbor::write_text(out, PROTECTED_CREDENTIAL_ISSUER_ID_FIELD).unwrap();
        cbor::write_bytes(out, b"issuer").unwrap();
        cbor::write_text(out, TRUST_ANCHOR_KID_FIELD).unwrap();
        cbor::write_bytes(out, kid).unwrap();
        cbor::write_text(out, TRUST_ANCHOR_PURPOSE_FIELD).unwrap();
        cbor::write_text(out, purpose).unwrap();
        cbor::write_text(out, TRUST_ANCHOR_ALG_FIELD).unwrap();
        cbor::write_text(out, alg).unwrap();
        cbor::write_text(out, TRUST_ANCHOR_CRV_FIELD).unwrap();
        cbor::write_text(out, TRUST_ANCHOR_CRV_P256).unwrap();
        cbor::write_text(out, PROTECTED_CREDENTIAL_NOT_BEFORE_FIELD).unwrap();
        cbor::write_uint(out, 1).unwrap();
        cbor::write_text(out, PROTECTED_CREDENTIAL_NOT_AFTER_FIELD).unwrap();
        cbor::write_uint(out, 2).unwrap();
        cbor::write_text(out, PROTECTED_CREDENTIAL_PROVISIONING_EPOCH_FIELD).unwrap();
        cbor::write_uint(out, 1).unwrap();
    }
}
