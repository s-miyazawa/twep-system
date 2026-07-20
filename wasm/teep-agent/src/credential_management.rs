// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause
use alloc::vec::Vec;

use ciborium::value::Value;

use crate::cbor;
pub(crate) use crate::protected_credentials::{
    attestam_message_verification_key, protected_credential_store_status,
    suit_content_verification_key, AttestamMessageVerificationKey, ProtectedCredentialStoreStatus,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CredentialPurpose {
    AttesTamMessageVerification,
    SuitContentVerification,
    EvidenceSigningCpu,
    EvidenceSigningTeepAgent,
    WasmAppCodeSignatureVerification,
}

impl CredentialPurpose {
    pub(crate) fn label(self) -> &'static [u8] {
        match self {
            CredentialPurpose::AttesTamMessageVerification => b"attestam-message-verification",
            CredentialPurpose::SuitContentVerification => b"suit-content-verification",
            CredentialPurpose::EvidenceSigningCpu => b"evidence-signing-cpu",
            CredentialPurpose::EvidenceSigningTeepAgent => b"evidence-signing-teep-agent",
            CredentialPurpose::WasmAppCodeSignatureVerification => {
                b"wasm-app-code-signature-verification"
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CredentialRequirement {
    pub(crate) purpose: CredentialPurpose,
    pub(crate) credential_id: &'static [u8],
}

impl CredentialRequirement {
    pub(crate) const fn new(
        purpose: CredentialPurpose,
        credential_id: &'static [u8],
    ) -> CredentialRequirement {
        CredentialRequirement {
            purpose,
            credential_id,
        }
    }
}

pub(crate) const ATTESTAM_MESSAGE_VERIFICATION_CREDENTIAL_ID: &[u8] =
    b"attestam-message-verification-key";
pub(crate) const SUIT_CONTENT_VERIFICATION_CREDENTIAL_ID: &[u8] = b"suit-content-verification-key";
pub(crate) const CPU_EVIDENCE_SIGNING_CREDENTIAL_ID: &[u8] = b"cpu-evidence-signing-key";
pub(crate) const TEEP_AGENT_EVIDENCE_SIGNING_CREDENTIAL_ID: &[u8] =
    b"teep-agent-evidence-signing-key";
pub(crate) const WASM_APP_CODE_SIGNATURE_VERIFICATION_CREDENTIAL_ID: &[u8] =
    b"wasm-app-code-signature-verification-key";

const ALL_CREDENTIAL_REQUIREMENTS: [CredentialRequirement; 5] = [
    CredentialRequirement::new(
        CredentialPurpose::AttesTamMessageVerification,
        ATTESTAM_MESSAGE_VERIFICATION_CREDENTIAL_ID,
    ),
    CredentialRequirement::new(
        CredentialPurpose::SuitContentVerification,
        SUIT_CONTENT_VERIFICATION_CREDENTIAL_ID,
    ),
    CredentialRequirement::new(
        CredentialPurpose::EvidenceSigningCpu,
        CPU_EVIDENCE_SIGNING_CREDENTIAL_ID,
    ),
    CredentialRequirement::new(
        CredentialPurpose::EvidenceSigningTeepAgent,
        TEEP_AGENT_EVIDENCE_SIGNING_CREDENTIAL_ID,
    ),
    CredentialRequirement::new(
        CredentialPurpose::WasmAppCodeSignatureVerification,
        WASM_APP_CODE_SIGNATURE_VERIFICATION_CREDENTIAL_ID,
    ),
];

pub(crate) fn verified_teep_required_credentials() -> &'static [CredentialRequirement] {
    &ALL_CREDENTIAL_REQUIREMENTS[..2]
}

pub(crate) fn credential_model_ready() -> bool {
    ALL_CREDENTIAL_REQUIREMENTS.iter().all(|requirement| {
        !requirement.purpose.label().is_empty() && !requirement.credential_id.is_empty()
    }) && verified_teep_required_credentials().len() == 2
        && protected_credential_store_status(None, None).load_status
            == TrustAnchorLoadStatus::Absent
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProtectedStorageBinding {
    Unsupported,
    ObservationOnly,
    TeeSecureStorageSmoke,
    TeeReeFsSecureStorage,
    TeeProtected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TrustAnchorBindingStatus {
    pub(crate) protected_store_bound: bool,
    pub(crate) issuer_allowlist_bound: bool,
    pub(crate) store_freshness_bound: bool,
    pub(crate) revocation_state_bound: bool,
    pub(crate) protected_storage_binding: ProtectedStorageBinding,
}

impl TrustAnchorBindingStatus {
    pub(crate) fn bound(self) -> bool {
        self.protected_store_bound
            && self.issuer_allowlist_bound
            && self.store_freshness_bound
            && self.revocation_state_bound
            && matches!(
                self.protected_storage_binding,
                ProtectedStorageBinding::TeeProtected
                    | ProtectedStorageBinding::TeeReeFsSecureStorage
            )
    }
}

pub(crate) fn trust_anchor_binding_status(
    protected_store_status: ProtectedCredentialStoreStatus,
    platform_policy_status: PlatformCredentialPolicyStatus,
    protected_storage_binding: ProtectedStorageBinding,
) -> TrustAnchorBindingStatus {
    let final_capable_storage = matches!(
        protected_storage_binding,
        ProtectedStorageBinding::TeeProtected | ProtectedStorageBinding::TeeReeFsSecureStorage
    );
    let protected_store_loaded_and_matched = protected_store_status.load_status
        == TrustAnchorLoadStatus::Loaded
        && protected_store_status.attestam_message_key_count != 0
        && protected_store_status.suit_content_key_count != 0
        && protected_store_status.observed_attestam_kid_match;
    TrustAnchorBindingStatus {
        protected_store_bound: final_capable_storage && protected_store_loaded_and_matched,
        issuer_allowlist_bound: final_capable_storage
            && protected_store_loaded_and_matched
            && platform_policy_status.issuer_allowlist_load_status == TrustAnchorLoadStatus::Loaded
            && platform_policy_status.protected_credential_issuers_allowed,
        store_freshness_bound: final_capable_storage
            && platform_policy_status.store_freshness_load_status == TrustAnchorLoadStatus::Loaded
            && platform_policy_status.protected_store_epoch_fresh,
        revocation_state_bound: final_capable_storage
            && platform_policy_status.revocation_state_load_status == TrustAnchorLoadStatus::Loaded
            && platform_policy_status.protected_credentials_not_revoked,
        protected_storage_binding,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TrustAnchorLoadStatus {
    Absent,
    Malformed,
    Unsupported,
    Loaded,
}

impl TrustAnchorLoadStatus {
    fn label(self) -> &'static [u8] {
        match self {
            TrustAnchorLoadStatus::Absent => b"absent",
            TrustAnchorLoadStatus::Malformed => b"malformed",
            TrustAnchorLoadStatus::Unsupported => b"unsupported",
            TrustAnchorLoadStatus::Loaded => b"loaded-unbound",
        }
    }
}

impl ProtectedStorageBinding {
    fn label(self) -> &'static [u8] {
        match self {
            ProtectedStorageBinding::Unsupported => b"unsupported",
            ProtectedStorageBinding::ObservationOnly => b"observation-only",
            ProtectedStorageBinding::TeeSecureStorageSmoke => b"tee-secure-storage-smoke",
            ProtectedStorageBinding::TeeReeFsSecureStorage => b"tee-ree-fs-secure-storage",
            ProtectedStorageBinding::TeeProtected => b"tee-protected",
        }
    }
}

const ATTESTAM_MESSAGE_VERIFICATION_KEYS_FIELD: &[u8] = b"attestam_message_verification_keys";
const SUIT_CONTENT_VERIFICATION_KEYS_FIELD: &[u8] = b"suit_content_verification_keys";
const TRUST_ANCHOR_KID_FIELD: &[u8] = b"kid";
const TRUST_ANCHOR_PURPOSE_FIELD: &[u8] = b"purpose";
const TRUST_ANCHOR_ALG_FIELD: &[u8] = b"alg";
const TRUST_ANCHOR_CRV_FIELD: &[u8] = b"crv";
const TRUST_ANCHOR_X_FIELD: &[u8] = b"x";
const TRUST_ANCHOR_Y_FIELD: &[u8] = b"y";
const TRUST_ANCHOR_PURPOSE_ATTESTAM_MESSAGE_VERIFICATION: &[u8] = b"attestam-message-verification";
const TRUST_ANCHOR_PURPOSE_SUIT_CONTENT_VERIFICATION: &[u8] = b"suit-content-verification";
const TRUST_ANCHOR_ALG_ESP256: &[u8] = b"ESP256";
const TRUST_ANCHOR_CRV_P256: &[u8] = b"P-256";
const PLATFORM_POLICY_SCHEMA_VERSION_FIELD: &[u8] = b"schema_version";
const PLATFORM_POLICY_ISSUER_IDS_FIELD: &[u8] = b"issuer_ids";
const PLATFORM_POLICY_MAX_STORE_EPOCH_FIELD: &[u8] = b"max_store_epoch";
const PLATFORM_POLICY_REVOKED_ENTRY_IDS_FIELD: &[u8] = b"revoked_entry_ids";
const PROTECTED_CREDENTIAL_ENTRY_ID_FIELD: &[u8] = b"entry_id";
const PROTECTED_CREDENTIAL_ISSUER_ID_FIELD: &[u8] = b"issuer_id";
const PROTECTED_CREDENTIAL_STORE_EPOCH_FIELD: &[u8] = b"store_epoch";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DevTrustAnchorStatus {
    pub(crate) load_status: TrustAnchorLoadStatus,
    pub(crate) observed_attestam_kid_match: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PlatformCredentialPolicyStatus {
    pub(crate) issuer_allowlist_load_status: TrustAnchorLoadStatus,
    pub(crate) store_freshness_load_status: TrustAnchorLoadStatus,
    pub(crate) revocation_state_load_status: TrustAnchorLoadStatus,
    pub(crate) protected_credential_issuers_allowed: bool,
    pub(crate) protected_store_epoch_fresh: bool,
    pub(crate) protected_credentials_not_revoked: bool,
}

impl PlatformCredentialPolicyStatus {
    #[cfg(test)]
    pub(crate) const fn absent() -> PlatformCredentialPolicyStatus {
        PlatformCredentialPolicyStatus {
            issuer_allowlist_load_status: TrustAnchorLoadStatus::Absent,
            store_freshness_load_status: TrustAnchorLoadStatus::Absent,
            revocation_state_load_status: TrustAnchorLoadStatus::Absent,
            protected_credential_issuers_allowed: false,
            protected_store_epoch_fresh: false,
            protected_credentials_not_revoked: false,
        }
    }
}

#[cfg(test)]
fn dev_trust_anchor_load_status(input: Option<&[u8]>) -> TrustAnchorLoadStatus {
    dev_trust_anchor_status(input, None).load_status
}

pub(crate) fn dev_trust_anchor_status(
    input: Option<&[u8]>,
    observed_attestam_kid: Option<&[u8]>,
) -> DevTrustAnchorStatus {
    let Some(input) = input else {
        return DevTrustAnchorStatus {
            load_status: TrustAnchorLoadStatus::Absent,
            observed_attestam_kid_match: false,
        };
    };
    match cbor::value(input) {
        Some(Value::Map(pairs)) => {
            let Some(attestam_keys) =
                map_array_field(&pairs, ATTESTAM_MESSAGE_VERIFICATION_KEYS_FIELD)
            else {
                return unsupported_dev_trust_anchor_status();
            };
            let Some(suit_keys) = map_array_field(&pairs, SUIT_CONTENT_VERIFICATION_KEYS_FIELD)
            else {
                return unsupported_dev_trust_anchor_status();
            };
            let Some(observed_attestam_kid_match) = key_entries_match_observed_kid(
                attestam_keys,
                TRUST_ANCHOR_PURPOSE_ATTESTAM_MESSAGE_VERIFICATION,
                observed_attestam_kid,
            ) else {
                return unsupported_dev_trust_anchor_status();
            };
            if !key_entries_are_supported(suit_keys, TRUST_ANCHOR_PURPOSE_SUIT_CONTENT_VERIFICATION)
            {
                return unsupported_dev_trust_anchor_status();
            }
            DevTrustAnchorStatus {
                load_status: TrustAnchorLoadStatus::Loaded,
                observed_attestam_kid_match,
            }
        }
        Some(_) => unsupported_dev_trust_anchor_status(),
        None => DevTrustAnchorStatus {
            load_status: TrustAnchorLoadStatus::Malformed,
            observed_attestam_kid_match: false,
        },
    }
}

fn unsupported_dev_trust_anchor_status() -> DevTrustAnchorStatus {
    DevTrustAnchorStatus {
        load_status: TrustAnchorLoadStatus::Unsupported,
        observed_attestam_kid_match: false,
    }
}

pub(crate) fn platform_issuer_allowlist_load_status(input: Option<&[u8]>) -> TrustAnchorLoadStatus {
    platform_policy_load_status(input, issuer_allowlist_is_supported)
}

pub(crate) fn platform_issuer_allowlist_covers_protected_credentials(
    issuer_allowlist: Option<&[u8]>,
    protected_credential_store: Option<&[u8]>,
) -> bool {
    let Some(issuer_allowlist) = issuer_allowlist else {
        return false;
    };
    let Some(protected_credential_store) = protected_credential_store else {
        return false;
    };
    let Some(Value::Map(allowlist_pairs)) = cbor::value(issuer_allowlist) else {
        return false;
    };
    if !issuer_allowlist_is_supported(&allowlist_pairs) {
        return false;
    }
    let Some(Value::Map(store_pairs)) = cbor::value(protected_credential_store) else {
        return false;
    };
    let Some(attestam_keys) =
        map_array_field(&store_pairs, ATTESTAM_MESSAGE_VERIFICATION_KEYS_FIELD)
    else {
        return false;
    };
    let Some(suit_keys) = map_array_field(&store_pairs, SUIT_CONTENT_VERIFICATION_KEYS_FIELD)
    else {
        return false;
    };
    protected_key_issuers_are_allowed(attestam_keys, &allowlist_pairs)
        && protected_key_issuers_are_allowed(suit_keys, &allowlist_pairs)
}

pub(crate) fn platform_store_freshness_load_status(input: Option<&[u8]>) -> TrustAnchorLoadStatus {
    platform_policy_load_status(input, store_freshness_is_supported)
}

pub(crate) fn platform_store_freshness_covers_protected_store(
    store_freshness: Option<&[u8]>,
    protected_credential_store: Option<&[u8]>,
) -> bool {
    let Some(store_freshness) = store_freshness else {
        return false;
    };
    let Some(protected_credential_store) = protected_credential_store else {
        return false;
    };
    let Some(Value::Map(freshness_pairs)) = cbor::value(store_freshness) else {
        return false;
    };
    if !store_freshness_is_supported(&freshness_pairs) {
        return false;
    }
    let Some(Value::Map(store_pairs)) = cbor::value(protected_credential_store) else {
        return false;
    };
    let Some(store_epoch) = map_uint_field(&store_pairs, PROTECTED_CREDENTIAL_STORE_EPOCH_FIELD)
    else {
        return false;
    };
    let Some(max_store_epoch) =
        map_uint_field(&freshness_pairs, PLATFORM_POLICY_MAX_STORE_EPOCH_FIELD)
    else {
        return false;
    };
    store_epoch >= max_store_epoch
}

pub(crate) fn platform_revocation_state_load_status(input: Option<&[u8]>) -> TrustAnchorLoadStatus {
    platform_policy_load_status(input, revocation_state_is_supported)
}

pub(crate) fn platform_revocation_state_covers_protected_credentials(
    revocation_state: Option<&[u8]>,
    protected_credential_store: Option<&[u8]>,
) -> bool {
    let Some(revocation_state) = revocation_state else {
        return false;
    };
    let Some(protected_credential_store) = protected_credential_store else {
        return false;
    };
    let Some(Value::Map(revocation_pairs)) = cbor::value(revocation_state) else {
        return false;
    };
    if !revocation_state_is_supported(&revocation_pairs) {
        return false;
    }
    let Some(Value::Map(store_pairs)) = cbor::value(protected_credential_store) else {
        return false;
    };
    let Some(attestam_keys) =
        map_array_field(&store_pairs, ATTESTAM_MESSAGE_VERIFICATION_KEYS_FIELD)
    else {
        return false;
    };
    let Some(suit_keys) = map_array_field(&store_pairs, SUIT_CONTENT_VERIFICATION_KEYS_FIELD)
    else {
        return false;
    };
    protected_key_entries_not_revoked(attestam_keys, &revocation_pairs)
        && protected_key_entries_not_revoked(suit_keys, &revocation_pairs)
}

fn platform_policy_load_status(
    input: Option<&[u8]>,
    is_supported: fn(&[(Value, Value)]) -> bool,
) -> TrustAnchorLoadStatus {
    let Some(input) = input else {
        return TrustAnchorLoadStatus::Absent;
    };
    match cbor::value(input) {
        Some(Value::Map(pairs)) if is_supported(&pairs) => TrustAnchorLoadStatus::Loaded,
        Some(_) => TrustAnchorLoadStatus::Unsupported,
        None => TrustAnchorLoadStatus::Malformed,
    }
}

fn issuer_allowlist_is_supported(pairs: &[(Value, Value)]) -> bool {
    map_uint_field(pairs, PLATFORM_POLICY_SCHEMA_VERSION_FIELD) == Some(1)
        && map_array_field(pairs, PLATFORM_POLICY_ISSUER_IDS_FIELD)
            .is_some_and(non_empty_bytes_values)
}

fn protected_key_issuers_are_allowed(
    entries: &[Value],
    allowlist_pairs: &[(Value, Value)],
) -> bool {
    !entries.is_empty()
        && entries.iter().all(|entry| {
            let Value::Map(entry_pairs) = entry else {
                return false;
            };
            let Some(issuer_id) =
                map_bytes_field(entry_pairs, PROTECTED_CREDENTIAL_ISSUER_ID_FIELD)
            else {
                return false;
            };
            issuer_id_is_allowed(issuer_id, allowlist_pairs)
        })
}

fn issuer_id_is_allowed(issuer_id: &[u8], allowlist_pairs: &[(Value, Value)]) -> bool {
    let Some(issuer_ids) = map_array_field(allowlist_pairs, PLATFORM_POLICY_ISSUER_IDS_FIELD)
    else {
        return false;
    };
    issuer_ids.iter().any(|value| match value {
        Value::Bytes(candidate) => candidate == issuer_id,
        _ => false,
    })
}

fn store_freshness_is_supported(pairs: &[(Value, Value)]) -> bool {
    map_uint_field(pairs, PLATFORM_POLICY_SCHEMA_VERSION_FIELD) == Some(1)
        && map_uint_field(pairs, PLATFORM_POLICY_MAX_STORE_EPOCH_FIELD).is_some()
}

fn revocation_state_is_supported(pairs: &[(Value, Value)]) -> bool {
    map_uint_field(pairs, PLATFORM_POLICY_SCHEMA_VERSION_FIELD) == Some(1)
        && map_array_field(pairs, PLATFORM_POLICY_REVOKED_ENTRY_IDS_FIELD).is_some_and(bytes_values)
}

fn protected_key_entries_not_revoked(
    entries: &[Value],
    revocation_pairs: &[(Value, Value)],
) -> bool {
    !entries.is_empty()
        && entries.iter().all(|entry| {
            let Value::Map(entry_pairs) = entry else {
                return false;
            };
            let Some(entry_id) = map_bytes_field(entry_pairs, PROTECTED_CREDENTIAL_ENTRY_ID_FIELD)
            else {
                return false;
            };
            !entry_id_is_revoked(entry_id, revocation_pairs)
        })
}

fn entry_id_is_revoked(entry_id: &[u8], revocation_pairs: &[(Value, Value)]) -> bool {
    let Some(revoked_entry_ids) =
        map_array_field(revocation_pairs, PLATFORM_POLICY_REVOKED_ENTRY_IDS_FIELD)
    else {
        return true;
    };
    revoked_entry_ids.iter().any(|value| match value {
        Value::Bytes(candidate) => candidate == entry_id,
        _ => true,
    })
}

fn key_entries_are_supported(entries: &[Value], expected_purpose: &[u8]) -> bool {
    entries
        .iter()
        .all(|entry| trust_anchor_key_entry_kid(entry, expected_purpose).is_some())
}

fn key_entries_match_observed_kid(
    entries: &[Value],
    expected_purpose: &[u8],
    observed_attestam_kid: Option<&[u8]>,
) -> Option<bool> {
    let mut matched = false;
    for entry in entries {
        let kid = trust_anchor_key_entry_kid(entry, expected_purpose)?;
        if let Some(observed_attestam_kid) = observed_attestam_kid {
            if kid == observed_attestam_kid {
                matched = true;
            }
        }
    }
    Some(matched)
}

fn trust_anchor_key_entry_kid<'a>(entry: &'a Value, expected_purpose: &[u8]) -> Option<&'a [u8]> {
    let pairs = match entry {
        Value::Map(pairs) => pairs,
        _ => return None,
    };
    let kid = map_bytes_field(pairs, TRUST_ANCHOR_KID_FIELD)?;
    let purpose = map_text_field(pairs, TRUST_ANCHOR_PURPOSE_FIELD)?;
    let alg = map_text_field(pairs, TRUST_ANCHOR_ALG_FIELD)?;
    let crv = map_text_field(pairs, TRUST_ANCHOR_CRV_FIELD)?;
    let x = map_bytes_field(pairs, TRUST_ANCHOR_X_FIELD)?;
    let y = map_bytes_field(pairs, TRUST_ANCHOR_Y_FIELD)?;
    if purpose != expected_purpose {
        return None;
    }
    if alg != TRUST_ANCHOR_ALG_ESP256 || crv != TRUST_ANCHOR_CRV_P256 {
        return None;
    }
    if x.len() != 32 || y.len() != 32 {
        return None;
    }
    Some(kid)
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

fn bytes_values(values: &[Value]) -> bool {
    values.iter().all(|value| matches!(value, Value::Bytes(_)))
}

fn non_empty_bytes_values(values: &[Value]) -> bool {
    !values.is_empty()
        && values.iter().all(|value| match value {
            Value::Bytes(bytes) => !bytes.is_empty(),
            _ => false,
        })
}

pub(crate) fn credential_status_text(
    observed_attestam_kid: Option<&[u8]>,
    trust_anchor_status: DevTrustAnchorStatus,
    protected_store_status: ProtectedCredentialStoreStatus,
    platform_policy_status: PlatformCredentialPolicyStatus,
    binding_status: TrustAnchorBindingStatus,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"credential-model-ready=");
    append_bool(&mut out, credential_model_ready());
    out.extend_from_slice(b"\nverified-teep-required-credentials=2\n");
    for requirement in verified_teep_required_credentials() {
        out.extend_from_slice(requirement.credential_id);
        out.extend_from_slice(b"=unbound\n");
    }
    out.extend_from_slice(b"attestam-message-verification-key-binding=");
    match observed_attestam_kid {
        Some(_) if trust_anchor_status.observed_attestam_kid_match => {
            out.extend_from_slice(b"observed-kid-entry-unbound");
        }
        Some(_) => out.extend_from_slice(b"observed-kid-unbound"),
        None => out.extend_from_slice(b"no-kid"),
    }
    out.push(b'\n');
    out.extend_from_slice(b"observed-attestam-kid=");
    match observed_attestam_kid {
        Some(kid) => append_hex(&mut out, kid),
        None => out.extend_from_slice(b"none"),
    }
    out.push(b'\n');
    out.extend_from_slice(b"trust-anchor-load=");
    out.extend_from_slice(trust_anchor_status.load_status.label());
    out.push(b'\n');
    out.extend_from_slice(b"protected-credential-store-load=");
    out.extend_from_slice(protected_store_status.load_status.label());
    out.push(b'\n');
    out.extend_from_slice(b"protected-credential-store-attestam-message-verification-keys=");
    append_usize_decimal(&mut out, protected_store_status.attestam_message_key_count);
    out.push(b'\n');
    out.extend_from_slice(b"protected-credential-store-suit-content-verification-keys=");
    append_usize_decimal(&mut out, protected_store_status.suit_content_key_count);
    out.push(b'\n');
    out.extend_from_slice(b"protected-credential-store-attestam-key-binding=");
    match observed_attestam_kid {
        Some(_)
            if protected_store_status.observed_attestam_kid_match
                && binding_status.protected_store_bound =>
        {
            out.extend_from_slice(b"observed-kid-entry-protected-storage-bound");
        }
        Some(_) if protected_store_status.observed_attestam_kid_match => {
            out.extend_from_slice(b"observed-kid-entry-unbound");
        }
        Some(_) => out.extend_from_slice(b"observed-kid-unbound"),
        None => out.extend_from_slice(b"no-kid"),
    }
    out.push(b'\n');
    out.extend_from_slice(b"protected-credential-store-issuer-binding=");
    append_bound_label(&mut out, binding_status.issuer_allowlist_bound);
    out.push(b'\n');
    out.extend_from_slice(b"protected-credential-store-issuer-allowlist-match=");
    append_bool(
        &mut out,
        platform_policy_status.protected_credential_issuers_allowed,
    );
    out.push(b'\n');
    out.extend_from_slice(b"protected-credential-store-rotation-policy=");
    append_policy_binding_label(
        &mut out,
        platform_policy_status.protected_store_epoch_fresh,
        binding_status.store_freshness_bound,
    );
    out.push(b'\n');
    out.extend_from_slice(b"protected-credential-store-revocation-status=");
    append_policy_binding_label(
        &mut out,
        platform_policy_status.protected_credentials_not_revoked,
        binding_status.revocation_state_bound,
    );
    out.push(b'\n');
    out.extend_from_slice(b"protected-revocation-state-match=");
    append_bool(
        &mut out,
        platform_policy_status.protected_credentials_not_revoked,
    );
    out.push(b'\n');
    out.extend_from_slice(b"protected-credential-store-freshness=");
    append_policy_binding_label(
        &mut out,
        platform_policy_status.protected_store_epoch_fresh,
        binding_status.store_freshness_bound,
    );
    out.push(b'\n');
    out.extend_from_slice(b"protected-store-freshness-epoch-match=");
    append_bool(&mut out, platform_policy_status.protected_store_epoch_fresh);
    out.push(b'\n');
    out.extend_from_slice(b"platform-issuer-allowlist-load=");
    out.extend_from_slice(platform_policy_status.issuer_allowlist_load_status.label());
    out.push(b'\n');
    out.extend_from_slice(b"platform-store-freshness-load=");
    out.extend_from_slice(platform_policy_status.store_freshness_load_status.label());
    out.push(b'\n');
    out.extend_from_slice(b"platform-revocation-state-load=");
    out.extend_from_slice(platform_policy_status.revocation_state_load_status.label());
    out.push(b'\n');
    out.extend_from_slice(b"protected-storage-binding=");
    out.extend_from_slice(binding_status.protected_storage_binding.label());
    out.push(b'\n');
    out.extend_from_slice(b"protected-credential-store-bound=");
    append_bool(&mut out, binding_status.protected_store_bound);
    out.push(b'\n');
    out.extend_from_slice(b"issuer-allowlist-bound=");
    append_bool(&mut out, binding_status.issuer_allowlist_bound);
    out.push(b'\n');
    out.extend_from_slice(b"store-freshness-bound=");
    append_bool(&mut out, binding_status.store_freshness_bound);
    out.push(b'\n');
    out.extend_from_slice(b"revocation-state-bound=");
    append_bool(&mut out, binding_status.revocation_state_bound);
    out.push(b'\n');
    out.extend_from_slice(b"trust-anchor-bound=");
    append_bool(&mut out, binding_status.bound());
    out.push(b'\n');
    out
}

fn append_bound_label(out: &mut Vec<u8>, bound: bool) {
    if bound {
        out.extend_from_slice(b"bound");
    } else {
        out.extend_from_slice(b"unverified");
    }
}

fn append_policy_binding_label(out: &mut Vec<u8>, matched: bool, bound: bool) {
    if bound {
        out.extend_from_slice(b"bound");
    } else if matched {
        out.extend_from_slice(b"matched-unbound");
    } else {
        out.extend_from_slice(b"unverified");
    }
}

fn append_bool(out: &mut Vec<u8>, value: bool) {
    if value {
        out.extend_from_slice(b"true");
    } else {
        out.extend_from_slice(b"false");
    }
}

fn append_hex(out: &mut Vec<u8>, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for b in bytes {
        out.push(HEX[(b >> 4) as usize]);
        out.push(HEX[(b & 0x0f) as usize]);
    }
}

fn append_usize_decimal(out: &mut Vec<u8>, mut value: usize) {
    if value == 0 {
        out.push(b'0');
        return;
    }
    let mut digits = [0u8; 20];
    let mut len = 0;
    while value != 0 {
        digits[len] = b'0' + (value % 10) as u8;
        value /= 10;
        len += 1;
    }
    while len != 0 {
        len -= 1;
        out.push(digits[len]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_purposes_have_stable_labels() {
        assert_eq!(
            CredentialPurpose::AttesTamMessageVerification.label(),
            b"attestam-message-verification"
        );
        assert_eq!(
            CredentialPurpose::SuitContentVerification.label(),
            b"suit-content-verification"
        );
        assert_eq!(
            CredentialPurpose::EvidenceSigningCpu.label(),
            b"evidence-signing-cpu"
        );
        assert_eq!(
            CredentialPurpose::EvidenceSigningTeepAgent.label(),
            b"evidence-signing-teep-agent"
        );
        assert_eq!(
            CredentialPurpose::WasmAppCodeSignatureVerification.label(),
            b"wasm-app-code-signature-verification"
        );
    }

    #[test]
    fn verified_teep_requires_tam_and_suit_verification_credentials() {
        let requirements = verified_teep_required_credentials();
        assert_eq!(
            requirements,
            &[
                CredentialRequirement::new(
                    CredentialPurpose::AttesTamMessageVerification,
                    ATTESTAM_MESSAGE_VERIFICATION_CREDENTIAL_ID,
                ),
                CredentialRequirement::new(
                    CredentialPurpose::SuitContentVerification,
                    SUIT_CONTENT_VERIFICATION_CREDENTIAL_ID,
                ),
            ]
        );
        assert!(credential_model_ready());
    }

    #[test]
    fn credential_status_reports_unbound_verified_teep_credentials() {
        assert_eq!(
            credential_status_text(
                Some(b"\x01\xab"),
                DevTrustAnchorStatus {
                    load_status: TrustAnchorLoadStatus::Malformed,
                    observed_attestam_kid_match: false,
                },
                empty_protected_credential_store_status(),
                PlatformCredentialPolicyStatus::absent(),
                TrustAnchorBindingStatus {
                    protected_store_bound: false,
                    issuer_allowlist_bound: false,
                    store_freshness_bound: false,
                    revocation_state_bound: false,
                    protected_storage_binding: ProtectedStorageBinding::ObservationOnly,
                },
            ),
            b"credential-model-ready=true\nverified-teep-required-credentials=2\nattestam-message-verification-key=unbound\nsuit-content-verification-key=unbound\nattestam-message-verification-key-binding=observed-kid-unbound\nobserved-attestam-kid=01ab\ntrust-anchor-load=malformed\nprotected-credential-store-load=absent\nprotected-credential-store-attestam-message-verification-keys=0\nprotected-credential-store-suit-content-verification-keys=0\nprotected-credential-store-attestam-key-binding=observed-kid-unbound\nprotected-credential-store-issuer-binding=unverified\nprotected-credential-store-issuer-allowlist-match=false\nprotected-credential-store-rotation-policy=unverified\nprotected-credential-store-revocation-status=unverified\nprotected-revocation-state-match=false\nprotected-credential-store-freshness=unverified\nprotected-store-freshness-epoch-match=false\nplatform-issuer-allowlist-load=absent\nplatform-store-freshness-load=absent\nplatform-revocation-state-load=absent\nprotected-storage-binding=observation-only\nprotected-credential-store-bound=false\nissuer-allowlist-bound=false\nstore-freshness-bound=false\nrevocation-state-bound=false\ntrust-anchor-bound=false\n".to_vec()
        );
        assert_eq!(
            credential_status_text(
                None,
                DevTrustAnchorStatus {
                    load_status: TrustAnchorLoadStatus::Absent,
                    observed_attestam_kid_match: false,
                },
                empty_protected_credential_store_status(),
                PlatformCredentialPolicyStatus::absent(),
                TrustAnchorBindingStatus {
                    protected_store_bound: false,
                    issuer_allowlist_bound: false,
                    store_freshness_bound: false,
                    revocation_state_bound: false,
                    protected_storage_binding: ProtectedStorageBinding::ObservationOnly,
                },
            ),
            b"credential-model-ready=true\nverified-teep-required-credentials=2\nattestam-message-verification-key=unbound\nsuit-content-verification-key=unbound\nattestam-message-verification-key-binding=no-kid\nobserved-attestam-kid=none\ntrust-anchor-load=absent\nprotected-credential-store-load=absent\nprotected-credential-store-attestam-message-verification-keys=0\nprotected-credential-store-suit-content-verification-keys=0\nprotected-credential-store-attestam-key-binding=no-kid\nprotected-credential-store-issuer-binding=unverified\nprotected-credential-store-issuer-allowlist-match=false\nprotected-credential-store-rotation-policy=unverified\nprotected-credential-store-revocation-status=unverified\nprotected-revocation-state-match=false\nprotected-credential-store-freshness=unverified\nprotected-store-freshness-epoch-match=false\nplatform-issuer-allowlist-load=absent\nplatform-store-freshness-load=absent\nplatform-revocation-state-load=absent\nprotected-storage-binding=observation-only\nprotected-credential-store-bound=false\nissuer-allowlist-bound=false\nstore-freshness-bound=false\nrevocation-state-bound=false\ntrust-anchor-bound=false\n".to_vec()
        );
        let platform_policy_status = PlatformCredentialPolicyStatus {
            issuer_allowlist_load_status: TrustAnchorLoadStatus::Loaded,
            store_freshness_load_status: TrustAnchorLoadStatus::Loaded,
            revocation_state_load_status: TrustAnchorLoadStatus::Loaded,
            protected_credential_issuers_allowed: true,
            protected_store_epoch_fresh: true,
            protected_credentials_not_revoked: true,
        };
        let protected_store_status = ProtectedCredentialStoreStatus {
            load_status: TrustAnchorLoadStatus::Loaded,
            attestam_message_key_count: 1,
            suit_content_key_count: 1,
            observed_attestam_kid_match: true,
        };
        assert_eq!(
            credential_status_text(
                Some(b"\x01\xab"),
                DevTrustAnchorStatus {
                    load_status: TrustAnchorLoadStatus::Loaded,
                    observed_attestam_kid_match: true,
                },
                protected_store_status,
                platform_policy_status,
                trust_anchor_binding_status(
                    protected_store_status,
                    platform_policy_status,
                    ProtectedStorageBinding::ObservationOnly,
                ),
            ),
            b"credential-model-ready=true\nverified-teep-required-credentials=2\nattestam-message-verification-key=unbound\nsuit-content-verification-key=unbound\nattestam-message-verification-key-binding=observed-kid-entry-unbound\nobserved-attestam-kid=01ab\ntrust-anchor-load=loaded-unbound\nprotected-credential-store-load=loaded-unbound\nprotected-credential-store-attestam-message-verification-keys=1\nprotected-credential-store-suit-content-verification-keys=1\nprotected-credential-store-attestam-key-binding=observed-kid-entry-unbound\nprotected-credential-store-issuer-binding=unverified\nprotected-credential-store-issuer-allowlist-match=true\nprotected-credential-store-rotation-policy=matched-unbound\nprotected-credential-store-revocation-status=matched-unbound\nprotected-revocation-state-match=true\nprotected-credential-store-freshness=matched-unbound\nprotected-store-freshness-epoch-match=true\nplatform-issuer-allowlist-load=loaded-unbound\nplatform-store-freshness-load=loaded-unbound\nplatform-revocation-state-load=loaded-unbound\nprotected-storage-binding=observation-only\nprotected-credential-store-bound=false\nissuer-allowlist-bound=false\nstore-freshness-bound=false\nrevocation-state-bound=false\ntrust-anchor-bound=false\n".to_vec()
        );
        assert_eq!(
            credential_status_text(
                Some(b"\x01\xab"),
                DevTrustAnchorStatus {
                    load_status: TrustAnchorLoadStatus::Absent,
                    observed_attestam_kid_match: false,
                },
                protected_store_status,
                platform_policy_status,
                trust_anchor_binding_status(
                    protected_store_status,
                    platform_policy_status,
                    ProtectedStorageBinding::TeeReeFsSecureStorage,
                ),
            ),
            b"credential-model-ready=true\nverified-teep-required-credentials=2\nattestam-message-verification-key=unbound\nsuit-content-verification-key=unbound\nattestam-message-verification-key-binding=observed-kid-unbound\nobserved-attestam-kid=01ab\ntrust-anchor-load=absent\nprotected-credential-store-load=loaded-unbound\nprotected-credential-store-attestam-message-verification-keys=1\nprotected-credential-store-suit-content-verification-keys=1\nprotected-credential-store-attestam-key-binding=observed-kid-entry-protected-storage-bound\nprotected-credential-store-issuer-binding=bound\nprotected-credential-store-issuer-allowlist-match=true\nprotected-credential-store-rotation-policy=bound\nprotected-credential-store-revocation-status=bound\nprotected-revocation-state-match=true\nprotected-credential-store-freshness=bound\nprotected-store-freshness-epoch-match=true\nplatform-issuer-allowlist-load=loaded-unbound\nplatform-store-freshness-load=loaded-unbound\nplatform-revocation-state-load=loaded-unbound\nprotected-storage-binding=tee-ree-fs-secure-storage\nprotected-credential-store-bound=true\nissuer-allowlist-bound=true\nstore-freshness-bound=true\nrevocation-state-bound=true\ntrust-anchor-bound=true\n".to_vec()
        );
    }

    #[test]
    fn trust_anchor_binding_accepts_tee_ree_fs_secure_storage() {
        let protected_store_status = ProtectedCredentialStoreStatus {
            load_status: TrustAnchorLoadStatus::Loaded,
            attestam_message_key_count: 1,
            suit_content_key_count: 1,
            observed_attestam_kid_match: true,
        };
        let platform_policy_status = PlatformCredentialPolicyStatus {
            issuer_allowlist_load_status: TrustAnchorLoadStatus::Loaded,
            store_freshness_load_status: TrustAnchorLoadStatus::Loaded,
            revocation_state_load_status: TrustAnchorLoadStatus::Loaded,
            protected_credential_issuers_allowed: true,
            protected_store_epoch_fresh: true,
            protected_credentials_not_revoked: true,
        };

        assert!(!trust_anchor_binding_status(
            protected_store_status,
            platform_policy_status,
            ProtectedStorageBinding::ObservationOnly,
        )
        .bound());
        assert!(!trust_anchor_binding_status(
            protected_store_status,
            platform_policy_status,
            ProtectedStorageBinding::TeeSecureStorageSmoke,
        )
        .bound());
        let ree_fs_status = trust_anchor_binding_status(
            protected_store_status,
            platform_policy_status,
            ProtectedStorageBinding::TeeReeFsSecureStorage,
        );
        assert!(ree_fs_status.protected_store_bound);
        assert!(ree_fs_status.issuer_allowlist_bound);
        assert!(ree_fs_status.store_freshness_bound);
        assert!(ree_fs_status.revocation_state_bound);
        assert!(ree_fs_status.bound());
        assert!(trust_anchor_binding_status(
            protected_store_status,
            platform_policy_status,
            ProtectedStorageBinding::TeeProtected,
        )
        .bound());
    }

    #[test]
    fn issuer_allowlist_mismatch_keeps_observed_kid_binding_non_final() {
        let protected_store_status = ProtectedCredentialStoreStatus {
            load_status: TrustAnchorLoadStatus::Loaded,
            attestam_message_key_count: 1,
            suit_content_key_count: 1,
            observed_attestam_kid_match: true,
        };
        let platform_policy_status = PlatformCredentialPolicyStatus {
            issuer_allowlist_load_status: TrustAnchorLoadStatus::Loaded,
            store_freshness_load_status: TrustAnchorLoadStatus::Loaded,
            revocation_state_load_status: TrustAnchorLoadStatus::Loaded,
            protected_credential_issuers_allowed: false,
            protected_store_epoch_fresh: true,
            protected_credentials_not_revoked: true,
        };
        let binding_status = trust_anchor_binding_status(
            protected_store_status,
            platform_policy_status,
            ProtectedStorageBinding::TeeReeFsSecureStorage,
        );

        assert!(binding_status.protected_store_bound);
        assert!(!binding_status.issuer_allowlist_bound);
        assert!(binding_status.store_freshness_bound);
        assert!(binding_status.revocation_state_bound);
        assert!(!binding_status.bound());
        assert_eq!(
            credential_status_text(
                Some(b"\x01\xab"),
                DevTrustAnchorStatus {
                    load_status: TrustAnchorLoadStatus::Absent,
                    observed_attestam_kid_match: false,
                },
                protected_store_status,
                platform_policy_status,
                binding_status,
            ),
            b"credential-model-ready=true\nverified-teep-required-credentials=2\nattestam-message-verification-key=unbound\nsuit-content-verification-key=unbound\nattestam-message-verification-key-binding=observed-kid-unbound\nobserved-attestam-kid=01ab\ntrust-anchor-load=absent\nprotected-credential-store-load=loaded-unbound\nprotected-credential-store-attestam-message-verification-keys=1\nprotected-credential-store-suit-content-verification-keys=1\nprotected-credential-store-attestam-key-binding=observed-kid-entry-protected-storage-bound\nprotected-credential-store-issuer-binding=unverified\nprotected-credential-store-issuer-allowlist-match=false\nprotected-credential-store-rotation-policy=bound\nprotected-credential-store-revocation-status=bound\nprotected-revocation-state-match=true\nprotected-credential-store-freshness=bound\nprotected-store-freshness-epoch-match=true\nplatform-issuer-allowlist-load=loaded-unbound\nplatform-store-freshness-load=loaded-unbound\nplatform-revocation-state-load=loaded-unbound\nprotected-storage-binding=tee-ree-fs-secure-storage\nprotected-credential-store-bound=true\nissuer-allowlist-bound=false\nstore-freshness-bound=true\nrevocation-state-bound=true\ntrust-anchor-bound=false\n".to_vec()
        );
    }

    #[test]
    fn credential_status_reports_store_freshness_bound_for_ree_fs_storage() {
        let protected_store_status = ProtectedCredentialStoreStatus {
            load_status: TrustAnchorLoadStatus::Loaded,
            attestam_message_key_count: 1,
            suit_content_key_count: 1,
            observed_attestam_kid_match: true,
        };
        let platform_policy_status = PlatformCredentialPolicyStatus {
            issuer_allowlist_load_status: TrustAnchorLoadStatus::Loaded,
            store_freshness_load_status: TrustAnchorLoadStatus::Loaded,
            revocation_state_load_status: TrustAnchorLoadStatus::Loaded,
            protected_credential_issuers_allowed: true,
            protected_store_epoch_fresh: true,
            protected_credentials_not_revoked: false,
        };

        assert_eq!(
            credential_status_text(
                Some(b"\x01\xab"),
                DevTrustAnchorStatus {
                    load_status: TrustAnchorLoadStatus::Absent,
                    observed_attestam_kid_match: false,
                },
                protected_store_status,
                platform_policy_status,
                trust_anchor_binding_status(
                    protected_store_status,
                    platform_policy_status,
                    ProtectedStorageBinding::TeeProtected,
                ),
            ),
            b"credential-model-ready=true\nverified-teep-required-credentials=2\nattestam-message-verification-key=unbound\nsuit-content-verification-key=unbound\nattestam-message-verification-key-binding=observed-kid-unbound\nobserved-attestam-kid=01ab\ntrust-anchor-load=absent\nprotected-credential-store-load=loaded-unbound\nprotected-credential-store-attestam-message-verification-keys=1\nprotected-credential-store-suit-content-verification-keys=1\nprotected-credential-store-attestam-key-binding=observed-kid-entry-protected-storage-bound\nprotected-credential-store-issuer-binding=bound\nprotected-credential-store-issuer-allowlist-match=true\nprotected-credential-store-rotation-policy=bound\nprotected-credential-store-revocation-status=unverified\nprotected-revocation-state-match=false\nprotected-credential-store-freshness=bound\nprotected-store-freshness-epoch-match=true\nplatform-issuer-allowlist-load=loaded-unbound\nplatform-store-freshness-load=loaded-unbound\nplatform-revocation-state-load=loaded-unbound\nprotected-storage-binding=tee-protected\nprotected-credential-store-bound=true\nissuer-allowlist-bound=true\nstore-freshness-bound=true\nrevocation-state-bound=false\ntrust-anchor-bound=false\n".to_vec()
        );

        let ree_fs_status = trust_anchor_binding_status(
            protected_store_status,
            platform_policy_status,
            ProtectedStorageBinding::TeeReeFsSecureStorage,
        );
        assert!(ree_fs_status.store_freshness_bound);
    }

    #[test]
    fn credential_status_reports_revocation_bound_for_ree_fs_storage() {
        let protected_store_status = ProtectedCredentialStoreStatus {
            load_status: TrustAnchorLoadStatus::Loaded,
            attestam_message_key_count: 1,
            suit_content_key_count: 1,
            observed_attestam_kid_match: true,
        };
        let platform_policy_status = PlatformCredentialPolicyStatus {
            issuer_allowlist_load_status: TrustAnchorLoadStatus::Loaded,
            store_freshness_load_status: TrustAnchorLoadStatus::Loaded,
            revocation_state_load_status: TrustAnchorLoadStatus::Loaded,
            protected_credential_issuers_allowed: true,
            protected_store_epoch_fresh: false,
            protected_credentials_not_revoked: true,
        };

        assert_eq!(
            credential_status_text(
                Some(b"\x01\xab"),
                DevTrustAnchorStatus {
                    load_status: TrustAnchorLoadStatus::Absent,
                    observed_attestam_kid_match: false,
                },
                protected_store_status,
                platform_policy_status,
                trust_anchor_binding_status(
                    protected_store_status,
                    platform_policy_status,
                    ProtectedStorageBinding::TeeProtected,
                ),
            ),
            b"credential-model-ready=true\nverified-teep-required-credentials=2\nattestam-message-verification-key=unbound\nsuit-content-verification-key=unbound\nattestam-message-verification-key-binding=observed-kid-unbound\nobserved-attestam-kid=01ab\ntrust-anchor-load=absent\nprotected-credential-store-load=loaded-unbound\nprotected-credential-store-attestam-message-verification-keys=1\nprotected-credential-store-suit-content-verification-keys=1\nprotected-credential-store-attestam-key-binding=observed-kid-entry-protected-storage-bound\nprotected-credential-store-issuer-binding=bound\nprotected-credential-store-issuer-allowlist-match=true\nprotected-credential-store-rotation-policy=unverified\nprotected-credential-store-revocation-status=bound\nprotected-revocation-state-match=true\nprotected-credential-store-freshness=unverified\nprotected-store-freshness-epoch-match=false\nplatform-issuer-allowlist-load=loaded-unbound\nplatform-store-freshness-load=loaded-unbound\nplatform-revocation-state-load=loaded-unbound\nprotected-storage-binding=tee-protected\nprotected-credential-store-bound=true\nissuer-allowlist-bound=true\nstore-freshness-bound=false\nrevocation-state-bound=true\ntrust-anchor-bound=false\n".to_vec()
        );

        let ree_fs_status = trust_anchor_binding_status(
            protected_store_status,
            platform_policy_status,
            ProtectedStorageBinding::TeeReeFsSecureStorage,
        );
        assert!(ree_fs_status.revocation_state_bound);
    }

    #[test]
    fn issuer_allowlist_must_cover_protected_credential_issuers() {
        assert!(platform_issuer_allowlist_covers_protected_credentials(
            Some(&issuer_allowlist()),
            Some(&protected_credential_store_with_issuer(b"issuer")),
        ));
        assert!(!platform_issuer_allowlist_covers_protected_credentials(
            Some(&issuer_allowlist()),
            Some(&protected_credential_store_with_issuer(b"other-issuer")),
        ));
    }

    #[test]
    fn platform_policy_status_reports_loaded_malformed_and_unsupported() {
        assert_eq!(
            platform_issuer_allowlist_load_status(None),
            TrustAnchorLoadStatus::Absent
        );
        assert_eq!(
            platform_store_freshness_load_status(Some(b"not-cbor")),
            TrustAnchorLoadStatus::Malformed
        );
        assert_eq!(
            platform_revocation_state_load_status(Some(b"\xa0")),
            TrustAnchorLoadStatus::Unsupported
        );

        assert_eq!(
            platform_issuer_allowlist_load_status(Some(&issuer_allowlist())),
            TrustAnchorLoadStatus::Loaded
        );
        assert_eq!(
            platform_store_freshness_load_status(Some(&store_freshness())),
            TrustAnchorLoadStatus::Loaded
        );
        assert_eq!(
            platform_revocation_state_load_status(Some(&revocation_state())),
            TrustAnchorLoadStatus::Loaded
        );
    }

    #[test]
    fn store_freshness_must_cover_protected_store_epoch() {
        assert!(platform_store_freshness_covers_protected_store(
            Some(&store_freshness()),
            Some(&protected_credential_store_with_issuer(b"issuer")),
        ));
        assert!(!platform_store_freshness_covers_protected_store(
            Some(&store_freshness_with_max_epoch(2)),
            Some(&protected_credential_store_with_issuer(b"issuer")),
        ));
        assert!(!platform_store_freshness_covers_protected_store(
            Some(&store_freshness()),
            Some(b"not-cbor"),
        ));
    }

    #[test]
    fn revocation_state_must_not_revoke_protected_credentials() {
        assert!(platform_revocation_state_covers_protected_credentials(
            Some(&revocation_state()),
            Some(&protected_credential_store_with_issuer(b"issuer")),
        ));
        assert!(!platform_revocation_state_covers_protected_credentials(
            Some(&revocation_state_with_entry_id(b"tam-entry")),
            Some(&protected_credential_store_with_issuer(b"issuer")),
        ));
        assert!(!platform_revocation_state_covers_protected_credentials(
            Some(&revocation_state()),
            Some(b"not-cbor"),
        ));
    }

    #[test]
    fn dev_trust_anchor_status_requires_cbor_map() {
        assert_eq!(
            dev_trust_anchor_load_status(None),
            TrustAnchorLoadStatus::Absent
        );
        assert_eq!(
            dev_trust_anchor_load_status(Some(b"not-cbor")),
            TrustAnchorLoadStatus::Malformed
        );
        assert_eq!(
            dev_trust_anchor_load_status(Some(b"\xa0")),
            TrustAnchorLoadStatus::Unsupported
        );
    }

    #[test]
    fn dev_trust_anchor_status_accepts_minimal_development_schema() {
        let mut input = Vec::new();
        cbor::write_map(&mut input, 2).unwrap();
        cbor::write_text(&mut input, ATTESTAM_MESSAGE_VERIFICATION_KEYS_FIELD).unwrap();
        cbor::write_array(&mut input, 0).unwrap();
        cbor::write_text(&mut input, SUIT_CONTENT_VERIFICATION_KEYS_FIELD).unwrap();
        cbor::write_array(&mut input, 0).unwrap();

        assert_eq!(
            dev_trust_anchor_load_status(Some(&input)),
            TrustAnchorLoadStatus::Loaded
        );
    }

    #[test]
    fn dev_trust_anchor_status_observes_matching_attestam_key_id() {
        let mut input = minimal_dev_trust_anchor_with_attestam_key_entry(b"tam-key");

        assert_eq!(
            dev_trust_anchor_status(Some(&input), Some(b"tam-key")),
            DevTrustAnchorStatus {
                load_status: TrustAnchorLoadStatus::Loaded,
                observed_attestam_kid_match: true,
            }
        );
        assert_eq!(
            dev_trust_anchor_status(Some(&input), Some(b"other-key")),
            DevTrustAnchorStatus {
                load_status: TrustAnchorLoadStatus::Loaded,
                observed_attestam_kid_match: false,
            }
        );

        input.pop();
        assert_eq!(
            dev_trust_anchor_status(Some(&input), Some(b"tam-key")),
            DevTrustAnchorStatus {
                load_status: TrustAnchorLoadStatus::Malformed,
                observed_attestam_kid_match: false,
            }
        );
    }

    #[test]
    fn dev_trust_anchor_status_rejects_key_entry_purpose_mismatch() {
        let input = minimal_dev_trust_anchor_with_key_entry_purpose(
            b"tam-key",
            TRUST_ANCHOR_PURPOSE_SUIT_CONTENT_VERIFICATION,
        );

        assert_eq!(
            dev_trust_anchor_status(Some(&input), Some(b"tam-key")),
            DevTrustAnchorStatus {
                load_status: TrustAnchorLoadStatus::Unsupported,
                observed_attestam_kid_match: false,
            }
        );
    }

    fn minimal_dev_trust_anchor_with_attestam_key_entry(kid: &[u8]) -> Vec<u8> {
        minimal_dev_trust_anchor_with_key_entry_purpose(
            kid,
            TRUST_ANCHOR_PURPOSE_ATTESTAM_MESSAGE_VERIFICATION,
        )
    }

    fn empty_protected_credential_store_status() -> ProtectedCredentialStoreStatus {
        ProtectedCredentialStoreStatus {
            load_status: TrustAnchorLoadStatus::Absent,
            attestam_message_key_count: 0,
            suit_content_key_count: 0,
            observed_attestam_kid_match: false,
        }
    }

    fn issuer_allowlist() -> Vec<u8> {
        let mut input = Vec::new();
        cbor::write_map(&mut input, 2).unwrap();
        cbor::write_text(&mut input, PLATFORM_POLICY_SCHEMA_VERSION_FIELD).unwrap();
        cbor::write_uint(&mut input, 1).unwrap();
        cbor::write_text(&mut input, PLATFORM_POLICY_ISSUER_IDS_FIELD).unwrap();
        cbor::write_array(&mut input, 1).unwrap();
        cbor::write_bytes(&mut input, b"issuer").unwrap();
        input
    }

    fn store_freshness() -> Vec<u8> {
        store_freshness_with_max_epoch(1)
    }

    fn store_freshness_with_max_epoch(max_epoch: usize) -> Vec<u8> {
        let mut input = Vec::new();
        cbor::write_map(&mut input, 2).unwrap();
        cbor::write_text(&mut input, PLATFORM_POLICY_SCHEMA_VERSION_FIELD).unwrap();
        cbor::write_uint(&mut input, 1).unwrap();
        cbor::write_text(&mut input, PLATFORM_POLICY_MAX_STORE_EPOCH_FIELD).unwrap();
        cbor::write_uint(&mut input, max_epoch).unwrap();
        input
    }

    fn revocation_state() -> Vec<u8> {
        revocation_state_with_entry_id(b"revoked-entry")
    }

    fn revocation_state_with_entry_id(entry_id: &[u8]) -> Vec<u8> {
        let mut input = Vec::new();
        cbor::write_map(&mut input, 2).unwrap();
        cbor::write_text(&mut input, PLATFORM_POLICY_SCHEMA_VERSION_FIELD).unwrap();
        cbor::write_uint(&mut input, 1).unwrap();
        cbor::write_text(&mut input, PLATFORM_POLICY_REVOKED_ENTRY_IDS_FIELD).unwrap();
        cbor::write_array(&mut input, 1).unwrap();
        cbor::write_bytes(&mut input, entry_id).unwrap();
        input
    }

    fn protected_credential_store_with_issuer(issuer: &[u8]) -> Vec<u8> {
        let mut input = Vec::new();
        let coordinate = [8u8; 32];
        cbor::write_map(&mut input, 4).unwrap();
        cbor::write_text(&mut input, PLATFORM_POLICY_SCHEMA_VERSION_FIELD).unwrap();
        cbor::write_uint(&mut input, 1).unwrap();
        cbor::write_text(&mut input, b"store_epoch").unwrap();
        cbor::write_uint(&mut input, 1).unwrap();
        cbor::write_text(&mut input, ATTESTAM_MESSAGE_VERIFICATION_KEYS_FIELD).unwrap();
        cbor::write_array(&mut input, 1).unwrap();
        cbor::write_map(&mut input, 11).unwrap();
        write_protected_key_entry_fields(
            &mut input,
            b"tam-entry",
            issuer,
            b"tam-key",
            TRUST_ANCHOR_PURPOSE_ATTESTAM_MESSAGE_VERIFICATION,
        );
        cbor::write_text(&mut input, TRUST_ANCHOR_X_FIELD).unwrap();
        cbor::write_bytes(&mut input, &coordinate).unwrap();
        cbor::write_text(&mut input, TRUST_ANCHOR_Y_FIELD).unwrap();
        cbor::write_bytes(&mut input, &coordinate).unwrap();
        cbor::write_text(&mut input, SUIT_CONTENT_VERIFICATION_KEYS_FIELD).unwrap();
        cbor::write_array(&mut input, 1).unwrap();
        cbor::write_map(&mut input, 11).unwrap();
        write_protected_key_entry_fields(
            &mut input,
            b"suit-entry",
            issuer,
            b"suit-key",
            TRUST_ANCHOR_PURPOSE_SUIT_CONTENT_VERIFICATION,
        );
        cbor::write_text(&mut input, TRUST_ANCHOR_X_FIELD).unwrap();
        cbor::write_bytes(&mut input, &coordinate).unwrap();
        cbor::write_text(&mut input, TRUST_ANCHOR_Y_FIELD).unwrap();
        cbor::write_bytes(&mut input, &coordinate).unwrap();
        input
    }

    fn write_protected_key_entry_fields(
        out: &mut Vec<u8>,
        entry_id: &[u8],
        issuer: &[u8],
        kid: &[u8],
        purpose: &[u8],
    ) {
        cbor::write_text(out, b"entry_id").unwrap();
        cbor::write_bytes(out, entry_id).unwrap();
        cbor::write_text(out, PROTECTED_CREDENTIAL_ISSUER_ID_FIELD).unwrap();
        cbor::write_bytes(out, issuer).unwrap();
        cbor::write_text(out, TRUST_ANCHOR_KID_FIELD).unwrap();
        cbor::write_bytes(out, kid).unwrap();
        cbor::write_text(out, TRUST_ANCHOR_PURPOSE_FIELD).unwrap();
        cbor::write_text(out, purpose).unwrap();
        cbor::write_text(out, TRUST_ANCHOR_ALG_FIELD).unwrap();
        cbor::write_text(out, TRUST_ANCHOR_ALG_ESP256).unwrap();
        cbor::write_text(out, TRUST_ANCHOR_CRV_FIELD).unwrap();
        cbor::write_text(out, TRUST_ANCHOR_CRV_P256).unwrap();
        cbor::write_text(out, b"not_before").unwrap();
        cbor::write_uint(out, 1).unwrap();
        cbor::write_text(out, b"not_after").unwrap();
        cbor::write_uint(out, 2).unwrap();
        cbor::write_text(out, b"provisioning_epoch").unwrap();
        cbor::write_uint(out, 1).unwrap();
    }

    fn minimal_dev_trust_anchor_with_key_entry_purpose(kid: &[u8], purpose: &[u8]) -> Vec<u8> {
        let mut input = Vec::new();
        let coordinate = [7u8; 32];
        cbor::write_map(&mut input, 2).unwrap();
        cbor::write_text(&mut input, ATTESTAM_MESSAGE_VERIFICATION_KEYS_FIELD).unwrap();
        cbor::write_array(&mut input, 1).unwrap();
        cbor::write_map(&mut input, 6).unwrap();
        cbor::write_text(&mut input, TRUST_ANCHOR_KID_FIELD).unwrap();
        cbor::write_bytes(&mut input, kid).unwrap();
        cbor::write_text(&mut input, TRUST_ANCHOR_PURPOSE_FIELD).unwrap();
        cbor::write_text(&mut input, purpose).unwrap();
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
}
