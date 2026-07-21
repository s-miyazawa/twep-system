// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause

use super::*;

fn malformed_dev_trust_anchor_status() -> credential_management::DevTrustAnchorStatus {
    credential_management::DevTrustAnchorStatus {
        load_status: credential_management::TrustAnchorLoadStatus::Malformed,
        observed_attestam_kid_match: false,
    }
}

pub(super) fn read_dev_trust_anchor_status(
    observed_attestam_kid: Option<&[u8]>,
) -> credential_management::DevTrustAnchorStatus {
    let Some(out_len) = (match host_io::read_file_len(DEV_TRUST_ANCHORS_PATH) {
        Ok(value) => value,
        Err(_) => return malformed_dev_trust_anchor_status(),
    }) else {
        return credential_management::dev_trust_anchor_status(None, observed_attestam_kid);
    };
    if out_len > 4096 {
        return malformed_dev_trust_anchor_status();
    }
    if out_len == 0 {
        return credential_management::dev_trust_anchor_status(Some(&[]), observed_attestam_kid);
    }
    let Some(bytes) = host_io::read_file_alloc(DEV_TRUST_ANCHORS_PATH, 4096) else {
        return malformed_dev_trust_anchor_status();
    };
    credential_management::dev_trust_anchor_status(Some(&bytes), observed_attestam_kid)
}

fn malformed_protected_credential_store_status(
) -> credential_management::ProtectedCredentialStoreStatus {
    credential_management::ProtectedCredentialStoreStatus {
        load_status: credential_management::TrustAnchorLoadStatus::Malformed,
        attestam_message_key_count: 0,
        suit_content_key_count: 0,
        observed_attestam_kid_match: false,
    }
}

pub(super) fn read_protected_credential_store_status(
    observed_attestam_kid: Option<&[u8]>,
) -> credential_management::ProtectedCredentialStoreStatus {
    if let Some(status) = read_platform_protected_credential_store_status(observed_attestam_kid) {
        return status;
    }

    let Some(out_len) = (match host_io::read_file_len(PROTECTED_CREDENTIAL_STORE_PATH) {
        Ok(value) => value,
        Err(_) => return malformed_protected_credential_store_status(),
    }) else {
        return credential_management::protected_credential_store_status(
            None,
            observed_attestam_kid,
        );
    };
    if out_len > 16384 {
        return malformed_protected_credential_store_status();
    }
    if out_len == 0 {
        return credential_management::protected_credential_store_status(
            Some(&[]),
            observed_attestam_kid,
        );
    }
    let Some(bytes) = host_io::read_file_alloc(PROTECTED_CREDENTIAL_STORE_PATH, 16384) else {
        return malformed_protected_credential_store_status();
    };
    credential_management::protected_credential_store_status(Some(&bytes), observed_attestam_kid)
}

fn read_platform_protected_credential_store_status(
    observed_attestam_kid: Option<&[u8]>,
) -> Option<credential_management::ProtectedCredentialStoreStatus> {
    let out_len = host_io::read_protected_len(PROTECTED_CREDENTIAL_STORE_OBJECT).ok()??;
    if out_len > 16384 {
        return Some(malformed_protected_credential_store_status());
    }
    if out_len == 0 {
        return Some(credential_management::protected_credential_store_status(
            Some(&[]),
            observed_attestam_kid,
        ));
    }
    let Some(bytes) = host_io::read_protected_alloc(PROTECTED_CREDENTIAL_STORE_OBJECT, 16384)
    else {
        return Some(malformed_protected_credential_store_status());
    };
    Some(credential_management::protected_credential_store_status(
        Some(&bytes),
        observed_attestam_kid,
    ))
}

pub(super) fn read_attestam_message_verification_key(
    observed_attestam_kid: &[u8],
) -> Option<credential_management::AttestamMessageVerificationKey> {
    let bytes = read_protected_credential_store_bytes()?;
    credential_management::attestam_message_verification_key(&bytes, observed_attestam_kid)
}

pub(super) fn read_protected_credential_store_bytes() -> Option<Vec<u8>> {
    if let Some(bytes) = read_platform_policy_object_bytes(PROTECTED_CREDENTIAL_STORE_OBJECT, 16384)
    {
        return Some(bytes);
    }
    host_io::read_file_alloc(PROTECTED_CREDENTIAL_STORE_PATH, 16384)
}

pub(super) fn read_platform_credential_policy_status(
) -> credential_management::PlatformCredentialPolicyStatus {
    let protected_credential_store =
        read_platform_policy_object_bytes(PROTECTED_CREDENTIAL_STORE_OBJECT, 16384);
    let issuer_allowlist =
        read_platform_policy_object_bytes(PROTECTED_ISSUER_ALLOWLIST_OBJECT, 4096);
    let store_freshness = read_platform_policy_object_bytes(PROTECTED_STORE_FRESHNESS_OBJECT, 4096);
    let revocation_state =
        read_platform_policy_object_bytes(PROTECTED_REVOCATION_STATE_OBJECT, 4096);
    credential_management::PlatformCredentialPolicyStatus {
        issuer_allowlist_load_status: credential_management::platform_issuer_allowlist_load_status(
            issuer_allowlist.as_deref(),
        ),
        store_freshness_load_status: credential_management::platform_store_freshness_load_status(
            store_freshness.as_deref(),
        ),
        revocation_state_load_status: credential_management::platform_revocation_state_load_status(
            revocation_state.as_deref(),
        ),
        protected_credential_issuers_allowed:
            credential_management::platform_issuer_allowlist_covers_protected_credentials(
                issuer_allowlist.as_deref(),
                protected_credential_store.as_deref(),
            ),
        protected_store_epoch_fresh:
            credential_management::platform_store_freshness_covers_protected_store(
                store_freshness.as_deref(),
                protected_credential_store.as_deref(),
            ),
        protected_credentials_not_revoked:
            credential_management::platform_revocation_state_covers_protected_credentials(
                revocation_state.as_deref(),
                protected_credential_store.as_deref(),
            ),
    }
}

fn read_platform_policy_object_bytes(object_name: &[u8], cap: u32) -> Option<Vec<u8>> {
    let out_len = host_io::read_protected_len(object_name).ok()??;
    if out_len > cap {
        return None;
    }
    if out_len == 0 {
        return Some(Vec::new());
    }
    host_io::read_protected_alloc(object_name, cap)
}
