use super::*;
use coset::{iana, CoseSign1Builder, HeaderBuilder};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};

mod agent_identity;
mod credentials;
mod dry_run;
mod evidence_status;
mod live_acceptance;
mod state;

fn signed_test_suit_auth(
    detached_payload: &[u8],
    unprotected_kid: Option<&[u8]>,
    protected_kid: Option<&[u8]>,
) -> (Vec<u8>, [u8; 32], [u8; 32]) {
    let signing_key = SigningKey::from_slice(&[3u8; 32]).expect("test signing key");
    let point = signing_key.verifying_key().to_encoded_point(false);
    let mut x = [0u8; 32];
    x.copy_from_slice(point.x().expect("test public x"));
    let mut y = [0u8; 32];
    y.copy_from_slice(point.y().expect("test public y"));
    let mut protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::ESP256)
        .build();
    if let Some(kid) = protected_kid {
        protected.key_id = kid.to_vec();
    }
    let mut unprotected = HeaderBuilder::new().build();
    if let Some(kid) = unprotected_kid {
        unprotected.key_id = kid.to_vec();
    }
    let auth_block = CoseSign1Builder::new()
        .protected(protected)
        .unprotected(unprotected)
        .try_create_detached_signature(detached_payload, &[], |tbs| {
            let signature: Signature = signing_key.sign(tbs);
            Ok::<_, ()>(signature.to_bytes().to_vec())
        })
        .expect("test SUIT auth signature")
        .build()
        .to_vec()
        .expect("test SUIT auth CBOR");
    (auth_block, x, y)
}

fn test_protected_credential_store(
    kid: &[u8],
    x: &[u8; 32],
    y: &[u8; 32],
    duplicate: bool,
) -> Vec<u8> {
    let mut out = Vec::new();
    cbor::write_map(&mut out, 4).unwrap();
    cbor::write_text(&mut out, b"schema_version").unwrap();
    cbor::write_uint(&mut out, 1).unwrap();
    cbor::write_text(&mut out, b"store_epoch").unwrap();
    cbor::write_uint(&mut out, 1).unwrap();
    cbor::write_text(&mut out, b"attestam_message_verification_keys").unwrap();
    cbor::write_array(&mut out, 0).unwrap();
    cbor::write_text(&mut out, b"suit_content_verification_keys").unwrap();
    cbor::write_array(&mut out, if duplicate { 2 } else { 1 }).unwrap();
    write_test_suit_content_key(&mut out, b"suit-entry", kid, x, y);
    if duplicate {
        write_test_suit_content_key(&mut out, b"duplicate-suit-entry", kid, x, y);
    }
    out
}

fn write_test_suit_content_key(
    out: &mut Vec<u8>,
    entry_id: &[u8],
    kid: &[u8],
    x: &[u8; 32],
    y: &[u8; 32],
) {
    cbor::write_map(out, 11).unwrap();
    cbor::write_text(out, b"entry_id").unwrap();
    cbor::write_bytes(out, entry_id).unwrap();
    cbor::write_text(out, b"issuer_id").unwrap();
    cbor::write_bytes(out, b"test-issuer").unwrap();
    cbor::write_text(out, b"kid").unwrap();
    cbor::write_bytes(out, kid).unwrap();
    cbor::write_text(out, b"purpose").unwrap();
    cbor::write_text(out, b"suit-content-verification").unwrap();
    cbor::write_text(out, b"alg").unwrap();
    cbor::write_text(out, b"ESP256").unwrap();
    cbor::write_text(out, b"crv").unwrap();
    cbor::write_text(out, b"P-256").unwrap();
    cbor::write_text(out, b"x").unwrap();
    cbor::write_bytes(out, x).unwrap();
    cbor::write_text(out, b"y").unwrap();
    cbor::write_bytes(out, y).unwrap();
    cbor::write_text(out, b"not_before").unwrap();
    cbor::write_uint(out, 1).unwrap();
    cbor::write_text(out, b"not_after").unwrap();
    cbor::write_uint(out, 2).unwrap();
    cbor::write_text(out, b"provisioning_epoch").unwrap();
    cbor::write_uint(out, 1).unwrap();
}

fn test_suit_auth_candidate<'a>(
    manifest_body: &'a [u8],
    manifest_digest: &'a [u8],
    auth_block: &'a [u8],
) -> TeepUpdateCandidate<'a> {
    TeepUpdateCandidate {
        manifest: b"manifest-envelope",
        manifest_count: 1,
        update_token: b"update-token",
        info: crate::suit::SuitManifestInfo {
            component_id: b"component-id",
            component_kind: ComponentKind::App,
            sequence_number: 1,
            manifest_body,
            manifest_digest,
            suit_auth_block: auth_block,
            payload_digest: b"payload-digest",
            payload_digest_sha256: b"payload-digest-sha256",
            payload_uri: b"#payload",
            payload: b"payload",
            app_command: Some(b"remotehello"),
            catalog_name: None,
        },
        payload_sha256: [0u8; 32],
    }
}

fn attestam_commit_candidate<'a>(
    component_id: &'a [u8],
    sequence_number: usize,
    manifest_count: usize,
) -> TeepUpdateCandidate<'a> {
    TeepUpdateCandidate {
        manifest: b"manifest",
        manifest_count,
        update_token: b"token",
        info: crate::suit::SuitManifestInfo {
            component_id,
            component_kind: ComponentKind::App,
            sequence_number,
            manifest_body: b"manifest-body",
            manifest_digest: b"manifest-digest",
            suit_auth_block: b"auth-block",
            payload_digest: b"payload-digest",
            payload_digest_sha256: b"payload-digest-sha256",
            payload_uri: b"#payload",
            payload: b"payload",
            app_command: Some(b"remotehello"),
            catalog_name: None,
        },
        payload_sha256: [0u8; 32],
    }
}

fn authoritative_test_catalog() -> Vec<u8> {
    let mut catalog = Vec::new();
    cbor::write_map(&mut catalog, 4).unwrap();
    cbor::write_text(&mut catalog, b"apps").unwrap();
    cbor::write_map(&mut catalog, 0).unwrap();
    cbor::write_text(&mut catalog, b"source").unwrap();
    cbor::write_text(&mut catalog, b"test").unwrap();
    cbor::write_text(&mut catalog, b"generated_at").unwrap();
    cbor::write_text(&mut catalog, b"2026-07-11T00:00:00Z").unwrap();
    cbor::write_text(&mut catalog, b"schema_version").unwrap();
    cbor::write_uint(&mut catalog, 1).unwrap();
    catalog
}

fn catalog_commit_candidate<'a>(
    component_id: &'a [u8],
    payload: &'a [u8],
) -> TeepUpdateCandidate<'a> {
    TeepUpdateCandidate {
        manifest: b"manifest",
        manifest_count: 1,
        update_token: b"token",
        info: crate::suit::SuitManifestInfo {
            component_id,
            component_kind: ComponentKind::Catalog,
            sequence_number: 1,
            manifest_body: b"manifest-body",
            manifest_digest: b"manifest-digest",
            suit_auth_block: b"auth-block",
            payload_digest: b"payload-digest",
            payload_digest_sha256: b"payload-digest-sha256",
            payload_uri: b"#catalog.cbor",
            payload,
            app_command: None,
            catalog_name: Some(b"default"),
        },
        payload_sha256: sha256(payload),
    }
}

fn bound_agent_identity_status() -> AgentIdentityStatus {
    AgentIdentityStatus {
        load_status: AgentIdentityLoadStatus::LoadedUnbound,
        backend_match: true,
        runtime_seen: true,
        runtime_match: true,
        teep_agent_seen: true,
        teep_agent_match: true,
        measurement_status: AgentIdentityMeasurementStatus::Matched,
    }
}

fn bound_trust_anchor_status() -> credential_management::TrustAnchorBindingStatus {
    credential_management::TrustAnchorBindingStatus {
        protected_store_bound: true,
        issuer_allowlist_bound: true,
        store_freshness_bound: true,
        revocation_state_bound: true,
        protected_storage_binding:
            credential_management::ProtectedStorageBinding::TeeReeFsSecureStorage,
    }
}

fn assert_acceptance_commit_not_ready(
    state: &VerificationState,
    candidate: &TeepUpdateCandidate<'_>,
    evidence_query_response: &[u8],
    binding_status: credential_management::TrustAnchorBindingStatus,
    agent_identity_status: &AgentIdentityStatus,
    platform_status: &[u8],
) {
    assert!(commit_attestam_acceptance_evidence_result_cbor_with(
        state,
        candidate,
        evidence_query_response,
        binding_status,
        agent_identity_status,
        platform_status,
        || panic!("acceptance_generation must not run before all acceptance gates are ready"),
        |_digest, _component_id, _sequence, _expected_generation| {
            panic!("commit_acceptance must not run before all acceptance gates are ready")
        },
    )
    .is_none());
}
