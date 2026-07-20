// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause
use alloc::vec::Vec;

use crate::cbor;
use crate::sha256;
use crate::teep::{teep_message_token, update_manifest_list};

const APP_METADATA_KEY: &[u8] = b"twep-app-v1-metadata";
const TWEP_APP_COMPONENT_PREFIX: &[u8] = b"twep-app-v1";
const TWEP_CATALOG_COMPONENT_PREFIX: &[u8] = b"twep-catalog-v1";
const INSTALLED_TC_PAYLOAD0_PATH: &[u8] = b"components/hello.txt";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ComponentKind {
    App,
    Catalog,
    Unsupported,
}

#[derive(Clone, Copy)]
pub(crate) struct SuitManifestInfo<'a> {
    pub(crate) component_id: &'a [u8],
    pub(crate) component_kind: ComponentKind,
    pub(crate) sequence_number: usize,
    pub(crate) manifest_body: &'a [u8],
    pub(crate) manifest_digest: &'a [u8],
    pub(crate) suit_auth_block: &'a [u8],
    pub(crate) payload_digest: &'a [u8],
    pub(crate) payload_digest_sha256: &'a [u8],
    pub(crate) payload_uri: &'a [u8],
    pub(crate) payload: &'a [u8],
    pub(crate) app_command: Option<&'a [u8]>,
    pub(crate) catalog_name: Option<&'a [u8]>,
}

pub(crate) struct TeepUpdateCandidate<'a> {
    pub(crate) manifest: &'a [u8],
    pub(crate) manifest_count: usize,
    pub(crate) update_token: &'a [u8],
    pub(crate) info: SuitManifestInfo<'a>,
    pub(crate) payload_sha256: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TeepUpdateCandidateError {
    MissingManifestList,
    ManifestParse,
    ComponentMismatch,
    PayloadHashMismatch,
    MissingToken,
}

impl TeepUpdateCandidateError {
    pub(crate) fn message(self) -> &'static [u8] {
        match self {
            TeepUpdateCandidateError::MissingManifestList => {
                b"AttesTAM Update manifest-list is missing"
            }
            TeepUpdateCandidateError::ManifestParse => b"AttesTAM SUIT manifest parse failed",
            TeepUpdateCandidateError::ComponentMismatch => {
                b"AttesTAM Update component id does not match request"
            }
            TeepUpdateCandidateError::PayloadHashMismatch => b"AttesTAM SUIT payload hash mismatch",
            TeepUpdateCandidateError::MissingToken => b"AttesTAM Update token is not available",
        }
    }
}

pub(crate) fn teep_update_candidate<'a>(
    update_payload: &'a [u8],
    requested_component_id: &[u8],
) -> Result<TeepUpdateCandidate<'a>, TeepUpdateCandidateError> {
    let candidate = teep_update_candidate_any(update_payload)?;
    if candidate.info.component_id != requested_component_id {
        return Err(TeepUpdateCandidateError::ComponentMismatch);
    }
    Ok(candidate)
}

pub(crate) fn teep_update_candidate_any<'a>(
    update_payload: &'a [u8],
) -> Result<TeepUpdateCandidate<'a>, TeepUpdateCandidateError> {
    let (manifest, manifest_count) = update_manifest_list(update_payload)
        .ok_or(TeepUpdateCandidateError::MissingManifestList)?;
    let info = suit_manifest_info(manifest).ok_or(TeepUpdateCandidateError::ManifestParse)?;
    if info.component_kind == ComponentKind::Unsupported {
        return Err(TeepUpdateCandidateError::ComponentMismatch);
    }
    let payload_sha256 = sha256(info.payload);
    if payload_sha256 != info.payload_digest_sha256 {
        return Err(TeepUpdateCandidateError::PayloadHashMismatch);
    }
    let update_token =
        teep_message_token(update_payload).ok_or(TeepUpdateCandidateError::MissingToken)?;
    Ok(TeepUpdateCandidate {
        manifest,
        manifest_count,
        update_token,
        info,
        payload_sha256,
    })
}

pub(crate) fn suit_manifest_info(input: &[u8]) -> Option<SuitManifestInfo<'_>> {
    let mut off = 0usize;
    let (mut major, mut value) = cbor::head(input, &mut off)?;
    if major == 6 {
        if value != 107 {
            return None;
        }
        (major, value) = cbor::head(input, &mut off)?;
    }
    if major != 5 {
        return None;
    }
    let mut manifest = None;
    let mut manifest_digest = None;
    let mut suit_auth_block = None;
    let mut payload_uri = None;
    let mut payload = None;
    for _ in 0..value {
        let (key_major, key_value) = cbor::head(input, &mut off)?;
        if key_major == 0 && key_value == 2 {
            let (digest, auth_block) = suit_auth_wrapper(cbor::bytes(input, &mut off)?)?;
            manifest_digest = Some(digest);
            suit_auth_block = Some(auth_block);
        } else if key_major == 0 && key_value == 3 {
            manifest = Some(cbor::bytes(input, &mut off)?);
        } else if key_major == 3 {
            if key_value > input.len().saturating_sub(off) {
                return None;
            }
            let key = &input[off..off + key_value];
            off += key_value;
            if key.first() == Some(&b'#') {
                payload_uri = Some(key);
                payload = Some(cbor::bytes(input, &mut off)?);
            } else if key == APP_METADATA_KEY {
                if !cbor::skip(input, &mut off) {
                    return None;
                }
            } else if !cbor::skip(input, &mut off) {
                return None;
            }
        } else if !cbor::skip(input, &mut off) {
            return None;
        }
    }
    let manifest = manifest?;
    let mut info = parse_suit_manifest(manifest)?;
    info.manifest_body = manifest;
    info.manifest_digest = manifest_digest?;
    info.suit_auth_block = suit_auth_block?;
    let uri = info.payload_uri;
    if let (Some(envelope_uri), Some(envelope_payload)) = (payload_uri, payload) {
        if uri == envelope_uri {
            info.payload = envelope_payload;
            let (component_kind, name) = component_kind_and_name(info.component_id);
            info.component_kind = component_kind;
            match component_kind {
                ComponentKind::App => info.app_command = name,
                ComponentKind::Catalog => info.catalog_name = name,
                ComponentKind::Unsupported => {}
            }
            return Some(info);
        }
    }
    None
}

fn suit_auth_wrapper(input: &[u8]) -> Option<(&[u8], &[u8])> {
    let mut off = 0usize;
    let (major, len) = cbor::head(input, &mut off)?;
    if major != 4 || len != 2 {
        return None;
    }
    let digest = cbor::bytes(input, &mut off)?;
    let auth_block = cbor::bytes(input, &mut off)?;
    if auth_block.is_empty() || off != input.len() {
        return None;
    }
    Some((digest, auth_block))
}

fn parse_suit_manifest(input: &[u8]) -> Option<SuitManifestInfo<'_>> {
    let mut off = 0usize;
    let (major, pairs) = cbor::head(input, &mut off)?;
    if major != 5 {
        return None;
    }
    let mut sequence_number = None;
    let mut common = None;
    let mut payload_fetch = None;
    for _ in 0..pairs {
        let (key_major, key_value) = cbor::head(input, &mut off)?;
        if key_major == 0 && key_value == 2 {
            let (seq_major, seq_value) = cbor::head(input, &mut off)?;
            if seq_major != 0 {
                return None;
            }
            sequence_number = Some(seq_value);
        } else if key_major == 0 && key_value == 3 {
            common = Some(cbor::bytes(input, &mut off)?);
        } else if key_major == 0 && key_value == 16 {
            payload_fetch = Some(cbor::bytes(input, &mut off)?);
        } else if !cbor::skip(input, &mut off) {
            return None;
        }
    }
    let (component_id, payload_digest, payload_digest_sha256) = parse_suit_common(common?)?;
    let payload_uri = suit_sequence_payload_uri(payload_fetch?)?;
    Some(SuitManifestInfo {
        component_id,
        component_kind: ComponentKind::Unsupported,
        sequence_number: sequence_number?,
        manifest_body: b"",
        manifest_digest: b"",
        suit_auth_block: b"",
        payload_digest,
        payload_digest_sha256,
        payload_uri,
        payload: b"",
        app_command: None,
        catalog_name: None,
    })
}

pub(crate) fn suit_manifest_digest_raw(manifest: &[u8]) -> Option<Vec<u8>> {
    let mut manifest_bstr = Vec::new();
    cbor::write_bytes(&mut manifest_bstr, manifest)?;
    let digest = sha256(&manifest_bstr);
    let mut out = Vec::new();
    cbor::write_array(&mut out, 2)?;
    out.push(0x2f);
    cbor::write_bytes(&mut out, &digest)?;
    Some(out)
}

fn parse_suit_common(input: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    let mut off = 0usize;
    let (major, pairs) = cbor::head(input, &mut off)?;
    if major != 5 {
        return None;
    }
    let mut component_id = None;
    let mut shared_sequence = None;
    for _ in 0..pairs {
        let (key_major, key_value) = cbor::head(input, &mut off)?;
        if key_major == 0 && key_value == 2 {
            let (components_major, component_count) = cbor::head(input, &mut off)?;
            if components_major != 4 || component_count == 0 {
                return None;
            }
            let component_start = off;
            if !cbor::skip(input, &mut off) {
                return None;
            }
            component_id = Some(&input[component_start..off]);
            for _ in 1..component_count {
                if !cbor::skip(input, &mut off) {
                    return None;
                }
            }
        } else if key_major == 0 && key_value == 4 {
            shared_sequence = Some(cbor::bytes(input, &mut off)?);
        } else if !cbor::skip(input, &mut off) {
            return None;
        }
    }
    let payload_digest = suit_shared_sequence_payload_digest(shared_sequence?)?;
    let payload_digest_sha256 = suit_sha256_digest_bytes(payload_digest)?;
    Some((component_id?, payload_digest, payload_digest_sha256))
}

fn suit_shared_sequence_payload_digest(input: &[u8]) -> Option<&[u8]> {
    let mut off = 0usize;
    let (major, len) = cbor::head(input, &mut off)?;
    if major != 4 {
        return None;
    }
    let mut i = 0usize;
    let mut payload_digest = None;
    while i < len {
        let item_start = off;
        let (item_major, item_value) = cbor::head(input, &mut off)?;
        i += 1;
        if item_major == 0 && item_value == 20 && i < len {
            let (params_major, pairs) = cbor::head(input, &mut off)?;
            if params_major != 5 {
                return None;
            }
            i += 1;
            for _ in 0..pairs {
                let (key_major, key_value) = cbor::head(input, &mut off)?;
                if key_major == 0 && key_value == 3 {
                    payload_digest = Some(cbor::bytes(input, &mut off)?);
                } else if !cbor::skip(input, &mut off) {
                    return None;
                }
            }
        } else {
            off = item_start;
            if !cbor::skip(input, &mut off) {
                return None;
            }
        }
    }
    payload_digest
}

fn suit_sequence_payload_uri(input: &[u8]) -> Option<&[u8]> {
    let mut off = 0usize;
    let (major, len) = cbor::head(input, &mut off)?;
    if major != 4 {
        return None;
    }
    let mut i = 0usize;
    while i < len {
        let item_start = off;
        let (item_major, item_value) = cbor::head(input, &mut off)?;
        i += 1;
        if item_major == 0 && item_value == 20 && i < len {
            let (params_major, pairs) = cbor::head(input, &mut off)?;
            if params_major != 5 {
                return None;
            }
            i += 1;
            for _ in 0..pairs {
                let (key_major, key_value) = cbor::head(input, &mut off)?;
                if key_major == 0 && key_value == 21 {
                    return cbor::text(input, &mut off);
                }
                if !cbor::skip(input, &mut off) {
                    return None;
                }
            }
        } else {
            off = item_start;
            if !cbor::skip(input, &mut off) {
                return None;
            }
        }
    }
    None
}

fn suit_sha256_digest_bytes(input: &[u8]) -> Option<&[u8]> {
    let mut off = 0usize;
    let (major, len) = cbor::head(input, &mut off)?;
    if major != 4 || len != 2 {
        return None;
    }
    let (alg_major, alg_value) = cbor::head(input, &mut off)?;
    if alg_major != 1 || alg_value != 15 {
        return None;
    }
    let digest = cbor::bytes(input, &mut off)?;
    if digest.len() != 32 || off != input.len() {
        return None;
    }
    Some(digest)
}

pub(crate) fn manifest_count_text(count: usize) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(b"manifest-count=");
    cbor_write_decimal(&mut out, count)?;
    out.push(b'\n');
    Some(out)
}

pub(crate) fn sequence_number_text(sequence_number: usize) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(b"sequence-number=");
    cbor_write_decimal(&mut out, sequence_number)?;
    out.push(b'\n');
    Some(out)
}

pub(crate) fn payload_uri_text(uri: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(b"payload-uri=");
    out.extend_from_slice(uri);
    out.push(b'\n');
    Some(out)
}

pub(crate) fn update_metadata(
    info: &SuitManifestInfo<'_>,
    payload_sha256: &[u8; 32],
    payload_file: &[u8],
) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    cbor::write_map(&mut out, 6)?;
    cbor::write_text(&mut out, b"schema_version")?;
    cbor::write_uint(&mut out, 1)?;
    cbor::write_text(&mut out, b"component_id_cbor")?;
    cbor::write_bytes(&mut out, info.component_id)?;
    cbor::write_text(&mut out, b"sequence_number")?;
    cbor::write_uint(&mut out, info.sequence_number)?;
    cbor::write_text(&mut out, b"payload_uri")?;
    cbor::write_text(&mut out, info.payload_uri)?;
    cbor::write_text(&mut out, b"payload_file")?;
    cbor::write_text(&mut out, payload_file)?;
    cbor::write_text(&mut out, b"payload_sha256")?;
    cbor::write_bytes(&mut out, payload_sha256)?;
    Some(out)
}

pub(crate) fn installed_payload_path(info: &SuitManifestInfo<'_>) -> Option<Vec<u8>> {
    match info.component_kind {
        ComponentKind::App => {
            let command = info.app_command?;
            let mut out = Vec::new();
            out.extend_from_slice(b"apps/");
            out.extend_from_slice(command);
            out.extend_from_slice(b".wasm");
            Some(out)
        }
        ComponentKind::Catalog => Some(b"catalog/catalog.cbor".to_vec()),
        ComponentKind::Unsupported => Some(INSTALLED_TC_PAYLOAD0_PATH.to_vec()),
    }
}

pub(crate) fn twep_app_component_id(command: &[u8]) -> Option<Vec<u8>> {
    if !valid_command(command) {
        return None;
    }
    let mut out = Vec::new();
    cbor::write_array(&mut out, 2)?;
    cbor::write_bytes(&mut out, TWEP_APP_COMPONENT_PREFIX)?;
    cbor::write_bytes(&mut out, command)?;
    Some(out)
}

pub(crate) fn twep_catalog_component_id(name: &[u8]) -> Option<Vec<u8>> {
    if !valid_command(name) {
        return None;
    }
    let mut out = Vec::new();
    cbor::write_array(&mut out, 2)?;
    cbor::write_bytes(&mut out, TWEP_CATALOG_COMPONENT_PREFIX)?;
    cbor::write_bytes(&mut out, name)?;
    Some(out)
}

#[cfg(test)]
pub(crate) fn fixture_test_update_payload(
    command: &[u8],
    digest_payload: &[u8],
    integrated_payload: &[u8],
    token: &[u8],
) -> (Vec<u8>, Vec<u8>, [u8; 32]) {
    let component_id = twep_app_component_id(command).expect("component id");
    fixture_test_update_payload_for_component(
        component_id,
        b"#payload",
        digest_payload,
        integrated_payload,
        token,
        b"auth-block",
    )
}

#[cfg(test)]
pub(crate) fn fixture_test_update_payload_with_suit_auth(
    command: &[u8],
    digest_payload: &[u8],
    integrated_payload: &[u8],
    token: &[u8],
) -> (Vec<u8>, Vec<u8>, [u8; 32]) {
    let component_id = twep_app_component_id(command).expect("component id");
    let payload_sha256 = sha256(digest_payload);
    let manifest = fixture_test_manifest(&component_id, b"#payload", &payload_sha256, 1);
    let manifest_digest = suit_manifest_digest_raw(&manifest).expect("manifest digest");
    let auth_block = crate::cose::sign_test_suit_auth_detached(&manifest_digest)
        .expect("signed SUIT auth block");
    let update = fixture_test_update_payload_for_manifest(
        b"#payload",
        integrated_payload,
        token,
        &manifest,
        &manifest_digest,
        &auth_block,
    );
    (update, component_id, payload_sha256)
}

#[cfg(test)]
pub(crate) fn fixture_test_catalog_update_payload(
    catalog_name: &[u8],
    digest_payload: &[u8],
    integrated_payload: &[u8],
    token: &[u8],
) -> (Vec<u8>, Vec<u8>, [u8; 32]) {
    let component_id = twep_catalog_component_id(catalog_name).expect("component id");
    fixture_test_update_payload_for_component(
        component_id,
        b"#catalog.cbor",
        digest_payload,
        integrated_payload,
        token,
        b"auth-block",
    )
}

#[cfg(test)]
fn fixture_test_update_payload_for_component(
    component_id: Vec<u8>,
    payload_uri: &[u8],
    digest_payload: &[u8],
    integrated_payload: &[u8],
    token: &[u8],
    auth_block: &[u8],
) -> (Vec<u8>, Vec<u8>, [u8; 32]) {
    let payload_sha256 = sha256(digest_payload);
    let manifest = fixture_test_manifest(&component_id, payload_uri, &payload_sha256, 1);
    let manifest_digest = suit_manifest_digest_raw(&manifest).expect("manifest digest");
    let update = fixture_test_update_payload_for_manifest(
        payload_uri,
        integrated_payload,
        token,
        &manifest,
        &manifest_digest,
        auth_block,
    );
    (update, component_id, payload_sha256)
}

#[cfg(test)]
fn fixture_test_manifest(
    component_id: &[u8],
    payload_uri: &[u8],
    payload_sha256: &[u8; 32],
    sequence_number: usize,
) -> Vec<u8> {
    let mut digest = Vec::new();
    cbor::write_array(&mut digest, 2).unwrap();
    digest.push(0x2f);
    cbor::write_bytes(&mut digest, payload_sha256).unwrap();

    let mut shared_sequence = Vec::new();
    cbor::write_array(&mut shared_sequence, 2).unwrap();
    cbor::write_uint(&mut shared_sequence, 20).unwrap();
    cbor::write_map(&mut shared_sequence, 1).unwrap();
    cbor::write_uint(&mut shared_sequence, 3).unwrap();
    cbor::write_bytes(&mut shared_sequence, &digest).unwrap();

    let mut common = Vec::new();
    cbor::write_map(&mut common, 2).unwrap();
    cbor::write_uint(&mut common, 2).unwrap();
    cbor::write_array(&mut common, 1).unwrap();
    common.extend_from_slice(component_id);
    cbor::write_uint(&mut common, 4).unwrap();
    cbor::write_bytes(&mut common, &shared_sequence).unwrap();

    let mut payload_fetch = Vec::new();
    cbor::write_array(&mut payload_fetch, 2).unwrap();
    cbor::write_uint(&mut payload_fetch, 20).unwrap();
    cbor::write_map(&mut payload_fetch, 1).unwrap();
    cbor::write_uint(&mut payload_fetch, 21).unwrap();
    cbor::write_text(&mut payload_fetch, payload_uri).unwrap();

    let mut manifest = Vec::new();
    cbor::write_map(&mut manifest, 3).unwrap();
    cbor::write_uint(&mut manifest, 2).unwrap();
    cbor::write_uint(&mut manifest, sequence_number).unwrap();
    cbor::write_uint(&mut manifest, 3).unwrap();
    cbor::write_bytes(&mut manifest, &common).unwrap();
    cbor::write_uint(&mut manifest, 16).unwrap();
    cbor::write_bytes(&mut manifest, &payload_fetch).unwrap();
    manifest
}

#[cfg(test)]
fn fixture_test_update_payload_for_manifest(
    payload_uri: &[u8],
    integrated_payload: &[u8],
    token: &[u8],
    manifest: &[u8],
    manifest_digest: &[u8],
    auth_block: &[u8],
) -> Vec<u8> {
    let mut auth_wrapper = Vec::new();
    cbor::write_array(&mut auth_wrapper, 2).unwrap();
    cbor::write_bytes(&mut auth_wrapper, manifest_digest).unwrap();
    cbor::write_bytes(&mut auth_wrapper, auth_block).unwrap();

    let mut envelope = Vec::new();
    envelope.push(0xd8);
    envelope.push(107);
    cbor::write_map(&mut envelope, 3).unwrap();
    cbor::write_uint(&mut envelope, 2).unwrap();
    cbor::write_bytes(&mut envelope, &auth_wrapper).unwrap();
    cbor::write_uint(&mut envelope, 3).unwrap();
    cbor::write_bytes(&mut envelope, manifest).unwrap();
    cbor::write_text(&mut envelope, payload_uri).unwrap();
    cbor::write_bytes(&mut envelope, integrated_payload).unwrap();

    let mut update = Vec::new();
    cbor::write_array(&mut update, 2).unwrap();
    cbor::write_uint(&mut update, crate::teep::TEEP_TYPE_UPDATE).unwrap();
    cbor::write_map(&mut update, 2).unwrap();
    cbor::write_uint(&mut update, 9).unwrap();
    cbor::write_array(&mut update, 1).unwrap();
    cbor::write_bytes(&mut update, &envelope).unwrap();
    cbor::write_uint(&mut update, 19).unwrap();
    cbor::write_bytes(&mut update, token).unwrap();

    update
}

fn component_kind_and_name(input: &[u8]) -> (ComponentKind, Option<&[u8]>) {
    let mut off = 0usize;
    let Some((major, len)) = cbor::head(input, &mut off) else {
        return (ComponentKind::Unsupported, None);
    };
    if major != 4 || len != 2 {
        return (ComponentKind::Unsupported, None);
    }
    let Some(prefix) = cbor::bytes(input, &mut off) else {
        return (ComponentKind::Unsupported, None);
    };
    let Some(name) = cbor::bytes(input, &mut off) else {
        return (ComponentKind::Unsupported, None);
    };
    if off != input.len() || !valid_command(name) {
        return (ComponentKind::Unsupported, None);
    }
    if prefix == TWEP_APP_COMPONENT_PREFIX {
        (ComponentKind::App, Some(name))
    } else if prefix == TWEP_CATALOG_COMPONENT_PREFIX {
        (ComponentKind::Catalog, Some(name))
    } else {
        (ComponentKind::Unsupported, None)
    }
}

#[cfg(test)]
fn twep_app_component_command(input: &[u8]) -> Option<&[u8]> {
    let (kind, name) = component_kind_and_name(input);
    (kind == ComponentKind::App).then_some(name).flatten()
}

fn valid_command(value: &[u8]) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_')
}

pub(crate) fn success_response_payload(
    info: &SuitManifestInfo<'_>,
    token: &[u8],
) -> Option<Vec<u8>> {
    let report = success_suit_report(info)?;
    let mut out = Vec::new();
    cbor::write_array(&mut out, 2)?;
    cbor::write_uint(&mut out, 4)?;
    cbor::write_map(&mut out, 2)?;
    cbor::write_uint(&mut out, 18)?;
    cbor::write_array(&mut out, 1)?;
    cbor::write_bytes(&mut out, &report)?;
    cbor::write_uint(&mut out, 19)?;
    cbor::write_bytes(&mut out, token)?;
    Some(out)
}

fn success_suit_report(info: &SuitManifestInfo<'_>) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    cbor::write_map(&mut out, 3)?;
    cbor::write_uint(&mut out, 99)?;
    cbor::write_array(&mut out, 2)?;
    cbor::write_text(&mut out, b"")?;
    out.extend_from_slice(info.manifest_digest);
    cbor::write_uint(&mut out, 3)?;
    cbor::write_array(&mut out, 1)?;
    cbor::write_map(&mut out, 3)?;
    cbor::write_uint(&mut out, 0)?;
    out.extend_from_slice(info.component_id);
    cbor::write_uint(&mut out, 14)?;
    cbor::write_uint(&mut out, info.payload.len())?;
    cbor::write_uint(&mut out, 3)?;
    cbor::write_bytes(&mut out, info.payload_digest)?;
    cbor::write_uint(&mut out, 4)?;
    cbor::write_bool(&mut out, true)?;
    Some(out)
}

fn cbor_write_decimal(out: &mut Vec<u8>, mut value: usize) -> Option<()> {
    let mut digits = [0u8; 20];
    let mut pos = digits.len();
    if value == 0 {
        out.push(b'0');
        return Some(());
    }
    while value > 0 {
        pos = pos.checked_sub(1)?;
        digits[pos] = b'0' + (value % 10) as u8;
        value /= 10;
    }
    out.extend_from_slice(&digits[pos..]);
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;

    #[test]
    fn twep_app_component_id_uses_bstr_array() {
        let got = twep_app_component_id(b"remotehello").expect("component id");
        let want = [
            &[0x82, 0x4b][..],
            b"twep-app-v1",
            &[0x4b][..],
            b"remotehello",
        ]
        .concat();

        assert_eq!(got, want);
        assert_eq!(
            twep_app_component_command(&got).expect("component command"),
            b"remotehello"
        );
    }

    #[test]
    fn twep_app_component_command_rejects_text_and_bad_command() {
        let text_elements = [&[0x82, 0x6b][..], b"twep-app-v1", &[0x65][..], b"hello"].concat();
        assert_eq!(twep_app_component_command(&text_elements), None);

        let mut bad_command = Vec::new();
        cbor::write_array(&mut bad_command, 2).unwrap();
        cbor::write_bytes(&mut bad_command, TWEP_APP_COMPONENT_PREFIX).unwrap();
        cbor::write_bytes(&mut bad_command, b"../hello").unwrap();
        assert_eq!(twep_app_component_command(&bad_command), None);
        assert_eq!(twep_app_component_id(b"../hello"), None);
    }

    #[test]
    fn twep_catalog_component_id_uses_bstr_array() {
        let got = twep_catalog_component_id(b"default").expect("component id");
        let want = [
            &[0x82, 0x4f][..],
            b"twep-catalog-v1",
            &[0x47][..],
            b"default",
        ]
        .concat();

        assert_eq!(got, want);
        assert_eq!(
            component_kind_and_name(&got),
            (ComponentKind::Catalog, Some(b"default".as_slice()))
        );
        assert_eq!(twep_app_component_command(&got), None);
    }

    #[test]
    fn installed_payload_path_uses_catalog_cbor_for_catalog_components() {
        let component_id = twep_catalog_component_id(b"default").expect("component id");
        let info = fixture_manifest_info_for_component(
            component_id,
            ComponentKind::Catalog,
            Some(b"default".as_slice()),
            None,
        );

        assert_eq!(
            installed_payload_path(&info).expect("payload path"),
            b"catalog/catalog.cbor".to_vec()
        );
    }

    #[test]
    fn teep_update_candidate_collects_verified_update_inputs() {
        let token = b"\x01\x02\x03";
        let payload = b"wasm bytes";
        let (update, component_id, payload_sha256) =
            fixture_update_payload(b"remotehello", payload, payload, token);

        let candidate = teep_update_candidate(&update, &component_id).expect("candidate");
        assert_eq!(candidate.manifest_count, 1);
        assert_eq!(candidate.update_token, token);
        assert_eq!(candidate.info.component_id, component_id.as_slice());
        assert_eq!(candidate.info.component_kind, ComponentKind::App);
        assert_eq!(candidate.info.sequence_number, 1);
        assert_eq!(candidate.info.payload_uri, b"#payload");
        assert_eq!(candidate.info.payload, payload);
        assert_eq!(candidate.info.app_command, Some(b"remotehello".as_slice()));
        assert_eq!(candidate.info.catalog_name, None);
        assert_eq!(candidate.payload_sha256, payload_sha256);
        assert_eq!(candidate.info.payload_digest_sha256, payload_sha256);
    }

    #[test]
    fn teep_update_candidate_any_collects_catalog_update_inputs_without_app_promotion() {
        let token = b"\x01\x02\x03";
        let payload = b"catalog cbor";
        let (update, component_id, payload_sha256) =
            fixture_catalog_update_payload(b"default", payload, payload, token);

        let candidate = teep_update_candidate_any(&update).expect("candidate");
        assert_eq!(candidate.info.component_id, component_id.as_slice());
        assert_eq!(candidate.info.component_kind, ComponentKind::Catalog);
        assert_eq!(candidate.info.app_command, None);
        assert_eq!(candidate.info.catalog_name, Some(b"default".as_slice()));
        assert_eq!(candidate.info.payload_uri, b"#catalog.cbor");
        assert_eq!(candidate.info.payload, payload);
        assert_eq!(candidate.payload_sha256, payload_sha256);

        let app_component_id = twep_app_component_id(b"remotehello").expect("component id");
        assert_eq!(
            teep_update_candidate(&update, &app_component_id).map(|_| ()),
            Err(TeepUpdateCandidateError::ComponentMismatch)
        );
    }

    #[test]
    fn teep_update_candidate_rejects_payload_hash_mismatch() {
        let token = b"\x01\x02\x03";
        let (update, component_id, _) = fixture_update_payload(
            b"remotehello",
            b"expected payload",
            b"changed payload",
            token,
        );

        assert_eq!(
            teep_update_candidate(&update, &component_id).map(|_| ()),
            Err(TeepUpdateCandidateError::PayloadHashMismatch)
        );
    }

    fn fixture_update_payload(
        command: &[u8],
        digest_payload: &[u8],
        integrated_payload: &[u8],
        token: &[u8],
    ) -> (Vec<u8>, Vec<u8>, [u8; 32]) {
        fixture_test_update_payload(command, digest_payload, integrated_payload, token)
    }

    fn fixture_catalog_update_payload(
        catalog_name: &[u8],
        digest_payload: &[u8],
        integrated_payload: &[u8],
        token: &[u8],
    ) -> (Vec<u8>, Vec<u8>, [u8; 32]) {
        fixture_test_catalog_update_payload(catalog_name, digest_payload, integrated_payload, token)
    }

    fn fixture_manifest_info_for_component(
        component_id: Vec<u8>,
        component_kind: ComponentKind,
        catalog_name: Option<&'static [u8]>,
        app_command: Option<&'static [u8]>,
    ) -> SuitManifestInfo<'static> {
        SuitManifestInfo {
            component_id: Box::leak(component_id.into_boxed_slice()),
            component_kind,
            sequence_number: 1,
            manifest_body: b"",
            manifest_digest: b"",
            suit_auth_block: b"",
            payload_digest: b"",
            payload_digest_sha256: b"",
            payload_uri: b"#catalog.cbor",
            payload: b"",
            app_command,
            catalog_name,
        }
    }
}
