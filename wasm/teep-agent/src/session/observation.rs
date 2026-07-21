// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause

//! Persistence of protocol observations; these files are diagnostics, not authority.

use crate::host_io;
use crate::suit::{
    manifest_count_text, payload_uri_text, sequence_number_text, suit_manifest_info,
    TeepUpdateCandidate,
};
use crate::teep::update_manifest_list;

const MANIFEST_PATH: &[u8] = b"teep-agent/update-manifest-0.cbor";
const MANIFEST_COUNT_PATH: &[u8] = b"teep-agent/update-manifest-count.txt";
const COMPONENT_ID_PATH: &[u8] = b"teep-agent/update-manifest-component-id.cbor";
const SEQUENCE_PATH: &[u8] = b"teep-agent/update-manifest-sequence-number.txt";
const PAYLOAD_DIGEST_PATH: &[u8] = b"teep-agent/update-manifest-payload-digest.cbor";
const PAYLOAD_DIGEST_SHA256_PATH: &[u8] = b"teep-agent/update-manifest-payload-digest-sha256.bin";
const PAYLOAD_PATH: &[u8] = b"teep-agent/update-payload-0.bin";
const PAYLOAD_URI_PATH: &[u8] = b"teep-agent/update-payload-uri.txt";
const PAYLOAD_SHA256_PATH: &[u8] = b"teep-agent/update-payload-sha256.bin";
const PAYLOAD_HASH_STATUS_PATH: &[u8] = b"teep-agent/update-payload-hash-status.txt";

pub(super) fn observe_manifest_summary(body_payload: &[u8]) -> Result<(), i32> {
    let Some((manifest, manifest_count)) = update_manifest_list(body_payload) else {
        return Ok(());
    };
    if !host_io::write_file(MANIFEST_PATH, manifest) {
        return Err(127);
    }
    let Some(count_text) = manifest_count_text(manifest_count) else {
        return Err(4);
    };
    if !host_io::write_file(MANIFEST_COUNT_PATH, &count_text) {
        return Err(127);
    }
    if let Some(info) = suit_manifest_info(manifest) {
        if !host_io::write_file(COMPONENT_ID_PATH, info.component_id) {
            return Err(127);
        }
    }
    Ok(())
}

pub(crate) fn write_update_candidate(candidate: &TeepUpdateCandidate<'_>) -> bool {
    write_update_candidate_checked(candidate).is_ok()
}

pub(super) fn write_update_candidate_checked(
    candidate: &TeepUpdateCandidate<'_>,
) -> Result<(), i32> {
    let info = candidate.info;
    if !host_io::write_file(MANIFEST_PATH, candidate.manifest) {
        return Err(127);
    }
    let Some(count_text) = manifest_count_text(candidate.manifest_count) else {
        return Err(4);
    };
    if !host_io::write_file(MANIFEST_COUNT_PATH, &count_text)
        || !host_io::write_file(COMPONENT_ID_PATH, info.component_id)
    {
        return Err(127);
    }
    let Some(sequence_text) = sequence_number_text(info.sequence_number) else {
        return Err(4);
    };
    let Some(uri_text) = payload_uri_text(info.payload_uri) else {
        return Err(4);
    };
    if !host_io::write_file(SEQUENCE_PATH, &sequence_text)
        || !host_io::write_file(PAYLOAD_DIGEST_PATH, info.payload_digest)
        || !host_io::write_file(PAYLOAD_DIGEST_SHA256_PATH, info.payload_digest_sha256)
        || !host_io::write_file(PAYLOAD_PATH, info.payload)
        || !host_io::write_file(PAYLOAD_SHA256_PATH, &candidate.payload_sha256)
        || !host_io::write_file(PAYLOAD_URI_PATH, &uri_text)
        || !host_io::write_file(PAYLOAD_HASH_STATUS_PATH, b"payload-hash=ok\n")
    {
        return Err(127);
    }
    Ok(())
}
