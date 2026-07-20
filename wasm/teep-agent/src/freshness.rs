// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause
use alloc::vec::Vec;

use crate::cbor;

struct DevSequenceEntry<'a> {
    component_id: &'a [u8],
    last_sequence: usize,
}

fn dev_sequence_entries(input: &[u8]) -> Option<Vec<DevSequenceEntry<'_>>> {
    let mut off = 0usize;
    let (major, pairs) = cbor::head(input, &mut off)?;
    if major != 5 {
        return None;
    }
    let mut entries = Vec::new();
    for _ in 0..pairs {
        let component_id = cbor::bytes(input, &mut off)?;
        let (seq_major, last_sequence) = cbor::head(input, &mut off)?;
        if seq_major != 0 {
            return None;
        }
        entries.push(DevSequenceEntry {
            component_id,
            last_sequence,
        });
    }
    if off == input.len() {
        Some(entries)
    } else {
        None
    }
}

pub(crate) fn dev_sequence_is_fresh_bytes(
    input: Option<&[u8]>,
    component_id: &[u8],
    sequence_number: usize,
) -> Option<bool> {
    let Some(input) = input else {
        return Some(true);
    };
    for entry in dev_sequence_entries(input)? {
        if entry.component_id == component_id {
            return Some(sequence_number > entry.last_sequence);
        }
    }
    Some(true)
}

pub(crate) fn dev_sequence_freshness_update(
    input: Option<&[u8]>,
    component_id: &[u8],
    sequence_number: usize,
) -> Option<Vec<u8>> {
    let mut entries = Vec::new();
    if let Some(input) = input {
        entries = dev_sequence_entries(input)?;
    }
    let has_existing = entries
        .iter()
        .any(|entry| entry.component_id == component_id);
    let mut out = Vec::new();
    cbor::write_map(&mut out, entries.len() + if has_existing { 0 } else { 1 })?;
    for entry in entries {
        if entry.component_id == component_id {
            cbor::write_bytes(&mut out, component_id)?;
            cbor::write_uint(&mut out, sequence_number)?;
        } else {
            cbor::write_bytes(&mut out, entry.component_id)?;
            cbor::write_uint(&mut out, entry.last_sequence)?;
        }
    }
    if !has_existing {
        cbor::write_bytes(&mut out, component_id)?;
        cbor::write_uint(&mut out, sequence_number)?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::suit::twep_app_component_id;

    #[test]
    fn dev_sequence_freshness_tracks_last_sequence_per_component() {
        let remotehello = twep_app_component_id(b"remotehello").expect("component id");
        let calcadd = twep_app_component_id(b"calcadd").expect("component id");
        assert_eq!(
            dev_sequence_is_fresh_bytes(None, &remotehello, 1),
            Some(true)
        );

        let state = dev_sequence_freshness_update(None, &remotehello, 1).expect("freshness state");
        assert_eq!(
            dev_sequence_is_fresh_bytes(Some(&state), &remotehello, 1),
            Some(false)
        );
        assert_eq!(
            dev_sequence_is_fresh_bytes(Some(&state), &remotehello, 0),
            Some(false)
        );
        assert_eq!(
            dev_sequence_is_fresh_bytes(Some(&state), &remotehello, 2),
            Some(true)
        );
        assert_eq!(
            dev_sequence_is_fresh_bytes(Some(&state), &calcadd, 1),
            Some(true)
        );

        let state =
            dev_sequence_freshness_update(Some(&state), &remotehello, 2).expect("freshness state");
        assert_eq!(
            dev_sequence_is_fresh_bytes(Some(&state), &remotehello, 2),
            Some(false)
        );
        assert_eq!(
            dev_sequence_is_fresh_bytes(Some(&state), &remotehello, 3),
            Some(true)
        );
    }

    #[test]
    fn dev_sequence_freshness_rejects_malformed_state() {
        assert_eq!(
            dev_sequence_is_fresh_bytes(Some(b"not-cbor"), b"component", 1),
            None
        );
        assert_eq!(
            dev_sequence_freshness_update(Some(b"not-cbor"), b"component", 1),
            None
        );
    }
}
