// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause
use alloc::vec::Vec;

use crate::{cbor, error_output, host_io, sha256, twep_app_alloc, write_output};

struct AppEntry<'a> {
    command: &'a [u8],
    component_id: &'a [u8],
    version: &'a [u8],
    abi: &'a [u8],
    wasm_file: &'a [u8],
    sha256: &'a [u8],
    accepted_formats: Option<&'a [u8]>,
    resource_limits: Option<&'a [u8]>,
}

pub(crate) fn authorizes_app_payload(
    catalog: &[u8],
    command: &[u8],
    payload_sha256: &[u8; 32],
) -> bool {
    catalog_entry(catalog, command)
        .map(|entry| entry.sha256 == payload_sha256)
        .unwrap_or(false)
}

pub(crate) fn protected_app_is_ready(catalog: &[u8], command: &[u8]) -> bool {
    catalog_entry(catalog, command)
        .map(|entry| verify_app_file(&entry) == 0)
        .unwrap_or(false)
}

pub(crate) fn authorizes_command(catalog: &[u8], command: &[u8]) -> bool {
    catalog_entry(catalog, command).is_ok()
}

pub(crate) fn resolve_from_catalog(
    out_desc_ptr: u32,
    catalog: &[u8],
    target_command: &[u8],
    probe_path: &[u8],
    probe: &[u8],
) -> i32 {
    let entry = match catalog_entry(catalog, target_command) {
        Ok(entry) => entry,
        Err(CatalogEntryError::NotFound) => {
            return write_output(
                out_desc_ptr,
                &error_output(b"catalog.not_found", b"target command not found"),
            )
        }
        Err(CatalogEntryError::Invalid) => {
            return write_output(
                out_desc_ptr,
                &error_output(b"catalog.invalid", b"catalog entry is invalid"),
            )
        }
    };
    let app_status = verify_app_file(&entry);
    if app_status == 7 {
        return write_output(
            out_desc_ptr,
            &error_output(b"app.hash_mismatch", b"app wasm hash mismatch"),
        );
    }
    if app_status != 0 && app_status != 3 {
        return 127;
    }
    if app_status == 0 {
        host_io::log(1, b"mock resolve");
    }
    if !host_io::write_file(probe_path, probe) {
        return 127;
    }
    let output = match resolve_output(&entry) {
        Some(output) => output,
        None => return 4,
    };
    write_output(out_desc_ptr, &output)
}

fn verify_app_file(entry: &AppEntry<'_>) -> i32 {
    let mut path = Vec::new();
    path.extend_from_slice(b"apps/");
    path.extend_from_slice(entry.wasm_file);
    let out_len = match host_io::read_file_len(&path) {
        Ok(None) => return 3,
        Ok(Some(value)) => value,
        Err(_) => return 127,
    };
    if out_len == 0 {
        return 7;
    }
    let app_ptr = twep_app_alloc(out_len);
    if app_ptr == 0 {
        return 4;
    }
    let app_buf = unsafe { core::slice::from_raw_parts_mut(app_ptr as *mut u8, out_len as usize) };
    let read_len = match host_io::read_file(&path, app_buf) {
        Ok(value) => value,
        Err(_) => return 127,
    };
    if read_len > out_len as usize {
        return 127;
    }
    let app = &app_buf[..read_len];
    if sha256(app) == entry.sha256 {
        0
    } else {
        7
    }
}

enum CatalogEntryError {
    NotFound,
    Invalid,
}

fn catalog_entry<'a>(
    catalog: &'a [u8],
    command: &'a [u8],
) -> Result<AppEntry<'a>, CatalogEntryError> {
    let mut off = 0usize;
    let (major, pairs) = cbor::head(catalog, &mut off).ok_or(CatalogEntryError::Invalid)?;
    if major != 5 {
        return Err(CatalogEntryError::Invalid);
    }
    for _ in 0..pairs {
        let key = cbor::text(catalog, &mut off).ok_or(CatalogEntryError::Invalid)?;
        if key != b"apps" {
            if !cbor::skip(catalog, &mut off) {
                return Err(CatalogEntryError::Invalid);
            }
            continue;
        }
        let (apps_major, app_count) =
            cbor::head(catalog, &mut off).ok_or(CatalogEntryError::Invalid)?;
        if apps_major != 5 {
            return Err(CatalogEntryError::Invalid);
        }
        for _ in 0..app_count {
            let app_command = cbor::text(catalog, &mut off).ok_or(CatalogEntryError::Invalid)?;
            let entry_start = off;
            if !cbor::skip(catalog, &mut off) {
                return Err(CatalogEntryError::Invalid);
            }
            if app_command == command {
                return parse_app_entry(app_command, &catalog[entry_start..off])
                    .ok_or(CatalogEntryError::Invalid);
            }
        }
        return Err(CatalogEntryError::NotFound);
    }
    Err(CatalogEntryError::NotFound)
}

fn parse_app_entry<'a>(command: &'a [u8], entry: &'a [u8]) -> Option<AppEntry<'a>> {
    let mut off = 0usize;
    let (major, pairs) = cbor::head(entry, &mut off)?;
    if major != 5 {
        return None;
    }
    let mut component_id = None;
    let mut version = None;
    let mut abi = None;
    let mut wasm_file = None;
    let mut sha256 = None;
    let mut accepted_formats = None;
    let mut resource_limits = None;
    for _ in 0..pairs {
        let key = cbor::text(entry, &mut off)?;
        let value_start = off;
        if key == b"component_id" {
            component_id = Some(cbor::text(entry, &mut off)?);
        } else if key == b"version" {
            version = Some(cbor::text(entry, &mut off)?);
        } else if key == b"abi" {
            abi = Some(cbor::text(entry, &mut off)?);
        } else if key == b"wasm_file" {
            wasm_file = Some(cbor::text(entry, &mut off)?);
        } else if key == b"sha256" {
            sha256 = Some(cbor::bytes(entry, &mut off)?);
        } else if key == b"accepted_formats" {
            if !cbor::skip(entry, &mut off) {
                return None;
            }
            accepted_formats = Some(&entry[value_start..off]);
        } else if key == b"resource_limits" {
            if !cbor::skip(entry, &mut off) {
                return None;
            }
            resource_limits = Some(&entry[value_start..off]);
        } else if !cbor::skip(entry, &mut off) {
            return None;
        }
    }
    let out = AppEntry {
        command,
        component_id: component_id?,
        version: version?,
        abi: abi?,
        wasm_file: wasm_file?,
        sha256: sha256?,
        accepted_formats,
        resource_limits,
    };
    if out.abi != b"twep-app-v1" || out.sha256.len() != 32 || !is_safe_wasm_basename(out.wasm_file)
    {
        return None;
    }
    Some(out)
}

fn is_safe_wasm_basename(wasm_file: &[u8]) -> bool {
    if wasm_file.is_empty() || !wasm_file.ends_with(b".wasm") {
        return false;
    }
    if wasm_file.windows(2).any(|value| value == b"..") {
        return false;
    }
    !wasm_file
        .iter()
        .any(|value| matches!(*value, b'/' | b'\\' | 0))
}

fn resolve_output(entry: &AppEntry<'_>) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut app_pairs = 6usize;
    if entry.accepted_formats.is_some() {
        app_pairs += 1;
    }
    if entry.resource_limits.is_some() {
        app_pairs += 1;
    }
    cbor::write_map(&mut out, 3)?;
    cbor::write_text(&mut out, b"schema_version")?;
    cbor::write_uint(&mut out, 1)?;
    cbor::write_text(&mut out, b"status")?;
    cbor::write_text(&mut out, b"ok")?;
    cbor::write_text(&mut out, b"app")?;
    cbor::write_map(&mut out, app_pairs)?;
    cbor::write_text(&mut out, b"command")?;
    cbor::write_text(&mut out, entry.command)?;
    cbor::write_text(&mut out, b"component_id")?;
    cbor::write_text(&mut out, entry.component_id)?;
    cbor::write_text(&mut out, b"version")?;
    cbor::write_text(&mut out, entry.version)?;
    cbor::write_text(&mut out, b"abi")?;
    cbor::write_text(&mut out, entry.abi)?;
    cbor::write_text(&mut out, b"wasm_file")?;
    cbor::write_text(&mut out, entry.wasm_file)?;
    cbor::write_text(&mut out, b"sha256")?;
    cbor::write_bytes(&mut out, entry.sha256)?;
    if let Some(formats) = entry.accepted_formats {
        cbor::write_text(&mut out, b"accepted_formats")?;
        out.extend_from_slice(formats);
    }
    if let Some(limits) = entry.resource_limits {
        cbor::write_text(&mut out, b"resource_limits")?;
        out.extend_from_slice(limits);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one_app_catalog(digest: &[u8; 32]) -> Vec<u8> {
        let mut out = Vec::new();
        cbor::write_map(&mut out, 1).unwrap();
        cbor::write_text(&mut out, b"apps").unwrap();
        cbor::write_map(&mut out, 1).unwrap();
        cbor::write_text(&mut out, b"remotehello").unwrap();
        cbor::write_map(&mut out, 6).unwrap();
        cbor::write_text(&mut out, b"abi").unwrap();
        cbor::write_text(&mut out, b"twep-app-v1").unwrap();
        cbor::write_text(&mut out, b"sha256").unwrap();
        cbor::write_bytes(&mut out, digest).unwrap();
        cbor::write_text(&mut out, b"version").unwrap();
        cbor::write_text(&mut out, b"1").unwrap();
        cbor::write_text(&mut out, b"wasm_file").unwrap();
        cbor::write_text(&mut out, b"remotehello.wasm").unwrap();
        cbor::write_text(&mut out, b"component_id").unwrap();
        cbor::write_text(&mut out, b"twep-app-v1/remotehello").unwrap();
        cbor::write_text(&mut out, b"display_name").unwrap();
        cbor::write_text(&mut out, b"Remote Hello").unwrap();
        out
    }

    #[test]
    fn protected_catalog_authorizes_only_the_named_payload_digest() {
        let digest = sha256(b"verified app");
        let catalog = one_app_catalog(&digest);

        assert!(authorizes_command(&catalog, b"remotehello"));
        assert!(authorizes_app_payload(&catalog, b"remotehello", &digest));
        assert!(!authorizes_app_payload(
            &catalog,
            b"remotehello",
            &sha256(b"different app")
        ));
        assert!(!authorizes_command(&catalog, b"other"));
    }
}
