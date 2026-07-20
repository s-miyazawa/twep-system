// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause
use ciborium::value::Value;

use crate::cbor;

pub(crate) const MAX_CATALOG_BYTES: usize = 65_536;
const MAX_CATALOG_APPS: usize = 256;
const MAX_CBOR_NESTING: usize = 16;

pub(crate) fn validate_authoritative_catalog(input: &[u8]) -> bool {
    if input.is_empty() || input.len() > MAX_CATALOG_BYTES || !is_canonical_cbor(input) {
        return false;
    }
    let Some(Value::Map(root)) = catalog_value(input) else {
        return false;
    };
    let Some(schema_version) = map_field(&root, "schema_version") else {
        return false;
    };
    if cbor::uint_value(schema_version) != Some(1) {
        return false;
    }
    let Some(Value::Map(apps)) = map_field(&root, "apps") else {
        return false;
    };
    if apps.len() > MAX_CATALOG_APPS {
        return false;
    }
    if !matches!(map_field(&root, "generated_at"), Some(Value::Text(value)) if !value.is_empty())
        || !matches!(map_field(&root, "source"), Some(Value::Text(value)) if !value.is_empty())
    {
        return false;
    }
    if !root.iter().all(|(key, value)| match text_key(key) {
        Some("schema_version") => cbor::uint_value(value) == Some(1),
        Some("apps") => matches!(value, Value::Map(_)),
        Some("generated_at" | "source") => matches!(value, Value::Text(value) if !value.is_empty()),
        _ => false,
    }) {
        return false;
    }
    apps.iter().all(|(command, entry)| {
        let Value::Text(command) = command else {
            return false;
        };
        valid_command(command.as_bytes()) && validate_app_entry(entry)
    })
}

fn catalog_value(input: &[u8]) -> Option<Value> {
    if let Some(value) = cbor::value(input) {
        return Some(value);
    }
    // `ciborium::Value` does not represent unassigned CBOR simple values. They are
    // nevertheless permitted by the Catalog CDDL's `args_schema => any`. Preserve
    // the already-validated item boundaries while substituting equivalent-size
    // placeholder values solely for schema inspection.
    let mut sanitized = input.to_vec();
    let mut offset = 0;
    sanitize_unknown_simple_values(&mut sanitized, &mut offset)?;
    (offset == sanitized.len()).then(|| cbor::value(&sanitized))?
}

fn sanitize_unknown_simple_values(input: &mut [u8], offset: &mut usize) -> Option<()> {
    let start = *offset;
    let first = *input.get(start)?;
    let major = first >> 5;
    let additional = first & 0x1f;
    if major == 7 {
        match additional {
            0..=19 => {
                input[start] = 0xf6;
                *offset += 1;
            }
            20..=23 => *offset += 1,
            24 => {
                input[start] = 0xc0;
                *input.get_mut(start.checked_add(1)?)? = 0xf6;
                *offset += 2;
            }
            25 => *offset += 3,
            26 => *offset += 5,
            27 => *offset += 9,
            _ => return None,
        }
        return (*offset <= input.len()).then_some(());
    }
    let (major, value) = canonical_head(input, offset)?;
    match major {
        0 | 1 => Some(()),
        2 | 3 => {
            *offset = offset.checked_add(value)?;
            (*offset <= input.len()).then_some(())
        }
        4 => {
            for _ in 0..value {
                sanitize_unknown_simple_values(input, offset)?;
            }
            Some(())
        }
        5 => {
            for _ in 0..value {
                sanitize_unknown_simple_values(input, offset)?;
                sanitize_unknown_simple_values(input, offset)?;
            }
            Some(())
        }
        6 => sanitize_unknown_simple_values(input, offset),
        _ => None,
    }
}

fn validate_app_entry(value: &Value) -> bool {
    let Value::Map(fields) = value else {
        return false;
    };
    let required_text = [
        "display_name",
        "component_id",
        "version",
        "abi",
        "wasm_file",
    ];
    if required_text
        .iter()
        .any(|key| !matches!(map_field(fields, key), Some(Value::Text(value)) if !value.is_empty()))
    {
        return false;
    }
    if !matches!(map_field(fields, "abi"), Some(Value::Text(value)) if value == "twep-app-v1")
        || !matches!(map_field(fields, "sha256"), Some(Value::Bytes(value)) if value.len() == 32)
        || !matches!(map_field(fields, "wasm_file"), Some(Value::Text(value)) if is_safe_wasm_basename(value.as_bytes()))
    {
        return false;
    }
    fields.iter().all(|(key, value)| match text_key(key) {
        Some("component_id" | "version" | "abi" | "wasm_file") => {
            matches!(value, Value::Text(value) if !value.is_empty())
        }
        Some("sha256") => matches!(value, Value::Bytes(value) if value.len() == 32),
        Some("display_name") => matches!(value, Value::Text(value) if !value.is_empty()),
        Some("description") => matches!(value, Value::Text(_)),
        Some("accepted_formats") => matches!(value, Value::Array(values) if values.iter().all(|value| matches!(value, Value::Text(_)))),
        Some("resource_limits") => validate_resource_limits(value),
        Some("args_schema") => true,
        _ => false,
    })
}

fn validate_resource_limits(value: &Value) -> bool {
    let Value::Map(fields) = value else {
        return false;
    };
    fields.iter().all(|(key, value)| {
        matches!(
            text_key(key),
            Some("stack_bytes" | "heap_bytes" | "timeout_ms" | "max_output_bytes")
        ) && cbor::uint_value(value).is_some()
    })
}

fn map_field<'a>(fields: &'a [(Value, Value)], wanted: &str) -> Option<&'a Value> {
    fields
        .iter()
        .find_map(|(key, value)| (text_key(key) == Some(wanted)).then_some(value))
}

fn text_key(value: &Value) -> Option<&str> {
    match value {
        Value::Text(value) => Some(value.as_str()),
        _ => None,
    }
}

fn valid_command(value: &[u8]) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-' || *byte == b'_')
}

fn is_safe_wasm_basename(value: &[u8]) -> bool {
    !value.is_empty()
        && value.ends_with(b".wasm")
        && value != b".wasm"
        && !value.windows(2).any(|pair| pair == b"..")
        && !value
            .iter()
            .any(|byte| *byte == 0 || *byte == b'/' || *byte == b'\\')
}

fn is_canonical_cbor(input: &[u8]) -> bool {
    let mut offset = 0usize;
    parse_item(input, &mut offset, 1).is_some() && offset == input.len()
}

fn parse_item(input: &[u8], offset: &mut usize, depth: usize) -> Option<()> {
    if depth > MAX_CBOR_NESTING {
        return None;
    }
    if input.get(*offset)? >> 5 == 7 {
        return parse_simple_or_float(input, offset);
    }
    let (major, value) = canonical_head(input, offset)?;
    match major {
        0 | 1 => Some(()),
        2 | 3 => {
            let end = offset.checked_add(value)?;
            if end > input.len()
                || (major == 3 && core::str::from_utf8(&input[*offset..end]).is_err())
            {
                return None;
            }
            *offset = end;
            Some(())
        }
        4 => {
            for _ in 0..value {
                parse_item(input, offset, depth + 1)?;
            }
            Some(())
        }
        5 => {
            let mut previous_key: Option<(usize, usize)> = None;
            for _ in 0..value {
                let key_start = *offset;
                parse_item(input, offset, depth + 1)?;
                let key_end = *offset;
                if let Some(previous) = previous_key {
                    if canonical_key_cmp(&input[previous.0..previous.1], &input[key_start..key_end])
                        != core::cmp::Ordering::Less
                    {
                        return None;
                    }
                }
                previous_key = Some((key_start, key_end));
                parse_item(input, offset, depth + 1)?;
            }
            Some(())
        }
        6 => parse_item(input, offset, depth + 1),
        _ => None,
    }
}

fn parse_simple_or_float(input: &[u8], offset: &mut usize) -> Option<()> {
    let first = *input.get(*offset)?;
    *offset += 1;
    match first & 0x1f {
        0..=23 => Some(()),
        24 => {
            let value = *input.get(*offset)?;
            *offset += 1;
            (value >= 32).then_some(())
        }
        25 => {
            let bytes = input.get(*offset..offset.checked_add(2)?)?;
            *offset += 2;
            let bits = u16::from_be_bytes([bytes[0], bytes[1]]);
            let is_nan = bits & 0x7c00 == 0x7c00 && bits & 0x03ff != 0;
            (!is_nan || bits == 0x7e00).then_some(())
        }
        26 => {
            let bytes = input.get(*offset..offset.checked_add(4)?)?;
            *offset += 4;
            let value =
                f32::from_bits(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
            (!value.is_nan() && !f32_is_exact_f16(value)).then_some(())
        }
        27 => {
            let bytes = input.get(*offset..offset.checked_add(8)?)?;
            *offset += 8;
            let value = f64::from_bits(u64::from_be_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]));
            let narrowed = value as f32;
            (!value.is_nan() && (narrowed as f64).to_bits() != value.to_bits()).then_some(())
        }
        _ => None,
    }
}

fn f32_is_exact_f16(value: f32) -> bool {
    let bits = value.to_bits();
    let exponent = ((bits >> 23) & 0xff) as i32;
    let fraction = bits & 0x7f_ffff;
    if exponent == 0xff {
        return fraction == 0;
    }
    if exponent == 0 {
        return fraction == 0;
    }
    let unbiased = exponent - 127;
    if (-14..=15).contains(&unbiased) {
        return fraction & 0x1fff == 0;
    }
    if (-24..=-15).contains(&unbiased) {
        let significand = (1 << 23) | fraction;
        let discarded_bits = (-unbiased - 1) as u32;
        return significand & ((1u32 << discarded_bits) - 1) == 0;
    }
    false
}

fn canonical_head(input: &[u8], offset: &mut usize) -> Option<(u8, usize)> {
    let first = *input.get(*offset)?;
    *offset += 1;
    let major = first >> 5;
    let additional = first & 0x1f;
    let value = match additional {
        0..=23 => additional as usize,
        24 => {
            let value = *input.get(*offset)? as usize;
            *offset += 1;
            if value < 24 {
                return None;
            }
            value
        }
        25 => {
            let bytes = input.get(*offset..offset.checked_add(2)?)?;
            *offset += 2;
            let value = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
            if value <= u8::MAX as usize {
                return None;
            }
            value
        }
        26 => {
            let bytes = input.get(*offset..offset.checked_add(4)?)?;
            *offset += 4;
            let value = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
            if value <= u16::MAX as usize {
                return None;
            }
            value
        }
        27 => {
            let bytes = input.get(*offset..offset.checked_add(8)?)?;
            *offset += 8;
            let raw = u64::from_be_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]);
            if raw <= u32::MAX as u64 {
                return None;
            }
            usize::try_from(raw).ok()?
        }
        _ => return None,
    };
    Some((major, value))
}

fn canonical_key_cmp(left: &[u8], right: &[u8]) -> core::cmp::Ordering {
    left.len().cmp(&right.len()).then_with(|| left.cmp(right))
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;
    use crate::cbor;

    fn valid_catalog(apps: usize) -> Vec<u8> {
        catalog(apps, None)
    }

    fn catalog(apps: usize, args_schema: Option<&[u8]>) -> Vec<u8> {
        let mut out = Vec::new();
        cbor::write_map(&mut out, 4).unwrap();
        cbor::write_text(&mut out, b"apps").unwrap();
        cbor::write_map(&mut out, apps).unwrap();
        for index in 0..apps {
            let command = alloc::format!("app{index:03}");
            cbor::write_text(&mut out, command.as_bytes()).unwrap();
            cbor::write_map(&mut out, 6 + usize::from(args_schema.is_some())).unwrap();
            cbor::write_text(&mut out, b"abi").unwrap();
            cbor::write_text(&mut out, b"twep-app-v1").unwrap();
            cbor::write_text(&mut out, b"sha256").unwrap();
            cbor::write_bytes(&mut out, &[index as u8; 32]).unwrap();
            cbor::write_text(&mut out, b"version").unwrap();
            cbor::write_text(&mut out, b"1").unwrap();
            cbor::write_text(&mut out, b"wasm_file").unwrap();
            let wasm = alloc::format!("{command}.wasm");
            cbor::write_text(&mut out, wasm.as_bytes()).unwrap();
            if let Some(args_schema) = args_schema {
                cbor::write_text(&mut out, b"args_schema").unwrap();
                out.extend_from_slice(args_schema);
            }
            cbor::write_text(&mut out, b"component_id").unwrap();
            cbor::write_text(&mut out, command.as_bytes()).unwrap();
            cbor::write_text(&mut out, b"display_name").unwrap();
            cbor::write_text(&mut out, command.as_bytes()).unwrap();
        }
        cbor::write_text(&mut out, b"source").unwrap();
        cbor::write_text(&mut out, b"test").unwrap();
        cbor::write_text(&mut out, b"generated_at").unwrap();
        cbor::write_text(&mut out, b"2026-07-11T00:00:00Z").unwrap();
        cbor::write_text(&mut out, b"schema_version").unwrap();
        cbor::write_uint(&mut out, 1).unwrap();
        out
    }

    fn catalog_without_root_field(omitted: &str) -> Vec<u8> {
        let mut out = Vec::new();
        cbor::write_map(&mut out, 3).unwrap();
        cbor::write_text(&mut out, b"apps").unwrap();
        cbor::write_map(&mut out, 0).unwrap();
        if omitted != "source" {
            cbor::write_text(&mut out, b"source").unwrap();
            cbor::write_text(&mut out, b"test").unwrap();
        }
        if omitted != "generated_at" {
            cbor::write_text(&mut out, b"generated_at").unwrap();
            cbor::write_text(&mut out, b"2026-07-11T00:00:00Z").unwrap();
        }
        cbor::write_text(&mut out, b"schema_version").unwrap();
        cbor::write_uint(&mut out, 1).unwrap();
        out
    }

    fn catalog_without_display_name() -> Vec<u8> {
        let mut out = Vec::new();
        cbor::write_map(&mut out, 4).unwrap();
        cbor::write_text(&mut out, b"apps").unwrap();
        cbor::write_map(&mut out, 1).unwrap();
        cbor::write_text(&mut out, b"app").unwrap();
        cbor::write_map(&mut out, 5).unwrap();
        cbor::write_text(&mut out, b"abi").unwrap();
        cbor::write_text(&mut out, b"twep-app-v1").unwrap();
        cbor::write_text(&mut out, b"sha256").unwrap();
        cbor::write_bytes(&mut out, &[0; 32]).unwrap();
        cbor::write_text(&mut out, b"version").unwrap();
        cbor::write_text(&mut out, b"1").unwrap();
        cbor::write_text(&mut out, b"wasm_file").unwrap();
        cbor::write_text(&mut out, b"app.wasm").unwrap();
        cbor::write_text(&mut out, b"component_id").unwrap();
        cbor::write_text(&mut out, b"example.component").unwrap();
        cbor::write_text(&mut out, b"source").unwrap();
        cbor::write_text(&mut out, b"test").unwrap();
        cbor::write_text(&mut out, b"generated_at").unwrap();
        cbor::write_text(&mut out, b"2026-07-11T00:00:00Z").unwrap();
        cbor::write_text(&mut out, b"schema_version").unwrap();
        cbor::write_uint(&mut out, 1).unwrap();
        out
    }

    #[test]
    fn accepts_complete_canonical_catalog() {
        assert!(validate_authoritative_catalog(&valid_catalog(1)));
    }

    #[test]
    fn enforces_app_count_and_required_fields() {
        assert!(validate_authoritative_catalog(&valid_catalog(256)));
        assert!(!validate_authoritative_catalog(&valid_catalog(257)));
        let mut missing = valid_catalog(1);
        let position = missing
            .windows(b"twep-app-v1".len())
            .position(|window| window == b"twep-app-v1")
            .unwrap();
        missing[position] = b'x';
        assert!(!validate_authoritative_catalog(&missing));
    }

    #[test]
    fn requires_catalog_provenance_and_app_display_name() {
        assert!(!validate_authoritative_catalog(
            &catalog_without_root_field("generated_at")
        ));
        assert!(!validate_authoritative_catalog(
            &catalog_without_root_field("source")
        ));
        assert!(!validate_authoritative_catalog(
            &catalog_without_display_name()
        ));
    }

    #[test]
    fn args_schema_accepts_any_deterministic_cbor_value() {
        assert!(validate_authoritative_catalog(&catalog(
            1,
            Some(&[0xf9, 0x3e, 0x00])
        )));
        assert!(validate_authoritative_catalog(&catalog(1, Some(&[0xe0]))));
        assert!(validate_authoritative_catalog(&catalog(
            1,
            Some(&[0xf8, 0x20])
        )));
        assert!(validate_authoritative_catalog(&catalog(1, Some(&[0xf7]))));

        // 1.5 has an exact half-precision representation, so float32 is not
        // deterministic CBOR for this value.
        assert!(!validate_authoritative_catalog(&catalog(
            1,
            Some(&[0xfa, 0x3f, 0xc0, 0x00, 0x00])
        )));
    }

    #[test]
    fn rejects_noncanonical_duplicate_trailing_indefinite_and_unsafe_paths() {
        let mut noncanonical = valid_catalog(1);
        noncanonical[0] = 0xb8;
        noncanonical.insert(1, 2);
        assert!(!validate_authoritative_catalog(&noncanonical));

        let mut duplicate = Vec::new();
        cbor::write_map(&mut duplicate, 2).unwrap();
        cbor::write_text(&mut duplicate, b"apps").unwrap();
        cbor::write_map(&mut duplicate, 0).unwrap();
        cbor::write_text(&mut duplicate, b"apps").unwrap();
        cbor::write_map(&mut duplicate, 0).unwrap();
        assert!(!validate_authoritative_catalog(&duplicate));

        let mut trailing = valid_catalog(1);
        trailing.push(0);
        assert!(!validate_authoritative_catalog(&trailing));
        assert!(!validate_authoritative_catalog(&[0xbf, 0xff]));

        let mut unsafe_path = valid_catalog(1);
        let position = unsafe_path
            .windows(b"app000.wasm".len())
            .position(|window| window == b"app000.wasm")
            .unwrap();
        unsafe_path[position] = b'/';
        assert!(!validate_authoritative_catalog(&unsafe_path));
    }

    #[test]
    fn rejects_nesting_deeper_than_sixteen() {
        let mut nested = Vec::new();
        for _ in 0..17 {
            cbor::write_array(&mut nested, 1).unwrap();
        }
        cbor::write_uint(&mut nested, 0).unwrap();
        assert!(!is_canonical_cbor(&nested));
    }
}
