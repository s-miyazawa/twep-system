// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause
use alloc::vec::Vec;

use ciborium::{de::from_reader, value::Value};

pub(crate) fn value(input: &[u8]) -> Option<Value> {
    let mut reader = input;
    let value = from_reader(&mut reader).ok()?;
    if reader.is_empty() {
        Some(value)
    } else {
        None
    }
}

pub(crate) fn uint_value(input: &Value) -> Option<usize> {
    usize::try_from(input.as_integer()?).ok()
}

pub(crate) fn text_field<'a>(input: &'a Value, key: &[u8]) -> Option<&'a [u8]> {
    let pairs = match input {
        Value::Map(pairs) => pairs,
        _ => return None,
    };
    for (field_key, field_value) in pairs {
        if let Value::Text(field_key) = field_key {
            if field_key.as_bytes() == key {
                if let Value::Text(value) = field_value {
                    return Some(value.as_bytes());
                }
            }
        }
    }
    None
}

pub(crate) fn text<'a>(input: &'a [u8], off: &mut usize) -> Option<&'a [u8]> {
    let (major, len) = head(input, off)?;
    if major != 3 || len > input.len().saturating_sub(*off) {
        return None;
    }
    let start = *off;
    *off += len;
    Some(&input[start..start + len])
}

pub(crate) fn bytes<'a>(input: &'a [u8], off: &mut usize) -> Option<&'a [u8]> {
    let (major, len) = head(input, off)?;
    if major != 2 || len > input.len().saturating_sub(*off) {
        return None;
    }
    let start = *off;
    *off += len;
    Some(&input[start..start + len])
}

pub(crate) fn skip(input: &[u8], off: &mut usize) -> bool {
    let (major, value) = match head(input, off) {
        Some(v) => v,
        None => return false,
    };
    match major {
        0 | 1 | 7 => true,
        2 | 3 => {
            if value > input.len().saturating_sub(*off) {
                return false;
            }
            *off += value;
            true
        }
        4 => {
            for _ in 0..value {
                if !skip(input, off) {
                    return false;
                }
            }
            true
        }
        5 => {
            for _ in 0..value {
                if !skip(input, off) || !skip(input, off) {
                    return false;
                }
            }
            true
        }
        6 => skip(input, off),
        _ => false,
    }
}

pub(crate) fn head(input: &[u8], off: &mut usize) -> Option<(u8, usize)> {
    let head = *input.get(*off)?;
    *off += 1;
    let major = head >> 5;
    let add = head & 0x1f;
    if add < 24 {
        Some((major, add as usize))
    } else if add == 24 {
        let value = *input.get(*off)? as usize;
        *off += 1;
        Some((major, value))
    } else if add == 25 {
        let hi = *input.get(*off)? as usize;
        let lo = *input.get(*off + 1)? as usize;
        *off += 2;
        Some((major, (hi << 8) | lo))
    } else if add == 26 {
        let b0 = *input.get(*off)? as usize;
        let b1 = *input.get(*off + 1)? as usize;
        let b2 = *input.get(*off + 2)? as usize;
        let b3 = *input.get(*off + 3)? as usize;
        *off += 4;
        Some((major, (b0 << 24) | (b1 << 16) | (b2 << 8) | b3))
    } else {
        None
    }
}

pub(crate) fn write_uint(out: &mut Vec<u8>, value: usize) -> Option<()> {
    write_type_len(out, 0, value)
}

pub(crate) fn write_uint64(out: &mut Vec<u8>, value: u64) -> Option<()> {
    let head = 0u8 << 5;
    if value < 24 {
        out.push(head | value as u8);
    } else if value <= 0xff {
        out.push(head | 24);
        out.push(value as u8);
    } else if value <= 0xffff {
        out.push(head | 25);
        out.push((value >> 8) as u8);
        out.push(value as u8);
    } else if value <= 0xffff_ffff {
        out.push(head | 26);
        out.push((value >> 24) as u8);
        out.push((value >> 16) as u8);
        out.push((value >> 8) as u8);
        out.push(value as u8);
    } else {
        out.push(head | 27);
        out.push((value >> 56) as u8);
        out.push((value >> 48) as u8);
        out.push((value >> 40) as u8);
        out.push((value >> 32) as u8);
        out.push((value >> 24) as u8);
        out.push((value >> 16) as u8);
        out.push((value >> 8) as u8);
        out.push(value as u8);
    }
    Some(())
}

pub(crate) fn write_array(out: &mut Vec<u8>, len: usize) -> Option<()> {
    write_type_len(out, 4, len)
}

pub(crate) fn write_bytes(out: &mut Vec<u8>, value: &[u8]) -> Option<()> {
    write_type_len(out, 2, value.len())?;
    out.extend_from_slice(value);
    Some(())
}

pub(crate) fn write_text(out: &mut Vec<u8>, value: &[u8]) -> Option<()> {
    write_type_len(out, 3, value.len())?;
    out.extend_from_slice(value);
    Some(())
}

pub(crate) fn write_bool(out: &mut Vec<u8>, value: bool) -> Option<()> {
    out.push(if value { 0xf5 } else { 0xf4 });
    Some(())
}

pub(crate) fn write_map(out: &mut Vec<u8>, pairs: usize) -> Option<()> {
    write_type_len(out, 5, pairs)
}

fn write_type_len(out: &mut Vec<u8>, major: u8, value: usize) -> Option<()> {
    let head = major << 5;
    if value < 24 {
        out.push(head | value as u8);
    } else if value <= 0xff {
        out.push(head | 24);
        out.push(value as u8);
    } else if value <= 0xffff {
        out.push(head | 25);
        out.push((value >> 8) as u8);
        out.push(value as u8);
    } else {
        #[cfg(target_pointer_width = "64")]
        if value > 0xffff_ffff {
            return None;
        }
        out.push(head | 26);
        out.push((value >> 24) as u8);
        out.push((value >> 16) as u8);
        out.push((value >> 8) as u8);
        out.push(value as u8);
    }
    Some(())
}

#[cfg(test)]
mod abi_vector_tests {
    use super::value;
    use alloc::vec::Vec;
    use ciborium::ser::into_writer;

    #[test]
    fn canonical_abi_vectors_round_trip_byte_for_byte() {
        let source = include_str!("../../../testdata/abi/vectors.hex");
        for line in source
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
        {
            let (name, encoded) = line.split_once('|').expect("named ABI vector");
            let bytes = decode_hex(encoded).expect("valid ABI vector hex");
            let decoded = value(&bytes).expect("valid single CBOR value");
            let mut reencoded = Vec::new();
            into_writer(&decoded, &mut reencoded).expect("CBOR re-encode");
            assert_eq!(reencoded, bytes, "non-canonical vector: {name}");
        }
    }

    fn decode_hex(input: &str) -> Option<Vec<u8>> {
        if !input.len().is_multiple_of(2) {
            return None;
        }
        input
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| Some((nibble(pair[0])? << 4) | nibble(pair[1])?))
            .collect()
    }

    fn nibble(value: u8) -> Option<u8> {
        match value {
            b'0'..=b'9' => Some(value - b'0'),
            b'a'..=b'f' => Some(value - b'a' + 10),
            _ => None,
        }
    }
}
