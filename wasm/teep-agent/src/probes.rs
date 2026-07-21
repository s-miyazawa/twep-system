// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause

//! Explicit smoke-only commands, kept out of the production resolver flow.

use ciborium::value::Value;

use crate::{cbor, error_output, host_io, ok_output, sha256, verified, write_output};

const COMMAND_KEY: &[u8] = b"command";
const ATTESTAM_URL_KEY: &[u8] = b"attestam_url";

pub(crate) fn dispatch(input: &Value, out_desc_ptr: u32) -> Option<i32> {
    let command = cbor::text_field(input, COMMAND_KEY)?;
    let status = match command {
        b"hostcall_http_probe" => http_probe(input, out_desc_ptr),
        b"hostcall_evidence_probe" => evidence_probe(out_desc_ptr),
        b"hostcall_acceptance_probe_1"
        | b"hostcall_acceptance_probe_2"
        | b"hostcall_acceptance_probe_3"
        | b"hostcall_acceptance_probe_stale" => acceptance_probe(command, out_desc_ptr),
        b"hostcall_bad_read_probe" => bad_read_probe(out_desc_ptr),
        b"hostcall_bad_write_probe" => bad_write_probe(out_desc_ptr),
        b"hostcall_verified_result_write_probe" => verified_result_write_probe(out_desc_ptr),
        b"hostcall_acceptance_result_stale_probe" => acceptance_result_stale_probe(out_desc_ptr),
        _ => return None,
    };
    Some(status)
}

fn http_probe(input: &Value, out_desc_ptr: u32) -> i32 {
    let url =
        cbor::text_field(input, ATTESTAM_URL_KEY).unwrap_or(b"https://ta.example.invalid/tam");
    let mut out = [0u8; 128];
    let (status, _) = host_io::http_post(url, b"", &mut out);
    if status == 0 {
        write_output(out_desc_ptr, &ok_output())
    } else {
        127
    }
}

fn evidence_probe(out_desc_ptr: u32) -> i32 {
    let challenge = [0x10u8, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17];
    let agent_public_key_cose = [0xa1u8, 0x61, b'k', 0x63, b'd', b'e', b'v'];
    let mut out = [0u8; 128];
    match host_io::create_evidence(&challenge, &agent_public_key_cose, &mut out) {
        Ok(_) => write_output(out_desc_ptr, &ok_output()),
        Err(_) => 127,
    }
}

fn acceptance_probe(command: &[u8], out_desc_ptr: u32) -> i32 {
    let (body, sequence) = if command.ends_with(b"_1") {
        (b"acceptance-probe-1".as_slice(), 1)
    } else if command.ends_with(b"_2") {
        (b"acceptance-probe-2".as_slice(), 2)
    } else if command.ends_with(b"_3") {
        (b"acceptance-probe-3".as_slice(), 3)
    } else {
        (b"acceptance-probe-stale".as_slice(), 3)
    };
    let mut out = [0u8; 128];
    let (status, _) = host_io::http_post(b"https://ta.example.invalid/tam", body, &mut out);
    if status != 0 {
        return 127;
    }
    let generation = match host_io::acceptance_generation() {
        Ok(value) => value,
        Err(_) => return 127,
    };
    let expected_generation = if command.ends_with(b"_stale") {
        generation.saturating_sub(1)
    } else {
        generation
    };
    match host_io::commit_acceptance(
        &sha256(body),
        b"\x82\x4btwep-app-v1\x4bremotehello",
        sequence,
        expected_generation,
    ) {
        Ok(new_generation) if new_generation == generation + 1 => {
            write_output(out_desc_ptr, &ok_output())
        }
        _ => 127,
    }
}

fn bad_read_probe(out_desc_ptr: u32) -> i32 {
    match host_io::read_file_len(b"../catalog/catalog.cbor") {
        Ok(None) | Err(_) => write_output(
            out_desc_ptr,
            &error_output(b"hostcall.bad_object_blocked", b"bad read object blocked"),
        ),
        Ok(Some(_)) => 127,
    }
}

fn bad_write_probe(out_desc_ptr: u32) -> i32 {
    if !host_io::write_file(b"../tmp/teep-agent-probe", b"probe") {
        return write_output(
            out_desc_ptr,
            &error_output(b"hostcall.bad_object_blocked", b"bad write object blocked"),
        );
    }
    127
}

fn verified_result_write_probe(out_desc_ptr: u32) -> i32 {
    if !host_io::write_file(crate::evidence::VERIFIED_EVIDENCE_RESULT_PATH, b"probe") {
        return write_output(
            out_desc_ptr,
            &error_output(
                b"hostcall.bad_object_blocked",
                b"generic acceptance result write blocked",
            ),
        );
    }
    127
}

fn acceptance_result_stale_probe(out_desc_ptr: u32) -> i32 {
    if verified::protected_evidence_result_is_stale() {
        write_output(
            out_desc_ptr,
            &error_output(
                b"hostcall.acceptance_result_stale",
                b"stale acceptance result rejected",
            ),
        )
    } else {
        127
    }
}
