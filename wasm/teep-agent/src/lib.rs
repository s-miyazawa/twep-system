#![no_std]
// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::vec::Vec;
use core::alloc::{GlobalAlloc, Layout};
#[cfg(not(test))]
use core::panic::PanicInfo;
use core::ptr::{self, addr_of_mut};
use core::sync::atomic::{AtomicUsize, Ordering};
use sha2::{Digest, Sha256};
mod catalog;
mod catalog_validator;
mod cbor;
mod cose;
mod credential_management;
mod evidence;
mod freshness;
mod host_io;
mod protected_credentials;
mod session;
mod suit;
mod teep;
mod verified;
mod wasm_signature;

use suit::{twep_app_component_id, twep_catalog_component_id};

struct BumpAllocator;

#[cfg(not(test))]
const HEAP_SIZE: usize = 512 * 1024;
#[cfg(test)]
const HEAP_SIZE: usize = 2 * 1024 * 1024;

#[repr(align(16))]
struct Heap([u8; HEAP_SIZE]);

static mut HEAP: Heap = Heap([0; HEAP_SIZE]);
static NEXT: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for BumpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let align = layout.align().max(1);
        let size = layout.size();
        let mut current = NEXT.load(Ordering::Relaxed);
        loop {
            let aligned = (current + align - 1) & !(align - 1);
            let next = match aligned.checked_add(size) {
                Some(v) => v,
                None => return ptr::null_mut(),
            };
            if next > HEAP_SIZE {
                return ptr::null_mut();
            }
            match NEXT.compare_exchange(current, next, Ordering::SeqCst, Ordering::Relaxed) {
                Ok(_) => return addr_of_mut!(HEAP.0).cast::<u8>().add(aligned),
                Err(v) => current = v,
            }
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator;

#[no_mangle]
pub extern "C" fn twep_app_abi_version() -> u32 {
    1
}

#[no_mangle]
pub extern "C" fn twep_app_alloc(len: u32) -> u32 {
    let layout = match Layout::from_size_align(len as usize, 1) {
        Ok(layout) => layout,
        Err(_) => return 0,
    };
    unsafe { ALLOCATOR.alloc(layout) as u32 }
}

#[no_mangle]
pub extern "C" fn twep_app_free(_ptr: u32, _len: u32) {}

const TARGET_COMMAND_KEY: &[u8] = b"target_command";
const RESOLVER_MODE_KEY: &[u8] = b"resolver_mode";
const ATTESTAM_URL_KEY: &[u8] = b"attestam_url";
const COMMAND_KEY: &[u8] = b"command";

#[no_mangle]
pub extern "C" fn twep_app_main(input_ptr: u32, input_len: u32, out_desc_ptr: u32) -> i32 {
    if input_ptr == 0 || input_len == 0 || out_desc_ptr == 0 {
        return 2;
    }
    let input = unsafe { core::slice::from_raw_parts(input_ptr as *const u8, input_len as usize) };
    let input_value = match cbor::value(input) {
        Some(value) => value,
        None => return 2,
    };
    if let Some(command) = cbor::text_field(&input_value, COMMAND_KEY) {
        if command == b"hostcall_http_probe" {
            let attestam_url = cbor::text_field(&input_value, ATTESTAM_URL_KEY)
                .unwrap_or(b"https://ta.example.invalid/tam");
            let mut out = [0u8; 128];
            let (status, _out_len) = host_io::http_post(attestam_url, b"", &mut out);
            return if status == 0 {
                write_output(out_desc_ptr, &ok_output())
            } else {
                127
            };
        }
        if command == b"hostcall_evidence_probe" {
            let challenge = [0x10u8, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17];
            let agent_public_key_cose = [0xa1u8, 0x61, b'k', 0x63, b'd', b'e', b'v'];
            let mut out = [0u8; 128];
            return match host_io::create_evidence(&challenge, &agent_public_key_cose, &mut out) {
                Ok(_) => write_output(out_desc_ptr, &ok_output()),
                Err(_) => 127,
            };
        }
        if command == b"hostcall_acceptance_probe_1"
            || command == b"hostcall_acceptance_probe_2"
            || command == b"hostcall_acceptance_probe_3"
            || command == b"hostcall_acceptance_probe_stale"
        {
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
            return match host_io::commit_acceptance(
                &sha256(body),
                b"\x82\x4btwep-app-v1\x4bremotehello",
                sequence,
                expected_generation,
            ) {
                Ok(new_generation) if new_generation == generation + 1 => {
                    write_output(out_desc_ptr, &ok_output())
                }
                _ => 127,
            };
        }
        if command == b"hostcall_bad_read_probe" {
            return match host_io::read_file_len(b"../catalog/catalog.cbor") {
                Ok(None) | Err(_) => write_output(
                    out_desc_ptr,
                    &error_output(b"hostcall.bad_object_blocked", b"bad read object blocked"),
                ),
                Ok(Some(_)) => 127,
            };
        }
        if command == b"hostcall_bad_write_probe" {
            if !host_io::write_file(b"../tmp/teep-agent-probe", b"probe") {
                return write_output(
                    out_desc_ptr,
                    &error_output(b"hostcall.bad_object_blocked", b"bad write object blocked"),
                );
            }
            return 127;
        }
        if command == b"hostcall_verified_result_write_probe" {
            if !host_io::write_file(crate::evidence::VERIFIED_EVIDENCE_RESULT_PATH, b"probe") {
                return write_output(
                    out_desc_ptr,
                    &error_output(
                        b"hostcall.bad_object_blocked",
                        b"generic acceptance result write blocked",
                    ),
                );
            }
            return 127;
        }
        if command == b"hostcall_acceptance_result_stale_probe" {
            return if verified::protected_evidence_result_is_stale() {
                write_output(
                    out_desc_ptr,
                    &error_output(
                        b"hostcall.acceptance_result_stale",
                        b"stale acceptance result rejected",
                    ),
                )
            } else {
                127
            };
        }
    }
    let target_command = match cbor::text_field(&input_value, TARGET_COMMAND_KEY) {
        Some(value) if !value.is_empty() => value,
        _ => return 2,
    };
    let requested_component_id = match twep_app_component_id(target_command) {
        Some(value) => value,
        None => return 2,
    };
    let resolver_mode = cbor::text_field(&input_value, RESOLVER_MODE_KEY).unwrap_or_default();
    if resolver_mode == b"attestam-verified" {
        let attestam_url = cbor::text_field(&input_value, ATTESTAM_URL_KEY).unwrap_or_default();
        if !attestam_url.is_empty() && verified::trustzone_live_poc_acceptance_supported() {
            let live_requested_component_id = match twep_catalog_component_id(b"default") {
                Some(value) => value,
                None => return 4,
            };
            return session::run_verified_poc_acceptance(
                out_desc_ptr,
                attestam_url,
                &live_requested_component_id,
            );
        }
        return verified::run_verified_dry_run(out_desc_ptr, &requested_component_id);
    }
    let attestam_url = cbor::text_field(&input_value, ATTESTAM_URL_KEY).unwrap_or_default();
    session::run_resolve_app(
        out_desc_ptr,
        target_command,
        &requested_component_id,
        attestam_url,
    )
}

pub(crate) fn write_output(out_desc_ptr: u32, output: &[u8]) -> i32 {
    let out_ptr = twep_app_alloc(output.len() as u32);
    if out_ptr == 0 {
        return 4;
    }
    unsafe {
        ptr::copy_nonoverlapping(output.as_ptr(), out_ptr as *mut u8, output.len());
        let desc = out_desc_ptr as *mut u8;
        ptr::copy_nonoverlapping(&out_ptr.to_le_bytes() as *const u8, desc, 4);
        ptr::copy_nonoverlapping(
            &(output.len() as u32).to_le_bytes() as *const u8,
            desc.add(4),
            4,
        );
    }
    0
}

pub(crate) fn sha256(input: &[u8]) -> [u8; 32] {
    Sha256::digest(input).into()
}

pub(crate) fn error_output(code: &[u8], message: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let _ = cbor::write_map(&mut out, 3);
    let _ = cbor::write_text(&mut out, b"schema_version");
    let _ = cbor::write_uint(&mut out, 1);
    let _ = cbor::write_text(&mut out, b"status");
    let _ = cbor::write_text(&mut out, b"error");
    let _ = cbor::write_text(&mut out, b"error");
    let _ = cbor::write_map(&mut out, 2);
    let _ = cbor::write_text(&mut out, b"code");
    let _ = cbor::write_text(&mut out, code);
    let _ = cbor::write_text(&mut out, b"message");
    let _ = cbor::write_text(&mut out, message);
    out
}

pub(crate) fn ok_output() -> Vec<u8> {
    let mut out = Vec::new();
    let _ = cbor::write_map(&mut out, 2);
    let _ = cbor::write_text(&mut out, b"schema_version");
    let _ = cbor::write_uint(&mut out, 1);
    let _ = cbor::write_text(&mut out, b"status");
    let _ = cbor::write_text(&mut out, b"ok");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cbor_text_field_reads_resolver_mode() {
        let mut input = Vec::new();
        cbor::write_map(&mut input, 2).unwrap();
        cbor::write_text(&mut input, TARGET_COMMAND_KEY).unwrap();
        cbor::write_text(&mut input, b"remotehello").unwrap();
        cbor::write_text(&mut input, RESOLVER_MODE_KEY).unwrap();
        cbor::write_text(&mut input, b"attestam-verified").unwrap();
        let input = cbor::value(&input).expect("request CBOR");

        assert_eq!(
            cbor::text_field(&input, RESOLVER_MODE_KEY),
            Some(b"attestam-verified".as_slice())
        );
    }

    #[test]
    fn cbor_text_field_reads_command() {
        let mut input = Vec::new();
        cbor::write_map(&mut input, 1).unwrap();
        cbor::write_text(&mut input, COMMAND_KEY).unwrap();
        cbor::write_text(&mut input, b"hostcall_http_probe").unwrap();
        let input = cbor::value(&input).expect("request CBOR");

        assert_eq!(
            cbor::text_field(&input, COMMAND_KEY),
            Some(b"hostcall_http_probe".as_slice())
        );
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    loop {}
}
