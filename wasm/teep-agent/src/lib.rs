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
#[cfg(any(not(feature = "m9-1-acceptance-only-smoke"), test))]
mod catalog_validator;
mod cbor;
mod cose;
mod credential_management;
mod evidence;
mod freshness;
mod host_io;
mod probes;
mod protected_credentials;
mod session;
mod suit;
mod teep;
mod verified;
mod wasm_signature;

use suit::twep_app_component_id;

struct BumpAllocator;

#[cfg(all(not(test), feature = "heap-512k-diagnostic"))]
const HEAP_SIZE: usize = 512 * 1024;
#[cfg(any(test, not(feature = "heap-512k-diagnostic")))]
const HEAP_SIZE: usize = 2 * 1024 * 1024;

#[repr(align(16))]
struct Heap([u8; HEAP_SIZE]);

static mut HEAP: Heap = Heap([0; HEAP_SIZE]);
static NEXT: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "sgx-test-hooks")]
static PEAK: AtomicUsize = AtomicUsize::new(0);

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
                Ok(_) => {
                    #[cfg(feature = "sgx-test-hooks")]
                    PEAK.fetch_max(next, Ordering::Relaxed);
                    return addr_of_mut!(HEAP.0).cast::<u8>().add(aligned);
                }
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

/// Private test-hook observation; absent from production Wasm artifacts.
#[cfg(feature = "sgx-test-hooks")]
#[no_mangle]
pub extern "C" fn twep_test_heap_peak_bytes() -> u32 {
    PEAK.load(Ordering::Relaxed) as u32
}

const TARGET_COMMAND_KEY: &[u8] = b"target_command";
const RESOLVER_MODE_KEY: &[u8] = b"resolver_mode";
const ATTESTAM_URL_KEY: &[u8] = b"attestam_url";
#[cfg(test)]
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
    if let Some(status) = probes::dispatch(&input_value, out_desc_ptr) {
        return status;
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
        if !attestam_url.is_empty() && verified::optee_live_poc_acceptance_supported() {
            return session::run_verified_poc_resolve(
                out_desc_ptr,
                target_command,
                attestam_url,
                requested_component_id.as_ref(),
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
    #[cfg(target_arch = "wasm32")]
    core::arch::wasm32::unreachable();
    #[cfg(not(target_arch = "wasm32"))]
    loop {}
}
