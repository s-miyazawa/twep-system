#![no_std]
// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause

extern crate alloc;

use alloc::vec::Vec;
use core::alloc::{GlobalAlloc, Layout};
#[cfg(not(test))]
use core::panic::PanicInfo;
use core::ptr::{self, addr_of_mut};
use core::sync::atomic::{AtomicUsize, Ordering};

use jpeg_encoder::{ColorType, Encoder};
use zune_jpeg::JpegDecoder;

struct BumpAllocator;

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

#[no_mangle]
pub extern "C" fn twep_app_main(input_ptr: u32, input_len: u32, out_desc_ptr: u32) -> i32 {
    if input_ptr == 0 || input_len == 0 || out_desc_ptr == 0 {
        return 1;
    }
    let input = unsafe { core::slice::from_raw_parts(input_ptr as *const u8, input_len as usize) };
    let jpeg = match read_input_jpeg(input) {
        Some(v) => v,
        None => return 1,
    };
    if !looks_like_jpeg(jpeg) {
        return 6;
    }
    let output_jpeg = match invert_jpeg(jpeg) {
        Some(v) => v,
        None => return 6,
    };
    let output = match encode_app_output(&output_jpeg) {
        Some(v) => v,
        None => return 3,
    };
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

fn read_input_jpeg(input: &[u8]) -> Option<&[u8]> {
    let files = read_map_field(input, b"files")?;
    read_bytes_field(files, b"input")
}

fn looks_like_jpeg(bytes: &[u8]) -> bool {
    bytes.len() >= 4
        && bytes[0] == 0xff
        && bytes[1] == 0xd8
        && bytes[bytes.len() - 2] == 0xff
        && bytes[bytes.len() - 1] == 0xd9
}

fn invert_jpeg(input: &[u8]) -> Option<Vec<u8>> {
    let mut decoder = JpegDecoder::new(input);
    let mut pixels = decoder.decode().ok()?;
    for channel in &mut pixels {
        *channel = 255u8.wrapping_sub(*channel);
    }
    let info = decoder.info()?;
    let mut out = Vec::new();
    let encoder = Encoder::new(&mut out, 90);
    encoder
        .encode(&pixels, info.width, info.height, ColorType::Rgb)
        .ok()?;
    Some(out)
}

fn encode_app_output(jpeg: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    put_map(&mut out, 5);
    put_text(&mut out, b"schema_version");
    put_uint(&mut out, 1);
    put_text(&mut out, b"status");
    put_text(&mut out, b"ok");
    put_text(&mut out, b"files");
    put_map(&mut out, 1);
    put_text(&mut out, b"output");
    put_bytes(&mut out, jpeg);
    put_text(&mut out, b"metadata");
    put_map(&mut out, 1);
    put_text(&mut out, b"output_mime");
    put_text(&mut out, b"image/jpeg");
    put_text(&mut out, b"stdout");
    put_bytes(&mut out, b"Saving a Reversed Color Image\n");
    Some(out)
}

fn read_map_field<'a>(input: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    let mut p = 0usize;
    let pairs = read_map_len(input, &mut p)?;
    for _ in 0..pairs {
        let map_key = read_text(input, &mut p)?;
        let value_start = p;
        skip_value(input, &mut p)?;
        if map_key == key {
            return input.get(value_start..p);
        }
    }
    None
}

fn read_bytes_field<'a>(input: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    let value = read_map_field(input, key)?;
    let mut p = 0usize;
    let bytes = read_bytes(value, &mut p)?;
    if p == value.len() {
        Some(bytes)
    } else {
        None
    }
}

fn read_text<'a>(input: &'a [u8], p: &mut usize) -> Option<&'a [u8]> {
    let head = *input.get(*p)?;
    *p += 1;
    if head >> 5 != 3 {
        return None;
    }
    let len = read_len(input, p, head & 0x1f)? as usize;
    let end = p.checked_add(len)?;
    let value = input.get(*p..end)?;
    *p = end;
    Some(value)
}

fn read_bytes<'a>(input: &'a [u8], p: &mut usize) -> Option<&'a [u8]> {
    let head = *input.get(*p)?;
    *p += 1;
    if head >> 5 != 2 {
        return None;
    }
    let len = read_len(input, p, head & 0x1f)? as usize;
    let end = p.checked_add(len)?;
    let value = input.get(*p..end)?;
    *p = end;
    Some(value)
}

fn read_map_len(input: &[u8], p: &mut usize) -> Option<usize> {
    let head = *input.get(*p)?;
    *p += 1;
    if head >> 5 != 5 {
        return None;
    }
    Some(read_len(input, p, head & 0x1f)? as usize)
}

fn read_len(input: &[u8], p: &mut usize, add: u8) -> Option<u64> {
    match add {
        0..=23 => Some(add as u64),
        24 => {
            let b = *input.get(*p)?;
            *p += 1;
            Some(b as u64)
        }
        25 => {
            let b = input.get(*p..p.checked_add(2)?)?;
            *p += 2;
            Some(u16::from_be_bytes([b[0], b[1]]) as u64)
        }
        26 => {
            let b = input.get(*p..p.checked_add(4)?)?;
            *p += 4;
            Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64)
        }
        27 => {
            let b = input.get(*p..p.checked_add(8)?)?;
            *p += 8;
            Some(u64::from_be_bytes([
                b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
            ]))
        }
        _ => None,
    }
}

fn skip_value(input: &[u8], p: &mut usize) -> Option<()> {
    let head = *input.get(*p)?;
    *p += 1;
    let major = head >> 5;
    let n = read_len(input, p, head & 0x1f)? as usize;
    match major {
        0 | 1 | 7 => Some(()),
        2 | 3 => {
            *p = p.checked_add(n)?;
            if *p <= input.len() {
                Some(())
            } else {
                None
            }
        }
        4 => {
            for _ in 0..n {
                skip_value(input, p)?;
            }
            Some(())
        }
        5 => {
            for _ in 0..n {
                skip_value(input, p)?;
                skip_value(input, p)?;
            }
            Some(())
        }
        _ => None,
    }
}

fn put_map(out: &mut Vec<u8>, n: u64) {
    put_type_len(out, 5, n);
}

fn put_uint(out: &mut Vec<u8>, n: u64) {
    put_type_len(out, 0, n);
}

fn put_text(out: &mut Vec<u8>, s: &[u8]) {
    put_type_len(out, 3, s.len() as u64);
    out.extend_from_slice(s);
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    put_type_len(out, 2, b.len() as u64);
    out.extend_from_slice(b);
}

fn put_type_len(out: &mut Vec<u8>, major: u8, n: u64) {
    let head = major << 5;
    match n {
        0..=23 => out.push(head | n as u8),
        24..=0xff => out.extend_from_slice(&[head | 24, n as u8]),
        0x100..=0xffff => out.extend_from_slice(&[head | 25, (n >> 8) as u8, n as u8]),
        0x1_0000..=0xffff_ffff => {
            out.extend_from_slice(&[
                head | 26,
                (n >> 24) as u8,
                (n >> 16) as u8,
                (n >> 8) as u8,
                n as u8,
            ]);
        }
        _ => {
            out.extend_from_slice(&[
                head | 27,
                (n >> 56) as u8,
                (n >> 48) as u8,
                (n >> 40) as u8,
                (n >> 32) as u8,
                (n >> 24) as u8,
                (n >> 16) as u8,
                (n >> 8) as u8,
                n as u8,
            ]);
        }
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    loop {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_input_jpeg_reads_only_top_level_files() {
        let mut input = Vec::new();
        put_map(&mut input, 2);
        put_text(&mut input, b"metadata");
        put_map(&mut input, 1);
        put_text(&mut input, b"files");
        put_map(&mut input, 1);
        put_text(&mut input, b"input");
        put_bytes(&mut input, b"wrong");
        put_text(&mut input, b"files");
        put_map(&mut input, 1);
        put_text(&mut input, b"input");
        put_bytes(&mut input, b"right");

        assert_eq!(read_input_jpeg(&input), Some(&b"right"[..]));
    }

    #[test]
    fn read_input_jpeg_ignores_key_bytes_inside_byte_string() {
        let mut input = Vec::new();
        put_map(&mut input, 2);
        put_text(&mut input, b"metadata");
        put_map(&mut input, 1);
        put_text(&mut input, b"blob");
        put_bytes(&mut input, b"files input");
        put_text(&mut input, b"files");
        put_map(&mut input, 1);
        put_text(&mut input, b"input");
        put_bytes(&mut input, b"right");

        assert_eq!(read_input_jpeg(&input), Some(&b"right"[..]));
    }
}
