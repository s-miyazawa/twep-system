#![cfg_attr(not(test), no_std)]
// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause

extern crate alloc;

#[cfg(not(test))]
use core::alloc::{GlobalAlloc, Layout};
#[cfg(not(test))]
use core::panic::PanicInfo;
use core::ptr;
#[cfg(not(test))]
use core::ptr::addr_of_mut;
#[cfg(not(test))]
use core::sync::atomic::{AtomicUsize, Ordering};

#[cfg(not(test))]
struct BumpAllocator;

#[cfg(not(test))]
const HEAP_SIZE: usize = 64 * 1024;

#[cfg(not(test))]
#[repr(align(16))]
struct Heap([u8; HEAP_SIZE]);

#[cfg(not(test))]
static mut HEAP: Heap = Heap([0; HEAP_SIZE]);
#[cfg(not(test))]
static NEXT: AtomicUsize = AtomicUsize::new(0);

#[cfg(not(test))]
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

#[cfg(not(test))]
#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator;

#[no_mangle]
pub extern "C" fn twep_app_abi_version() -> u32 {
    1
}

#[no_mangle]
#[cfg(not(test))]
pub extern "C" fn twep_app_alloc(len: u32) -> u32 {
    let layout = match Layout::from_size_align(len as usize, 1) {
        Ok(layout) => layout,
        Err(_) => return 0,
    };
    unsafe { ALLOCATOR.alloc(layout) as u32 }
}

#[no_mangle]
#[cfg(test)]
pub extern "C" fn twep_app_alloc(_len: u32) -> u32 {
    0
}

#[no_mangle]
pub extern "C" fn twep_app_free(_ptr: u32, _len: u32) {}

#[no_mangle]
pub extern "C" fn twep_app_main(input_ptr: u32, input_len: u32, out_desc_ptr: u32) -> i32 {
    if input_ptr == 0 || input_len == 0 || out_desc_ptr == 0 {
        return 1;
    }
    let input = unsafe { core::slice::from_raw_parts(input_ptr as *const u8, input_len as usize) };
    let sum = match sum_inferred_params(input) {
        Some(v) => v,
        None => return 2,
    };
    let mut out = [0u8; 96];
    let out_len = match encode_output(sum, &mut out) {
        Some(v) => v,
        None => return 3,
    };
    let out_ptr = twep_app_alloc(out_len as u32);
    if out_ptr == 0 {
        return 4;
    }
    unsafe {
        ptr::copy_nonoverlapping(out.as_ptr(), out_ptr as *mut u8, out_len);
        let desc = out_desc_ptr as *mut u8;
        ptr::copy_nonoverlapping(&out_ptr.to_le_bytes() as *const u8, desc, 4);
        ptr::copy_nonoverlapping(&(out_len as u32).to_le_bytes() as *const u8, desc.add(4), 4);
    }
    0
}

fn sum_inferred_params(input: &[u8]) -> Option<i64> {
    let params = read_map_field(input, b"inferred_params")?;
    let mut p = 0usize;
    let n = read_array_len(params, &mut p)?;
    let mut sum = 0i64;
    let mut count = 0usize;
    for _ in 0..n {
        let end = skip_value(params, p)?;
        let item = &params[p..end];
        p = end;
        let typ = read_map_text_field(item, b"type")?;
        if typ != b"int" && typ != b"uint" {
            continue;
        }
        let value = read_map_int_field(item, b"value")?;
        sum = sum.checked_add(value)?;
        count += 1;
    }
    if count == 0 {
        return None;
    }
    Some(sum)
}

fn encode_output(sum: i64, out: &mut [u8]) -> Option<usize> {
    let mut text = [0u8; 32];
    let text_len = write_decimal(sum, &mut text)?;
    let mut p = 0usize;
    put(out, &mut p, 0xa4)?;
    put_text(out, &mut p, b"schema_version")?;
    put(out, &mut p, 0x01)?;
    put_text(out, &mut p, b"status")?;
    put_text(out, &mut p, b"ok")?;
    put_text(out, &mut p, b"stdout")?;
    put_bytes(out, &mut p, &text[..text_len])?;
    put_text(out, &mut p, b"result")?;
    put(out, &mut p, 0xa1)?;
    put_text(out, &mut p, b"sum")?;
    put_i64(out, &mut p, sum)?;
    Some(p)
}

fn read_map_field<'a>(input: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    let mut p = 0usize;
    let pairs = read_map_len(input, &mut p)?;
    for _ in 0..pairs {
        let map_key = read_text(input, &mut p)?;
        let value_start = p;
        let value_end = skip_value(input, p)?;
        if map_key == key {
            return input.get(value_start..value_end);
        }
        p = value_end;
    }
    None
}

fn read_map_text_field<'a>(input: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    let value = read_map_field(input, key)?;
    let mut p = 0usize;
    let text = read_text(value, &mut p)?;
    if p == value.len() {
        Some(text)
    } else {
        None
    }
}

fn read_map_int_field(input: &[u8], key: &[u8]) -> Option<i64> {
    let value = read_map_field(input, key)?;
    let mut p = 0usize;
    let n = read_int(value, &mut p)?;
    if p == value.len() {
        Some(n)
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

fn read_array_len(input: &[u8], p: &mut usize) -> Option<usize> {
    let head = *input.get(*p)?;
    *p += 1;
    if head >> 5 != 4 {
        return None;
    }
    Some(read_len(input, p, head & 0x1f)? as usize)
}

fn read_map_len(input: &[u8], p: &mut usize) -> Option<usize> {
    let head = *input.get(*p)?;
    *p += 1;
    if head >> 5 != 5 {
        return None;
    }
    Some(read_len(input, p, head & 0x1f)? as usize)
}

fn read_int(input: &[u8], p: &mut usize) -> Option<i64> {
    let head = *input.get(*p)?;
    *p += 1;
    let major = head >> 5;
    let n = read_len(input, p, head & 0x1f)?;
    match major {
        0 => i64::try_from(n).ok(),
        1 => i64::try_from(n).ok().map(|v| -1 - v),
        _ => None,
    }
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

fn skip_value(input: &[u8], mut p: usize) -> Option<usize> {
    let head = *input.get(p)?;
    p += 1;
    let major = head >> 5;
    let n = read_len(input, &mut p, head & 0x1f)? as usize;
    match major {
        0 | 1 | 7 => Some(p),
        2 | 3 => p.checked_add(n).filter(|end| *end <= input.len()),
        4 => {
            let mut end = p;
            for _ in 0..n {
                end = skip_value(input, end)?;
            }
            Some(end)
        }
        5 => {
            let mut end = p;
            for _ in 0..n {
                end = skip_value(input, end)?;
                end = skip_value(input, end)?;
            }
            Some(end)
        }
        _ => None,
    }
}

fn write_decimal(v: i64, out: &mut [u8]) -> Option<usize> {
    if v == 0 {
        *out.get_mut(0)? = b'0';
        *out.get_mut(1)? = b'\n';
        return Some(2);
    }
    let negative = v < 0;
    let mut n = if negative {
        v.checked_neg()? as u64
    } else {
        v as u64
    };
    let mut tmp = [0u8; 20];
    let mut len = 0usize;
    while n != 0 {
        tmp[len] = b'0' + (n % 10) as u8;
        n /= 10;
        len += 1;
    }
    let mut p = 0usize;
    if negative {
        *out.get_mut(p)? = b'-';
        p += 1;
    }
    while len != 0 {
        len -= 1;
        *out.get_mut(p)? = tmp[len];
        p += 1;
    }
    *out.get_mut(p)? = b'\n';
    Some(p + 1)
}

fn put(out: &mut [u8], p: &mut usize, b: u8) -> Option<()> {
    *out.get_mut(*p)? = b;
    *p += 1;
    Some(())
}

fn put_text(out: &mut [u8], p: &mut usize, s: &[u8]) -> Option<()> {
    if s.len() > 23 {
        return None;
    }
    put(out, p, 0x60 | s.len() as u8)?;
    let end = p.checked_add(s.len())?;
    out.get_mut(*p..end)?.copy_from_slice(s);
    *p = end;
    Some(())
}

fn put_bytes(out: &mut [u8], p: &mut usize, b: &[u8]) -> Option<()> {
    if b.len() > 23 {
        return None;
    }
    put(out, p, 0x40 | b.len() as u8)?;
    let end = p.checked_add(b.len())?;
    out.get_mut(*p..end)?.copy_from_slice(b);
    *p = end;
    Some(())
}

fn put_i64(out: &mut [u8], p: &mut usize, v: i64) -> Option<()> {
    if v >= 0 {
        put_uint(out, p, 0, v as u64)
    } else {
        put_uint(out, p, 1, (-1 - v) as u64)
    }
}

fn put_uint(out: &mut [u8], p: &mut usize, major: u8, v: u64) -> Option<()> {
    let prefix = major << 5;
    if v <= 23 {
        put(out, p, prefix | v as u8)
    } else if v <= u8::MAX as u64 {
        put(out, p, prefix | 24)?;
        put(out, p, v as u8)
    } else if v <= u16::MAX as u64 {
        put(out, p, prefix | 25)?;
        let bytes = (v as u16).to_be_bytes();
        put(out, p, bytes[0])?;
        put(out, p, bytes[1])
    } else if v <= u32::MAX as u64 {
        put(out, p, prefix | 26)?;
        let bytes = (v as u32).to_be_bytes();
        for byte in bytes {
            put(out, p, byte)?;
        }
        Some(())
    } else {
        put(out, p, prefix | 27)?;
        for byte in v.to_be_bytes() {
            put(out, p, byte)?;
        }
        Some(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_encodes_sum_above_small_int_range() {
        let mut out = [0u8; 96];
        assert!(encode_output(25, &mut out).is_some());
    }

    #[test]
    fn output_encodes_negative_sum_below_small_int_range() {
        let mut out = [0u8; 96];
        assert!(encode_output(-25, &mut out).is_some());
    }

    #[test]
    fn sum_reads_only_top_level_inferred_params() {
        let mut input = [0u8; 160];
        let mut p = 0usize;
        put(&mut input, &mut p, 0xa2).unwrap();
        put_text(&mut input, &mut p, b"metadata").unwrap();
        put(&mut input, &mut p, 0xa1).unwrap();
        put_text(&mut input, &mut p, b"inferred_params").unwrap();
        put(&mut input, &mut p, 0x81).unwrap();
        put(&mut input, &mut p, 0xa2).unwrap();
        put_text(&mut input, &mut p, b"type").unwrap();
        put_text(&mut input, &mut p, b"int").unwrap();
        put_text(&mut input, &mut p, b"value").unwrap();
        put_uint(&mut input, &mut p, 0, 99).unwrap();
        put_text(&mut input, &mut p, b"inferred_params").unwrap();
        put(&mut input, &mut p, 0x82).unwrap();
        put(&mut input, &mut p, 0xa2).unwrap();
        put_text(&mut input, &mut p, b"type").unwrap();
        put_text(&mut input, &mut p, b"int").unwrap();
        put_text(&mut input, &mut p, b"value").unwrap();
        put(&mut input, &mut p, 0x01).unwrap();
        put(&mut input, &mut p, 0xa2).unwrap();
        put_text(&mut input, &mut p, b"type").unwrap();
        put_text(&mut input, &mut p, b"uint").unwrap();
        put_text(&mut input, &mut p, b"value").unwrap();
        put(&mut input, &mut p, 0x02).unwrap();

        assert_eq!(sum_inferred_params(&input[..p]), Some(3));
    }

    #[test]
    fn sum_ignores_key_bytes_inside_byte_string() {
        let mut input = [0u8; 160];
        let mut p = 0usize;
        put(&mut input, &mut p, 0xa2).unwrap();
        put_text(&mut input, &mut p, b"metadata").unwrap();
        put(&mut input, &mut p, 0xa1).unwrap();
        put_text(&mut input, &mut p, b"blob").unwrap();
        put_bytes(&mut input, &mut p, b"inferred_params").unwrap();
        put_text(&mut input, &mut p, b"inferred_params").unwrap();
        put(&mut input, &mut p, 0x81).unwrap();
        put(&mut input, &mut p, 0xa2).unwrap();
        put_text(&mut input, &mut p, b"type").unwrap();
        put_text(&mut input, &mut p, b"int").unwrap();
        put_text(&mut input, &mut p, b"value").unwrap();
        put(&mut input, &mut p, 0x04).unwrap();

        assert_eq!(sum_inferred_params(&input[..p]), Some(4));
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    loop {}
}
