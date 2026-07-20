#![no_std]
// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause

extern crate alloc;

use core::alloc::{GlobalAlloc, Layout};
#[cfg(not(test))]
use core::panic::PanicInfo;
use core::ptr::{self, addr_of_mut};
use core::sync::atomic::{AtomicUsize, Ordering};

struct BumpAllocator;

const HEAP_SIZE: usize = 64 * 1024;

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

const OUTPUT: &[u8] = &[
    0xa3, 0x66, b's', b't', b'a', b't', b'u', b's', 0x62, b'o', b'k', 0x66, b's', b't', b'd', b'o',
    b'u', b't', 0x4f, b'H', b'e', b'l', b'l', b'o', b',', b' ', b'W', b'o', b'r', b'l', b'd', b'!',
    b'!', b'\n', 0x6e, b's', b'c', b'h', b'e', b'm', b'a', b'_', b'v', b'e', b'r', b's', b'i',
    b'o', b'n', 0x01,
];

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
pub extern "C" fn twep_app_main(_input_ptr: u32, _input_len: u32, out_desc_ptr: u32) -> i32 {
    if out_desc_ptr == 0 {
        return 2;
    }
    let out_ptr = twep_app_alloc(OUTPUT.len() as u32);
    if out_ptr == 0 {
        return 4;
    }
    unsafe {
        ptr::copy_nonoverlapping(OUTPUT.as_ptr(), out_ptr as *mut u8, OUTPUT.len());
        let desc = out_desc_ptr as *mut u8;
        ptr::copy_nonoverlapping(&out_ptr.to_le_bytes() as *const u8, desc, 4);
        ptr::copy_nonoverlapping(
            &(OUTPUT.len() as u32).to_le_bytes() as *const u8,
            desc.add(4),
            4,
        );
    }
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    loop {}
}
