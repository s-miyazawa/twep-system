// Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause
#[link(wasm_import_module = "twep_teep_env")]
extern "C" {
    fn twep_host_log(level: u32, msg_ptr: u32, msg_len: u32);
    fn twep_host_read_file(
        path_ptr: u32,
        path_len: u32,
        buf_ptr: u32,
        buf_cap: u32,
        out_len_ptr: u32,
    ) -> i32;
    fn twep_host_write_file(path_ptr: u32, path_len: u32, data_ptr: u32, data_len: u32) -> i32;
    fn twep_host_read_protected(
        object_name_ptr: u32,
        object_name_len: u32,
        buf_ptr: u32,
        buf_cap: u32,
        out_len_ptr: u32,
    ) -> i32;
    fn twep_host_http_post(
        url_ptr: u32,
        url_len: u32,
        body_ptr: u32,
        body_len: u32,
        buf_ptr: u32,
        buf_cap: u32,
        out_len_ptr: u32,
    ) -> i32;
    fn twep_host_create_evidence(
        challenge_ptr: u32,
        challenge_len: u32,
        agent_public_key_cose_ptr: u32,
        agent_public_key_cose_len: u32,
        buf_ptr: u32,
        buf_cap: u32,
        out_len_ptr: u32,
    ) -> i32;
    fn twep_host_platform_status(buf_ptr: u32, buf_cap: u32, out_len_ptr: u32) -> i32;
    fn twep_host_teep_agent_measurement_sha256(buf_ptr: u32, buf_cap: u32, out_len_ptr: u32)
        -> i32;
    fn twep_host_acceptance_generation(generation_ptr: u32) -> i32;
    #[allow(dead_code)]
    fn twep_host_commit_acceptance(
        digest_ptr: u32,
        digest_len: u32,
        component_id_ptr: u32,
        component_id_len: u32,
        sequence: u64,
        expected_generation: u64,
        new_generation_ptr: u32,
    ) -> i32;
    #[cfg(not(feature = "m9-1-acceptance-only-smoke"))]
    fn twep_host_commit_catalog(
        digest_ptr: u32,
        digest_len: u32,
        component_id_ptr: u32,
        component_id_len: u32,
        sequence: u64,
        expected_generation: u64,
        catalog_ptr: u32,
        catalog_len: u32,
        catalog_sha256_ptr: u32,
        catalog_sha256_len: u32,
        new_generation_ptr: u32,
    ) -> i32;
    #[cfg(not(feature = "m9-1-acceptance-only-smoke"))]
    fn twep_host_commit_app(
        digest_ptr: u32,
        digest_len: u32,
        component_id_ptr: u32,
        component_id_len: u32,
        sequence: u64,
        expected_generation: u64,
        wasm_ptr: u32,
        wasm_len: u32,
        wasm_sha256_ptr: u32,
        wasm_sha256_len: u32,
        new_generation_ptr: u32,
    ) -> i32;
    fn twep_host_random(buf_ptr: u32, buf_len: u32) -> i32;
    fn twep_host_unix_time_ms() -> u64;
}

pub(crate) fn log(level: u32, msg: &[u8]) {
    unsafe {
        twep_host_log(level, msg.as_ptr() as u32, msg.len() as u32);
    }
}

pub(crate) fn read_file_len(path: &[u8]) -> Result<Option<u32>, i32> {
    let mut out_len = 0u32;
    let status = unsafe {
        twep_host_read_file(
            path.as_ptr() as u32,
            path.len() as u32,
            0,
            0,
            &mut out_len as *mut u32 as u32,
        )
    };
    if status == 3 {
        Ok(None)
    } else if status == 0 || status == 2 {
        Ok(Some(out_len))
    } else {
        Err(status)
    }
}

pub(crate) fn read_file(path: &[u8], buf: &mut [u8]) -> Result<usize, i32> {
    let mut out_len = buf.len() as u32;
    let status = unsafe {
        twep_host_read_file(
            path.as_ptr() as u32,
            path.len() as u32,
            buf.as_mut_ptr() as u32,
            buf.len() as u32,
            &mut out_len as *mut u32 as u32,
        )
    };
    if status == 0 && out_len as usize <= buf.len() {
        Ok(out_len as usize)
    } else {
        Err(status)
    }
}

pub(crate) fn read_file_alloc(path: &[u8], max_len: u32) -> Option<alloc::vec::Vec<u8>> {
    let out_len = match read_file_len(path).ok()? {
        Some(value) if value > 0 && value <= max_len => value,
        _ => return None,
    };
    let ptr = crate::twep_app_alloc(out_len);
    if ptr == 0 {
        return None;
    }
    let buf = unsafe { core::slice::from_raw_parts_mut(ptr as *mut u8, out_len as usize) };
    let read_len = read_file(path, buf).ok()?;
    Some(buf[..read_len].to_vec())
}

pub(crate) fn write_file(path: &[u8], contents: &[u8]) -> bool {
    unsafe {
        twep_host_write_file(
            path.as_ptr() as u32,
            path.len() as u32,
            contents.as_ptr() as u32,
            contents.len() as u32,
        ) == 0
    }
}

pub(crate) fn read_protected_len(object_name: &[u8]) -> Result<Option<u32>, i32> {
    let mut out_len = 0u32;
    let status = unsafe {
        twep_host_read_protected(
            object_name.as_ptr() as u32,
            object_name.len() as u32,
            0,
            0,
            &mut out_len as *mut u32 as u32,
        )
    };
    if status == 3 || status == 8 {
        Ok(None)
    } else if status == 0 || status == 2 {
        Ok(Some(out_len))
    } else {
        Err(status)
    }
}

pub(crate) fn read_protected(object_name: &[u8], buf: &mut [u8]) -> Result<usize, i32> {
    let mut out_len = buf.len() as u32;
    let status = unsafe {
        twep_host_read_protected(
            object_name.as_ptr() as u32,
            object_name.len() as u32,
            buf.as_mut_ptr() as u32,
            buf.len() as u32,
            &mut out_len as *mut u32 as u32,
        )
    };
    if status == 0 && out_len as usize <= buf.len() {
        Ok(out_len as usize)
    } else {
        Err(status)
    }
}

pub(crate) fn read_protected_alloc(
    object_name: &[u8],
    max_len: u32,
) -> Option<alloc::vec::Vec<u8>> {
    let out_len = match read_protected_len(object_name).ok()? {
        Some(value) if value > 0 && value <= max_len => value,
        _ => return None,
    };
    let ptr = crate::twep_app_alloc(out_len);
    if ptr == 0 {
        return None;
    }
    let buf = unsafe { core::slice::from_raw_parts_mut(ptr as *mut u8, out_len as usize) };
    let read_len = read_protected(object_name, buf).ok()?;
    Some(buf[..read_len].to_vec())
}

pub(crate) fn http_post(url: &[u8], body: &[u8], buf: &mut [u8]) -> (i32, u32) {
    let mut out_len = 0u32;
    let status = unsafe {
        twep_host_http_post(
            url.as_ptr() as u32,
            url.len() as u32,
            body.as_ptr() as u32,
            body.len() as u32,
            buf.as_mut_ptr() as u32,
            buf.len() as u32,
            &mut out_len as *mut u32 as u32,
        )
    };
    (status, out_len)
}

pub(crate) fn create_evidence(
    challenge: &[u8],
    agent_public_key: &[u8],
    out: &mut [u8],
) -> Result<usize, (i32, usize)> {
    let mut out_len = 0u32;
    let status = unsafe {
        twep_host_create_evidence(
            challenge.as_ptr() as u32,
            challenge.len() as u32,
            agent_public_key.as_ptr() as u32,
            agent_public_key.len() as u32,
            out.as_mut_ptr() as u32,
            out.len() as u32,
            &mut out_len as *mut u32 as u32,
        )
    };
    if status == 0 {
        Ok(out_len as usize)
    } else {
        Err((status, out_len as usize))
    }
}

pub(crate) fn platform_status(buf: &mut [u8]) -> Result<usize, i32> {
    let mut out_len = 0u32;
    let status = unsafe {
        twep_host_platform_status(
            buf.as_mut_ptr() as u32,
            buf.len() as u32,
            &mut out_len as *mut u32 as u32,
        )
    };
    if status == 0 && out_len as usize <= buf.len() {
        Ok(out_len as usize)
    } else {
        Err(status)
    }
}

pub(crate) fn teep_agent_measurement_sha256() -> Result<Option<[u8; 32]>, i32> {
    let mut out = [0u8; 32];
    let mut out_len = 0u32;
    let status = unsafe {
        twep_host_teep_agent_measurement_sha256(
            out.as_mut_ptr() as u32,
            out.len() as u32,
            &mut out_len as *mut u32 as u32,
        )
    };
    if status == 8 {
        Ok(None)
    } else if status == 0 && out_len == out.len() as u32 {
        Ok(Some(out))
    } else {
        Err(status)
    }
}

pub(crate) fn acceptance_generation() -> Result<u64, i32> {
    let mut generation = 0u64;
    let status = unsafe { twep_host_acceptance_generation(&mut generation as *mut u64 as u32) };
    if status == 0 {
        Ok(generation)
    } else {
        Err(status)
    }
}

#[allow(dead_code)]
pub(crate) fn commit_acceptance(
    digest: &[u8; 32],
    component_id: &[u8],
    sequence: u64,
    expected_generation: u64,
) -> Result<u64, i32> {
    let mut generation = 0u64;
    let status = unsafe {
        twep_host_commit_acceptance(
            digest.as_ptr() as u32,
            digest.len() as u32,
            component_id.as_ptr() as u32,
            component_id.len() as u32,
            sequence,
            expected_generation,
            &mut generation as *mut u64 as u32,
        )
    };
    if status == 0 {
        Ok(generation)
    } else {
        Err(status)
    }
}

#[cfg(not(feature = "m9-1-acceptance-only-smoke"))]
pub(crate) fn commit_catalog(
    digest: &[u8; 32],
    component_id: &[u8],
    sequence: u64,
    expected_generation: u64,
    catalog: &[u8],
    catalog_sha256: &[u8; 32],
) -> Result<u64, i32> {
    let mut generation = 0u64;
    let status = unsafe {
        twep_host_commit_catalog(
            digest.as_ptr() as u32,
            digest.len() as u32,
            component_id.as_ptr() as u32,
            component_id.len() as u32,
            sequence,
            expected_generation,
            catalog.as_ptr() as u32,
            catalog.len() as u32,
            catalog_sha256.as_ptr() as u32,
            catalog_sha256.len() as u32,
            &mut generation as *mut u64 as u32,
        )
    };
    if status == 0 {
        Ok(generation)
    } else {
        Err(status)
    }
}

#[cfg(not(feature = "m9-1-acceptance-only-smoke"))]
pub(crate) fn commit_app(
    digest: &[u8; 32],
    component_id: &[u8],
    sequence: u64,
    expected_generation: u64,
    wasm: &[u8],
    wasm_sha256: &[u8; 32],
) -> Result<u64, i32> {
    let mut generation = 0u64;
    let status = unsafe {
        twep_host_commit_app(
            digest.as_ptr() as u32,
            digest.len() as u32,
            component_id.as_ptr() as u32,
            component_id.len() as u32,
            sequence,
            expected_generation,
            wasm.as_ptr() as u32,
            wasm.len() as u32,
            wasm_sha256.as_ptr() as u32,
            wasm_sha256.len() as u32,
            &mut generation as *mut u64 as u32,
        )
    };
    if status == 0 {
        Ok(generation)
    } else {
        Err(status)
    }
}

pub(crate) fn random(buf: &mut [u8]) -> bool {
    unsafe { twep_host_random(buf.as_mut_ptr() as u32, buf.len() as u32) == 0 }
}

pub(crate) fn unix_time_ms() -> u64 {
    unsafe { twep_host_unix_time_ms() }
}
