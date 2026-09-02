/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */
#include "sgx_runtime_internal.h"

#include <sgx_tcrypto.h>
#include <string.h>

static const uint8_t app_code_signing_x[32] = {
    0xe5,0xb5,0x8f,0xb0,0x88,0xd3,0xa0,0x75,0xc3,0x22,0xd9,0xc2,0xca,0x0e,0xf4,0xd6,
    0xca,0xdb,0xcc,0x5c,0x30,0x6a,0x5e,0x44,0x01,0x2e,0x65,0x18,0xa4,0xbc,0x2f,0x58,
};
static const uint8_t app_code_signing_y[32] = {
    0x2a,0xb7,0xd2,0x2f,0x7c,0xdb,0x0f,0x36,0xb5,0x83,0x8d,0x39,0xbd,0x89,0xbd,0x8e,
    0x68,0xdc,0x99,0x8c,0x1b,0xf7,0x5b,0x41,0x30,0xef,0xd3,0x67,0x5c,0x1b,0x3d,0x1c,
};
static const uint8_t teep_code_signing_x[32] = {
    0x82,0x82,0x0a,0xb9,0x8d,0x42,0x91,0xc4,0x9d,0x9a,0x3c,0x95,0x07,0x13,0x52,0x1a,
    0xed,0x4e,0xb4,0x7f,0xf0,0xd2,0x3e,0x9c,0xd8,0xd6,0x38,0x8f,0x23,0x09,0x20,0xc9,
};
static const uint8_t teep_code_signing_y[32] = {
    0x9b,0x7f,0xb3,0x3e,0x03,0x5f,0x63,0xb7,0x9e,0x9c,0xcf,0x53,0x64,0x60,0x55,0xb8,
    0x38,0x75,0x18,0xae,0x86,0x65,0xd0,0x2e,0x3f,0x80,0xba,0x60,0x88,0xe4,0xa7,0xa1,
};

static int read_varuint32(const uint8_t *buf, size_t len, size_t *off,
                          uint32_t *out)
{
    uint32_t value = 0, shift = 0;
    size_t i;
    for (i = 0; i < 5; ++i) {
        uint8_t b;
        if (*off >= len) return 0;
        b = buf[(*off)++];
        value |= (uint32_t)(b & 0x7f) << shift;
        if (!(b & 0x80)) { *out = value; return 1; }
        shift += 7;
    }
    return 0;
}

int sgx_wasm_signature_verify(const uint8_t *wasm, size_t wasm_len,
                              enum sgx_wasm_role expected_role)
{
    size_t off = 8, section_start, payload_off, name_len, key_len, value_len;
    uint32_t section_len, encoded_name_len;
    const uint8_t *key, *sig = NULL, *role = NULL, *alg = NULL, *kid = NULL;
    const uint8_t *expected_x, *expected_y;
    const char *expected_role_text, *expected_kid;
    size_t sig_len = 0, role_len = 0, alg_len = 0, kid_len = 0;
    struct sgx_cbor_cursor cur;
    uint64_t pairs, i;
    sgx_ec256_public_t public_key;
    sgx_ec256_signature_t signature;
    sgx_ecc_state_handle_t handle = NULL;
    uint8_t result = SGX_EC_INVALID_SIGNATURE;
    sgx_status_t status;
    if (expected_role == SGX_WASM_ROLE_TEEP_AGENT) {
        expected_x = teep_code_signing_x;
        expected_y = teep_code_signing_y;
        expected_role_text = "teep-agent";
        expected_kid = "twep-demo-teep-agent-code-signing-v1";
    } else {
        expected_x = app_code_signing_x;
        expected_y = app_code_signing_y;
        expected_role_text = "app";
        expected_kid = "twep-demo-app-code-signing-v1";
    }
    if (wasm_len < 8 || memcmp(wasm, "\0asm\1\0\0\0", 8) != 0)
        return 0;
    while (off < wasm_len) {
        uint8_t id;
        section_start = off;
        id = wasm[off++];
        if (!read_varuint32(wasm, wasm_len, &off, &section_len)
            || section_len > wasm_len - off)
            return 0;
        payload_off = off;
        off += section_len;
        if (id != 0)
            continue;
        if (!read_varuint32(wasm, off, &payload_off, &encoded_name_len)
            || encoded_name_len > off - payload_off)
            return 0;
        name_len = encoded_name_len;
        if (name_len != 8 || memcmp(wasm + payload_off, "twep.sig", 8) != 0)
            continue;
        payload_off += name_len;
        if (off != wasm_len)
            return 0;
        cur.buf = wasm + payload_off;
        cur.len = off - payload_off;
        cur.off = 0;
        if (!sgx_cbor_len(&cur, 5, &pairs))
            return 0;
        for (i = 0; i < pairs; ++i) {
            if (!sgx_cbor_view(&cur, 3, &key, &key_len))
                return 0;
            if (sgx_cbor_text_eq(key, key_len, "role")) {
                if (!sgx_cbor_view(&cur, 3, &role, &role_len)) return 0;
            } else if (sgx_cbor_text_eq(key, key_len, "alg")) {
                if (!sgx_cbor_view(&cur, 3, &alg, &alg_len)) return 0;
            } else if (sgx_cbor_text_eq(key, key_len, "kid")) {
                if (!sgx_cbor_view(&cur, 2, &kid, &kid_len)) return 0;
            } else if (sgx_cbor_text_eq(key, key_len, "sig")) {
                if (!sgx_cbor_view(&cur, 2, &sig, &sig_len)) return 0;
            } else if (!sgx_cbor_skip(&cur, 0)) return 0;
        }
        if (cur.off != cur.len || !role
            || !sgx_cbor_text_eq(role, role_len, expected_role_text)
            || !alg || !sgx_cbor_text_eq(alg, alg_len, "ESP256")
            || !kid || kid_len != strlen(expected_kid)
            || memcmp(kid, expected_kid, kid_len) != 0
            || !sig || sig_len != 64)
            return 0;
        for (i = 0; i < 32; ++i) {
            public_key.gx[i] = expected_x[31 - i];
            public_key.gy[i] = expected_y[31 - i];
            ((uint8_t *)signature.x)[i] = sig[31 - i];
            ((uint8_t *)signature.y)[i] = sig[63 - i];
        }
        status = sgx_ecc256_open_context(&handle);
        if (status == SGX_SUCCESS)
            status = sgx_ecdsa_verify(wasm, (uint32_t)section_start,
                                      &public_key, &signature, &result, handle);
        if (handle) (void)sgx_ecc256_close_context(handle);
        return status == SGX_SUCCESS && result == SGX_EC_VALID;
    }
    return 0;
}
