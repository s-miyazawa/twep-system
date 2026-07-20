/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */
#include "runtime_internal.h"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>

#include <string.h>

#define TWEP_WR_WASM_SIG_NAME "twep.sig"
#define TWEP_WR_WASM_SIG_NAME_LEN 8u

typedef struct {
    bytes_view_t alg;
    bytes_view_t kid;
    bytes_view_t role;
    bytes_view_t sig;
    const uint8_t *prefix;
    size_t prefix_len;
} wasm_signature_t;

static const uint8_t teep_agent_code_signing_x[32] = {
    0x82, 0x82, 0x0a, 0xb9, 0x8d, 0x42, 0x91, 0xc4, 0x9d, 0x9a, 0x3c, 0x95, 0x07, 0x13, 0x52, 0x1a,
    0xed, 0x4e, 0xb4, 0x7f, 0xf0, 0xd2, 0x3e, 0x9c, 0xd8, 0xd6, 0x38, 0x8f, 0x23, 0x09, 0x20, 0xc9,
};

static const uint8_t teep_agent_code_signing_y[32] = {
    0x9b, 0x7f, 0xb3, 0x3e, 0x03, 0x5f, 0x63, 0xb7, 0x9e, 0x9c, 0xcf, 0x53, 0x64, 0x60, 0x55, 0xb8,
    0x38, 0x75, 0x18, 0xae, 0x86, 0x65, 0xd0, 0x2e, 0x3f, 0x80, 0xba, 0x60, 0x88, 0xe4, 0xa7, 0xa1,
};

static const uint8_t app_code_signing_x[32] = {
    0xe5, 0xb5, 0x8f, 0xb0, 0x88, 0xd3, 0xa0, 0x75, 0xc3, 0x22, 0xd9, 0xc2, 0xca, 0x0e, 0xf4, 0xd6,
    0xca, 0xdb, 0xcc, 0x5c, 0x30, 0x6a, 0x5e, 0x44, 0x01, 0x2e, 0x65, 0x18, 0xa4, 0xbc, 0x2f, 0x58,
};

static const uint8_t app_code_signing_y[32] = {
    0x2a, 0xb7, 0xd2, 0x2f, 0x7c, 0xdb, 0x0f, 0x36, 0xb5, 0x83, 0x8d, 0x39, 0xbd, 0x89, 0xbd, 0x8e,
    0x68, 0xdc, 0x99, 0x8c, 0x1b, 0xf7, 0x5b, 0x41, 0x30, 0xef, 0xd3, 0x67, 0x5c, 0x1b, 0x3d, 0x1c,
};

static bool read_varuint32(const uint8_t *buf, size_t len, size_t *off, uint32_t *out)
{
    uint32_t value = 0;
    uint32_t shift = 0;
    for (size_t i = 0; i < 5; i++) {
        if (*off >= len) {
            return false;
        }
        uint8_t b = buf[(*off)++];
        value |= (uint32_t)(b & 0x7fu) << shift;
        if ((b & 0x80u) == 0) {
            *out = value;
            return true;
        }
        shift += 7;
    }
    return false;
}

static bool custom_section_name(const uint8_t *payload, size_t payload_len, bytes_view_t *out_name, size_t *out_name_end)
{
    size_t off = 0;
    uint32_t name_len = 0;
    if (!read_varuint32(payload, payload_len, &off, &name_len) || name_len > payload_len - off) {
        return false;
    }
    out_name->ptr = payload + off;
    out_name->len = name_len;
    *out_name_end = off + name_len;
    return true;
}

static bool parse_signature_payload(const uint8_t *payload, size_t payload_len, wasm_signature_t *out)
{
    size_t off = 0;
    uint8_t major = 0;
    uint64_t pairs = 0;
    if (!twep_wr_cbor_read_head(payload, payload_len, &off, &major, &pairs) || major != 5) {
        return false;
    }
    for (uint64_t i = 0; i < pairs; i++) {
        bytes_view_t key;
        if (!twep_wr_cbor_read_text_view(payload, payload_len, &off, &key)) {
            return false;
        }
        if (twep_wr_bytes_equal_text(key, "alg")) {
            if (!twep_wr_cbor_read_text_view(payload, payload_len, &off, &out->alg)) {
                return false;
            }
        } else if (twep_wr_bytes_equal_text(key, "kid")) {
            if (!twep_wr_cbor_read_bytes_view(payload, payload_len, &off, &out->kid)) {
                return false;
            }
        } else if (twep_wr_bytes_equal_text(key, "role")) {
            if (!twep_wr_cbor_read_text_view(payload, payload_len, &off, &out->role)) {
                return false;
            }
        } else if (twep_wr_bytes_equal_text(key, "sig")) {
            if (!twep_wr_cbor_read_bytes_view(payload, payload_len, &off, &out->sig)) {
                return false;
            }
        } else if (!twep_wr_cbor_skip_value(payload, payload_len, &off)) {
            return false;
        }
    }
    return off == payload_len && twep_wr_bytes_equal_text(out->alg, "ESP256") && out->kid.len > 0 && out->sig.len == 64;
}

static bool parse_wasm_signature(const uint8_t *wasm, size_t wasm_len, wasm_signature_t *out)
{
    static const uint8_t wasm_magic[4] = { 0x00, 0x61, 0x73, 0x6d };
    if (wasm_len < 8 || memcmp(wasm, wasm_magic, sizeof(wasm_magic)) != 0) {
        return false;
    }
    size_t off = 8;
    while (off < wasm_len) {
        size_t section_start = off;
        uint8_t section_id = wasm[off++];
        uint32_t section_size = 0;
        if (!read_varuint32(wasm, wasm_len, &off, &section_size) || section_size > wasm_len - off) {
            return false;
        }
        const uint8_t *payload = wasm + off;
        size_t payload_len = section_size;
        size_t section_end = off + section_size;
        if (section_id == 0) {
            bytes_view_t name;
            size_t name_end = 0;
            if (custom_section_name(payload, payload_len, &name, &name_end)
                && name.len == TWEP_WR_WASM_SIG_NAME_LEN
                && memcmp(name.ptr, TWEP_WR_WASM_SIG_NAME, TWEP_WR_WASM_SIG_NAME_LEN) == 0) {
                if (section_end != wasm_len) {
                    return false;
                }
                out->prefix = wasm;
                out->prefix_len = section_start;
                return parse_signature_payload(payload + name_end, payload_len - name_end, out);
            }
        }
        off = section_end;
    }
    return false;
}

static bool der_encode_raw_signature(const uint8_t *raw_sig, size_t raw_sig_len, uint8_t *out, size_t *out_len)
{
    if (raw_sig_len != 64) {
        return false;
    }
    ECDSA_SIG *sig = ECDSA_SIG_new();
    BIGNUM *r = BN_bin2bn(raw_sig, 32, NULL);
    BIGNUM *s = BN_bin2bn(raw_sig + 32, 32, NULL);
    if (sig == NULL || r == NULL || s == NULL || ECDSA_SIG_set0(sig, r, s) != 1) {
        ECDSA_SIG_free(sig);
        BN_free(r);
        BN_free(s);
        return false;
    }
    r = NULL;
    s = NULL;
    int der_len = i2d_ECDSA_SIG(sig, NULL);
    if (der_len <= 0 || (size_t)der_len > *out_len) {
        ECDSA_SIG_free(sig);
        return false;
    }
    uint8_t *p = out;
    der_len = i2d_ECDSA_SIG(sig, &p);
    ECDSA_SIG_free(sig);
    if (der_len <= 0) {
        return false;
    }
    *out_len = (size_t)der_len;
    return true;
}

static EVP_PKEY *p256_public_key_from_coordinates(const uint8_t x[32], const uint8_t y[32])
{
    uint8_t sec1[65];
    sec1[0] = 0x04;
    memcpy(sec1 + 1, x, 32);
    memcpy(sec1 + 33, y, 32);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (ctx == NULL || EVP_PKEY_fromdata_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    EVP_PKEY *pkey = NULL;
    if (bld == NULL
        || OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0) != 1
        || OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, sec1, sizeof(sec1)) != 1) {
        OSSL_PARAM_BLD_free(bld);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);
    if (params != NULL) {
        (void)EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params);
        OSSL_PARAM_free(params);
    }
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static bool verify_esp256(const uint8_t x[32], const uint8_t y[32], const uint8_t *signature, size_t signature_len,
                          const uint8_t *message, size_t message_len)
{
    uint8_t der_sig[80];
    size_t der_sig_len = sizeof(der_sig);
    if (!der_encode_raw_signature(signature, signature_len, der_sig, &der_sig_len)) {
        return false;
    }
    EVP_PKEY *pkey = p256_public_key_from_coordinates(x, y);
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    bool ok = false;
    if (pkey != NULL && md_ctx != NULL
        && EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, pkey) == 1
        && EVP_DigestVerify(md_ctx, der_sig, der_sig_len, message, message_len) == 1) {
        ok = true;
    }
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    return ok;
}

bool twep_wr_verify_wasm_signature(const uint8_t *wasm, size_t wasm_len, twep_wr_wasm_signature_role_t role)
{
    wasm_signature_t sig = { 0 };
    if (!parse_wasm_signature(wasm, wasm_len, &sig)) {
        return false;
    }
    if (role == TWEP_WR_WASM_SIGNATURE_ROLE_TEEP_AGENT) {
        if (!twep_wr_bytes_equal_text(sig.role, "teep-agent")) {
            return false;
        }
        return verify_esp256(teep_agent_code_signing_x, teep_agent_code_signing_y, sig.sig.ptr, sig.sig.len,
                             sig.prefix, sig.prefix_len);
    }
    if (role == TWEP_WR_WASM_SIGNATURE_ROLE_APP) {
        if (!twep_wr_bytes_equal_text(sig.role, "app")) {
            return false;
        }
        return verify_esp256(app_code_signing_x, app_code_signing_y, sig.sig.ptr, sig.sig.len,
                             sig.prefix, sig.prefix_len);
    }
    return false;
}
