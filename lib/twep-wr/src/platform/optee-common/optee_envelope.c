/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */
#include "optee_internal.h"

#include <stdlib.h>
#include <string.h>

static size_t type_len_size(uint64_t n)
{
    if (n < 24u) return 1u;
    if (n <= 0xffu) return 2u;
    if (n <= 0xffffu) return 3u;
    if (n <= 0xffffffffu) return 5u;
    return 9u;
}

static void write_type_len(uint8_t **p, uint8_t major, uint64_t n)
{
    if (n < 24u) {
        *(*p)++ = (uint8_t)((major << 5) | n);
    } else if (n <= 0xffu) {
        *(*p)++ = (uint8_t)((major << 5) | 24u); *(*p)++ = (uint8_t)n;
    } else if (n <= 0xffffu) {
        *(*p)++ = (uint8_t)((major << 5) | 25u);
        *(*p)++ = (uint8_t)(n >> 8); *(*p)++ = (uint8_t)n;
    } else {
        *(*p)++ = (uint8_t)((major << 5) | 26u);
        *(*p)++ = (uint8_t)(n >> 24); *(*p)++ = (uint8_t)(n >> 16);
        *(*p)++ = (uint8_t)(n >> 8); *(*p)++ = (uint8_t)n;
    }
}

static void write_text(uint8_t **p, const char *text)
{
    size_t len = strlen(text);
    write_type_len(p, 3, len); memcpy(*p, text, len); *p += len;
}

static void write_bytes(uint8_t **p, const uint8_t *bytes, size_t len)
{
    write_type_len(p, 2, len);
    if (len != 0u) { memcpy(*p, bytes, len); *p += len; }
}

static size_t text_field_len(const char *key, const char *value)
{
    return type_len_size(strlen(key)) + strlen(key)
           + type_len_size(strlen(value)) + strlen(value);
}

static size_t bytes_field_len(const char *key, size_t value_len)
{
    return type_len_size(strlen(key)) + strlen(key) + type_len_size(value_len) + value_len;
}

uint8_t *twep_optee_make_execute_envelope(
    const twep_wr_context_t *ctx, const twep_wr_normalized_request_t *request,
    const uint8_t *teep_agent_wasm, size_t teep_agent_wasm_len,
    const uint8_t *catalog, size_t catalog_len,
    const uint8_t *app_wasm, size_t app_wasm_len,
    const uint8_t *dev_agent_public_key, size_t dev_agent_public_key_len,
    uint32_t timeout_ms, size_t *out_len)
{
    size_t len;
    uint8_t *buf, *p;
    const char *resolver_mode, *attestam_url;

    if (ctx == NULL || request == NULL || out_len == NULL) return NULL;
    resolver_mode = ctx->resolver_mode != NULL ? ctx->resolver_mode : "mock";
    attestam_url = ctx->attestam_url != NULL ? ctx->attestam_url : "";
    len = 1u + text_field_len("request_id", request->request_id)
          + text_field_len("command", request->command)
          + text_field_len("resolver_mode", resolver_mode)
          + text_field_len("attestam_url", attestam_url)
          + type_len_size(strlen("insecure")) + strlen("insecure") + 1u
          + bytes_field_len("app_input_cbor", request->app_input_cbor.len)
          + type_len_size(strlen("request_timeout_ms")) + strlen("request_timeout_ms")
          + type_len_size(timeout_ms) + bytes_field_len("wasm_bytes", teep_agent_wasm_len)
          + bytes_field_len("catalog_cbor", catalog_len)
          + bytes_field_len("app_wasm_bytes", app_wasm_len)
          + bytes_field_len("dev_agent_public_key_cbor", dev_agent_public_key_len);
    buf = malloc(len);
    if (buf == NULL) return NULL;
    p = buf; *p++ = 0xab;
    write_text(&p, "request_id"); write_text(&p, request->request_id);
    write_text(&p, "command"); write_text(&p, request->command);
    write_text(&p, "resolver_mode"); write_text(&p, resolver_mode);
    write_text(&p, "attestam_url"); write_text(&p, attestam_url);
    write_text(&p, "insecure"); *p++ = ctx->insecure_demo_mode ? 0xf5 : 0xf4;
    write_text(&p, "app_input_cbor"); write_bytes(&p, request->app_input_cbor.ptr, request->app_input_cbor.len);
    write_text(&p, "request_timeout_ms"); write_type_len(&p, 0, timeout_ms);
    write_text(&p, "wasm_bytes"); write_bytes(&p, teep_agent_wasm, teep_agent_wasm_len);
    write_text(&p, "catalog_cbor"); write_bytes(&p, catalog, catalog_len);
    write_text(&p, "app_wasm_bytes"); write_bytes(&p, app_wasm, app_wasm_len);
    write_text(&p, "dev_agent_public_key_cbor");
    write_bytes(&p, dev_agent_public_key, dev_agent_public_key_len);
    *out_len = (size_t)(p - buf);
    return buf;
}
