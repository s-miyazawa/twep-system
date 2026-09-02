/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */
#include "sgx_runtime_internal.h"

#include <limits.h>
#include <string.h>

int sgx_cbor_len(struct sgx_cbor_cursor *cur, uint8_t want, uint64_t *value)
{
    uint8_t initial, ai;
    size_t n = 0, i;
    uint64_t v = 0;
    if (cur->off >= cur->len)
        return 0;
    initial = cur->buf[cur->off++];
    if ((initial >> 5) != want)
        return 0;
    ai = initial & 31;
    if (ai < 24) {
        *value = ai;
        return 1;
    }
    if (ai == 24) n = 1;
    else if (ai == 25) n = 2;
    else if (ai == 26) n = 4;
    else if (ai == 27) n = 8;
    else return 0;
    if (n > cur->len - cur->off)
        return 0;
    for (i = 0; i < n; ++i)
        v = (v << 8) | cur->buf[cur->off++];
    *value = v;
    return 1;
}

int sgx_cbor_view(struct sgx_cbor_cursor *cur, uint8_t major,
                  const uint8_t **ptr, size_t *len)
{
    uint64_t n;
    if (!sgx_cbor_len(cur, major, &n) || n > cur->len - cur->off)
        return 0;
    *ptr = cur->buf + cur->off;
    *len = (size_t)n;
    cur->off += (size_t)n;
    return 1;
}

int sgx_cbor_skip(struct sgx_cbor_cursor *cur, unsigned depth)
{
    uint8_t major;
    uint64_t n, i;
    const uint8_t *unused;
    size_t unused_len;
    if (depth > 8 || cur->off >= cur->len)
        return 0;
    major = cur->buf[cur->off] >> 5;
    if (major == 0 || major == 1)
        return sgx_cbor_len(cur, major, &n);
    if (major == 2 || major == 3)
        return sgx_cbor_view(cur, major, &unused, &unused_len);
    if (major == 4 || major == 5) {
        if (!sgx_cbor_len(cur, major, &n))
            return 0;
        n *= major == 5 ? 2 : 1;
        for (i = 0; i < n; ++i)
            if (!sgx_cbor_skip(cur, depth + 1))
                return 0;
        return 1;
    }
    if (major == 7 && (cur->buf[cur->off] & 31) < 24) {
        ++cur->off;
        return 1;
    }
    return 0;
}

int sgx_cbor_text_eq(const uint8_t *p, size_t n, const char *s)
{
    size_t m = strlen(s);
    return n == m && memcmp(p, s, m) == 0;
}

static int parse_limits(struct sgx_cbor_cursor *cur,
                        struct sgx_catalog_app *app)
{
    uint64_t pairs, value, i;
    const uint8_t *key;
    size_t key_len;
    if (!sgx_cbor_len(cur, 5, &pairs))
        return 0;
    for (i = 0; i < pairs; ++i) {
        if (!sgx_cbor_view(cur, 3, &key, &key_len))
            return 0;
        if (sgx_cbor_text_eq(key, key_len, "stack_bytes")) {
            if (!sgx_cbor_len(cur, 0, &value) || value > 1024u * 1024u) return 0;
            app->stack_bytes = (uint32_t)value;
        } else if (sgx_cbor_text_eq(key, key_len, "heap_bytes")) {
            if (!sgx_cbor_len(cur, 0, &value) || value > 16u * 1024u * 1024u) return 0;
            app->heap_bytes = (uint32_t)value;
        } else if (sgx_cbor_text_eq(key, key_len, "timeout_ms")) {
            if (!sgx_cbor_len(cur, 0, &value) || value > UINT32_MAX) return 0;
            app->timeout_ms = (uint32_t)value;
        } else if (sgx_cbor_text_eq(key, key_len, "max_output_bytes")) {
            if (!sgx_cbor_len(cur, 0, &value) || value > SGX_APP_OUTPUT_DEFAULT) return 0;
            app->max_output_bytes = (uint32_t)value;
        } else if (!sgx_cbor_skip(cur, 0)) {
            return 0;
        }
    }
    return 1;
}

static int parse_app_entry(struct sgx_cbor_cursor *cur,
                           struct sgx_catalog_app *app)
{
    uint64_t pairs, i;
    const uint8_t *key, *value;
    size_t key_len, value_len;
    int have_file = 0, have_digest = 0;
    if (!sgx_cbor_len(cur, 5, &pairs))
        return 0;
    for (i = 0; i < pairs; ++i) {
        if (!sgx_cbor_view(cur, 3, &key, &key_len))
            return 0;
        if (sgx_cbor_text_eq(key, key_len, "wasm_file")) {
            if (!sgx_cbor_view(cur, 3, &value, &value_len)
                || value_len == 0 || value_len >= sizeof(app->wasm_file))
                return 0;
            memcpy(app->wasm_file, value, value_len);
            app->wasm_file[value_len] = '\0';
            have_file = 1;
        } else if (sgx_cbor_text_eq(key, key_len, "sha256")) {
            if (!sgx_cbor_view(cur, 2, &value, &value_len) || value_len != 32)
                return 0;
            memcpy(app->digest, value, 32);
            have_digest = 1;
        } else if (sgx_cbor_text_eq(key, key_len, "resource_limits")) {
            if (!parse_limits(cur, app))
                return 0;
        } else if (!sgx_cbor_skip(cur, 0)) {
            return 0;
        }
    }
    return have_file && have_digest;
}

int sgx_resolve_output_parse(const uint8_t *buf, size_t len,
                             const char *command,
                             struct sgx_catalog_app *app)
{
    struct sgx_cbor_cursor cur = { buf, len, 0 };
    uint64_t top_pairs, i;
    const uint8_t *key, *value;
    size_t key_len, value_len;
    int have_ok = 0, have_app = 0;
    (void)command;
    memset(app, 0, sizeof(*app));
    app->stack_bytes = SGX_APP_STACK_DEFAULT;
    app->heap_bytes = SGX_APP_HEAP_DEFAULT;
    app->max_output_bytes = SGX_APP_OUTPUT_DEFAULT;
    if (!sgx_cbor_len(&cur, 5, &top_pairs))
        return 0;
    for (i = 0; i < top_pairs; ++i) {
        if (!sgx_cbor_view(&cur, 3, &key, &key_len))
            return 0;
        if (sgx_cbor_text_eq(key, key_len, "status")) {
            if (!sgx_cbor_view(&cur, 3, &value, &value_len))
                return 0;
            have_ok = sgx_cbor_text_eq(value, value_len, "ok");
        } else if (sgx_cbor_text_eq(key, key_len, "app")) {
            if (!parse_app_entry(&cur, app))
                return 0;
            have_app = 1;
        } else if (!sgx_cbor_skip(&cur, 0)) {
            return 0;
        }
    }
    return cur.off == cur.len && have_ok && have_app;
}

int sgx_catalog_safe_wasm_basename(const char *name)
{
    size_t n = strlen(name), i;
    if (n < 6 || n >= 128 || strcmp(name + n - 5, ".wasm") != 0)
        return 0;
    for (i = 0; i < n; ++i)
        if (!((name[i] >= 'a' && name[i] <= 'z') ||
              (name[i] >= 'A' && name[i] <= 'Z') ||
              (name[i] >= '0' && name[i] <= '9') ||
              name[i] == '.' || name[i] == '_' || name[i] == '-'))
            return 0;
    return 1;
}
