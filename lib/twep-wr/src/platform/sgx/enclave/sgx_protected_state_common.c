/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */
#include "sgx_protected_state_internal.h"

#include <limits.h>
#include <sgx_tcrypto.h>
#include <string.h>

/* Canonical CBOR order is part of the persisted plaintext format, not merely
 * presentation.  Keep strict parsing, encoding, and digest helpers shared so
 * acceptance, Catalog, and app records apply identical byte-level rules. */
int sgx_protected_uint_read(struct sgx_protected_cursor *c, unsigned major, uint64_t *v)
{
    uint8_t initial;
    uint8_t additional;
    size_t encoded_bytes = 0;
    size_t i;
    uint64_t value = 0;

    if (c->off >= c->n) {
        return 0;
    }
    initial = c->p[c->off++];
    if ((initial >> 5) != major) {
        return 0;
    }
    additional = initial & 31;
    if (additional < 24) {
        *v = additional;
        return 1;
    }
    if (additional == 24) {
        encoded_bytes = 1;
    } else if (additional == 25) {
        encoded_bytes = 2;
    } else if (additional == 26) {
        encoded_bytes = 4;
    } else if (additional == 27) {
        encoded_bytes = 8;
    } else {
        return 0;
    }
    if (encoded_bytes > c->n - c->off) {
        return 0;
    }
    for (i = 0; i < encoded_bytes; ++i) {
        value = (value << 8) | c->p[c->off++];
    }
    if ((encoded_bytes == 1 && value < 24) ||
        (encoded_bytes == 2 && value <= UINT8_MAX) ||
        (encoded_bytes == 4 && value <= UINT16_MAX) ||
        (encoded_bytes == 8 && value <= UINT32_MAX)) {
        return 0;
    }
    *v = value;
    return 1;
}
int sgx_protected_view(struct sgx_protected_cursor *c, unsigned major, const uint8_t **p, size_t *n)
{
    uint64_t len;
    if (!sgx_protected_uint_read(c, major, &len) || len > SIZE_MAX ||
        (size_t)len > c->n - c->off) {
        return 0;
    }
    *p = c->p + c->off;
    *n = (size_t)len;
    c->off += *n;
    return 1;
}
int sgx_protected_text(struct sgx_protected_cursor *c, const char *s)
{
    const uint8_t *p;
    size_t n;
    size_t want = strlen(s);

    return sgx_protected_view(c, 3, &p, &n) && n == want && memcmp(p, s, n) == 0;
}
int sgx_protected_id_cmp(const uint8_t *a, size_t an, const uint8_t *b, size_t bn)
{
    if (an != bn) {
        return an < bn ? -1 : 1;
    }
    return memcmp(a, b, an);
}
size_t sgx_protected_uint_len(uint64_t value)
{
    return value < 24          ? 1
           : value <= UINT8_MAX  ? 2
           : value <= UINT16_MAX ? 3
           : value <= UINT32_MAX ? 5
                                 : 9;
}
void sgx_protected_put_len(uint8_t **cursor, unsigned major, uint64_t value)
{
    size_t encoded_bytes = sgx_protected_uint_len(value) - 1;
    size_t i;

    if (!encoded_bytes) {
        *(*cursor)++ = (uint8_t)((major << 5) | value);
        return;
    }
    *(*cursor)++ = (uint8_t)((major << 5) |
                             (encoded_bytes == 1   ? 24
                              : encoded_bytes == 2 ? 25
                              : encoded_bytes == 4 ? 26
                                                   : 27));
    for (i = encoded_bytes; i; --i) {
        *(*cursor)++ = (uint8_t)(value >> ((i - 1) * 8));
    }
}
void sgx_protected_put_text(uint8_t **cursor, const char *text_value)
{
    size_t len = strlen(text_value);

    sgx_protected_put_len(cursor, 3, len);
    memcpy(*cursor, text_value, len);
    *cursor += len;
}
void sgx_protected_put_bytes(uint8_t **cursor, const uint8_t *bytes, size_t len)
{
    sgx_protected_put_len(cursor, 2, len);
    memcpy(*cursor, bytes, len);
    *cursor += len;
}
size_t sgx_protected_text_len(const char *text_value)
{
    return sgx_protected_uint_len(strlen(text_value)) + strlen(text_value);
}
size_t sgx_protected_bytes_len(size_t len)
{
    return sgx_protected_uint_len(len) + len;
}
int sgx_protected_sha256(const uint8_t *bytes, size_t len, uint8_t out[32])
{
    return bytes && len && len <= UINT32_MAX &&
           sgx_sha256_msg(bytes, (uint32_t)len,
                          (sgx_sha256_hash_t *)out) == SGX_SUCCESS;
}
int sgx_protected_canonical_item(struct sgx_protected_cursor *cursor, unsigned depth,
                          size_t *map_entries)
{
    size_t start = cursor->off;
    size_t i;
    size_t key_start;
    size_t key_end;
    size_t previous_start = 0;
    size_t previous_end = 0;
    uint8_t initial;
    uint8_t major;
    uint8_t additional;
    uint64_t count = 0;
    const uint8_t *unused;
    size_t unused_len;

    (void)map_entries;
    if (depth > 16 || start >= cursor->n) {
        return 0;
    }
    initial = cursor->p[start];
    major = initial >> 5;
    additional = initial & 31;
    if (major <= 1) {
        return sgx_protected_uint_read(cursor, major, &count);
    }
    if (major == 2 || major == 3) {
        return sgx_protected_view(cursor, major, &unused, &unused_len);
    }
    if (major == 4) {
        if (!sgx_protected_uint_read(cursor, 4, &count)) {
            return 0;
        }
        for (i = 0; i < count; ++i) {
            if (!sgx_protected_canonical_item(cursor, depth + 1, map_entries)) {
                return 0;
            }
        }
        return 1;
    }
    if (major == 5) {
        if (!sgx_protected_uint_read(cursor, 5, &count) || count > 256) {
            return 0;
        }
        for (i = 0; i < count; ++i) {
            key_start = cursor->off;
            if (!sgx_protected_canonical_item(cursor, depth + 1, map_entries)) {
                return 0;
            }
            key_end = cursor->off;
            if (i &&
                (key_end - key_start < previous_end - previous_start ||
                 (key_end - key_start == previous_end - previous_start &&
                  memcmp(cursor->p + previous_start, cursor->p + key_start,
                         key_end - key_start) >= 0))) {
                return 0;
            }
            previous_start = key_start;
            previous_end = key_end;
            if (!sgx_protected_canonical_item(cursor, depth + 1, map_entries)) {
                return 0;
            }
        }
        return 1;
    }
    if (major == 6) {
        if (!sgx_protected_uint_read(cursor, 6, &count)) {
            return 0;
        }
        return sgx_protected_canonical_item(cursor, depth + 1, map_entries);
    }
    if (major != 7 || additional == 31) {
        return 0;
    }
    if (additional < 24) {
        ++cursor->off;
        return 1;
    }
    if (additional == 24) {
        if (cursor->off + 2 > cursor->n || cursor->p[cursor->off + 1] < 32) {
            return 0;
        }
        cursor->off += 2;
        return 1;
    }
    if (additional == 25 || additional == 26 || additional == 27) {
        size_t encoded_len = additional == 25 ? 3 : additional == 26 ? 5 : 9;
        if (cursor->off + encoded_len > cursor->n) {
            return 0;
        }
        cursor->off += encoded_len;
        return 1;
    }
    return 0;
}
int sgx_protected_catalog_payload_valid(const uint8_t *bytes, size_t len)
{
    struct sgx_protected_cursor cursor = {bytes, len, 0};
    size_t entries = 0;

    return sgx_protected_canonical_item(&cursor, 0, &entries) && cursor.off == len;
}
uint32_t sgx_protected_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}
uint64_t sgx_protected_be64(const uint8_t *p)
{
    uint64_t value = 0;
    int i;
    for (i = 0; i < 8; ++i) {
        value = (value << 8) | p[i];
    }
    return value;
}
void sgx_protected_write_be32(uint8_t *p, uint32_t value)
{
    p[0] = value >> 24;
    p[1] = value >> 16;
    p[2] = value >> 8;
    p[3] = value;
}
void sgx_protected_write_be64(uint8_t *p, uint64_t value)
{
    int i;
    for (i = 7; i >= 0; --i) {
        p[i] = (uint8_t)value;
        value >>= 8;
    }
}
/* Strictly parse the persisted Catalog record in its canonical CBOR key order. */
