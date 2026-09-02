/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef SGX_PROTECTED_STATE_INTERNAL_H
#define SGX_PROTECTED_STATE_INTERNAL_H

#include "sgx_runtime_internal.h"

#include <stddef.h>
#include <stdint.h>

#define SGX_PROTECTED_MAX_COMPONENTS 32u
#define SGX_PROTECTED_APP_HEADER 68u

struct sgx_protected_component {
    const uint8_t *id;
    size_t len;
    uint64_t sequence;
};

struct sgx_protected_acceptance {
    uint8_t raw[SGX_ACCEPTANCE_MAX];
    size_t raw_len;
    uint64_t generation;
    uint8_t digest[32];
    int have_digest;
    int slot;
    struct sgx_protected_component components[SGX_PROTECTED_MAX_COMPONENTS];
    size_t count;
};

struct sgx_protected_cursor {
    const uint8_t *p;
    size_t n;
    size_t off;
};

int sgx_protected_uint_read(struct sgx_protected_cursor *cursor,
                            unsigned major, uint64_t *value);
int sgx_protected_view(struct sgx_protected_cursor *cursor, unsigned major,
                       const uint8_t **bytes, size_t *len);
int sgx_protected_text(struct sgx_protected_cursor *cursor, const char *text);
int sgx_protected_id_cmp(const uint8_t *a, size_t a_len, const uint8_t *b,
                         size_t b_len);
size_t sgx_protected_uint_len(uint64_t value);
void sgx_protected_put_len(uint8_t **cursor, unsigned major, uint64_t value);
void sgx_protected_put_text(uint8_t **cursor, const char *text);
void sgx_protected_put_bytes(uint8_t **cursor, const uint8_t *bytes,
                             size_t len);
size_t sgx_protected_text_len(const char *text);
size_t sgx_protected_bytes_len(size_t len);
int sgx_protected_sha256(const uint8_t *bytes, size_t len, uint8_t out[32]);
int sgx_protected_canonical_item(struct sgx_protected_cursor *cursor,
                                 unsigned depth, size_t *map_entries);
int sgx_protected_catalog_payload_valid(const uint8_t *bytes, size_t len);
uint32_t sgx_protected_be32(const uint8_t *bytes);
uint64_t sgx_protected_be64(const uint8_t *bytes);
void sgx_protected_write_be32(uint8_t *bytes, uint32_t value);
void sgx_protected_write_be64(uint8_t *bytes, uint64_t value);

int sgx_protected_load_acceptance(struct sgx_protected_acceptance *out);
int sgx_protected_find_sequence(
    const struct sgx_protected_acceptance *acceptance, const uint8_t *id,
    size_t id_len, uint64_t *sequence);

#endif
