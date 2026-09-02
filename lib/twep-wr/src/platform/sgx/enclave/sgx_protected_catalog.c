/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */
#include "sgx_protected_state_internal.h"

#include <stdlib.h>
#include <string.h>

static const uint8_t catalog_id[] = {
    0x82,0x4f,'t','w','e','p','-','c','a','t','a','l','o','g','-','v','1',
    0x47,'d','e','f','a','u','l','t'
};
struct catalog {
    uint8_t *raw;
    size_t raw_len;
    size_t catalog_len;
    const uint8_t *bytes;
    const uint8_t *digest;
    uint64_t generation;
    uint64_t sequence;
    int slot;
};
static int catalog_parse(struct catalog *catalog)
{
    struct sgx_protected_cursor cursor = {catalog->raw, catalog->raw_len, 0};
    uint64_t pair_count;
    uint64_t schema_version;
    const uint8_t *component_id;
    const uint8_t *catalog_bytes;
    const uint8_t *stored_digest;
    size_t component_id_len;
    size_t digest_len;
    uint8_t computed_digest[32];

    if (!sgx_protected_uint_read(&cursor, 5, &pair_count) || pair_count != 6 ||
        !sgx_protected_text(&cursor, "catalog_cbor") ||
        !sgx_protected_view(&cursor, 2, &catalog_bytes, &catalog->catalog_len) ||
        !catalog->catalog_len || catalog->catalog_len > SGX_CATALOG_MAX ||
        !sgx_protected_text(&cursor, "catalog_sha256") ||
        !sgx_protected_view(&cursor, 2, &stored_digest, &digest_len) || digest_len != 32 ||
        !sgx_protected_text(&cursor, "schema_version") || !sgx_protected_uint_read(&cursor, 0, &schema_version) ||
        !sgx_protected_text(&cursor, "sequence_number") ||
        !sgx_protected_uint_read(&cursor, 0, &catalog->sequence) || !catalog->sequence ||
        !sgx_protected_text(&cursor, "component_id_cbor") ||
        !sgx_protected_view(&cursor, 2, &component_id, &component_id_len) ||
        !sgx_protected_text(&cursor, "acceptance_generation") ||
        !sgx_protected_uint_read(&cursor, 0, &catalog->generation) || !catalog->generation ||
        cursor.off != cursor.n) {
        return 0;
    }
    if (schema_version != 1) {
        return -1;
    }
    if (component_id_len != sizeof(catalog_id) ||
        memcmp(component_id, catalog_id, component_id_len) != 0 ||
        !sgx_protected_sha256(catalog_bytes, catalog->catalog_len, computed_digest) ||
        memcmp(stored_digest, computed_digest, sizeof(computed_digest)) != 0) {
        return 0;
    }

    catalog->bytes = catalog_bytes;
    catalog->digest = stored_digest;
    return 1;
}

static void catalog_free(struct catalog *catalog)
{
    free(catalog->raw);
    memset(catalog, 0, sizeof(*catalog));
}

/* Read and strictly validate one physical Catalog slot. */
static int catalog_slot(int slot, struct catalog *catalog)
{
    const char *name = slot ? "catalog-slot-1" : "catalog-slot-0";
    size_t record_len = 0;
    int parse_status;
    int status;

    status = sgx_store_read(name, "catalog-state", NULL, 0, &record_len);
    if (status != SGX_STORE_OK) {
        return status;
    }
    if (!record_len || record_len > SGX_CATALOG_MAX + 512) {
        return SGX_STORE_CORRUPT;
    }

    catalog->raw = malloc(record_len);
    if (!catalog->raw) {
        return SGX_STORE_PLATFORM;
    }
    status = sgx_store_read(name, "catalog-state", catalog->raw, record_len,
                        &catalog->raw_len);
    if (status != SGX_STORE_OK) {
        goto cleanup;
    }

    catalog->slot = slot;
    parse_status = catalog_parse(catalog);
    if (parse_status == 1) {
        return SGX_STORE_OK;
    }
    status = parse_status < 0 ? SGX_STORE_UNSUPPORTED : SGX_STORE_CORRUPT;

cleanup:
    catalog_free(catalog);
    return status;
}

/* Select the newest slot activated by protected acceptance state. */
static int active_catalog(struct catalog *out)
{
    struct sgx_protected_acceptance acceptance;
    struct catalog slots[2] = {{0}};
    uint64_t accepted_sequence;
    int selected_slot = -1;
    int matching_slots = 0;
    int status;
    int slot;

    status = sgx_protected_load_acceptance(&acceptance);
    if (status != SGX_STORE_OK) {
        return status;
    }
    if (!sgx_protected_find_sequence(&acceptance, catalog_id, sizeof(catalog_id),
                       &accepted_sequence)) {
        return SGX_STORE_NOT_FOUND;
    }

    for (slot = 0; slot < 2; ++slot) {
        status = catalog_slot(slot, &slots[slot]);
        if (status == SGX_STORE_NOT_FOUND) {
            continue;
        }
        if (status == SGX_STORE_UNSUPPORTED) {
            goto cleanup;
        }
        if (status != SGX_STORE_OK || slots[slot].sequence != accepted_sequence) {
            continue;
        }

        ++matching_slots;
        if (selected_slot < 0 ||
            slots[slot].generation > slots[selected_slot].generation) {
            selected_slot = slot;
        }
    }

    if (!matching_slots) {
        status = SGX_STORE_CORRUPT;
        goto cleanup;
    }
    if (matching_slots == 2 &&
        (slots[0].sequence != slots[1].sequence ||
         slots[0].catalog_len != slots[1].catalog_len ||
         memcmp(slots[0].digest, slots[1].digest, 32) != 0 ||
         memcmp(slots[0].bytes, slots[1].bytes, slots[0].catalog_len) != 0)) {
        status = SGX_STORE_CORRUPT;
        goto cleanup;
    }

    *out = slots[selected_slot];
    memset(&slots[selected_slot], 0, sizeof(slots[selected_slot]));
    status = SGX_STORE_OK;

cleanup:
    catalog_free(&slots[0]);
    catalog_free(&slots[1]);
    return status;
}
int sgx_catalog_read_active(uint8_t *out,size_t cap,size_t *len)
{
    struct catalog catalog = {0};
    int status;

    if (!len) {
        return SGX_STORE_INVALID;
    }
    status = active_catalog(&catalog);
    if (status != SGX_STORE_OK) {
        return status;
    }

    *len = catalog.catalog_len;
    if (!out || cap < catalog.catalog_len) {
        status = SGX_STORE_SHORT_BUFFER;
    } else {
        memcpy(out, catalog.bytes, catalog.catalog_len);
    }

    catalog_free(&catalog);
    return status;
}

/* Stage the inactive Catalog slot, then commit its protected acceptance state. */
int sgx_catalog_commit(const uint8_t q[32],const uint8_t *id,size_t ilen,
 uint64_t seq,uint64_t expected,const uint8_t *bytes,size_t n,
 const uint8_t supplied[32],uint64_t *next)
{
    struct sgx_protected_acceptance acceptance;
    struct catalog active = {0};
    uint8_t digest[32];
    uint8_t *record = NULL;
    uint8_t *cursor;
    size_t record_len = 0;
    uint64_t prior_sequence;
    int target_slot = 0;
    int status;

    if (!q || !id || ilen != sizeof(catalog_id) ||
        memcmp(id, catalog_id, ilen) != 0 || !seq || !bytes || !n ||
        n > SGX_CATALOG_MAX || !supplied || !next || !sgx_protected_sha256(bytes, n, digest) ||
        memcmp(digest, supplied, sizeof(digest)) != 0 ||
        !sgx_protected_catalog_payload_valid(bytes, n)) {
        return SGX_STORE_INVALID;
    }

    status = sgx_protected_load_acceptance(&acceptance);
    if (status != SGX_STORE_OK) {
        return status;
    }
    if (acceptance.generation != expected) {
        return SGX_PROTECTED_STATE_CONFLICT;
    }
    if (sgx_protected_find_sequence(&acceptance, id, ilen, &prior_sequence)) {
        if (seq <= prior_sequence) {
            return SGX_PROTECTED_STATE_CONFLICT;
        }
        status = active_catalog(&active);
        if (status != SGX_STORE_OK) {
            goto cleanup;
        }
        target_slot = 1 - active.slot;
    }

    /* This order is the persisted Catalog CBOR schema, not presentation order. */
    record_len = 1 + sgx_protected_text_len("catalog_cbor") + sgx_protected_bytes_len(n) +
                 sgx_protected_text_len("catalog_sha256") + sgx_protected_bytes_len(32) +
                 sgx_protected_text_len("schema_version") + 1 + sgx_protected_text_len("sequence_number") +
                 sgx_protected_uint_len(seq) + sgx_protected_text_len("component_id_cbor") + sgx_protected_bytes_len(ilen) +
                 sgx_protected_text_len("acceptance_generation") + sgx_protected_uint_len(expected + 1);
    record = malloc(record_len);
    if (!record) {
        status = SGX_STORE_PLATFORM;
        goto cleanup;
    }

    cursor = record;
    sgx_protected_put_len(&cursor, 5, 6);
    sgx_protected_put_text(&cursor, "catalog_cbor");
    sgx_protected_put_bytes(&cursor, bytes, n);
    sgx_protected_put_text(&cursor, "catalog_sha256");
    sgx_protected_put_bytes(&cursor, digest, sizeof(digest));
    sgx_protected_put_text(&cursor, "schema_version");
    sgx_protected_put_len(&cursor, 0, 1);
    sgx_protected_put_text(&cursor, "sequence_number");
    sgx_protected_put_len(&cursor, 0, seq);
    sgx_protected_put_text(&cursor, "component_id_cbor");
    sgx_protected_put_bytes(&cursor, id, ilen);
    sgx_protected_put_text(&cursor, "acceptance_generation");
    sgx_protected_put_len(&cursor, 0, expected + 1);

    status = sgx_store_write_verified(target_slot ? "catalog-slot-1" :
                                                    "catalog-slot-0",
                                      "catalog-state", record, record_len);
    if (status == SGX_STORE_OK) {
        status = sgx_acceptance_commit(q, id, ilen, seq, expected, next);
    }

cleanup:
    if (record) {
        memset(record, 0, record_len);
        free(record);
    }
    catalog_free(&active);
    return status;
}
