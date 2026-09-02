/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */
#include "sgx_protected_state_internal.h"

#include <limits.h>
#include <string.h>

static int parse_components(struct sgx_protected_cursor *c, struct sgx_protected_acceptance *s)
{
    uint64_t count;
    uint64_t sequence;
    const uint8_t *id;
    size_t len;
    size_t i;

    if (!sgx_protected_uint_read(c, 5, &count) || count > SGX_PROTECTED_MAX_COMPONENTS) {
        return 0;
    }
    for (i = 0; i < count; ++i) {
        if (!sgx_protected_view(c, 2, &id, &len) || !len ||
            !sgx_protected_uint_read(c, 0, &sequence) ||
            (i && sgx_protected_id_cmp(s->components[i - 1].id, s->components[i - 1].len,
                         id, len) >= 0)) {
            return 0;
        }
        s->components[i] = (struct sgx_protected_component){id, len, sequence};
    }
    s->count = (size_t)count;
    return 1;
}
/* 1 valid, 0 malformed, -1 unsupported. */
static int parse_acceptance(struct sgx_protected_acceptance *s, int legacy)
{
    struct sgx_protected_cursor c = {s->raw, s->raw_len, 0};
    uint64_t pairs;
    uint64_t schema;
    const uint8_t *digest;
    size_t digest_len;

    if (legacy) {
        s->generation = 0;
        s->have_digest = 0;
        return parse_components(&c, s) && c.off == c.n;
    }
    if (!sgx_protected_uint_read(&c, 5, &pairs) || pairs != 4
        || !sgx_protected_text(&c, "generation") || !sgx_protected_uint_read(&c, 0, &s->generation)
        || !s->generation || !sgx_protected_text(&c, "schema_version")
        || !sgx_protected_uint_read(&c, 0, &schema)
        || !sgx_protected_text(&c, "component_sequences") || !parse_components(&c, s)
        || !sgx_protected_text(&c, "last_consumed_query_response_sha256")
        || !sgx_protected_view(&c, 2, &digest, &digest_len) || digest_len != 32
        || c.off != c.n) {
        return 0;
    }
    memcpy(s->digest, digest, 32);
    s->have_digest = 1;
    return schema == 1 ? 1 : -1;
}
/* Select the newest valid protected acceptance-state slot, or migrate legacy state. */
int sgx_protected_load_acceptance(struct sgx_protected_acceptance *out)
{
    struct sgx_protected_acceptance slots[2];
    int valid[2] = {0, 0};
    int any_slot_present = 0;
    int selected_slot = -1;
    const char *names[2] = {"acceptance-slot-0", "acceptance-slot-1"};
    size_t slot;
    int status;

    memset(slots, 0, sizeof(slots));
    for (slot = 0; slot < 2; ++slot) {
        status = sgx_store_read(names[slot], "acceptance-state", slots[slot].raw,
                            sizeof(slots[slot].raw), &slots[slot].raw_len);
        if (status == SGX_STORE_NOT_FOUND) {
            continue;
        }
        any_slot_present = 1;
        if (status != SGX_STORE_OK) {
            continue;
        }
        valid[slot] = parse_acceptance(&slots[slot], 0);
        if (valid[slot] < 0) {
            return SGX_STORE_UNSUPPORTED;
        }
        if (valid[slot] &&
            (selected_slot < 0 ||
             slots[slot].generation > slots[selected_slot].generation)) {
            selected_slot = (int)slot;
        }
    }

    if (selected_slot >= 0) {
        if (valid[0] && valid[1] &&
            slots[0].generation == slots[1].generation &&
            (slots[0].raw_len != slots[1].raw_len ||
             memcmp(slots[0].raw, slots[1].raw, slots[0].raw_len) != 0)) {
            return SGX_STORE_CORRUPT;
        }
        *out = slots[selected_slot];
        out->slot = selected_slot;
        return parse_acceptance(out, 0) == 1 ? SGX_STORE_OK : SGX_STORE_CORRUPT;
    }
    if (any_slot_present) {
        return SGX_STORE_CORRUPT;
    }

    memset(out, 0, sizeof(*out));
    out->slot = -1;
    status = sgx_store_read("sequence-freshness", "sequence-freshness", out->raw,
                        sizeof(out->raw), &out->raw_len);
    if (status == SGX_STORE_NOT_FOUND) {
        return SGX_STORE_OK;
    }
    return status == SGX_STORE_OK && parse_acceptance(out, 1)
               ? SGX_STORE_OK
               : SGX_STORE_CORRUPT;
}
int sgx_protected_find_sequence(const struct sgx_protected_acceptance *acceptance, const uint8_t *id,
                         size_t len, uint64_t *sequence)
{
    size_t i;

    for (i = 0; i < acceptance->count; ++i) {
        if (acceptance->components[i].len != len ||
            memcmp(acceptance->components[i].id, id, len) != 0) {
            continue;
        }
        if (sequence) {
            *sequence = acceptance->components[i].sequence;
        }
        return 1;
    }
    return 0;
}
/* Encode protected acceptance-state keys and component IDs canonically. */
static int encode_acceptance(const struct sgx_protected_acceptance *old,
                             const uint8_t digest[32], const uint8_t *id,
                             size_t len, uint64_t sequence,
                             uint8_t out[SGX_ACCEPTANCE_MAX], size_t *out_len)
{
    struct sgx_protected_component components[SGX_PROTECTED_MAX_COMPONENTS];
    size_t count = old->count;
    size_t i;
    size_t j;
    size_t required_len;
    int found = 0;
    uint8_t *cursor = out;

    for (i = 0; i < count; ++i) {
        components[i] = old->components[i];
        if (components[i].len == len &&
            memcmp(components[i].id, id, len) == 0) {
            components[i].sequence = sequence;
            found = 1;
        }
    }
    if (!found) {
        if (count == SGX_PROTECTED_MAX_COMPONENTS) {
            return 0;
        }
        components[count++] = (struct sgx_protected_component){id, len, sequence};
    }
    for (i = 1; i < count; ++i) {
        struct sgx_protected_component component = components[i];
        j = i;
        while (j && sgx_protected_id_cmp(components[j - 1].id, components[j - 1].len,
                           component.id, component.len) > 0) {
            components[j] = components[j - 1];
            --j;
        }
        components[j] = component;
    }

    required_len = 1 + sgx_protected_text_len("generation") + sgx_protected_uint_len(old->generation + 1) +
                   sgx_protected_text_len("schema_version") + 1 +
                   sgx_protected_text_len("component_sequences") + sgx_protected_uint_len(count) +
                   sgx_protected_text_len("last_consumed_query_response_sha256") + sgx_protected_bytes_len(32);
    for (i = 0; i < count; ++i) {
        required_len += sgx_protected_bytes_len(components[i].len) + sgx_protected_uint_len(components[i].sequence);
    }
    if (required_len > SGX_ACCEPTANCE_MAX) {
        return 0;
    }

    sgx_protected_put_len(&cursor, 5, 4);
    sgx_protected_put_text(&cursor, "generation");
    sgx_protected_put_len(&cursor, 0, old->generation + 1);
    sgx_protected_put_text(&cursor, "schema_version");
    sgx_protected_put_len(&cursor, 0, 1);
    sgx_protected_put_text(&cursor, "component_sequences");
    sgx_protected_put_len(&cursor, 5, count);
    for (i = 0; i < count; ++i) {
        sgx_protected_put_bytes(&cursor, components[i].id, components[i].len);
        sgx_protected_put_len(&cursor, 0, components[i].sequence);
    }
    sgx_protected_put_text(&cursor, "last_consumed_query_response_sha256");
    sgx_protected_put_bytes(&cursor, digest, 32);

    *out_len = (size_t)(cursor - out);
    return *out_len == required_len;
}
int sgx_acceptance_generation(uint64_t *generation)
{
    struct sgx_protected_acceptance acceptance;
    int status;

    if (!generation) {
        return SGX_STORE_INVALID;
    }
    status = sgx_protected_load_acceptance(&acceptance);
    if (status == SGX_STORE_OK) {
        *generation = acceptance.generation;
    }
    return status;
}

/* Commit the protected acceptance state that activates a staged object. */
int sgx_acceptance_commit(const uint8_t digest[32],const uint8_t *component,
 size_t component_len,uint64_t sequence,uint64_t expected,uint64_t *next)
{
    struct sgx_protected_acceptance acceptance;
    uint8_t record[SGX_ACCEPTANCE_MAX];
    size_t record_len;
    uint64_t prior_sequence;
    int status;

    if (!digest || !component || !component_len || !sequence || !next ||
        expected == UINT64_MAX) {
        return SGX_STORE_INVALID;
    }
    status = sgx_protected_load_acceptance(&acceptance);
    if (status != SGX_STORE_OK) {
        return status;
    }
    if (acceptance.generation != expected ||
        (acceptance.have_digest &&
         memcmp(acceptance.digest, digest, sizeof(acceptance.digest)) == 0) ||
        (sgx_protected_find_sequence(&acceptance, component, component_len, &prior_sequence) &&
         sequence <= prior_sequence)) {
        return SGX_PROTECTED_STATE_CONFLICT;
    }
    if (!encode_acceptance(&acceptance, digest, component, component_len, sequence,
                           record, &record_len)) {
        return SGX_STORE_INVALID;
    }

    status = sgx_store_write_verified(
        acceptance.slot == 0 ? "acceptance-slot-1" : "acceptance-slot-0",
        "acceptance-state", record, record_len);
    if (status == SGX_STORE_OK) {
        *next = expected + 1;
    }
    return status;
}
