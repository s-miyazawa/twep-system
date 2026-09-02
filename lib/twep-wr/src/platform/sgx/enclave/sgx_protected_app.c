/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */
#include "sgx_protected_state_internal.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t app_magic[8] = {'T','W','E','P','A','P','P',1};
struct app {
    uint8_t *raw;
    size_t raw_len;
    size_t wasm_len;
    size_t component_len;
    const uint8_t *wasm;
    const uint8_t *digest;
    const uint8_t *component;
    uint64_t generation;
    uint64_t sequence;
    int slot;
};
static int app_id(const uint8_t *id, size_t id_len)
{
    static const uint8_t tag[] = "twep-app-v1";
    size_t offset = 2 + sizeof(tag) - 1;
    size_t name_len;
    size_t i;

    if (!id || id_len < offset + 2 || id[0] != 0x82 ||
        id[1] != 0x40 + sizeof(tag) - 1 ||
        memcmp(id + 2, tag, sizeof(tag) - 1) != 0) {
        return 0;
    }
    if (id[offset] >= 0x41 && id[offset] <= 0x57) {
        name_len = id[offset++] - 0x40;
    } else if (id[offset] == 0x58 && offset + 1 < id_len &&
               id[offset + 1] >= 24) {
        name_len = id[offset + 1];
        offset += 2;
    } else {
        return 0;
    }
    if (!name_len || offset + name_len != id_len) {
        return 0;
    }
    for (i = offset; i < id_len; ++i) {
        if (!id[i]) {
            return 0;
        }
    }
    return 1;
}
/* Validate the fixed binary app record without changing its byte layout. */
static int app_parse(struct app *app)
{
    uint32_t component_len;
    uint32_t wasm_len;
    uint8_t computed_digest[32];

    if (!app->raw || app->raw_len < SGX_PROTECTED_APP_HEADER ||
        memcmp(app->raw, app_magic, sizeof(app_magic)) != 0) {
        return 0;
    }

    app->generation = sgx_protected_be64(app->raw + 8);
    app->sequence = sgx_protected_be64(app->raw + 16);
    component_len = sgx_protected_be32(app->raw + 24);
    wasm_len = sgx_protected_be32(app->raw + 28);
    if (!app->generation || !app->sequence || !component_len || !wasm_len ||
        wasm_len > SGX_PROTECTED_APP_MAX ||
        SGX_PROTECTED_APP_HEADER + (size_t)component_len + wasm_len != app->raw_len) {
        return 0;
    }

    app->digest = app->raw + 32;
    app->component = app->raw + SGX_PROTECTED_APP_HEADER;
    app->component_len = component_len;
    app->wasm = app->component + component_len;
    app->wasm_len = wasm_len;
    return app_id(app->component, component_len) &&
           sgx_protected_sha256(app->wasm, wasm_len, computed_digest) &&
           memcmp(computed_digest, app->digest, sizeof(computed_digest)) == 0;
}

static void app_free(struct app *app)
{
    if (app->raw) {
        memset(app->raw, 0, app->raw_len);
        free(app->raw);
    }
    memset(app, 0, sizeof(*app));
}

/* Read and validate one physical protected-app slot. */
static int app_slot(int slot, struct app *app)
{
    const char *name = slot ? "app-slot-1" : "app-slot-0";
    size_t record_len = 0;
    int status;

    status = sgx_store_read(name, "app-state", NULL, 0, &record_len);
    if (status != SGX_STORE_OK) {
        return status;
    }
    if (!record_len || record_len > SGX_PROTECTED_APP_MAX + 512) {
        return SGX_STORE_CORRUPT;
    }

    app->raw = malloc(record_len);
    if (!app->raw) {
        return SGX_STORE_PLATFORM;
    }
    status = sgx_store_read(name, "app-state", app->raw, record_len, &app->raw_len);
    if (status != SGX_STORE_OK || !app_parse(app)) {
        if (status == SGX_STORE_OK) {
            status = SGX_STORE_CORRUPT;
        }
        app_free(app);
        return status;
    }

    app->slot = slot;
    return SGX_STORE_OK;
}

/* Select the newest app slot activated by protected acceptance state. */
static int active_app(struct app *out)
{
    struct sgx_protected_acceptance acceptance;
    struct app slots[2] = {{0}};
    uint64_t accepted_sequence;
    int selected_slot = -1;
    int matching_slots = 0;
    int status;
    int slot;

    status = sgx_protected_load_acceptance(&acceptance);
    if (status != SGX_STORE_OK) {
        return status;
    }
    for (slot = 0; slot < 2; ++slot) {
        status = app_slot(slot, &slots[slot]);
        if (status == SGX_STORE_NOT_FOUND) {
            continue;
        }
        if (status != SGX_STORE_OK ||
            !sgx_protected_find_sequence(&acceptance, slots[slot].component,
                           slots[slot].component_len, &accepted_sequence) ||
            accepted_sequence != slots[slot].sequence ||
            acceptance.generation < slots[slot].generation) {
            continue;
        }

        ++matching_slots;
        if (selected_slot < 0 ||
            slots[slot].generation > slots[selected_slot].generation) {
            selected_slot = slot;
        }
    }

    if (!matching_slots) {
        status = SGX_STORE_NOT_FOUND;
        goto cleanup;
    }
    if (matching_slots == 2 && slots[0].generation == slots[1].generation &&
        (slots[0].raw_len != slots[1].raw_len ||
         memcmp(slots[0].raw, slots[1].raw, slots[0].raw_len) != 0)) {
        status = SGX_STORE_CORRUPT;
        goto cleanup;
    }

    *out = slots[selected_slot];
    memset(&slots[selected_slot], 0, sizeof(slots[selected_slot]));
    status = SGX_STORE_OK;

cleanup:
    app_free(&slots[0]);
    app_free(&slots[1]);
    return status;
}
int sgx_app_read_active(uint8_t *out,size_t cap,size_t *len,uint8_t digest[32],
 uint8_t *component,size_t component_cap,size_t *component_len,uint64_t *seq)
{
    struct app app = {0};
    int status;

    if (!len) {
        return SGX_STORE_INVALID;
    }
    status = active_app(&app);
    if (status != SGX_STORE_OK) {
        return status;
    }

    *len = app.wasm_len;
    if (component_len) {
        *component_len = app.component_len;
    }
    if (!out || cap < app.wasm_len ||
        (component && component_cap < app.component_len)) {
        status = SGX_STORE_SHORT_BUFFER;
    } else {
        memcpy(out, app.wasm, app.wasm_len);
        if (digest) {
            memcpy(digest, app.digest, 32);
        }
        if (component) {
            memcpy(component, app.component, app.component_len);
        }
        if (seq) {
            *seq = app.sequence;
        }
    }

    app_free(&app);
    return status;
}

/* Stage the inactive app slot, then activate it by acceptance-state commit. */
int sgx_app_commit(const uint8_t q[32],const uint8_t *id,size_t ilen,uint64_t seq,
 uint64_t expected,const uint8_t *wasm,size_t n,const uint8_t supplied[32],uint64_t *next)
{
    struct sgx_protected_acceptance acceptance;
    struct app active = {0};
    uint8_t digest[32];
    uint8_t *record = NULL;
    size_t record_len = 0;
    uint64_t prior_sequence;
    int target_slot = 0;
    int status;

    if (!q || !app_id(id, ilen) || !seq || !wasm || !n ||
        n > SGX_PROTECTED_APP_MAX || !supplied || !next ||
        !sgx_protected_sha256(wasm, n, digest) || memcmp(digest, supplied, sizeof(digest)) != 0 ||
        expected == UINT64_MAX) {
        return SGX_STORE_INVALID;
    }

    status = sgx_protected_load_acceptance(&acceptance);
    if (status != SGX_STORE_OK) {
        return status;
    }
    if (acceptance.generation != expected) {
        return SGX_PROTECTED_STATE_CONFLICT;
    }
    if (sgx_protected_find_sequence(&acceptance, id, ilen, &prior_sequence) &&
        seq <= prior_sequence) {
        return SGX_PROTECTED_STATE_CONFLICT;
    }

    status = active_app(&active);
    if (status == SGX_STORE_OK) {
        target_slot = 1 - active.slot;
    } else if (status != SGX_STORE_NOT_FOUND) {
        goto cleanup;
    }

    record_len = SGX_PROTECTED_APP_HEADER + ilen + n;
    record = malloc(record_len);
    if (!record) {
        status = SGX_STORE_PLATFORM;
        goto cleanup;
    }
    memcpy(record, app_magic, sizeof(app_magic));
    sgx_protected_write_be64(record + 8, expected + 1);
    sgx_protected_write_be64(record + 16, seq);
    sgx_protected_write_be32(record + 24, (uint32_t)ilen);
    sgx_protected_write_be32(record + 28, (uint32_t)n);
    memcpy(record + 32, digest, sizeof(digest));
    memcpy(record + SGX_PROTECTED_APP_HEADER, id, ilen);
    memcpy(record + SGX_PROTECTED_APP_HEADER + ilen, wasm, n);

    status = sgx_store_write_verified(target_slot ? "app-slot-1" : "app-slot-0",
                                      "app-state", record, record_len);
    if (status == SGX_STORE_OK) {
        status = sgx_acceptance_commit(q, id, ilen, seq, expected, next);
    }

cleanup:
    if (record) {
        memset(record, 0, record_len);
        free(record);
    }
    app_free(&active);
    return status;
}
