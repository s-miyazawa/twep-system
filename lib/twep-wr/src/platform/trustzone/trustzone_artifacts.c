/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */
#include "trustzone_internal.h"

#include <stdlib.h>
#include <string.h>

void twep_tz_free_artifacts(uint8_t *teep_agent_wasm, uint8_t *catalog, uint8_t *app_wasm)
{
    free(teep_agent_wasm);
    free(catalog);
    free(app_wasm);
}
twep_wr_status_t twep_tz_read_dev_agent_public_key(
    const twep_wr_context_t *ctx,
    uint8_t **out_public_key,
    size_t *out_public_key_len)
{
    char path[TWEP_WR_MAX_PATH_LEN];

    if (ctx == NULL || out_public_key == NULL || out_public_key_len == NULL) {
        return TWEP_WR_ERR_INVALID_ARGUMENT;
    }
    *out_public_key = NULL;
    *out_public_key_len = 0;
    if (!twep_wr_state_path(ctx, "teep-agent", "dev-agent-public-key.cbor", path, sizeof(path))) {
        return TWEP_WR_ERR_INVALID_ARGUMENT;
    }
    if (!twep_wr_file_exists(path)) {
        return TWEP_WR_OK;
    }
    *out_public_key = twep_wr_read_file(path, out_public_key_len);
    if (*out_public_key == NULL) {
        return TWEP_WR_ERR_TEEP;
    }
    return TWEP_WR_OK;
}

bool twep_tz_bytes_view_equals(bytes_view_t view, const uint8_t *bytes, size_t len)
{
    if (bytes == NULL || view.ptr == NULL || view.len != len) {
        return false;
    }
    return memcmp(view.ptr, bytes, len) == 0;
}

twep_wr_status_t twep_tz_read_teep_agent_wasm(const twep_wr_context_t *ctx,
                                                       uint8_t **out_teep_agent_wasm,
                                                       size_t *out_teep_agent_wasm_len)
{
    char path[TWEP_WR_MAX_PATH_LEN];

    if (ctx == NULL || out_teep_agent_wasm == NULL || out_teep_agent_wasm_len == NULL) {
        return TWEP_WR_ERR_INVALID_ARGUMENT;
    }
    *out_teep_agent_wasm = NULL;
    *out_teep_agent_wasm_len = 0;
    if (!twep_wr_state_path(ctx, "teep-agent", "teep-agent.wasm", path, sizeof(path))) {
        return TWEP_WR_ERR_TEEP;
    }
    *out_teep_agent_wasm = twep_wr_read_file(path, out_teep_agent_wasm_len);
    if (*out_teep_agent_wasm == NULL) {
        return TWEP_WR_ERR_TEEP;
    }
    return TWEP_WR_OK;
}
