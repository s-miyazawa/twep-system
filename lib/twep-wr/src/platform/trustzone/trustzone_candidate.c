/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */
#include "trustzone_internal.h"

#include <stdlib.h>
#include <string.h>

twep_wr_status_t twep_tz_read_wrapped_error_artifacts(
    const twep_wr_context_t *ctx,
    uint8_t **out_teep_agent_wasm,
    size_t *out_teep_agent_wasm_len,
    uint8_t **out_catalog,
    size_t *out_catalog_len,
    uint8_t **out_app_wasm,
    size_t *out_app_wasm_len)
{
    char path[TWEP_WR_MAX_PATH_LEN];
    twep_wr_status_t status;

    if (ctx == NULL || out_teep_agent_wasm == NULL || out_teep_agent_wasm_len == NULL
        || out_catalog == NULL || out_catalog_len == NULL || out_app_wasm == NULL || out_app_wasm_len == NULL) {
        return TWEP_WR_ERR_INVALID_ARGUMENT;
    }
    *out_teep_agent_wasm = NULL;
    *out_teep_agent_wasm_len = 0;
    *out_catalog = NULL;
    *out_catalog_len = 0;
    *out_app_wasm = NULL;
    *out_app_wasm_len = 0;

    status = twep_wr_ensure_state_layout(ctx);
    if (status != TWEP_WR_OK) {
        return status;
    }
    status = twep_wr_ensure_teep_agent(ctx);
    if (status != TWEP_WR_OK) {
        return status;
    }
    status = twep_wr_ensure_state_catalog(ctx);
    if (status != TWEP_WR_OK) {
        return status;
    }
    status = twep_wr_ensure_state_app(ctx, "helloworld.wasm");
    if (status != TWEP_WR_OK) {
        return status;
    }

    status = twep_tz_read_teep_agent_wasm(ctx, out_teep_agent_wasm, out_teep_agent_wasm_len);
    if (status != TWEP_WR_OK) {
        return status;
    }
    if (!twep_wr_state_path(ctx, "catalog", "catalog.cbor", path, sizeof(path))) {
        twep_tz_free_artifacts(*out_teep_agent_wasm, NULL, NULL);
        *out_teep_agent_wasm = NULL;
        return TWEP_WR_ERR_CATALOG;
    }
    *out_catalog = twep_wr_read_file(path, out_catalog_len);
    if (*out_catalog == NULL) {
        twep_tz_free_artifacts(*out_teep_agent_wasm, NULL, NULL);
        *out_teep_agent_wasm = NULL;
        return TWEP_WR_ERR_CATALOG;
    }
    if (!twep_wr_state_path(ctx, "apps", "helloworld.wasm", path, sizeof(path))) {
        twep_tz_free_artifacts(*out_teep_agent_wasm, *out_catalog, NULL);
        *out_teep_agent_wasm = NULL;
        *out_catalog = NULL;
        return TWEP_WR_ERR_WASM_LOAD;
    }
    *out_app_wasm = twep_wr_read_file(path, out_app_wasm_len);
    if (*out_app_wasm == NULL) {
        twep_tz_free_artifacts(*out_teep_agent_wasm, *out_catalog, NULL);
        *out_teep_agent_wasm = NULL;
        *out_catalog = NULL;
        return TWEP_WR_ERR_WASM_LOAD;
    }
    return TWEP_WR_OK;
}

twep_wr_status_t twep_tz_read_resolved_app_artifacts(
    const twep_wr_context_t *ctx,
    const char *wasm_file,
    uint8_t **out_teep_agent_wasm,
    size_t *out_teep_agent_wasm_len,
    uint8_t **out_catalog,
    size_t *out_catalog_len,
    uint8_t **out_app_wasm,
    size_t *out_app_wasm_len)
{
    char path[TWEP_WR_MAX_PATH_LEN];
    twep_wr_status_t status;

    if (ctx == NULL || wasm_file == NULL || out_teep_agent_wasm == NULL || out_teep_agent_wasm_len == NULL
        || out_catalog == NULL || out_catalog_len == NULL || out_app_wasm == NULL || out_app_wasm_len == NULL) {
        return TWEP_WR_ERR_INVALID_ARGUMENT;
    }
    *out_teep_agent_wasm = NULL;
    *out_teep_agent_wasm_len = 0;
    *out_catalog = NULL;
    *out_catalog_len = 0;
    *out_app_wasm = NULL;
    *out_app_wasm_len = 0;

    status = twep_wr_ensure_state_layout(ctx);
    if (status != TWEP_WR_OK) {
        return status;
    }
    status = twep_wr_ensure_teep_agent(ctx);
    if (status != TWEP_WR_OK) {
        return status;
    }
    status = twep_wr_ensure_state_catalog(ctx);
    if (status != TWEP_WR_OK) {
        return status;
    }
    status = twep_wr_ensure_state_app(ctx, wasm_file);
    if (status != TWEP_WR_OK) {
        return status;
    }

    status = twep_tz_read_teep_agent_wasm(ctx, out_teep_agent_wasm, out_teep_agent_wasm_len);
    if (status != TWEP_WR_OK) {
        return status;
    }
    if (!twep_wr_state_path(ctx, "catalog", "catalog.cbor", path, sizeof(path))) {
        twep_tz_free_artifacts(*out_teep_agent_wasm, NULL, NULL);
        *out_teep_agent_wasm = NULL;
        return TWEP_WR_ERR_CATALOG;
    }
    *out_catalog = twep_wr_read_file(path, out_catalog_len);
    if (*out_catalog == NULL) {
        twep_tz_free_artifacts(*out_teep_agent_wasm, NULL, NULL);
        *out_teep_agent_wasm = NULL;
        return TWEP_WR_ERR_CATALOG;
    }
    if (!twep_wr_state_path(ctx, "apps", wasm_file, path, sizeof(path))) {
        twep_tz_free_artifacts(*out_teep_agent_wasm, *out_catalog, NULL);
        *out_teep_agent_wasm = NULL;
        *out_catalog = NULL;
        return TWEP_WR_ERR_WASM_LOAD;
    }
    *out_app_wasm = twep_wr_read_file(path, out_app_wasm_len);
    if (*out_app_wasm == NULL) {
        twep_tz_free_artifacts(*out_teep_agent_wasm, *out_catalog, NULL);
        *out_teep_agent_wasm = NULL;
        *out_catalog = NULL;
        return TWEP_WR_ERR_WASM_LOAD;
    }
    return TWEP_WR_OK;
}

twep_wr_status_t twep_tz_read_verified_acceptance_artifacts(
    const twep_wr_context_t *ctx,
    uint8_t **out_teep_agent_wasm,
    size_t *out_teep_agent_wasm_len)
{
    twep_wr_status_t status;

    if (ctx == NULL || out_teep_agent_wasm == NULL || out_teep_agent_wasm_len == NULL) {
        return TWEP_WR_ERR_INVALID_ARGUMENT;
    }
    *out_teep_agent_wasm = NULL;
    *out_teep_agent_wasm_len = 0;

    status = twep_wr_ensure_state_layout(ctx);
    if (status != TWEP_WR_OK) {
        return status;
    }
    status = twep_wr_ensure_teep_agent(ctx);
    if (status != TWEP_WR_OK) {
        return status;
    }
    return twep_tz_read_teep_agent_wasm(ctx, out_teep_agent_wasm, out_teep_agent_wasm_len);
}
