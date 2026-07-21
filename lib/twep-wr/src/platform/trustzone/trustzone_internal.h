/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef TWEP_WR_TRUSTZONE_INTERNAL_H
#define TWEP_WR_TRUSTZONE_INTERNAL_H

#include "runtime_internal.h"

#include <stdbool.h>

#include <tee_client_api.h>

#if defined(__GNUC__)
#define TWEP_TZ_HIDDEN __attribute__((visibility("hidden")))
#else
#define TWEP_TZ_HIDDEN
#endif

typedef struct {
    TEEC_Context ctx;
    TEEC_Session sess;
    bool context_open;
    bool session_open;
} twep_tz_session_t;

TWEP_TZ_HIDDEN twep_wr_platform_status_t twep_tz_open(twep_tz_session_t *session);
TWEP_TZ_HIDDEN void twep_tz_close(twep_tz_session_t *session);
TWEP_TZ_HIDDEN twep_wr_platform_status_t twep_tz_platform_status(TEEC_Result result);
TWEP_TZ_HIDDEN twep_wr_status_t twep_tz_wr_status(TEEC_Result result);

/*
 * REE transport helpers carry candidate and diagnostic bytes only.  They do
 * not authorize Catalog publication, app promotion, or app execution.
 */
TWEP_TZ_HIDDEN uint8_t *twep_tz_make_execute_envelope(
    const twep_wr_context_t *ctx,
    const twep_wr_normalized_request_t *request,
    const uint8_t *teep_agent_wasm,
    size_t teep_agent_wasm_len,
    const uint8_t *catalog,
    size_t catalog_len,
    const uint8_t *app_wasm,
    size_t app_wasm_len,
    const uint8_t *dev_agent_public_key,
    size_t dev_agent_public_key_len,
    uint32_t timeout_ms,
    size_t *out_len);

#endif
