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

typedef enum {
    TWEP_WR_TZ_RESPONSE_FINAL,
    TWEP_WR_TZ_RESPONSE_NEED_HOST_IO,
} twep_wr_tz_response_kind_t;

typedef struct {
    bytes_view_t request_id;
    bytes_view_t io_id;
    bytes_view_t kind;
    bytes_view_t url;
    bytes_view_t body;
    bytes_view_t challenge;
    bytes_view_t agent_public_key_cose;
    bytes_view_t request_body_sha256;
    bytes_view_t normalized_input_sha256;
    uint32_t sequence;
} twep_wr_tz_need_host_io_t;

TWEP_TZ_HIDDEN twep_wr_platform_status_t twep_tz_open(twep_tz_session_t *session);
TWEP_TZ_HIDDEN void twep_tz_close(twep_tz_session_t *session);
TWEP_TZ_HIDDEN twep_wr_platform_status_t twep_tz_platform_status(TEEC_Result result);
TWEP_TZ_HIDDEN twep_wr_status_t twep_tz_wr_status(TEEC_Result result);
TWEP_TZ_HIDDEN void twep_tz_free_artifacts(
    uint8_t *teep_agent_wasm,
    uint8_t *catalog,
    uint8_t *app_wasm);
TWEP_TZ_HIDDEN twep_wr_status_t twep_tz_read_dev_agent_public_key(
    const twep_wr_context_t *ctx,
    uint8_t **out_public_key,
    size_t *out_public_key_len);
TWEP_TZ_HIDDEN twep_wr_status_t twep_tz_read_teep_agent_wasm(
    const twep_wr_context_t *ctx,
    uint8_t **out_teep_agent_wasm,
    size_t *out_teep_agent_wasm_len);
TWEP_TZ_HIDDEN twep_wr_status_t twep_tz_read_wrapped_error_artifacts(
    const twep_wr_context_t *ctx,
    uint8_t **out_teep_agent_wasm,
    size_t *out_teep_agent_wasm_len,
    uint8_t **out_catalog,
    size_t *out_catalog_len,
    uint8_t **out_app_wasm,
    size_t *out_app_wasm_len);
TWEP_TZ_HIDDEN twep_wr_status_t twep_tz_read_resolved_app_artifacts(
    const twep_wr_context_t *ctx,
    const char *wasm_file,
    uint8_t **out_teep_agent_wasm,
    size_t *out_teep_agent_wasm_len,
    uint8_t **out_catalog,
    size_t *out_catalog_len,
    uint8_t **out_app_wasm,
    size_t *out_app_wasm_len);
TWEP_TZ_HIDDEN twep_wr_status_t twep_tz_read_verified_acceptance_artifacts(
    const twep_wr_context_t *ctx,
    uint8_t **out_teep_agent_wasm,
    size_t *out_teep_agent_wasm_len);
TWEP_TZ_HIDDEN bool twep_tz_bytes_view_equals(
    bytes_view_t view,
    const uint8_t *bytes,
    size_t len);
TWEP_TZ_HIDDEN void twep_tz_write_verified_diagnostics(
    const twep_wr_context_t *ctx);
TWEP_TZ_HIDDEN void twep_tz_write_verified_evidence_snapshot(
    const twep_wr_context_t *ctx,
    const uint8_t *evidence_result,
    size_t evidence_result_len,
    const uint8_t *acceptance_slot0,
    size_t acceptance_slot0_len,
    const uint8_t *acceptance_slot1,
    size_t acceptance_slot1_len);
TWEP_TZ_HIDDEN twep_wr_platform_status_t twep_tz_session_secure_storage_get(
    twep_tz_session_t *session,
    const char *object_name,
    uint8_t **out,
    size_t *out_len);
TWEP_TZ_HIDDEN bool twep_tz_parse_response(
    const uint8_t *buf,
    size_t len,
    twep_wr_tz_response_kind_t *out_kind,
    bytes_view_t *out_final_response,
    twep_wr_tz_need_host_io_t *out_need);
TWEP_TZ_HIDDEN twep_wr_status_t twep_tz_perform_host_io(
    const twep_wr_context_t *ctx,
    const twep_wr_tz_need_host_io_t *need,
    uint8_t **out_result,
    size_t *out_result_len);
TWEP_TZ_HIDDEN uint8_t *twep_tz_make_resume_envelope(
    bytes_view_t request_id,
    const uint8_t *host_io_result,
    size_t host_io_result_len,
    size_t *out_len);

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
