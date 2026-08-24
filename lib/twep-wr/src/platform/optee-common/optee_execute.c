/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */
#include "optee_internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <twep_wr_ta.h>
#include <tee_client_api.h>

#define TWEP_WR_OPTEE_EXECUTE_RESPONSE_CAP (64u * 1024u)
#define TWEP_WR_OPTEE_HOST_IO_MAX_ROUNDS 8u

twep_wr_status_t twep_wr_optee_execute(const twep_wr_context_t *ctx,
                                           const twep_wr_normalized_request_t *request,
                                           twep_wr_owned_bytes_t *out_response_cbor)
{
    twep_optee_session_t session;
    twep_wr_platform_status_t platform_status;
    TEEC_Operation op;
    TEEC_Result res;
    uint32_t origin = 0;
    uint8_t *teep_agent_wasm = NULL;
    uint8_t *catalog = NULL;
    uint8_t *app_wasm = NULL;
    uint8_t *dev_agent_public_key = NULL;
    uint8_t *envelope = NULL;
    uint8_t *response = NULL;
    size_t teep_agent_wasm_len = 0;
    size_t catalog_len = 0;
    size_t app_wasm_len = 0;
    size_t dev_agent_public_key_len = 0;
    size_t envelope_len = 0;
    uint32_t timeout_ms;
    twep_wr_status_t status;
    const char *wasm_file = NULL;
    bool command_is_wrapped;
    bool verified_acceptance;

    if (ctx == NULL || request == NULL || out_response_cbor == NULL) {
        return TWEP_WR_ERR_INVALID_ARGUMENT;
    }

    command_is_wrapped = strcmp(request->command, "teep-agent-resolve-wrapped") == 0;
    verified_acceptance = ctx->resolver_mode != NULL &&
                          strcmp(ctx->resolver_mode, "attestam-verified") == 0;
    if (command_is_wrapped) {
        if (request->app_input_cbor.ptr == NULL || request->app_input_cbor.len == 0u) {
            return TWEP_WR_ERR_INVALID_ARGUMENT;
        }
    } else if (strcmp(request->command, "helloworld") == 0 ||
               strcmp(request->command, "remotehello") == 0) {
        wasm_file = "helloworld.wasm";
    } else if (strcmp(request->command, "calcadd") == 0) {
        wasm_file = "calcadd.wasm";
    } else if (strcmp(request->command, "negaposi") == 0) {
        wasm_file = "negaposi.wasm";
    } else {
        return TWEP_WR_ERR_TEEP;
    }

    if (verified_acceptance) {
        status = twep_optee_read_verified_acceptance_artifacts(
            ctx, &teep_agent_wasm, &teep_agent_wasm_len);
        if (status != TWEP_WR_OK) {
            return status;
        }
    } else if (command_is_wrapped) {
        status = twep_optee_read_wrapped_error_artifacts(
            ctx, &teep_agent_wasm, &teep_agent_wasm_len, &catalog, &catalog_len, &app_wasm, &app_wasm_len);
        if (status != TWEP_WR_OK) {
            return status;
        }
    } else {
        status = twep_optee_read_resolved_app_artifacts(
            ctx, wasm_file, &teep_agent_wasm, &teep_agent_wasm_len, &catalog, &catalog_len,
            &app_wasm, &app_wasm_len);
        if (status != TWEP_WR_OK) {
            return status;
        }
    }
    status = twep_optee_read_dev_agent_public_key(ctx, &dev_agent_public_key, &dev_agent_public_key_len);
    if (status != TWEP_WR_OK) {
        twep_optee_free_artifacts(teep_agent_wasm, catalog, app_wasm);
        return status;
    }
    timeout_ms = request->request_timeout_ms == 0u ? ctx->default_timeout_ms : request->request_timeout_ms;
    envelope = twep_optee_make_execute_envelope(ctx, request, teep_agent_wasm, teep_agent_wasm_len, catalog, catalog_len,
                                               app_wasm, app_wasm_len, dev_agent_public_key, dev_agent_public_key_len,
                                               timeout_ms, &envelope_len);
    twep_optee_free_artifacts(teep_agent_wasm, catalog, app_wasm);
    free(dev_agent_public_key);
    if (envelope == NULL) {
        return TWEP_WR_ERR_NO_MEMORY;
    }
    response = (uint8_t *)malloc(TWEP_WR_OPTEE_EXECUTE_RESPONSE_CAP);
    if (response == NULL) {
        free(envelope);
        return TWEP_WR_ERR_NO_MEMORY;
    }
    twep_optee_write_verified_diagnostics(ctx);

    platform_status = twep_optee_open(&session);
    if (platform_status != TWEP_WR_PLATFORM_OK) {
        free(response);
        free(envelope);
        return platform_status == TWEP_WR_PLATFORM_ERR_NO_MEMORY ? TWEP_WR_ERR_NO_MEMORY : TWEP_WR_ERR_TEEP;
    }

    for (uint32_t round = 0; round < TWEP_WR_OPTEE_HOST_IO_MAX_ROUNDS; round++) {
        twep_wr_optee_response_kind_t response_kind;
        twep_wr_optee_need_host_io_t need;
        bytes_view_t final_response = {0};
        uint8_t *host_io_result = NULL;
        uint8_t *resume_envelope = NULL;
        size_t host_io_result_len = 0;
        size_t resume_envelope_len = 0;
        uint32_t command = round == 0 ? TA_TWEP_WR_CMD_EXECUTE : TA_TWEP_WR_CMD_RESUME_HOST_IO;

        memset(&op, 0, sizeof(op));
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                         TEEC_MEMREF_TEMP_OUTPUT,
                                         TEEC_NONE, TEEC_NONE);
        op.params[0].tmpref.buffer = envelope;
        op.params[0].tmpref.size = envelope_len;
        op.params[1].tmpref.buffer = response;
        op.params[1].tmpref.size = TWEP_WR_OPTEE_EXECUTE_RESPONSE_CAP;

        res = TEEC_InvokeCommand(&session.sess, command, &op, &origin);
        free(envelope);
        envelope = NULL;
        envelope_len = 0;
        if (res != TEEC_SUCCESS) {
            twep_optee_close(&session);
            free(response);
            return twep_optee_wr_status(res);
        }
        if (!twep_optee_parse_response(response, op.params[1].tmpref.size,
                                      &response_kind, &final_response, &need)) {
            uint8_t *evidence_result = NULL;
            uint8_t *acceptance_slot0 = NULL;
            uint8_t *acceptance_slot1 = NULL;
            size_t evidence_result_len = 0;
            size_t acceptance_slot0_len = 0;
            size_t acceptance_slot1_len = 0;
            bool have_evidence_snapshot = false;

            out_response_cbor->ptr = response;
            out_response_cbor->len = op.params[1].tmpref.size;
            if (verified_acceptance &&
                twep_optee_session_secure_storage_get(
                    &session, "verified-evidence-result.cbor",
                    &evidence_result, &evidence_result_len) == TWEP_WR_PLATFORM_OK &&
                twep_optee_session_secure_storage_get(
                    &session, "teep-acceptance-state.0.cbor",
                    &acceptance_slot0, &acceptance_slot0_len) == TWEP_WR_PLATFORM_OK) {
                (void)twep_optee_session_secure_storage_get(
                    &session, "teep-acceptance-state.1.cbor",
                    &acceptance_slot1, &acceptance_slot1_len);
                have_evidence_snapshot = true;
            }
            twep_optee_close(&session);
            if (have_evidence_snapshot) {
                twep_optee_write_verified_evidence_snapshot(
                    ctx, evidence_result, evidence_result_len,
                    acceptance_slot0, acceptance_slot0_len,
                    acceptance_slot1, acceptance_slot1_len);
            }
            free(evidence_result);
            free(acceptance_slot0);
            free(acceptance_slot1);
            return TWEP_WR_OK;
        }
        if (response_kind == TWEP_WR_OPTEE_RESPONSE_FINAL) {
            uint8_t *final_copy = (uint8_t *)malloc(final_response.len == 0u ? 1u : final_response.len);
            uint8_t *evidence_result = NULL;
            uint8_t *acceptance_slot0 = NULL;
            uint8_t *acceptance_slot1 = NULL;
            size_t evidence_result_len = 0;
            size_t acceptance_slot0_len = 0;
            size_t acceptance_slot1_len = 0;
            bool have_evidence_snapshot = false;
            if (final_copy == NULL) {
                twep_optee_close(&session);
                free(response);
                return TWEP_WR_ERR_NO_MEMORY;
            }
            if (final_response.len != 0u) {
                memcpy(final_copy, final_response.ptr, final_response.len);
            }
            free(response);
            out_response_cbor->ptr = final_copy;
            out_response_cbor->len = final_response.len;
            if (verified_acceptance &&
                twep_optee_session_secure_storage_get(
                    &session, "verified-evidence-result.cbor",
                    &evidence_result, &evidence_result_len) == TWEP_WR_PLATFORM_OK &&
                twep_optee_session_secure_storage_get(
                    &session, "teep-acceptance-state.0.cbor",
                    &acceptance_slot0, &acceptance_slot0_len) == TWEP_WR_PLATFORM_OK) {
                (void)twep_optee_session_secure_storage_get(
                    &session, "teep-acceptance-state.1.cbor",
                    &acceptance_slot1, &acceptance_slot1_len);
                have_evidence_snapshot = true;
            }
            twep_optee_close(&session);
            if (have_evidence_snapshot) {
                twep_optee_write_verified_evidence_snapshot(
                    ctx, evidence_result, evidence_result_len,
                    acceptance_slot0, acceptance_slot0_len,
                    acceptance_slot1, acceptance_slot1_len);
            } else {
                twep_optee_write_verified_diagnostics(ctx);
            }
            free(evidence_result);
            free(acceptance_slot0);
            free(acceptance_slot1);
            return TWEP_WR_OK;
        }

        status = twep_optee_perform_host_io(ctx, &need, &host_io_result, &host_io_result_len);
        if (status != TWEP_WR_OK) {
            free(host_io_result);
            twep_optee_close(&session);
            free(response);
            return status;
        }
        resume_envelope = twep_optee_make_resume_envelope(need.request_id, host_io_result,
                                                         host_io_result_len, &resume_envelope_len);
        free(host_io_result);
        if (resume_envelope == NULL) {
            twep_optee_close(&session);
            free(response);
            return TWEP_WR_ERR_NO_MEMORY;
        }
        envelope = resume_envelope;
        envelope_len = resume_envelope_len;
    }
    twep_optee_close(&session);
    free(envelope);
    free(response);
    return TWEP_WR_ERR_TEEP;
}
