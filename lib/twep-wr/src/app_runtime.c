/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */
#include "runtime_internal.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint8_t *read_wasm_from_state(const twep_wr_context_t *ctx, const char *wasm_file, size_t *wasm_len);
static void apply_instruction_budget(wasm_exec_env_t exec_env, uint32_t timeout_ms);
static twep_wr_status_t extract_optional_stdout(const uint8_t *app_output, size_t app_output_len,
                                                const uint8_t **out_stdout, size_t *out_stdout_len);

twep_wr_status_t twep_wr_run_app_wasm(const twep_wr_context_t *ctx, const twep_wr_normalized_request_t *request,
                                      twep_wr_owned_bytes_t *out_response_cbor)
{
    catalog_entry_t entry;
    twep_wr_status_t catalog_status = twep_wr_lookup_catalog_entry(ctx, request->command, &entry);
    if (catalog_status != TWEP_WR_OK) {
        return catalog_status;
    }
    uint32_t effective_timeout_ms = entry.timeout_ms == 0 ? ctx->default_timeout_ms : entry.timeout_ms;
    if (request->request_timeout_ms != 0 && request->request_timeout_ms < effective_timeout_ms) {
        effective_timeout_ms = request->request_timeout_ms;
    }
    if (effective_timeout_ms == 0) {
        effective_timeout_ms = 5000u;
    }

    size_t wasm_len = 0;
    uint8_t *wasm_bytes = read_wasm_from_state(ctx, entry.wasm_file, &wasm_len);
    if (wasm_bytes == NULL) {
        return TWEP_WR_ERR_WASM_LOAD;
    }
    if (!twep_wr_sha256_matches(wasm_bytes, wasm_len, entry.sha256)) {
        free(wasm_bytes);
        return TWEP_WR_ERR_SECURITY;
    }
    if (!twep_wr_verify_wasm_signature(wasm_bytes, wasm_len, TWEP_WR_WASM_SIGNATURE_ROLE_APP)) {
        free(wasm_bytes);
        return TWEP_WR_ERR_WASM_SIGNATURE;
    }

    char error_buf[TWEP_WR_ERROR_BUF_SIZE] = { 0 };
    wasm_module_t module = wasm_runtime_load(wasm_bytes, (uint32_t)wasm_len, error_buf, sizeof(error_buf));
    if (module == NULL) {
        free(wasm_bytes);
        return TWEP_WR_ERR_WASM_LOAD;
    }

    wasm_module_inst_t module_inst =
        wasm_runtime_instantiate(module, entry.stack_bytes, entry.heap_bytes, error_buf, sizeof(error_buf));
    if (module_inst == NULL) {
        wasm_runtime_unload(module);
        free(wasm_bytes);
        return TWEP_WR_ERR_WASM_LOAD;
    }

    wasm_exec_env_t exec_env = wasm_runtime_create_exec_env(module_inst, entry.stack_bytes);
    if (exec_env == NULL) {
        wasm_runtime_deinstantiate(module_inst);
        wasm_runtime_unload(module);
        free(wasm_bytes);
        return TWEP_WR_ERR_NO_MEMORY;
    }

    twep_wr_status_t status = TWEP_WR_OK;
    uint32_t abi_version = 0;
    uint32_t input_ptr = 0;
    uint8_t *input_native = NULL;
    uint32_t desc_ptr = 0;
    uint8_t *desc_native = NULL;
    uint32_t argv[3] = { 0, 0, 0 };
    uint32_t output_ptr = 0;
    uint32_t output_len = 0;
    uint8_t *output_native = NULL;
    const uint8_t *stdout_bytes = NULL;
    size_t stdout_len = 0;

    status = twep_wr_call_u32_no_args(exec_env, module_inst, "twep_app_abi_version", &abi_version);
    if (status != TWEP_WR_OK || abi_version != 1) {
        status = TWEP_WR_ERR_WASM_ABI;
        goto cleanup;
    }

    if (request->app_input_cbor.len > 0) {
        input_ptr = (uint32_t)wasm_runtime_module_malloc(module_inst, request->app_input_cbor.len, (void **)&input_native);
        if (input_ptr == 0 || input_native == NULL) {
            status = TWEP_WR_ERR_NO_MEMORY;
            goto cleanup;
        }
        memcpy(input_native, request->app_input_cbor.ptr, request->app_input_cbor.len);
    }

    desc_ptr = (uint32_t)wasm_runtime_module_malloc(module_inst, 8, (void **)&desc_native);
    if (desc_ptr == 0 || desc_native == NULL) {
        status = TWEP_WR_ERR_NO_MEMORY;
        goto cleanup;
    }
    memset(desc_native, 0, 8);

    wasm_function_inst_t main_func = wasm_runtime_lookup_function(module_inst, "twep_app_main");
    if (main_func == NULL) {
        status = TWEP_WR_ERR_WASM_ABI;
        goto cleanup;
    }

    argv[0] = input_ptr;
    argv[1] = (uint32_t)request->app_input_cbor.len;
    argv[2] = desc_ptr;
    apply_instruction_budget(exec_env, effective_timeout_ms);
    if (!wasm_runtime_call_wasm(exec_env, main_func, 3, argv)) {
        const char *exception = wasm_runtime_get_exception(module_inst);
        if (exception != NULL) {
            fprintf(stderr, "twep-wr wasm exception: %s\n", exception);
        }
        status = TWEP_WR_ERR_WASM_RUNTIME;
        goto cleanup;
    }
    if ((int32_t)argv[0] != 0) {
        status = twep_wr_make_app_error_response(request->request_id, (int32_t)argv[0], request->command,
                                                 entry.wasm_file, out_response_cbor);
        goto cleanup;
    }

    output_ptr = (uint32_t)desc_native[0] | ((uint32_t)desc_native[1] << 8) | ((uint32_t)desc_native[2] << 16)
                 | ((uint32_t)desc_native[3] << 24);
    output_len = (uint32_t)desc_native[4] | ((uint32_t)desc_native[5] << 8) | ((uint32_t)desc_native[6] << 16)
                 | ((uint32_t)desc_native[7] << 24);
    if (output_ptr == 0 || output_len == 0 || !wasm_runtime_validate_app_addr(module_inst, output_ptr, output_len)) {
        status = TWEP_WR_ERR_WASM_ABI;
        goto cleanup;
    }
    if (output_len > entry.max_output_bytes) {
        status = TWEP_WR_ERR_WASM_RUNTIME;
        goto cleanup;
    }
    output_native = (uint8_t *)wasm_runtime_addr_app_to_native(module_inst, output_ptr);
    if (output_native == NULL) {
        status = TWEP_WR_ERR_WASM_ABI;
        goto cleanup;
    }
    status = extract_optional_stdout(output_native, output_len, &stdout_bytes, &stdout_len);
    if (status != TWEP_WR_OK) {
        goto cleanup;
    }
    status = twep_wr_make_response(request->request_id, stdout_bytes, stdout_len, output_native, output_len,
                                   out_response_cbor);

cleanup:
    if (output_ptr != 0) {
        (void)twep_wr_call_free(exec_env, module_inst, output_ptr, output_len);
    }
    if (desc_ptr != 0) {
        wasm_runtime_module_free(module_inst, desc_ptr);
    }
    if (input_ptr != 0) {
        wasm_runtime_module_free(module_inst, input_ptr);
    }
    wasm_runtime_destroy_exec_env(exec_env);
    wasm_runtime_deinstantiate(module_inst);
    wasm_runtime_unload(module);
    free(wasm_bytes);
    return status;
}

static uint8_t *read_wasm_from_state(const twep_wr_context_t *ctx, const char *wasm_file, size_t *wasm_len)
{
    char path[TWEP_WR_MAX_PATH_LEN];
    if (!twep_wr_state_path(ctx, "apps", wasm_file, path, sizeof(path))) {
        return NULL;
    }
    return twep_wr_read_file(path, wasm_len);
}

static void apply_instruction_budget(wasm_exec_env_t exec_env, uint32_t timeout_ms)
{
    if (timeout_ms == 0) {
        return;
    }
    uint64_t budget = (uint64_t)timeout_ms * 100000u;
    if (budget > INT32_MAX) {
        budget = INT32_MAX;
    }
    wasm_runtime_set_instruction_count_limit(exec_env, (int)budget);
}

static twep_wr_status_t extract_optional_stdout(const uint8_t *app_output, size_t app_output_len,
                                                const uint8_t **out_stdout, size_t *out_stdout_len)
{
    *out_stdout = NULL;
    *out_stdout_len = 0;
    size_t off = 0;
    uint8_t major = 0;
    uint64_t pairs = 0;
    if (!twep_wr_cbor_read_head(app_output, app_output_len, &off, &major, &pairs) || major != 5) {
        return TWEP_WR_ERR_WASM_ABI;
    }
    for (uint64_t i = 0; i < pairs; i++) {
        bytes_view_t key;
        if (!twep_wr_cbor_read_text_view(app_output, app_output_len, &off, &key)) {
            return TWEP_WR_ERR_WASM_ABI;
        }
        if (twep_wr_bytes_equal_text(key, "stdout")) {
            bytes_view_t stdout_view;
            if (!twep_wr_cbor_read_bytes_view(app_output, app_output_len, &off, &stdout_view)) {
                return TWEP_WR_ERR_WASM_ABI;
            }
            *out_stdout = stdout_view.ptr;
            *out_stdout_len = stdout_view.len;
        } else if (!twep_wr_cbor_skip_value(app_output, app_output_len, &off)) {
            return TWEP_WR_ERR_WASM_ABI;
        }
    }
    if (off != app_output_len) {
        return TWEP_WR_ERR_WASM_ABI;
    }
    return TWEP_WR_OK;
}
