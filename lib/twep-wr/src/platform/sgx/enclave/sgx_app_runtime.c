/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */
#include "sgx_runtime_internal.h"
#include "twep_wr_sgx_t.h"

#include <sgx_tcrypto.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wasm_export.h>

/*
 * General applications execute entirely inside the Enclave and receive no
 * native hostcalls.  The REE may transport an app in development modes, but
 * the Catalog digest, role signature, limits, and Wasm memory checks below
 * remain Enclave decisions.
 */
static int wamr_initialized;

int sgx_wamr_ensure_initialized(void)
{
    if (!wamr_initialized && !wasm_runtime_init())
        return 0;
    wamr_initialized = 1;
    return 1;
}

static int read_artifact(const char *path, uint8_t **out, size_t *out_len)
{
    size_t len = 0;
    int result = 1;
    if (ocall_twep_read_artifact(&result, path, NULL, 0, &len) != SGX_SUCCESS
        || result != 0 || len == 0 || len > UINT32_MAX)
        return 0;
    *out = malloc(len);
    if (!*out)
        return 0;
    if (ocall_twep_read_artifact(&result, path, *out, len, &len) != SGX_SUCCESS
        || result != 0) {
        free(*out);
        *out = NULL;
        return 0;
    }
    *out_len = len;
    return 1;
}

static int protected_component_command(const uint8_t *id, size_t id_len,
                                       const char *command)
{
    static const uint8_t tag[] = "twep-app-v1";
    size_t off = 2 + sizeof(tag) - 1, command_len;
    if (!id || id_len <= off || id[0] != 0x82
        || id[1] != 0x40 + sizeof(tag) - 1
        || memcmp(id + 2, tag, sizeof(tag) - 1))
        return 0;
    if (id[off] >= 0x41 && id[off] <= 0x57)
        command_len = id[off++] - 0x40;
    else if (id[off] == 0x58 && off + 1 < id_len) {
        command_len = id[off + 1];
        off += 2;
    } else {
        return 0;
    }
    return off + command_len == id_len
        && strlen(command) == command_len
        && memcmp(id + off, command, command_len) == 0;
}

static void write_type_len(uint8_t **p, uint8_t major, size_t n)
{
    if (n < 24) *(*p)++ = (uint8_t)((major << 5) | n);
    else if (n <= 255) { *(*p)++ = (uint8_t)((major << 5) | 24); *(*p)++ = (uint8_t)n; }
    else if (n <= 65535) { *(*p)++ = (uint8_t)((major << 5) | 25);
        *(*p)++ = (uint8_t)(n >> 8); *(*p)++ = (uint8_t)n; }
    else { *(*p)++ = (uint8_t)((major << 5) | 26);
        *(*p)++ = (uint8_t)(n >> 24); *(*p)++ = (uint8_t)(n >> 16);
        *(*p)++ = (uint8_t)(n >> 8); *(*p)++ = (uint8_t)n; }
}

static void write_text(uint8_t **p, const char *s)
{
    size_t n = strlen(s);
    write_type_len(p, 3, n);
    memcpy(*p, s, n);
    *p += n;
}

static int make_response(const char *request_id, const uint8_t *app_output,
                         size_t app_output_len, uint8_t *out, size_t cap,
                         size_t *out_len)
{
    struct sgx_cbor_cursor cur = { app_output, app_output_len, 0 };
    const uint8_t *stdout_ptr = NULL, *key;
    size_t stdout_len = 0, key_len;
    uint64_t pairs, i;
    size_t need = 128 + strlen(request_id) + app_output_len;
    uint8_t *p = out;
    if (!sgx_cbor_len(&cur, 5, &pairs))
        return 6;
    for (i = 0; i < pairs; ++i) {
        if (!sgx_cbor_view(&cur, 3, &key, &key_len))
            return 6;
        if (sgx_cbor_text_eq(key, key_len, "stdout")) {
            if (!sgx_cbor_view(&cur, 2, &stdout_ptr, &stdout_len)) return 6;
        } else if (!sgx_cbor_skip(&cur, 0)) return 6;
    }
    if (cur.off != cur.len || need > cap)
        return need > cap ? 9 : 6;
    *p++ = 0xa6;
    write_text(&p, "schema_version"); *p++ = 1;
    write_text(&p, "request_id"); write_text(&p, request_id);
    write_text(&p, "status"); write_text(&p, "ok");
    write_text(&p, "exit_code"); *p++ = 0;
    write_text(&p, "stdout"); write_type_len(&p, 2, stdout_len);
    if (stdout_len) { memcpy(p, stdout_ptr, stdout_len); p += stdout_len; }
    write_text(&p, "app_output"); write_type_len(&p, 2, app_output_len);
    memcpy(p, app_output, app_output_len); p += app_output_len;
    *out_len = (size_t)(p - out);
    return 0;
}

struct app_execution {
    uint8_t *wasm;
    size_t wasm_len;
    wasm_module_t module;
    wasm_module_inst_t instance;
    wasm_exec_env_t exec_env;
    uint32_t input_ptr;
    uint32_t descriptor_ptr;
    uint32_t app_output_ptr;
    uint32_t app_output_len;
};

static int load_app_bytes(const char *command, const struct sgx_catalog_app *app,
                          struct app_execution *execution)
{
    char app_path[160];

    if (sgx_verified_mode()) {
        uint8_t stored_digest[32];
        uint8_t component[160];
        size_t component_len = 0;
        int status;

        /* The REE cannot supply verified-mode app bytes.  Read the active
         * protected record selected by acceptance state, then bind its
         * component identifier and stored digest back to this Catalog entry. */
        status = sgx_app_read_active(NULL, 0, &execution->wasm_len, NULL,
                                     NULL, 0, &component_len, NULL);
        if (status != SGX_STORE_SHORT_BUFFER || execution->wasm_len == 0
            || execution->wasm_len > SGX_PROTECTED_APP_MAX
            || component_len > sizeof(component))
            return 5;
        execution->wasm = malloc(execution->wasm_len);
        if (!execution->wasm)
            return 5;
        status = sgx_app_read_active(execution->wasm, execution->wasm_len,
                                     &execution->wasm_len, stored_digest,
                                     component, sizeof(component),
                                     &component_len, NULL);
        if (status != SGX_STORE_OK
            || !protected_component_command(component, component_len, command)
            || memcmp(stored_digest, app->digest, sizeof(stored_digest)) != 0)
            return 8;
        return 0;
    }

    if (snprintf(app_path, sizeof(app_path), "apps/%s", app->wasm_file) < 0
        || !read_artifact(app_path, &execution->wasm, &execution->wasm_len)) {
        (void)ocall_twep_log(app_path);
        return 5;
    }
    return 0;
}

static int verify_and_instantiate(const struct sgx_catalog_app *app,
                                  struct app_execution *execution)
{
    char error[128] = { 0 };
    sgx_sha256_hash_t digest;

    /* Recompute the digest even for protected storage.  This checks both the
     * sealed record and the Catalog authorization at the point of execution. */
    if (sgx_sha256_msg(execution->wasm, (uint32_t)execution->wasm_len, &digest)
            != SGX_SUCCESS
        || memcmp(digest, app->digest, sizeof(digest)) != 0)
        return 8;
    if (!sgx_wasm_signature_verify(execution->wasm, execution->wasm_len,
                                   SGX_WASM_ROLE_APP))
        return 12;
    if (!sgx_wamr_ensure_initialized())
        return 2;
    execution->module = wasm_runtime_load(execution->wasm,
        (uint32_t)execution->wasm_len, error, sizeof(error));
    if (!execution->module) {
        (void)ocall_twep_log(error);
        return 5;
    }
    execution->instance = wasm_runtime_instantiate(
        execution->module, app->stack_bytes, app->heap_bytes, error,
        sizeof(error));
    if (!execution->instance) {
        (void)ocall_twep_log(error);
        return 5;
    }
    execution->exec_env = wasm_runtime_create_exec_env(
        execution->instance, app->stack_bytes);
    return execution->exec_env ? 0 : 9;
}

static void app_execution_cleanup(struct app_execution *execution)
{
    wasm_function_inst_t free_function;

    if (execution->app_output_ptr && execution->instance
        && execution->exec_env) {
        uint32_t arguments[2] = {
            execution->app_output_ptr, execution->app_output_len
        };
        free_function = wasm_runtime_lookup_function(execution->instance,
                                                     "twep_app_free");
        if (free_function)
            (void)wasm_runtime_call_wasm(execution->exec_env, free_function,
                                         2, arguments);
    }
    if (execution->descriptor_ptr && execution->instance)
        wasm_runtime_module_free(execution->instance,
                                 execution->descriptor_ptr);
    if (execution->input_ptr && execution->instance)
        wasm_runtime_module_free(execution->instance, execution->input_ptr);
    if (execution->exec_env)
        wasm_runtime_destroy_exec_env(execution->exec_env);
    if (execution->instance)
        wasm_runtime_deinstantiate(execution->instance);
    if (execution->module)
        wasm_runtime_unload(execution->module);
    free(execution->wasm);
}

int sgx_app_execute(const char *request_id, const char *command,
                    const uint8_t *input, size_t input_len,
                    uint32_t timeout_ms, uint8_t *output, size_t output_cap,
                    size_t *output_len)
{
    struct app_execution execution = { 0 };
    struct sgx_catalog_app app;
    wasm_function_inst_t func;
    uint32_t argv[3] = { 0 };
    uint8_t *input_native = NULL, *desc_native = NULL, *app_output;
    uint64_t budget;
    int status = 5;

    status = sgx_teep_agent_resolve(request_id, command, &app);
    if (status != 0)
        goto out;
    if (!sgx_catalog_safe_wasm_basename(app.wasm_file)) {
        status = 4;
        goto out;
    }
    status = load_app_bytes(command, &app, &execution);
    if (status != 0)
        goto out;
    status = verify_and_instantiate(&app, &execution);
    if (status != 0)
        goto out;
    func = wasm_runtime_lookup_function(execution.instance,
                                        "twep_app_abi_version");
    if (!func || !wasm_runtime_call_wasm(execution.exec_env, func, 0, argv)
        || argv[0] != 1) {
        status = 6;
        goto out;
    }
    if (input_len) {
        execution.input_ptr = (uint32_t)wasm_runtime_module_malloc(
            execution.instance, (uint32_t)input_len, (void **)&input_native);
        if (!execution.input_ptr || !input_native) {
            status = 9;
            goto out;
        }
        memcpy(input_native, input, input_len);
    }
    execution.descriptor_ptr = (uint32_t)wasm_runtime_module_malloc(
        execution.instance, 8, (void **)&desc_native);
    if (!execution.descriptor_ptr || !desc_native) {
        status = 9;
        goto out;
    }
    memset(desc_native, 0, 8);
    func = wasm_runtime_lookup_function(execution.instance, "twep_app_main");
    if (!func) {
        status = 6;
        goto out;
    }
    argv[0] = execution.input_ptr;
    argv[1] = (uint32_t)input_len;
    argv[2] = execution.descriptor_ptr;
    if (!timeout_ms)
        timeout_ms = app.timeout_ms ? app.timeout_ms : 5000;
    else if (app.timeout_ms && app.timeout_ms < timeout_ms)
        timeout_ms = app.timeout_ms;
    budget = (uint64_t)timeout_ms * 100000u;
    if (budget > INT32_MAX)
        budget = INT32_MAX;
    /* Instruction metering turns the Catalog/request timeout into an Enclave-
     * enforced upper bound; the REE cannot extend an app's execution budget. */
    wasm_runtime_set_instruction_count_limit(execution.exec_env, (int)budget);
    if (!wasm_runtime_call_wasm(execution.exec_env, func, 3, argv)) {
        status = 7;
        goto out;
    }
    if ((int32_t)argv[0] != 0) {
        status = 7;
        goto out;
    }
    execution.app_output_ptr = (uint32_t)desc_native[0]
        | ((uint32_t)desc_native[1] << 8)
        | ((uint32_t)desc_native[2] << 16)
        | ((uint32_t)desc_native[3] << 24);
    execution.app_output_len = (uint32_t)desc_native[4]
        | ((uint32_t)desc_native[5] << 8)
        | ((uint32_t)desc_native[6] << 16)
        | ((uint32_t)desc_native[7] << 24);
    /* Never trust pointers returned by Wasm.  Validate the complete range
     * before translating it into an Enclave-native address. */
    if (!execution.app_output_ptr || !execution.app_output_len
        || !wasm_runtime_validate_app_addr(execution.instance,
                                            execution.app_output_ptr,
                                            execution.app_output_len)) {
        status = 6;
        goto out;
    }
    if (execution.app_output_len > app.max_output_bytes) {
        status = 7;
        goto out;
    }
    app_output = wasm_runtime_addr_app_to_native(execution.instance,
                                                 execution.app_output_ptr);
    if (!app_output) {
        status = 6;
        goto out;
    }
    status = make_response(request_id, app_output, execution.app_output_len,
                           output, output_cap, output_len);

out:
    app_execution_cleanup(&execution);
    return status;
}
