/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */
#include "runtime_internal.h"

#include <stdlib.h>
#include <string.h>

static twep_wr_status_t make_teep_resolve_input(const twep_wr_context_t *ctx, const char *command, uint8_t **out,
                                                size_t *out_len);
static twep_wr_status_t teep_error_status_from_code(bytes_view_t code);
static twep_wr_status_t parse_teep_resolve_output(const uint8_t *output, size_t output_len, const char *command,
                                                  catalog_entry_t *entry);
static twep_wr_status_t run_teep_agent_resolve(const twep_wr_context_t *ctx, const char *command,
                                               catalog_entry_t *entry);
static twep_wr_status_t lookup_catalog_entry_dev_resolver(const twep_wr_context_t *ctx, const char *command,
                                                          catalog_entry_t *entry);
static twep_wr_status_t lookup_catalog_entry_verified_resolver(const twep_wr_context_t *ctx, const char *command,
                                                               catalog_entry_t *entry);
static twep_wr_status_t parse_cbor_resource_limits(const uint8_t *buf, size_t len, size_t *off, catalog_entry_t *entry);
static bool is_safe_wasm_basename(const char *wasm_file);
static void apply_default_resource_limits(catalog_entry_t *entry);
static void clamp_resource_limits(catalog_entry_t *entry);
static bool write_text(uint8_t **p, const char *text);
static bool write_text_view(uint8_t **p, const char *text, size_t len);
static size_t cbor_type_len_size(uint64_t n);
static void write_type_len(uint8_t **p, uint8_t major, uint64_t n);

twep_wr_status_t twep_wr_lookup_catalog_entry(const twep_wr_context_t *ctx, const char *command, catalog_entry_t *entry)
{
    if (ctx == NULL || command == NULL || entry == NULL) {
        return TWEP_WR_ERR_INVALID_ARGUMENT;
    }
    if (strcmp(ctx->resolver_mode, "attestam-verified") == 0) {
        return lookup_catalog_entry_verified_resolver(ctx, command, entry);
    }
    return lookup_catalog_entry_dev_resolver(ctx, command, entry);
}

static twep_wr_status_t make_teep_resolve_input(const twep_wr_context_t *ctx, const char *command, uint8_t **out,
                                                size_t *out_len)
{
    const char *state_dir = ctx != NULL && ctx->state_dir != NULL ? ctx->state_dir : "";
    const char *resolver_mode = ctx != NULL && ctx->resolver_mode != NULL ? ctx->resolver_mode : "";
    const char *attestam_url = ctx != NULL && ctx->attestam_url != NULL ? ctx->attestam_url : "";
    const size_t command_len = command != NULL ? strlen(command) : 0;
    const size_t state_dir_len = strlen(state_dir);
    const size_t resolver_mode_len = strlen(resolver_mode);
    const size_t attestam_url_len = strlen(attestam_url);

    if (command_len == 0 || command_len > TWEP_WR_MAX_COMMAND_LEN || out == NULL || out_len == NULL) {
        return TWEP_WR_ERR_INVALID_ARGUMENT;
    }

    size_t len = 1
                 + cbor_type_len_size(14) + 14 + 1
                 + cbor_type_len_size(7) + 7 + cbor_type_len_size(11) + 11
                 + cbor_type_len_size(14) + 14 + cbor_type_len_size(command_len) + command_len
                 + cbor_type_len_size(13) + 13 + cbor_type_len_size(resolver_mode_len) + resolver_mode_len
                 + cbor_type_len_size(9) + 9 + cbor_type_len_size(state_dir_len) + state_dir_len
                 + cbor_type_len_size(12) + 12 + cbor_type_len_size(attestam_url_len) + attestam_url_len;
    uint8_t *buf = (uint8_t *)malloc(len);
    if (buf == NULL) {
        return TWEP_WR_ERR_NO_MEMORY;
    }

    uint8_t *p = buf;
    *p++ = 0xa6;
    (void)write_text(&p, "schema_version");
    *p++ = 0x01;
    (void)write_text(&p, "command");
    (void)write_text(&p, "resolve_app");
    (void)write_text(&p, "target_command");
    write_text_view(&p, command, command_len);
    (void)write_text(&p, "resolver_mode");
    write_text_view(&p, resolver_mode, resolver_mode_len);
    (void)write_text(&p, "state_dir");
    write_text_view(&p, state_dir, state_dir_len);
    (void)write_text(&p, "attestam_url");
    write_text_view(&p, attestam_url, attestam_url_len);

    *out = buf;
    *out_len = (size_t)(p - buf);
    return TWEP_WR_OK;
}

static twep_wr_status_t teep_error_status_from_code(bytes_view_t code)
{
    if (twep_wr_bytes_equal_text(code, "catalog.not_found") || twep_wr_bytes_equal_text(code, "catalog.invalid")) {
        return TWEP_WR_ERR_CATALOG;
    }
    if (twep_wr_bytes_equal_text(code, "app.hash_mismatch")) {
        return TWEP_WR_ERR_SECURITY;
    }
    if (twep_wr_bytes_equal_text(code, "teep.network")) {
        return TWEP_WR_ERR_TEEP_NETWORK;
    }
    if (twep_wr_bytes_equal_text(code, "teep.attestation_unsupported")) {
        return TWEP_WR_ERR_TEEP_ATTESTATION_UNSUPPORTED;
    }
    if (twep_wr_bytes_equal_text(code, "teep.verified_required")) {
        return TWEP_WR_ERR_TEEP;
    }
    return TWEP_WR_ERR_TEEP;
}

static twep_wr_status_t parse_teep_resolve_output(const uint8_t *output, size_t output_len, const char *command,
                                                  catalog_entry_t *entry)
{
    size_t off = 0;
    uint8_t major = 0;
    uint64_t pairs = 0;
    bool have_ok_status = false;
    bool have_app = false;
    bool have_error_status = false;
    twep_wr_status_t error_status = TWEP_WR_ERR_TEEP;
    if (output == NULL || command == NULL || entry == NULL || strlen(command) >= sizeof(entry->command)
        || !twep_wr_cbor_read_head(output, output_len, &off, &major, &pairs) || major != 5) {
        return TWEP_WR_ERR_TEEP;
    }
    memset(entry, 0, sizeof(*entry));
    apply_default_resource_limits(entry);
    for (uint64_t i = 0; i < pairs; i++) {
        bytes_view_t key;
        if (!twep_wr_cbor_read_text_view(output, output_len, &off, &key)) {
            return TWEP_WR_ERR_TEEP;
        }
        if (twep_wr_bytes_equal_text(key, "status")) {
            bytes_view_t status;
            if (!twep_wr_cbor_read_text_view(output, output_len, &off, &status)) {
                return TWEP_WR_ERR_TEEP;
            }
            if (twep_wr_bytes_equal_text(status, "ok")) {
                have_ok_status = true;
            } else if (twep_wr_bytes_equal_text(status, "error")) {
                have_error_status = true;
            } else {
                return TWEP_WR_ERR_TEEP;
            }
        } else if (twep_wr_bytes_equal_text(key, "error")) {
            uint64_t error_pairs = 0;
            bool have_code = false;
            if (!twep_wr_cbor_read_head(output, output_len, &off, &major, &error_pairs) || major != 5) {
                return TWEP_WR_ERR_TEEP;
            }
            for (uint64_t j = 0; j < error_pairs; j++) {
                bytes_view_t error_key;
                if (!twep_wr_cbor_read_text_view(output, output_len, &off, &error_key)) {
                    return TWEP_WR_ERR_TEEP;
                }
                if (twep_wr_bytes_equal_text(error_key, "code")) {
                    bytes_view_t code;
                    if (!twep_wr_cbor_read_text_view(output, output_len, &off, &code) || code.len == 0) {
                        return TWEP_WR_ERR_TEEP;
                    }
                    error_status = teep_error_status_from_code(code);
                    have_code = true;
                } else if (!twep_wr_cbor_skip_value(output, output_len, &off)) {
                    return TWEP_WR_ERR_TEEP;
                }
            }
            if (!have_code) {
                return TWEP_WR_ERR_TEEP;
            }
        } else if (twep_wr_bytes_equal_text(key, "app")) {
            uint64_t app_pairs = 0;
            bool have_command = false;
            bool have_component_id = false;
            bool have_version = false;
            bool have_abi = false;
            bool have_wasm_file = false;
            bool have_sha = false;
            if (!twep_wr_cbor_read_head(output, output_len, &off, &major, &app_pairs) || major != 5) {
                return TWEP_WR_ERR_TEEP;
            }
            for (uint64_t j = 0; j < app_pairs; j++) {
                bytes_view_t app_key;
                if (!twep_wr_cbor_read_text_view(output, output_len, &off, &app_key)) {
                    return TWEP_WR_ERR_TEEP;
                }
                if (twep_wr_bytes_equal_text(app_key, "command")) {
                    bytes_view_t resolved_command;
                    if (!twep_wr_cbor_read_text_view(output, output_len, &off, &resolved_command)
                        || !twep_wr_bytes_equal_text(resolved_command, command)) {
                        return TWEP_WR_ERR_TEEP;
                    }
                    have_command = true;
                } else if (twep_wr_bytes_equal_text(app_key, "component_id")) {
                    bytes_view_t component_id;
                    if (!twep_wr_cbor_read_text_view(output, output_len, &off, &component_id) || component_id.len == 0) {
                        return TWEP_WR_ERR_TEEP;
                    }
                    have_component_id = true;
                } else if (twep_wr_bytes_equal_text(app_key, "version")) {
                    bytes_view_t version;
                    if (!twep_wr_cbor_read_text_view(output, output_len, &off, &version) || version.len == 0) {
                        return TWEP_WR_ERR_TEEP;
                    }
                    have_version = true;
                } else if (twep_wr_bytes_equal_text(app_key, "abi")) {
                    bytes_view_t abi;
                    if (!twep_wr_cbor_read_text_view(output, output_len, &off, &abi)
                        || !twep_wr_bytes_equal_text(abi, "twep-app-v1")) {
                        return TWEP_WR_ERR_TEEP;
                    }
                    have_abi = true;
                } else if (twep_wr_bytes_equal_text(app_key, "wasm_file")) {
                    bytes_view_t wasm_file_view;
                    if (!twep_wr_cbor_read_text_view(output, output_len, &off, &wasm_file_view)
                        || !twep_wr_copy_text_view(wasm_file_view, entry->wasm_file, sizeof(entry->wasm_file))
                        || !is_safe_wasm_basename(entry->wasm_file)) {
                        return TWEP_WR_ERR_TEEP;
                    }
                    have_wasm_file = true;
                } else if (twep_wr_bytes_equal_text(app_key, "sha256")) {
                    bytes_view_t sha;
                    if (!twep_wr_cbor_read_bytes_view(output, output_len, &off, &sha) || sha.len != SHA256_DIGEST_LENGTH) {
                        return TWEP_WR_ERR_TEEP;
                    }
                    memcpy(entry->sha256, sha.ptr, SHA256_DIGEST_LENGTH);
                    have_sha = true;
                } else if (twep_wr_bytes_equal_text(app_key, "resource_limits")) {
                    twep_wr_status_t status = parse_cbor_resource_limits(output, output_len, &off, entry);
                    if (status != TWEP_WR_OK) {
                        return TWEP_WR_ERR_TEEP;
                    }
                } else if (!twep_wr_cbor_skip_value(output, output_len, &off)) {
                    return TWEP_WR_ERR_TEEP;
                }
            }
            if (!have_command || !have_component_id || !have_version || !have_abi || !have_wasm_file || !have_sha) {
                return TWEP_WR_ERR_TEEP;
            }
            have_app = true;
        } else if (!twep_wr_cbor_skip_value(output, output_len, &off)) {
            return TWEP_WR_ERR_TEEP;
        }
    }
    if (!have_ok_status || !have_app) {
        if (have_error_status) {
            return error_status;
        }
        return TWEP_WR_ERR_TEEP;
    }
    strcpy(entry->command, command);
    clamp_resource_limits(entry);
    return TWEP_WR_OK;
}

static twep_wr_status_t run_teep_agent_resolve(const twep_wr_context_t *ctx, const char *command,
                                               catalog_entry_t *entry)
{
    twep_wr_status_t status = twep_wr_ensure_teep_agent(ctx);
    if (status != TWEP_WR_OK) {
        return status;
    }

    char path[TWEP_WR_MAX_PATH_LEN];
    if (!twep_wr_state_path(ctx, "teep-agent", "teep-agent.wasm", path, sizeof(path))) {
        return TWEP_WR_ERR_TEEP;
    }
    size_t wasm_len = 0;
    uint8_t *wasm_bytes = twep_wr_read_file(path, &wasm_len);
    if (wasm_bytes == NULL) {
        return TWEP_WR_ERR_TEEP;
    }
    if (!twep_wr_verify_wasm_signature(wasm_bytes, wasm_len, TWEP_WR_WASM_SIGNATURE_ROLE_TEEP_AGENT)) {
        free(wasm_bytes);
        return TWEP_WR_ERR_WASM_SIGNATURE;
    }

    char error_buf[TWEP_WR_ERROR_BUF_SIZE] = { 0 };
    wasm_module_t module = wasm_runtime_load(wasm_bytes, (uint32_t)wasm_len, error_buf, sizeof(error_buf));
    if (module == NULL) {
        free(wasm_bytes);
        return TWEP_WR_ERR_TEEP;
    }
    wasm_module_inst_t module_inst =
        wasm_runtime_instantiate(module, TWEP_WR_DEFAULT_STACK_SIZE, TWEP_WR_DEFAULT_HEAP_SIZE, error_buf, sizeof(error_buf));
    if (module_inst == NULL) {
        wasm_runtime_unload(module);
        free(wasm_bytes);
        return TWEP_WR_ERR_TEEP;
    }
    wasm_exec_env_t exec_env = wasm_runtime_create_exec_env(module_inst, TWEP_WR_DEFAULT_STACK_SIZE);
    if (exec_env == NULL) {
        wasm_runtime_deinstantiate(module_inst);
        wasm_runtime_unload(module);
        free(wasm_bytes);
        return TWEP_WR_ERR_NO_MEMORY;
    }
    teep_agent_exec_context_t teep_exec_ctx = {
        .ctx = ctx,
        .teep_agent_wasm = wasm_bytes,
        .teep_agent_wasm_len = wasm_len,
        .capability = TWEP_WR_TEEP_AGENT_CAPABILITY,
    };
    wasm_runtime_set_user_data(exec_env, (void *)&teep_exec_ctx);

    uint32_t abi_version = 0;
    uint8_t *input = NULL;
    size_t input_len = 0;
    uint32_t input_ptr = 0;
    uint8_t *input_native = NULL;
    uint32_t desc_ptr = 0;
    uint8_t *desc_native = NULL;
    uint32_t output_ptr = 0;
    uint32_t output_len = 0;
    uint8_t *output_native = NULL;
    uint32_t argv[4] = { 0, 0, 0, 0 };

    status = twep_wr_call_u32_no_args(exec_env, module_inst, "twep_app_abi_version", &abi_version);
    if (status != TWEP_WR_OK || abi_version != 1) {
        status = TWEP_WR_ERR_TEEP;
        goto cleanup;
    }
    status = make_teep_resolve_input(ctx, command, &input, &input_len);
    if (status != TWEP_WR_OK) {
        goto cleanup;
    }
    input_ptr = (uint32_t)wasm_runtime_module_malloc(module_inst, input_len, (void **)&input_native);
    if (input_ptr == 0 || input_native == NULL) {
        status = TWEP_WR_ERR_NO_MEMORY;
        goto cleanup;
    }
    memcpy(input_native, input, input_len);

    desc_ptr = (uint32_t)wasm_runtime_module_malloc(module_inst, 8, (void **)&desc_native);
    if (desc_ptr == 0 || desc_native == NULL) {
        status = TWEP_WR_ERR_NO_MEMORY;
        goto cleanup;
    }
    memset(desc_native, 0, 8);

    wasm_function_inst_t main_func = wasm_runtime_lookup_function(module_inst, "twep_app_main");
    if (main_func == NULL) {
        status = TWEP_WR_ERR_TEEP;
        goto cleanup;
    }
    argv[0] = input_ptr;
    argv[1] = (uint32_t)input_len;
    argv[2] = desc_ptr;
    if (!wasm_runtime_call_wasm(exec_env, main_func, 3, argv)) {
        status = TWEP_WR_ERR_TEEP;
        goto cleanup;
    }
    if ((int32_t)argv[0] == 5) {
        status = TWEP_WR_ERR_CATALOG;
        goto cleanup;
    }
    if ((int32_t)argv[0] == 7) {
        status = TWEP_WR_ERR_SECURITY;
        goto cleanup;
    }
    if ((int32_t)argv[0] != 0) {
        status = TWEP_WR_ERR_TEEP;
        goto cleanup;
    }
    output_ptr = (uint32_t)desc_native[0] | ((uint32_t)desc_native[1] << 8) | ((uint32_t)desc_native[2] << 16)
                 | ((uint32_t)desc_native[3] << 24);
    output_len = (uint32_t)desc_native[4] | ((uint32_t)desc_native[5] << 8) | ((uint32_t)desc_native[6] << 16)
                 | ((uint32_t)desc_native[7] << 24);
    if (output_ptr == 0 || output_len == 0 || !wasm_runtime_validate_app_addr(module_inst, output_ptr, output_len)) {
        status = TWEP_WR_ERR_TEEP;
        goto cleanup;
    }
    output_native = (uint8_t *)wasm_runtime_addr_app_to_native(module_inst, output_ptr);
    if (output_native == NULL) {
        status = TWEP_WR_ERR_TEEP;
        goto cleanup;
    }
    status = parse_teep_resolve_output(output_native, output_len, command, entry);

cleanup:
    if (output_ptr != 0) {
        (void)twep_wr_call_free(exec_env, module_inst, output_ptr, output_len);
    }
    if (input_ptr != 0) {
        wasm_runtime_module_free(module_inst, input_ptr);
    }
    if (desc_ptr != 0) {
        wasm_runtime_module_free(module_inst, desc_ptr);
    }
    wasm_runtime_destroy_exec_env(exec_env);
    wasm_runtime_deinstantiate(module_inst);
    wasm_runtime_unload(module);
    free(wasm_bytes);
    free(input);
    return status;
}

static twep_wr_status_t lookup_catalog_entry_dev_resolver(const twep_wr_context_t *ctx, const char *command,
                                                          catalog_entry_t *entry)
{
    twep_wr_status_t status = twep_wr_ensure_state_layout(ctx);
    if (status != TWEP_WR_OK) {
        return status;
    }
    const char *catalog_cbor_path = getenv("TWEP_CATALOG_CBOR");
    status = twep_wr_ensure_state_catalog(ctx);
    if (status != TWEP_WR_OK) {
        return status;
    }
    if (catalog_cbor_path != NULL && catalog_cbor_path[0] != '\0') {
        char state_catalog[TWEP_WR_MAX_PATH_LEN];
        if (!twep_wr_state_path(ctx, "catalog", "catalog.cbor", state_catalog, sizeof(state_catalog))) {
            return TWEP_WR_ERR_CATALOG;
        }
        status = twep_wr_copy_file(catalog_cbor_path, state_catalog);
        if (status != TWEP_WR_OK) {
            return status;
        }
    }

    status = run_teep_agent_resolve(ctx, command, entry);
    if (status != TWEP_WR_OK) {
        return status;
    }
    char app_path[TWEP_WR_MAX_PATH_LEN];
    if (!twep_wr_state_path(ctx, "apps", entry->wasm_file, app_path, sizeof(app_path))) {
        return TWEP_WR_ERR_CATALOG;
    }
    if (twep_wr_file_exists(app_path)) {
        return TWEP_WR_OK;
    }
    status = twep_wr_ensure_state_app(ctx, entry->wasm_file);
    if (status != TWEP_WR_OK) {
        return status;
    }
    status = run_teep_agent_resolve(ctx, command, entry);
    if (status != TWEP_WR_OK) {
        return status;
    }
    return TWEP_WR_OK;
}

static twep_wr_status_t lookup_catalog_entry_verified_resolver(const twep_wr_context_t *ctx, const char *command,
                                                               catalog_entry_t *entry)
{
    twep_wr_status_t status = twep_wr_ensure_state_layout(ctx);
    if (status != TWEP_WR_OK) {
        return status;
    }
    return run_teep_agent_resolve(ctx, command, entry);
}

static twep_wr_status_t parse_cbor_resource_limits(const uint8_t *buf, size_t len, size_t *off, catalog_entry_t *entry)
{
    uint8_t major = 0;
    uint64_t pairs = 0;
    if (!twep_wr_cbor_read_head(buf, len, off, &major, &pairs) || major != 5) {
        return TWEP_WR_ERR_CATALOG;
    }
    for (uint64_t i = 0; i < pairs; i++) {
        bytes_view_t key;
        uint32_t value = 0;
        if (!twep_wr_cbor_read_text_view(buf, len, off, &key)) {
            return TWEP_WR_ERR_CATALOG;
        }
        if (twep_wr_bytes_equal_text(key, "stack_bytes")) {
            if (!twep_wr_cbor_read_uint32(buf, len, off, &value)) {
                return TWEP_WR_ERR_CATALOG;
            }
            entry->stack_bytes = value;
        } else if (twep_wr_bytes_equal_text(key, "heap_bytes")) {
            if (!twep_wr_cbor_read_uint32(buf, len, off, &value)) {
                return TWEP_WR_ERR_CATALOG;
            }
            entry->heap_bytes = value;
        } else if (twep_wr_bytes_equal_text(key, "timeout_ms")) {
            if (!twep_wr_cbor_read_uint32(buf, len, off, &value)) {
                return TWEP_WR_ERR_CATALOG;
            }
            entry->timeout_ms = value;
        } else if (twep_wr_bytes_equal_text(key, "max_output_bytes")) {
            if (!twep_wr_cbor_read_uint32(buf, len, off, &value)) {
                return TWEP_WR_ERR_CATALOG;
            }
            entry->max_output_bytes = value;
        } else if (!twep_wr_cbor_skip_value(buf, len, off)) {
            return TWEP_WR_ERR_CATALOG;
        }
    }
    return TWEP_WR_OK;
}

static bool is_safe_wasm_basename(const char *wasm_file)
{
    if (wasm_file == NULL || wasm_file[0] == '\0') {
        return false;
    }
    size_t len = strlen(wasm_file);
    if (len <= 5 || strcmp(wasm_file + len - 5, ".wasm") != 0) {
        return false;
    }
    for (size_t i = 0; i < len; i++) {
        char ch = wasm_file[i];
        bool ok = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9')
                  || ch == '.' || ch == '_' || ch == '-';
        if (!ok) {
            return false;
        }
    }
    return true;
}

static void apply_default_resource_limits(catalog_entry_t *entry)
{
    entry->stack_bytes = TWEP_WR_DEFAULT_STACK_SIZE;
    entry->heap_bytes = TWEP_WR_DEFAULT_HEAP_SIZE;
    entry->timeout_ms = 0;
    entry->max_output_bytes = TWEP_WR_DEFAULT_MAX_OUTPUT_SIZE;
}

static void clamp_resource_limits(catalog_entry_t *entry)
{
    if (entry->stack_bytes == 0 || entry->stack_bytes > TWEP_WR_GLOBAL_MAX_STACK_SIZE) {
        entry->stack_bytes = TWEP_WR_GLOBAL_MAX_STACK_SIZE;
    }
    if (entry->heap_bytes == 0 || entry->heap_bytes > TWEP_WR_GLOBAL_MAX_HEAP_SIZE) {
        entry->heap_bytes = TWEP_WR_GLOBAL_MAX_HEAP_SIZE;
    }
    if (entry->max_output_bytes == 0 || entry->max_output_bytes > TWEP_WR_GLOBAL_MAX_OUTPUT_SIZE) {
        entry->max_output_bytes = TWEP_WR_GLOBAL_MAX_OUTPUT_SIZE;
    }
}

static bool write_text(uint8_t **p, const char *text)
{
    size_t len = strlen(text);
    if (len > 23) {
        return false;
    }
    *(*p)++ = 0x60 | (uint8_t)len;
    memcpy(*p, text, len);
    *p += len;
    return true;
}

static bool write_text_view(uint8_t **p, const char *text, size_t len)
{
    if (p == NULL || text == NULL) {
        return false;
    }
    write_type_len(p, 3, len);
    memcpy(*p, text, len);
    *p += len;
    return true;
}

static size_t cbor_type_len_size(uint64_t n)
{
    if (n < 24) {
        return 1;
    }
    if (n <= 0xff) {
        return 2;
    }
    if (n <= 0xffff) {
        return 3;
    }
    if (n <= 0xffffffff) {
        return 5;
    }
    return 9;
}

static void write_type_len(uint8_t **p, uint8_t major, uint64_t n)
{
    uint8_t head = (uint8_t)(major << 5);
    if (n < 24) {
        *(*p)++ = head | (uint8_t)n;
    } else if (n <= 0xff) {
        *(*p)++ = head | 24;
        *(*p)++ = (uint8_t)n;
    } else if (n <= 0xffff) {
        *(*p)++ = head | 25;
        *(*p)++ = (uint8_t)(n >> 8);
        *(*p)++ = (uint8_t)n;
    } else if (n <= 0xffffffff) {
        *(*p)++ = head | 26;
        *(*p)++ = (uint8_t)(n >> 24);
        *(*p)++ = (uint8_t)(n >> 16);
        *(*p)++ = (uint8_t)(n >> 8);
        *(*p)++ = (uint8_t)n;
    } else {
        *(*p)++ = head | 27;
        *(*p)++ = (uint8_t)(n >> 56);
        *(*p)++ = (uint8_t)(n >> 48);
        *(*p)++ = (uint8_t)(n >> 40);
        *(*p)++ = (uint8_t)(n >> 32);
        *(*p)++ = (uint8_t)(n >> 24);
        *(*p)++ = (uint8_t)(n >> 16);
        *(*p)++ = (uint8_t)(n >> 8);
        *(*p)++ = (uint8_t)n;
    }
}
