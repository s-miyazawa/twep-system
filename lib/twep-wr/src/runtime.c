/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */
#include "runtime_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

uint32_t twep_wr_get_abi_version(void)
{
    return TWEP_WR_ABI_VERSION;
}

twep_wr_status_t twep_wr_init(
    const twep_wr_config_t *config,
    twep_wr_context_t **out_ctx)
{
    if (config == NULL || out_ctx == NULL) {
        return TWEP_WR_ERR_INVALID_ARGUMENT;
    }
    if (config->max_request_bytes == 0 || config->max_response_bytes == 0) {
        return TWEP_WR_ERR_INVALID_ARGUMENT;
    }
    if (config->state_dir == NULL || config->state_dir[0] == '\0') {
        return TWEP_WR_ERR_INVALID_ARGUMENT;
    }
    if (config->resolver_mode == NULL || !twep_wr_is_valid_resolver_mode(config->resolver_mode)) {
        return TWEP_WR_ERR_INVALID_ARGUMENT;
    }
    if (config->attestam_url == NULL) {
        return TWEP_WR_ERR_INVALID_ARGUMENT;
    }
    if (strcmp(config->resolver_mode, "attestam-verified") == 0 && config->insecure_demo_mode) {
        return TWEP_WR_ERR_INVALID_ARGUMENT;
    }

    twep_wr_context_t *ctx = (twep_wr_context_t *)calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
        return TWEP_WR_ERR_NO_MEMORY;
    }
    ctx->state_dir = twep_wr_string_dup(config->state_dir);
    ctx->resolver_mode = twep_wr_string_dup(config->resolver_mode);
    ctx->attestam_url = twep_wr_string_dup(config->attestam_url);
    if (ctx->state_dir == NULL || ctx->resolver_mode == NULL || ctx->attestam_url == NULL) {
        free(ctx->attestam_url);
        free(ctx->resolver_mode);
        free(ctx->state_dir);
        free(ctx);
        return TWEP_WR_ERR_NO_MEMORY;
    }
    ctx->insecure_demo_mode = config->insecure_demo_mode;
    ctx->default_timeout_ms = config->default_timeout_ms == 0 ? 5000u : config->default_timeout_ms;
    ctx->max_request_bytes = config->max_request_bytes;
    ctx->max_response_bytes = config->max_response_bytes;
#ifndef TWEP_WR_PLATFORM_BACKEND_TRUSTZONE
    if (!wasm_runtime_init()) {
        free(ctx->attestam_url);
        free(ctx->resolver_mode);
        free(ctx->state_dir);
        free(ctx);
        return TWEP_WR_ERR_INIT;
    }
    if (twep_wr_register_teep_agent_hostcalls() != TWEP_WR_OK) {
        wasm_runtime_destroy();
        free(ctx->attestam_url);
        free(ctx->resolver_mode);
        free(ctx->state_dir);
        free(ctx);
        return TWEP_WR_ERR_INIT;
    }
    ctx->runtime_initialized = true;
#endif
    ctx->abi_version = TWEP_WR_ABI_VERSION;
    *out_ctx = ctx;
    return TWEP_WR_OK;
}

twep_wr_status_t twep_wr_execute(
    twep_wr_context_t *ctx,
    const twep_wr_normalized_request_t *request,
    twep_wr_owned_bytes_t *out_response_cbor)
{
    if (ctx == NULL || request == NULL || out_response_cbor == NULL || request->request_id == NULL
        || request->request_id[0] == '\0' || request->command == NULL || request->command[0] == '\0') {
        return TWEP_WR_ERR_INVALID_ARGUMENT;
    }
    out_response_cbor->ptr = NULL;
    out_response_cbor->len = 0;
    if (ctx->abi_version != TWEP_WR_ABI_VERSION) {
        return TWEP_WR_ERR_INIT;
    }
    if (request->app_input_cbor.ptr == NULL && request->app_input_cbor.len != 0) {
        return TWEP_WR_ERR_INVALID_ARGUMENT;
    }
    size_t request_id_len = strlen(request->request_id);
    size_t command_len = strlen(request->command);
    if (command_len >= TWEP_WR_MAX_COMMAND_LEN) {
        return TWEP_WR_ERR_INVALID_ARGUMENT;
    }
    size_t remaining = ctx->max_request_bytes;
    if (request_id_len > remaining) {
        return TWEP_WR_ERR_INVALID_ARGUMENT;
    }
    remaining -= request_id_len;
    if (command_len > remaining) {
        return TWEP_WR_ERR_INVALID_ARGUMENT;
    }
    remaining -= command_len;
    if (request->app_input_cbor.len > remaining) {
        return TWEP_WR_ERR_INVALID_ARGUMENT;
    }

    twep_wr_status_t status;
#ifdef TWEP_WR_PLATFORM_BACKEND_TRUSTZONE
    status = twep_wr_trustzone_execute(ctx, request, out_response_cbor);
#else
    status = twep_wr_run_app_wasm(ctx, request, out_response_cbor);
#endif
    if (status == TWEP_WR_OK && out_response_cbor->len > ctx->max_response_bytes) {
        twep_wr_free_bytes(*out_response_cbor);
        out_response_cbor->ptr = NULL;
        out_response_cbor->len = 0;
        return TWEP_WR_ERR_WASM_RUNTIME;
    }
    return status;
}

twep_wr_status_t twep_wr_set_host_io(
    twep_wr_context_t *ctx,
    const twep_wr_host_io_t *host_io)
{
    if (ctx == NULL) {
        return TWEP_WR_ERR_INVALID_ARGUMENT;
    }
    if (host_io == NULL) {
        memset(&ctx->host_io, 0, sizeof(ctx->host_io));
        return TWEP_WR_OK;
    }
    ctx->host_io = *host_io;
    return TWEP_WR_OK;
}

void twep_wr_free_bytes(twep_wr_owned_bytes_t bytes)
{
    free(bytes.ptr);
}

void twep_wr_shutdown(twep_wr_context_t *ctx)
{
    if (ctx != NULL && ctx->runtime_initialized) {
        wasm_runtime_destroy();
        ctx->runtime_initialized = false;
    }
    free(ctx->attestam_url);
    free(ctx->resolver_mode);
    free(ctx->state_dir);
    free(ctx);
}

const char *twep_wr_status_string(twep_wr_status_t status)
{
    switch (status) {
    case TWEP_WR_OK:
        return "ok";
    case TWEP_WR_ERR_INVALID_ARGUMENT:
        return "invalid argument";
    case TWEP_WR_ERR_INIT:
        return "init error";
    case TWEP_WR_ERR_CATALOG:
        return "catalog error";
    case TWEP_WR_ERR_TEEP:
        return "teep error";
    case TWEP_WR_ERR_WASM_LOAD:
        return "wasm load error";
    case TWEP_WR_ERR_WASM_ABI:
        return "wasm abi error";
    case TWEP_WR_ERR_WASM_RUNTIME:
        return "wasm runtime error";
    case TWEP_WR_ERR_SECURITY:
        return "security error";
    case TWEP_WR_ERR_NO_MEMORY:
        return "no memory";
    case TWEP_WR_ERR_TEEP_NETWORK:
        return "teep network error";
    case TWEP_WR_ERR_TEEP_ATTESTATION_UNSUPPORTED:
        return "teep attestation unsupported";
    case TWEP_WR_ERR_WASM_SIGNATURE:
        return "wasm signature error";
    default:
        return "unknown";
    }
}

uint8_t *twep_wr_read_file(const char *path, size_t *out_len)
{
    uint8_t *buf = NULL;
    size_t len = 0;
    if (twep_wr_platform_read_file(path, &buf, &len) != TWEP_WR_PLATFORM_OK) {
        return NULL;
    }
    *out_len = len;
    return buf;
}

bool twep_wr_file_exists(const char *path)
{
    return twep_wr_platform_file_exists(path);
}

twep_wr_status_t twep_wr_copy_file(const char *src, const char *dst)
{
    size_t len = 0;
    uint8_t *bytes = twep_wr_read_file(src, &len);
    if (bytes == NULL) {
        return TWEP_WR_ERR_CATALOG;
    }
    twep_wr_platform_status_t status = twep_wr_platform_write_file(dst, bytes, len);
    free(bytes);
    if (status != TWEP_WR_PLATFORM_OK) {
        return TWEP_WR_ERR_CATALOG;
    }
    return TWEP_WR_OK;
}

twep_wr_status_t twep_wr_mkdir_if_needed(const char *path)
{
    if (twep_wr_platform_mkdir_if_needed(path) == TWEP_WR_PLATFORM_OK) {
        return TWEP_WR_OK;
    }
    return TWEP_WR_ERR_CATALOG;
}

char *twep_wr_string_dup(const char *s)
{
    size_t len = strlen(s);
    char *out = (char *)malloc(len + 1);
    if (out == NULL) {
        return NULL;
    }
    memcpy(out, s, len + 1);
    return out;
}

bool twep_wr_is_valid_resolver_mode(const char *mode)
{
    return strcmp(mode, "mock") == 0
           || strcmp(mode, "attestam-insecure") == 0
           || strcmp(mode, "attestam-verified") == 0;
}

bool twep_wr_relative_state_file_path(const char *path, size_t path_len, char *out, size_t out_cap)
{
    if (path == NULL || path_len == 0 || path_len >= out_cap) {
        return false;
    }
    if (path[0] == '/' || path[0] == '\\') {
        return false;
    }
    for (size_t i = 0; i < path_len; i++) {
        char c = path[i];
        if (c == '\0' || c == '\\') {
            return false;
        }
    }
    memcpy(out, path, path_len);
    out[path_len] = '\0';
    if (strstr(out, "..") != NULL) {
        return false;
    }
    return true;
}

bool twep_wr_protected_object_name(const char *name, size_t name_len, char *out, size_t out_cap)
{
    if (name == NULL || out == NULL || name_len == 0 || name_len >= out_cap || name[0] == '.') {
        return false;
    }
    for (size_t i = 0; i < name_len; i++) {
        char ch = name[i];
        bool ok = (ch >= 'A' && ch <= 'Z')
                  || (ch >= 'a' && ch <= 'z')
                  || (ch >= '0' && ch <= '9')
                  || ch == '-' || ch == '_' || ch == '.';
        if (!ok) {
            return false;
        }
    }
    memcpy(out, name, name_len);
    out[name_len] = '\0';
    return true;
}

bool twep_wr_platform_supports_protected_storage(void)
{
    const twep_wr_platform_info_t *info = twep_wr_platform_info();
    if (info == NULL) {
        return false;
    }
    return info->sealed_storage_security == TWEP_WR_PLATFORM_SEALED_OBSERVATION_ONLY
           || info->sealed_storage_security == TWEP_WR_PLATFORM_SEALED_TEE_PROTECTED
           || info->sealed_storage_security == TWEP_WR_PLATFORM_SEALED_TEE_SECURE_STORAGE_SMOKE
           || info->sealed_storage_security == TWEP_WR_PLATFORM_SEALED_TEE_REE_FS_SECURE_STORAGE;
}

const char *twep_wr_platform_sealed_security_label(twep_wr_platform_sealed_security_t security)
{
    switch (security) {
    case TWEP_WR_PLATFORM_SEALED_OBSERVATION_ONLY:
        return "observation-only";
    case TWEP_WR_PLATFORM_SEALED_TEE_PROTECTED:
        return "tee-protected";
    case TWEP_WR_PLATFORM_SEALED_TEE_SECURE_STORAGE_SMOKE:
        return "tee-secure-storage-smoke";
    case TWEP_WR_PLATFORM_SEALED_TEE_REE_FS_SECURE_STORAGE:
        return "tee-ree-fs-secure-storage";
    case TWEP_WR_PLATFORM_SEALED_UNSUPPORTED:
    default:
        return "unsupported";
    }
}

const char *twep_wr_bool_label(bool value)
{
    return value ? "true" : "false";
}

bool twep_wr_state_relative_path(const twep_wr_context_t *ctx, const char *relative, char *out, size_t out_cap)
{
    int n = snprintf(out, out_cap, "%s/%s", ctx->state_dir, relative);
    return n > 0 && (size_t)n < out_cap;
}

twep_wr_status_t twep_wr_ensure_state_layout(const twep_wr_context_t *ctx)
{
    char path[TWEP_WR_MAX_PATH_LEN];
    if (ctx == NULL || ctx->state_dir == NULL) {
        return TWEP_WR_ERR_INVALID_ARGUMENT;
    }
    if (twep_wr_mkdir_if_needed(ctx->state_dir) != TWEP_WR_OK) {
        return TWEP_WR_ERR_CATALOG;
    }
    if (!twep_wr_state_path(ctx, "catalog", NULL, path, sizeof(path)) || twep_wr_mkdir_if_needed(path) != TWEP_WR_OK) {
        return TWEP_WR_ERR_CATALOG;
    }
    if (!twep_wr_state_path(ctx, "apps", NULL, path, sizeof(path)) || twep_wr_mkdir_if_needed(path) != TWEP_WR_OK) {
        return TWEP_WR_ERR_CATALOG;
    }
    if (!twep_wr_state_path(ctx, "teep-agent", NULL, path, sizeof(path)) || twep_wr_mkdir_if_needed(path) != TWEP_WR_OK) {
        return TWEP_WR_ERR_CATALOG;
    }
    if (!twep_wr_state_path(ctx, "tmp", NULL, path, sizeof(path)) || twep_wr_mkdir_if_needed(path) != TWEP_WR_OK) {
        return TWEP_WR_ERR_CATALOG;
    }
    if (!twep_wr_state_path(ctx, "components", NULL, path, sizeof(path)) || twep_wr_mkdir_if_needed(path) != TWEP_WR_OK) {
        return TWEP_WR_ERR_CATALOG;
    }
    if (!twep_wr_state_path(ctx, "locks", NULL, path, sizeof(path)) || twep_wr_mkdir_if_needed(path) != TWEP_WR_OK) {
        return TWEP_WR_ERR_CATALOG;
    }
    twep_wr_platform_status_t sealed_status = twep_wr_platform_sealed_init(ctx->state_dir);
    if (sealed_status != TWEP_WR_PLATFORM_OK && sealed_status != TWEP_WR_PLATFORM_ERR_UNSUPPORTED) {
        return TWEP_WR_ERR_CATALOG;
    }
    return TWEP_WR_OK;
}

twep_wr_status_t twep_wr_ensure_state_catalog(const twep_wr_context_t *ctx)
{
    char cbor_dst[TWEP_WR_MAX_PATH_LEN];
    if (!twep_wr_state_path(ctx, "catalog", "catalog.cbor", cbor_dst, sizeof(cbor_dst))) {
        return TWEP_WR_ERR_CATALOG;
    }
    if (!twep_wr_file_exists(cbor_dst)) {
        twep_wr_status_t status = twep_wr_copy_file("build/catalog.dev.cbor", cbor_dst);
        if (status != TWEP_WR_OK) {
            status = twep_wr_copy_file("../../build/catalog.dev.cbor", cbor_dst);
        }
        if (status != TWEP_WR_OK) {
            return status;
        }
    }

    char json_dst[TWEP_WR_MAX_PATH_LEN];
    if (!twep_wr_state_path(ctx, "catalog", "catalog.dev.json", json_dst, sizeof(json_dst))) {
        return TWEP_WR_ERR_CATALOG;
    }
    if (!twep_wr_file_exists(json_dst)) {
        twep_wr_status_t status = twep_wr_copy_file("build/catalog.dev.json", json_dst);
        if (status != TWEP_WR_OK) {
            status = twep_wr_copy_file("../../build/catalog.dev.json", json_dst);
        }
        if (status != TWEP_WR_OK) {
            return status;
        }
    }
    return TWEP_WR_OK;
}

twep_wr_status_t twep_wr_ensure_state_app(const twep_wr_context_t *ctx, const char *wasm_file)
{
    char dst[TWEP_WR_MAX_PATH_LEN];
    if (!twep_wr_state_path(ctx, "apps", wasm_file, dst, sizeof(dst))) {
        return TWEP_WR_ERR_CATALOG;
    }
    if (twep_wr_file_exists(dst)) {
        return TWEP_WR_OK;
    }
    char src[TWEP_WR_MAX_PATH_LEN];
    if (!twep_wr_build_path(wasm_file, src, sizeof(src))) {
        return TWEP_WR_ERR_CATALOG;
    }
    twep_wr_status_t status = twep_wr_copy_file(src, dst);
    if (status == TWEP_WR_OK) {
        return status;
    }
    char fallback[TWEP_WR_MAX_PATH_LEN];
    int n = snprintf(fallback, sizeof(fallback), "../../build/%s", wasm_file);
    if (n <= 0 || (size_t)n >= sizeof(fallback)) {
        return TWEP_WR_ERR_WASM_LOAD;
    }
    status = twep_wr_copy_file(fallback, dst);
    return status == TWEP_WR_OK ? TWEP_WR_OK : TWEP_WR_ERR_WASM_LOAD;
}

twep_wr_status_t twep_wr_ensure_teep_agent(const twep_wr_context_t *ctx)
{
    char dst[TWEP_WR_MAX_PATH_LEN];
    if (!twep_wr_state_path(ctx, "teep-agent", "teep-agent.wasm", dst, sizeof(dst))) {
        return TWEP_WR_ERR_TEEP;
    }
    if (twep_wr_file_exists(dst)) {
        return TWEP_WR_OK;
    }
    twep_wr_status_t status = twep_wr_copy_file("build/teep-agent.wasm", dst);
    if (status == TWEP_WR_OK) {
        return TWEP_WR_OK;
    }
    status = twep_wr_copy_file("../../build/teep-agent.wasm", dst);
    return status == TWEP_WR_OK ? TWEP_WR_OK : TWEP_WR_ERR_TEEP;
}

bool twep_wr_state_path(const twep_wr_context_t *ctx, const char *subdir, const char *name, char *out, size_t out_cap)
{
    int n;
    if (name == NULL) {
        n = snprintf(out, out_cap, "%s/%s", ctx->state_dir, subdir);
    } else {
        n = snprintf(out, out_cap, "%s/%s/%s", ctx->state_dir, subdir, name);
    }
    return n > 0 && (size_t)n < out_cap;
}

bool twep_wr_build_path(const char *name, char *out, size_t out_cap)
{
    int n = snprintf(out, out_cap, "build/%s", name);
    return n > 0 && (size_t)n < out_cap;
}

bool twep_wr_cbor_read_head(const uint8_t *buf, size_t len, size_t *off, uint8_t *major, uint64_t *value)
{
    if (*off >= len) {
        return false;
    }
    uint8_t head = buf[(*off)++];
    *major = head >> 5;
    uint8_t add = head & 0x1f;
    if (add < 24) {
        *value = add;
        return true;
    }
    if (add == 24) {
        if (*off + 1 > len) {
            return false;
        }
        *value = buf[(*off)++];
        return true;
    }
    if (add == 25) {
        if (*off + 2 > len) {
            return false;
        }
        *value = ((uint64_t)buf[*off] << 8) | buf[*off + 1];
        *off += 2;
        return true;
    }
    if (add == 26) {
        if (*off + 4 > len) {
            return false;
        }
        *value = ((uint64_t)buf[*off] << 24) | ((uint64_t)buf[*off + 1] << 16)
                 | ((uint64_t)buf[*off + 2] << 8) | buf[*off + 3];
        *off += 4;
        return true;
    }
    return false;
}

bool twep_wr_cbor_read_text_view(const uint8_t *buf, size_t len, size_t *off, bytes_view_t *view)
{
    uint8_t major = 0;
    uint64_t value = 0;
    if (!twep_wr_cbor_read_head(buf, len, off, &major, &value) || major != 3 || value > len - *off) {
        return false;
    }
    view->ptr = buf + *off;
    view->len = (size_t)value;
    *off += (size_t)value;
    return true;
}

bool twep_wr_cbor_read_bytes_view(const uint8_t *buf, size_t len, size_t *off, bytes_view_t *view)
{
    uint8_t major = 0;
    uint64_t value = 0;
    if (!twep_wr_cbor_read_head(buf, len, off, &major, &value) || major != 2 || value > len - *off) {
        return false;
    }
    view->ptr = buf + *off;
    view->len = (size_t)value;
    *off += (size_t)value;
    return true;
}

bool twep_wr_cbor_read_uint32(const uint8_t *buf, size_t len, size_t *off, uint32_t *out)
{
    uint8_t major = 0;
    uint64_t value = 0;
    if (!twep_wr_cbor_read_head(buf, len, off, &major, &value) || major != 0 || value > UINT32_MAX) {
        return false;
    }
    *out = (uint32_t)value;
    return true;
}

bool twep_wr_cbor_skip_value(const uint8_t *buf, size_t len, size_t *off)
{
    uint8_t major = 0;
    uint64_t value = 0;
    if (!twep_wr_cbor_read_head(buf, len, off, &major, &value)) {
        return false;
    }
    if (major == 0 || major == 1 || major == 7) {
        return true;
    }
    if (major == 2 || major == 3) {
        if (value > len - *off) {
            return false;
        }
        *off += (size_t)value;
        return true;
    }
    if (major == 4) {
        for (uint64_t i = 0; i < value; i++) {
            if (!twep_wr_cbor_skip_value(buf, len, off)) {
                return false;
            }
        }
        return true;
    }
    if (major == 5) {
        for (uint64_t i = 0; i < value; i++) {
            if (!twep_wr_cbor_skip_value(buf, len, off) || !twep_wr_cbor_skip_value(buf, len, off)) {
                return false;
            }
        }
        return true;
    }
    return false;
}

bool twep_wr_bytes_equal_text(bytes_view_t view, const char *text)
{
    size_t text_len = strlen(text);
    return view.len == text_len && memcmp(view.ptr, text, text_len) == 0;
}

bool twep_wr_copy_text_view(bytes_view_t view, char *out, size_t out_cap)
{
    if (view.len >= out_cap) {
        return false;
    }
    memcpy(out, view.ptr, view.len);
    out[view.len] = '\0';
    return true;
}

bool twep_wr_sha256_matches(const uint8_t *bytes, size_t len, const uint8_t expected[SHA256_DIGEST_LENGTH])
{
    uint8_t actual[SHA256_DIGEST_LENGTH];
    SHA256(bytes, len, actual);
    return memcmp(actual, expected, SHA256_DIGEST_LENGTH) == 0;
}

twep_wr_status_t twep_wr_call_u32_no_args(wasm_exec_env_t exec_env, wasm_module_inst_t module_inst,
                                          const char *name, uint32_t *out_value)
{
    wasm_function_inst_t func = wasm_runtime_lookup_function(module_inst, name);
    if (func == NULL) {
        return TWEP_WR_ERR_WASM_ABI;
    }
    uint32_t argv[1] = { 0 };
    if (!wasm_runtime_call_wasm(exec_env, func, 0, argv)) {
        return TWEP_WR_ERR_WASM_RUNTIME;
    }
    *out_value = argv[0];
    return TWEP_WR_OK;
}

twep_wr_status_t twep_wr_call_free(wasm_exec_env_t exec_env, wasm_module_inst_t module_inst,
                                   uint32_t ptr, uint32_t len)
{
    wasm_function_inst_t free_func = wasm_runtime_lookup_function(module_inst, "twep_app_free");
    if (free_func == NULL) {
        return TWEP_WR_ERR_WASM_ABI;
    }
    uint32_t argv[2] = { ptr, len };
    if (!wasm_runtime_call_wasm(exec_env, free_func, 2, argv)) {
        return TWEP_WR_ERR_WASM_RUNTIME;
    }
    return TWEP_WR_OK;
}
