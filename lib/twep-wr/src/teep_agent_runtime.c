/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */
#include "runtime_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void twep_host_log(wasm_exec_env_t exec_env, uint32_t level, const char *msg, uint32_t msg_len);
static int32_t twep_host_read_file(wasm_exec_env_t exec_env, const char *path, uint32_t path_len,
                                   uint8_t *buf, uint32_t buf_cap, uint32_t *out_len);
static int32_t twep_host_write_file(wasm_exec_env_t exec_env, const char *path, uint32_t path_len,
                                    const uint8_t *data, uint32_t data_len);
static int32_t twep_host_read_protected(wasm_exec_env_t exec_env, const char *object_name, uint32_t object_name_len,
                                        uint8_t *buf, uint32_t buf_cap, uint32_t *out_len);
static int32_t twep_host_http_post(wasm_exec_env_t exec_env, const char *url, uint32_t url_len,
                                   const uint8_t *body, uint32_t body_len, uint8_t *buf, uint32_t buf_cap,
                                   uint32_t *out_len);
static int32_t twep_host_create_evidence(wasm_exec_env_t exec_env, const uint8_t *challenge, uint32_t challenge_len,
                                         const uint8_t *agent_public_key_cose, uint32_t agent_public_key_cose_len,
                                         uint8_t *buf, uint32_t buf_cap, uint32_t *out_len);
static int32_t twep_host_attestation_payload_format(wasm_exec_env_t exec_env, uint8_t *buf,
                                                     uint32_t buf_cap, uint32_t *out_len);
static int32_t twep_host_platform_status(wasm_exec_env_t exec_env, uint8_t *buf, uint32_t buf_cap,
                                         uint32_t *out_len);
static int32_t twep_host_teep_agent_measurement_sha256(wasm_exec_env_t exec_env, uint8_t *buf, uint32_t buf_cap,
                                                       uint32_t *out_len);
static int32_t twep_host_acceptance_generation(wasm_exec_env_t exec_env, uint64_t *generation);
static int32_t twep_host_commit_acceptance(wasm_exec_env_t exec_env, const uint8_t *digest, uint32_t digest_len,
                                           const uint8_t *component_id, uint32_t component_id_len,
                                           uint64_t sequence, uint64_t expected_generation,
                                           uint64_t *new_generation);
static int32_t twep_host_commit_catalog(wasm_exec_env_t exec_env, const uint8_t *digest, uint32_t digest_len,
                                        const uint8_t *component_id, uint32_t component_id_len,
                                        uint64_t sequence, uint64_t expected_generation,
                                        const uint8_t *catalog, uint32_t catalog_len,
                                        const uint8_t *catalog_digest, uint32_t catalog_digest_len,
                                        uint64_t *new_generation);
static int32_t twep_host_random(wasm_exec_env_t exec_env, uint8_t *buf, uint32_t buf_len);
static uint64_t twep_host_unix_time_ms(wasm_exec_env_t exec_env);

static NativeSymbol teep_agent_native_symbols[] = {
    { "twep_host_log", twep_host_log, "(i*~)", NULL },
    { "twep_host_read_file", twep_host_read_file, "(*~*~*)i", NULL },
    { "twep_host_write_file", twep_host_write_file, "(*~*~)i", NULL },
    { "twep_host_read_protected", twep_host_read_protected, "(*~*~*)i", NULL },
    { "twep_host_http_post", twep_host_http_post, "(*~*~*~*)i", NULL },
    { "twep_host_create_evidence", twep_host_create_evidence, "(*~*~*~*)i", NULL },
    { "twep_host_attestation_payload_format", twep_host_attestation_payload_format, "(*~*)i", NULL },
    { "twep_host_platform_status", twep_host_platform_status, "(*~*)i", NULL },
    { "twep_host_teep_agent_measurement_sha256", twep_host_teep_agent_measurement_sha256, "(*~*)i", NULL },
    { "twep_host_acceptance_generation", twep_host_acceptance_generation, "(*)i", NULL },
    { "twep_host_commit_acceptance", twep_host_commit_acceptance, "(*~*~II*)i", NULL },
    { "twep_host_commit_catalog", twep_host_commit_catalog, "(*~*~II*~*~*)i", NULL },
    { "twep_host_random", twep_host_random, "(*~)i", NULL },
    { "twep_host_unix_time_ms", twep_host_unix_time_ms, "()I", NULL },
};

twep_wr_status_t twep_wr_register_teep_agent_hostcalls(void)
{
    if (!wasm_runtime_register_natives("twep_teep_env", teep_agent_native_symbols,
                                       sizeof(teep_agent_native_symbols) / sizeof(teep_agent_native_symbols[0]))) {
        return TWEP_WR_ERR_INIT;
    }
    return TWEP_WR_OK;
}

static int32_t platform_status_to_host_status(twep_wr_platform_status_t status)
{
    switch (status) {
    case TWEP_WR_PLATFORM_OK: return 0;
    case TWEP_WR_PLATFORM_ERR_NO_MEMORY: return 2;
    case TWEP_WR_PLATFORM_ERR_UNSUPPORTED: return 8;
    case TWEP_WR_PLATFORM_ERR_IO: return 7;
    }
    return 7;
}

const twep_wr_context_t *twep_wr_teep_agent_context_from_exec_env(wasm_exec_env_t exec_env)
{
    teep_agent_exec_context_t *teep_ctx =
        (teep_agent_exec_context_t *)wasm_runtime_get_user_data(exec_env);
    if (teep_ctx == NULL || teep_ctx->capability != TWEP_WR_TEEP_AGENT_CAPABILITY || teep_ctx->ctx == NULL) {
        return NULL;
    }
    return teep_ctx->ctx;
}

static void twep_host_log(wasm_exec_env_t exec_env, uint32_t level, const char *msg, uint32_t msg_len)
{
    if (twep_wr_teep_agent_context_from_exec_env(exec_env) == NULL) {
        return;
    }
    fprintf(stderr, "teep-agent[%u]: %.*s\n", level, (int)msg_len, msg);
}

static int32_t twep_host_read_file(wasm_exec_env_t exec_env, const char *path, uint32_t path_len,
                                   uint8_t *buf, uint32_t buf_cap, uint32_t *out_len)
{
    const twep_wr_context_t *ctx = twep_wr_teep_agent_context_from_exec_env(exec_env);
    char relative[TWEP_WR_MAX_PATH_LEN];
    char full_path[TWEP_WR_MAX_PATH_LEN];
    if (ctx == NULL || out_len == NULL
        || !twep_wr_relative_state_file_path(path, path_len, relative, sizeof(relative))
        || !twep_wr_state_relative_path(ctx, relative, full_path, sizeof(full_path))) {
        return 1;
    }
    size_t file_len = 0;
    uint8_t *bytes = twep_wr_read_file(full_path, &file_len);
    if (bytes == NULL) {
        return 3;
    }
    *out_len = file_len > UINT32_MAX ? UINT32_MAX : (uint32_t)file_len;
    if (file_len > buf_cap) {
        free(bytes);
        return 2;
    }
    if (file_len != 0 && buf != NULL) {
        memcpy(buf, bytes, file_len);
    }
    free(bytes);
    return 0;
}

static int32_t twep_host_write_file(wasm_exec_env_t exec_env, const char *path, uint32_t path_len,
                                    const uint8_t *data, uint32_t data_len)
{
    const twep_wr_context_t *ctx = twep_wr_teep_agent_context_from_exec_env(exec_env);
    char relative[TWEP_WR_MAX_PATH_LEN];
    char full_path[TWEP_WR_MAX_PATH_LEN];
    if (ctx == NULL || data == NULL
        || !twep_wr_relative_state_file_path(path, path_len, relative, sizeof(relative))
        || !twep_wr_state_relative_path(ctx, relative, full_path, sizeof(full_path))) {
        return 1;
    }
    twep_wr_platform_status_t status = twep_wr_platform_write_file_atomic(full_path, data, data_len);
    return status == TWEP_WR_PLATFORM_OK ? 0 : 7;
}

static int32_t twep_host_read_protected(wasm_exec_env_t exec_env, const char *object_name, uint32_t object_name_len,
                                        uint8_t *buf, uint32_t buf_cap, uint32_t *out_len)
{
    const twep_wr_context_t *ctx = twep_wr_teep_agent_context_from_exec_env(exec_env);
    char name[TWEP_WR_MAX_PATH_LEN];
    if (ctx == NULL || ctx->state_dir == NULL || out_len == NULL
        || !twep_wr_protected_object_name(object_name, object_name_len, name, sizeof(name))) {
        return 1;
    }
    if (!twep_wr_platform_supports_protected_storage()) {
        return 8;
    }

    uint8_t *bytes = NULL;
    size_t sealed_len = 0;
    twep_wr_platform_status_t status = twep_wr_platform_sealed_read(ctx->state_dir, name, &bytes, &sealed_len);
    if (status == TWEP_WR_PLATFORM_ERR_UNSUPPORTED) {
        return 8;
    }
    if (status != TWEP_WR_PLATFORM_OK) {
        return 3;
    }
    *out_len = sealed_len > UINT32_MAX ? UINT32_MAX : (uint32_t)sealed_len;
    if (sealed_len > buf_cap) {
        free(bytes);
        return 2;
    }
    if (sealed_len != 0 && buf != NULL) {
        memcpy(buf, bytes, sealed_len);
    }
    free(bytes);
    return 0;
}

static int32_t twep_host_http_post(wasm_exec_env_t exec_env, const char *url, uint32_t url_len,
                                   const uint8_t *body, uint32_t body_len, uint8_t *buf, uint32_t buf_cap,
                                   uint32_t *out_len)
{
    const twep_wr_context_t *ctx = twep_wr_teep_agent_context_from_exec_env(exec_env);
    (void)body;
    (void)body_len;
    (void)buf;
    (void)buf_cap;
    if (ctx == NULL || url == NULL || out_len == NULL) {
        return 1;
    }
    *out_len = 0;
    if (strcmp(ctx->resolver_mode, "attestam-insecure") != 0 || !ctx->insecure_demo_mode) {
        return 4;
    }
    size_t allowed_len = strlen(ctx->attestam_url);
    if (allowed_len == 0 || allowed_len != url_len || memcmp(ctx->attestam_url, url, url_len) != 0) {
        return 4;
    }
    if (ctx->host_io.http_post == NULL) {
        return 5;
    }
    size_t response_len = 0;
    int32_t status = ctx->host_io.http_post(ctx->host_io.user_data, (const uint8_t *)url, url_len,
                                            body, body_len, buf, buf_cap, &response_len);
    *out_len = response_len > UINT32_MAX ? UINT32_MAX : (uint32_t)response_len;
    return status;
}

static int32_t twep_host_create_evidence(wasm_exec_env_t exec_env, const uint8_t *challenge, uint32_t challenge_len,
                                         const uint8_t *agent_public_key_cose, uint32_t agent_public_key_cose_len,
                                         uint8_t *buf, uint32_t buf_cap, uint32_t *out_len)
{
    const twep_wr_context_t *ctx = twep_wr_teep_agent_context_from_exec_env(exec_env);
    if (ctx == NULL || out_len == NULL || (challenge == NULL && challenge_len != 0)
        || (agent_public_key_cose == NULL && agent_public_key_cose_len != 0)) {
        return 1;
    }
    *out_len = 0;
    if (strcmp(ctx->resolver_mode, "attestam-insecure") != 0 || !ctx->insecure_demo_mode) {
        return 4;
    }
    if (ctx->host_io.create_evidence == NULL) {
        return 8;
    }
    size_t evidence_len = 0;
    int32_t status = ctx->host_io.create_evidence(ctx->host_io.user_data, challenge, challenge_len,
                                                  agent_public_key_cose, agent_public_key_cose_len,
                                                  buf, buf_cap, &evidence_len);
    *out_len = evidence_len > UINT32_MAX ? UINT32_MAX : (uint32_t)evidence_len;
    return status;
}

static int32_t twep_host_attestation_payload_format(wasm_exec_env_t exec_env, uint8_t *buf,
                                                     uint32_t buf_cap, uint32_t *out_len)
{
    static const char format[] =
        "application/eat+cwt; eat_profile=\"urn:ietf:rfc:rfc9711\"";
    const size_t format_len = sizeof(format) - 1;
    if (twep_wr_teep_agent_context_from_exec_env(exec_env) == NULL || out_len == NULL) {
        return 1;
    }
    *out_len = (uint32_t)format_len;
    if (buf_cap < format_len) {
        return 2;
    }
    if (format_len != 0 && buf != NULL) {
        memcpy(buf, format, format_len);
    }
    return 0;
}

static int32_t twep_host_platform_status(wasm_exec_env_t exec_env, uint8_t *buf, uint32_t buf_cap,
                                         uint32_t *out_len)
{
    if (twep_wr_teep_agent_context_from_exec_env(exec_env) == NULL || out_len == NULL) {
        return 1;
    }
    const twep_wr_platform_info_t *info = twep_wr_platform_info();
    if (info == NULL || info->backend_name == NULL) {
        return 7;
    }

    char text[256];
    int n = snprintf(text, sizeof(text),
                     "platform-backend=%s\n"
                     "sealed-storage-security=%s\n"
                     "sealed-storage-rollback-protected=%s\n"
                     "protected-storage-supported=%s\n"
                     "file-io=%s\n"
                     "random=%s\n"
                     "time=%s\n",
                     info->backend_name,
                     twep_wr_platform_sealed_security_label(info->sealed_storage_security),
                     twep_wr_bool_label(info->sealed_storage_security == TWEP_WR_PLATFORM_SEALED_TEE_PROTECTED),
                     twep_wr_bool_label(twep_wr_platform_supports_protected_storage()),
                     twep_wr_bool_label(info->supports_file_io),
                     twep_wr_bool_label(info->supports_random),
                     twep_wr_bool_label(info->supports_time));
    if (n <= 0 || (size_t)n >= sizeof(text)) {
        return 7;
    }
    *out_len = (uint32_t)n;
    if ((uint32_t)n > buf_cap) {
        return 2;
    }
    if (n != 0 && buf != NULL) {
        memcpy(buf, text, (size_t)n);
    }
    return 0;
}

static int32_t twep_host_teep_agent_measurement_sha256(wasm_exec_env_t exec_env, uint8_t *buf, uint32_t buf_cap,
                                                       uint32_t *out_len)
{
    teep_agent_exec_context_t *teep_ctx =
        (teep_agent_exec_context_t *)wasm_runtime_get_user_data(exec_env);
    uint8_t digest[SHA256_DIGEST_LENGTH];
    if (teep_ctx == NULL || teep_ctx->capability != TWEP_WR_TEEP_AGENT_CAPABILITY || out_len == NULL) {
        return 1;
    }
    if (teep_ctx->teep_agent_wasm == NULL || teep_ctx->teep_agent_wasm_len == 0) {
        *out_len = 0;
        return 8;
    }
    *out_len = SHA256_DIGEST_LENGTH;
    if (buf_cap < SHA256_DIGEST_LENGTH) {
        return 2;
    }
    if (buf == NULL) {
        return 1;
    }
    SHA256(teep_ctx->teep_agent_wasm, teep_ctx->teep_agent_wasm_len, digest);
    memcpy(buf, digest, sizeof(digest));
    return 0;
}

static int32_t twep_host_acceptance_generation(wasm_exec_env_t exec_env, uint64_t *generation)
{
    if (twep_wr_teep_agent_context_from_exec_env(exec_env) == NULL || generation == NULL) {
        return 1;
    }
    *generation = 0;
    return 8;
}

static int32_t twep_host_commit_acceptance(wasm_exec_env_t exec_env, const uint8_t *digest, uint32_t digest_len,
                                           const uint8_t *component_id, uint32_t component_id_len,
                                           uint64_t sequence, uint64_t expected_generation,
                                           uint64_t *new_generation)
{
    (void)digest;
    (void)digest_len;
    (void)component_id;
    (void)component_id_len;
    (void)sequence;
    (void)expected_generation;
    if (twep_wr_teep_agent_context_from_exec_env(exec_env) == NULL || new_generation == NULL) {
        return 1;
    }
    *new_generation = 0;
    return 8;
}

static int32_t twep_host_commit_catalog(wasm_exec_env_t exec_env, const uint8_t *digest, uint32_t digest_len,
                                        const uint8_t *component_id, uint32_t component_id_len,
                                        uint64_t sequence, uint64_t expected_generation,
                                        const uint8_t *catalog, uint32_t catalog_len,
                                        const uint8_t *catalog_digest, uint32_t catalog_digest_len,
                                        uint64_t *new_generation)
{
    (void)digest;
    (void)digest_len;
    (void)component_id;
    (void)component_id_len;
    (void)sequence;
    (void)expected_generation;
    (void)catalog;
    (void)catalog_len;
    (void)catalog_digest;
    (void)catalog_digest_len;
    if (twep_wr_teep_agent_context_from_exec_env(exec_env) == NULL || new_generation == NULL) {
        return 1;
    }
    *new_generation = 0;
    return 8;
}

static int32_t twep_host_random(wasm_exec_env_t exec_env, uint8_t *buf, uint32_t buf_len)
{
    if (twep_wr_teep_agent_context_from_exec_env(exec_env) == NULL) {
        return 1;
    }
    if (buf == NULL && buf_len != 0) {
        return 1;
    }
    return twep_wr_platform_random(buf, buf_len) == TWEP_WR_PLATFORM_OK ? 0 : 7;
}

static uint64_t twep_host_unix_time_ms(wasm_exec_env_t exec_env)
{
    if (twep_wr_teep_agent_context_from_exec_env(exec_env) == NULL) {
        return 0;
    }
    return twep_wr_platform_unix_time_ms();
}
