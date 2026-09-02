/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */
#include "sgx_runtime_internal.h"
#include "twep_wr_sgx_t.h"

#include <limits.h>
#include <sgx_tcrypto.h>
#include <sgx_trts.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wasm_export.h>

/*
 * This is the only WAMR instance that receives TEEP hostcalls.  A valid
 * exec-env capability is necessary but each hostcall also validates its
 * buffers and resolver mode before transporting bytes through the REE or
 * changing Enclave-owned protected state.
 */
#define TEEP_CAPABILITY 0x54454550u
#define TEEP_STACK (64u * 1024u)
#define TEEP_HEAP (2u * 1024u * 1024u)
#define HOST_UNSUPPORTED 8

struct teep_host_context {
    uint32_t capability;
    uint8_t transient[256];
    size_t transient_len;
    uint8_t pending_query_response_sha256[32];
    int pending_query_response;
};

static void transcript_begin_http(struct teep_host_context *ctx)
{
    if (!ctx)
        return;
    ctx->pending_query_response = 0;
    memset(ctx->pending_query_response_sha256, 0,
           sizeof(ctx->pending_query_response_sha256));
}

static int transcript_record_http(struct teep_host_context *ctx,
                                  const uint8_t *body, uint32_t body_len)
{
    sgx_sha256_hash_t digest;
    if (!ctx || (!body && body_len)
        || sgx_sha256_msg(body, body_len, &digest) != SGX_SUCCESS)
        return 0;
    memcpy(ctx->pending_query_response_sha256, digest, sizeof(digest));
    ctx->pending_query_response = 1;
    memset(&digest, 0, sizeof(digest));
    return 1;
}

static struct teep_host_context *host_context(wasm_exec_env_t env)
{
    struct teep_host_context *ctx = wasm_runtime_get_user_data(env);
    return ctx && ctx->capability == TEEP_CAPABILITY ? ctx : NULL;
}

static int artifact_path(const char *p, uint32_t n, char out[160])
{
    if (!p || !n || n >= 160)
        return 0;
    memcpy(out, p, n);
    out[n] = '\0';
    if (sgx_verified_mode()
        && (strcmp(out, "catalog/catalog.cbor") == 0
            || strncmp(out, "apps/", 5) == 0))
        return 0;
    return !strcmp(out, "catalog/catalog.cbor")
        || !strcmp(out, "teep-agent/dev-agent-public-key.cbor")
        || (!strncmp(out, "apps/", 5)
            && sgx_catalog_safe_wasm_basename(out + 5));
}

static int32_t host_read(wasm_exec_env_t env, const char *path,
                         uint32_t path_len, uint8_t *buf, uint32_t cap,
                         uint32_t *out_len)
{
    char relative[160];
    size_t len = 0;
    int result = 1;
    if (!host_context(env) || !out_len || !path
        || path_len >= sizeof(relative))
        return 1;
    memcpy(relative, path, path_len);
    relative[path_len] = '\0';
    if (sgx_verified_mode()
        && strcmp(relative, "catalog/catalog.cbor") == 0) {
        int status = sgx_catalog_read_active(buf, cap, &len);
        if (status != SGX_STORE_OK && status != SGX_STORE_SHORT_BUFFER)
            (void)ocall_twep_log("protected Catalog read failed");
        *out_len = len > UINT32_MAX ? UINT32_MAX : (uint32_t)len;
        return status;
    }
    if (sgx_verified_mode() && strncmp(relative, "apps/", 5) == 0
        && sgx_catalog_safe_wasm_basename(relative + 5)) {
        int status = sgx_app_read_active(buf, cap, &len, NULL, NULL, 0,
                                         NULL, NULL);
        if (status != SGX_STORE_OK && status != SGX_STORE_SHORT_BUFFER)
            (void)ocall_twep_log("protected app read failed");
        *out_len = len > UINT32_MAX ? UINT32_MAX : (uint32_t)len;
        return status;
    }
    if (!artifact_path(path, path_len, relative))
        return 1;
    if (ocall_twep_read_artifact(&result, relative, NULL, 0, &len)
        != SGX_SUCCESS || result != 0)
        return 3;
    *out_len = len > UINT32_MAX ? UINT32_MAX : (uint32_t)len;
    if (len > cap)
        return 2;
    if (ocall_twep_read_artifact(&result, relative, buf, cap, &len)
        != SGX_SUCCESS || result != 0)
        return 7;
    return 0;
}

static int32_t host_write(wasm_exec_env_t env, const char *path,
                          uint32_t path_len, const uint8_t *data,
                          uint32_t data_len)
{
    static const char probe[] = "tmp/teep-agent-probe";
    struct teep_host_context *ctx = host_context(env);
    int result = 1;
    if (!ctx || !path || !data)
        return 1;
    if (path_len == sizeof(probe) - 1
        && memcmp(path, probe, sizeof(probe) - 1) == 0
        && data_len <= sizeof(ctx->transient)) {
        memcpy(ctx->transient, data, data_len);
        ctx->transient_len = data_len;
        return 0;
    }
#ifdef TWEP_WR_SGX_HW
    if (path_len < sizeof("teep-agent/") - 1
        || memcmp(path, "teep-agent/", sizeof("teep-agent/") - 1) != 0
        || data_len > 128u * 1024u)
        return 1;
    if (ocall_twep_write_diagnostic(&result, (const uint8_t *)path, path_len,
                                    data, data_len) != SGX_SUCCESS)
        return 7;
    return result;
#else
    return 1;
#endif
}

static void host_log(wasm_exec_env_t env, uint32_t level, const char *msg,
                     uint32_t msg_len)
{
    char line[160];
    size_t n;
    (void)level;
    if (!host_context(env) || !msg)
        return;
    n = msg_len < sizeof(line) - 1 ? msg_len : sizeof(line) - 1;
    memcpy(line, msg, n);
    line[n] = '\0';
    (void)ocall_twep_log(line);
}

static int32_t host_read_protected(wasm_exec_env_t env, const char *name,
                                   uint32_t name_len, uint8_t *buf,
                                   uint32_t cap, uint32_t *out_len)
{
    if (!host_context(env) || !out_len) return 1;
    size_t len = 0;
    int status = sgx_store_read_protected(name, name_len, buf, cap, &len);
    *out_len = len > UINT32_MAX ? UINT32_MAX : (uint32_t)len;
    return status;
}

static int32_t unsupported_read(wasm_exec_env_t env, const char *name,
                                uint32_t name_len, uint8_t *buf,
                                uint32_t cap, uint32_t *out_len)
{
    (void)name; (void)name_len; (void)buf; (void)cap;
    if (!host_context(env) || !out_len) return 1;
    *out_len = 0;
    return HOST_UNSUPPORTED;
}

static int32_t unsupported_http(wasm_exec_env_t env, const char *url,
                                uint32_t url_len, const uint8_t *body,
                                uint32_t body_len, uint8_t *buf,
                                uint32_t cap, uint32_t *out_len)
{
    (void)url; (void)url_len; (void)body; (void)body_len;
    return unsupported_read(env, "", 0, buf, cap, out_len);
}

static int32_t host_http(wasm_exec_env_t env, const char *url,
                         uint32_t url_len, const uint8_t *body,
                         uint32_t body_len, uint8_t *buf, uint32_t cap,
                         uint32_t *out_len)
{
#ifdef TWEP_WR_SGX_HW
    struct teep_host_context *ctx = host_context(env);
    const char *allowed = sgx_attestam_url();
    size_t response_len = 0, allowed_len = strlen(allowed);
    int result = 7;
    if (!ctx || !out_len)
        return 1;
    *out_len = 0;
    transcript_begin_http(ctx);
    if (!url || (!body && body_len)
        || body_len > 32u * 1024u || cap > 128u * 1024u)
        return 1;
    if (!sgx_verified_mode() || !allowed_len || allowed_len != url_len
        || memcmp(allowed, url, url_len) != 0)
        return 4;
    if (ocall_twep_http_post(&result, (const uint8_t *)url, url_len, body,
                             body_len, buf, cap, &response_len) != SGX_SUCCESS) {
        transcript_begin_http(ctx);
        return 7;
    }
    *out_len = response_len > UINT32_MAX ? UINT32_MAX : (uint32_t)response_len;
    if (result != 0 || response_len > cap)
        transcript_begin_http(ctx);
    else if (!transcript_record_http(ctx, body, body_len))
        return 7;
    return result;
#else
    return unsupported_http(env, url, url_len, body, body_len, buf, cap,
                            out_len);
#endif
}

static int32_t host_evidence(wasm_exec_env_t env, const uint8_t *challenge,
                             uint32_t challenge_len, const uint8_t *key,
                             uint32_t key_len, uint8_t *buf, uint32_t cap,
                             uint32_t *out_len)
{
    size_t len = 0;
    int status;
    if (!host_context(env) || !out_len) return 1;
    status = sgx_dcap_create_evidence(challenge, challenge_len, key, key_len,
                                      buf, cap, &len);
    *out_len = len > UINT32_MAX ? UINT32_MAX : (uint32_t)len;
    return status;
}

static int32_t host_attestation_format(wasm_exec_env_t env, uint8_t *buf,
                                       uint32_t cap, uint32_t *out_len)
{
#ifdef TWEP_WR_SGX_HW
    static const char format[] = "application/sgx-quote3-teep-bundle";
    if (!host_context(env) || !out_len) return 1;
    *out_len = sizeof(format) - 1;
    if (cap < sizeof(format) - 1) return 2;
    memcpy(buf, format, sizeof(format) - 1);
    return 0;
#else
    (void)buf; (void)cap;
    if (!host_context(env) || !out_len) return 1;
    *out_len = 0;
    return HOST_UNSUPPORTED;
#endif
}

static int32_t unsupported_simple(wasm_exec_env_t env, uint8_t *buf,
                                  uint32_t cap, uint32_t *out_len)
{
    return unsupported_read(env, "", 0, buf, cap, out_len);
}
static int32_t host_platform_status(wasm_exec_env_t env, uint8_t *buf,
                                    uint32_t cap, uint32_t *out_len)
{
    static const char status[] =
        "platform-backend=sgx\n"
        "sealed-storage-security=tee-protected\n"
        "sealed-storage-rollback-protected=false\n"
        "runtime-location=sgx-enclave\n"
        "teep-agent-location=sgx-enclave\n"
        "catalog-resolution-location=sgx-enclave\n"
        "final-verified=false\n";
    if (!host_context(env) || !out_len) return 1;
    *out_len = sizeof(status) - 1;
    if (cap < sizeof(status) - 1) return 2;
    memcpy(buf, status, sizeof(status) - 1);
    return 0;
}
static int32_t host_measurement(wasm_exec_env_t env, uint8_t *buf,
                                uint32_t cap, uint32_t *out_len)
{
    if (!host_context(env) || !out_len) return 1;
    *out_len = 32;
    if (cap < 32) return 2;
    memcpy(buf, sgx_teep_agent_measurement(), 32);
    return 0;
}
static int32_t host_generation(wasm_exec_env_t env, uint64_t *gen)
{
    if (!host_context(env) || !gen) return 1;
    return sgx_acceptance_generation(gen);
}
static int transcript_consume(struct teep_host_context *ctx,
                              const uint8_t *digest, uint32_t digest_len)
{
    int match = ctx && digest && digest_len == 32
        && ctx->pending_query_response
        && memcmp(ctx->pending_query_response_sha256, digest, 32) == 0;
    if (ctx) {
        /* Consume on both match and mismatch.  A failed commit must not leave
         * an earlier QueryResponse reusable by a later hostcall. */
        ctx->pending_query_response = 0;
        memset(ctx->pending_query_response_sha256, 0,
               sizeof(ctx->pending_query_response_sha256));
    }
    return match;
}

#ifdef TWEP_WR_SGX_TEST_HOOKS
int sgx_teep_transcript_test(uint32_t scenario)
{
    static const uint8_t request_a[] = {0x84, 0x01, 0x02, 0x03};
    static const uint8_t request_b[] = {0x84, 0x04, 0x05, 0x06};
    static const uint8_t response_a[] = {0x84, 0x11};
    static const uint8_t response_b[] = {0x84, 0x22};
    uint8_t digest_a[32], digest_b[32], wrong[32] = {0};
    struct teep_host_context ctx = { .capability = TEEP_CAPABILITY };
    sgx_sha256_hash_t hash;
    uint32_t wrapper;

    if (sgx_sha256_msg(request_a, sizeof(request_a), &hash) != SGX_SUCCESS)
        return 7;
    memcpy(digest_a, hash, sizeof(digest_a));
    if (sgx_sha256_msg(request_b, sizeof(request_b), &hash) != SGX_SUCCESS)
        return 7;
    memcpy(digest_b, hash, sizeof(digest_b));
    memset(&hash, 0, sizeof(hash));

    if (scenario == 1) {
        /* Different response bytes never enter the production record helper. */
        if (memcmp(response_a, response_b, sizeof(response_a)) == 0)
            return 1;
        transcript_begin_http(&ctx);
        if (!transcript_record_http(&ctx, request_a, sizeof(request_a))
            || !transcript_consume(&ctx, digest_a, sizeof(digest_a)))
            return 1;
        transcript_begin_http(&ctx);
        if (!transcript_record_http(&ctx, request_a, sizeof(request_a))
            || !transcript_consume(&ctx, digest_a, sizeof(digest_a))
            || transcript_consume(&ctx, digest_a, sizeof(digest_a)))
            return 1;
        return 0;
    }
    if (scenario == 2) {
        transcript_begin_http(&ctx);
        if (!transcript_record_http(&ctx, request_a, sizeof(request_a))
            || transcript_consume(&ctx, wrong, sizeof(wrong))
            || transcript_consume(&ctx, digest_a, sizeof(digest_a)))
            return 1;
        transcript_begin_http(&ctx);
        if (!transcript_record_http(&ctx, request_a, sizeof(request_a))
            || transcript_consume(&ctx, digest_a, 31)
            || transcript_consume(&ctx, digest_a, sizeof(digest_a))
            || transcript_consume(&ctx, digest_a, sizeof(digest_a)))
            return 1;
        return 0;
    }
    if (scenario == 3) {
        transcript_begin_http(&ctx);
        if (!transcript_record_http(&ctx, request_a, sizeof(request_a)))
            return 1;
        transcript_begin_http(&ctx); /* failed attempt invalidates A */
        if (transcript_consume(&ctx, digest_a, sizeof(digest_a)))
            return 1;
        if (!transcript_record_http(&ctx, request_a, sizeof(request_a)))
            return 1;
        transcript_begin_http(&ctx);
        if (!transcript_record_http(&ctx, request_b, sizeof(request_b))
            || transcript_consume(&ctx, digest_a, sizeof(digest_a))
            || transcript_consume(&ctx, digest_b, sizeof(digest_b)))
            return 1;
        transcript_begin_http(&ctx);
        return transcript_record_http(&ctx, request_b, sizeof(request_b))
            && transcript_consume(&ctx, digest_b, sizeof(digest_b)) ? 0 : 1;
    }
    if (scenario == 4) {
        /* acceptance, Catalog, and App wrappers all use this same gate. */
        for (wrapper = 0; wrapper < 3; ++wrapper) {
            transcript_begin_http(&ctx);
            if (!transcript_record_http(&ctx, request_a, sizeof(request_a))
                || !transcript_consume(&ctx, digest_a, sizeof(digest_a))
                || transcript_consume(&ctx, digest_a, sizeof(digest_a)))
                return 1;
        }
        return 0;
    }
    return 1;
}
#endif

static int32_t host_commit_acceptance(wasm_exec_env_t env, const uint8_t *d,
    uint32_t dl, const uint8_t *c, uint32_t cl, uint64_t s, uint64_t g,
    uint64_t *ng)
{
    struct teep_host_context *ctx = host_context(env);
    if (!ctx || !ng || !d || !c)
        return 1;
    if (!sgx_verified_mode())
        return HOST_UNSUPPORTED;
    if (!transcript_consume(ctx, d, dl))
        return SGX_PROTECTED_STATE_CONFLICT;
    return sgx_acceptance_commit(d, c, cl, s, g, ng);
}

static int32_t host_commit_catalog(wasm_exec_env_t env, const uint8_t *d,
    uint32_t dl, const uint8_t *c, uint32_t cl, uint64_t s, uint64_t g,
    const uint8_t *b, uint32_t bl, const uint8_t *h, uint32_t hl,
    uint64_t *ng)
{
    struct teep_host_context *ctx = host_context(env);
    int result;
    if (!ctx || !ng || !d || !c || !b || !h || hl != 32)
        return 1;
    if (!sgx_verified_mode())
        return HOST_UNSUPPORTED;
    if (!transcript_consume(ctx, d, dl))
        return SGX_PROTECTED_STATE_CONFLICT;
    result = sgx_catalog_commit(d, c, cl, s, g, b, bl, h, ng);
    if (result != 0) {
        char line[64];
        (void)snprintf(line, sizeof(line), "Catalog commit status=%d", result);
        (void)ocall_twep_log(line);
    }
    return result;
}

static int32_t host_commit_app(wasm_exec_env_t env, const uint8_t *d,
    uint32_t dl, const uint8_t *c, uint32_t cl, uint64_t s, uint64_t g,
    const uint8_t *b, uint32_t bl, const uint8_t *h, uint32_t hl,
    uint64_t *ng)
{
    struct teep_host_context *ctx = host_context(env);
    int result;
    if (!ctx || !ng || !d || !c || !b || !h || hl != 32)
        return 1;
    if (!sgx_verified_mode())
        return HOST_UNSUPPORTED;
    if (!transcript_consume(ctx, d, dl))
        return SGX_PROTECTED_STATE_CONFLICT;
    result = sgx_app_commit(d, c, cl, s, g, b, bl, h, ng);
    if (result != 0) {
        char line[64];
        (void)snprintf(line, sizeof(line), "app commit status=%d", result);
        (void)ocall_twep_log(line);
    }
    return result;
}
static int32_t host_random(wasm_exec_env_t env, uint8_t *buf, uint32_t len)
{
#ifdef TWEP_WR_SGX_HW
    if (!host_context(env) || (!buf && len)) return 1;
    return sgx_read_rand(buf, len) == SGX_SUCCESS ? 0 : 7;
#else
    uint32_t i;
    if (!host_context(env) || (!buf && len)) return 1;
    for (i = 0; i < len; ++i) buf[i] = (uint8_t)(0x5a ^ i);
    return 0;
#endif
}
static uint64_t host_time(wasm_exec_env_t env)
{
    /*
     * Compatibility/probe value only. SGX has no trusted wall clock here and
     * protocol freshness and authorization must never depend on this value.
     */
    return host_context(env) ? 1700000000000ULL : 0;
}

static NativeSymbol symbols[] = {
    { "twep_host_log", host_log, "(i*~)", NULL },
    { "twep_host_read_file", host_read, "(*~*~*)i", NULL },
    { "twep_host_write_file", host_write, "(*~*~)i", NULL },
    { "twep_host_read_protected", host_read_protected, "(*~*~*)i", NULL },
    { "twep_host_http_post", host_http, "(*~*~*~*)i", NULL },
    { "twep_host_create_evidence", host_evidence, "(*~*~*~*)i", NULL },
    { "twep_host_attestation_payload_format", host_attestation_format, "(*~*)i", NULL },
    { "twep_host_platform_status", host_platform_status, "(*~*)i", NULL },
    { "twep_host_teep_agent_measurement_sha256", host_measurement, "(*~*)i", NULL },
    { "twep_host_acceptance_generation", host_generation, "(*)i", NULL },
    { "twep_host_commit_acceptance", host_commit_acceptance, "(*~*~II*)i", NULL },
    { "twep_host_commit_catalog", host_commit_catalog, "(*~*~II*~*~*)i", NULL },
    { "twep_host_commit_app", host_commit_app, "(*~*~II*~*~*)i", NULL },
    { "twep_host_random", host_random, "(*~)i", NULL },
    { "twep_host_unix_time_ms", host_time, "()I", NULL },
};

static void type_len(uint8_t **p, uint8_t major, size_t n)
{
    if (n < 24) *(*p)++ = (uint8_t)(major << 5 | n);
    else { *(*p)++ = (uint8_t)(major << 5 | 24); *(*p)++ = (uint8_t)n; }
}
static void text(uint8_t **p, const char *s)
{
    size_t n = strlen(s); type_len(p, 3, n); memcpy(*p, s, n); *p += n;
}

static int contains(const uint8_t *buf, size_t len, const char *text_value)
{
    size_t n = strlen(text_value), i;
    for (i = 0; i + n <= len; ++i)
        if (!memcmp(buf + i, text_value, n))
            return 1;
    return 0;
}

struct teep_agent_execution {
    uint8_t *wasm_bytes;
    size_t wasm_len;
    int natives_registered;
    wasm_module_t module;
    wasm_module_inst_t instance;
    wasm_exec_env_t exec_env;
    struct teep_host_context host;
    uint32_t input_addr;
    uint8_t *input_native;
    uint32_t descriptor_addr;
    uint8_t *descriptor_native;
    uint32_t output_addr;
    uint32_t output_len;
    uint8_t *output_native;
};

static int load_teep_agent(struct teep_agent_execution *execution)
{
    static const char path[] = "teep-agent/teep-agent.wasm";
    size_t artifact_len = 0, loaded_len = 0;
    sgx_sha256_hash_t measurement;
    int ocall_result = 1;

    /* The REE transports the Agent bytes.  The Enclave verifies the role
     * signature before granting hostcall capability or loading the module. */
    if (ocall_twep_read_artifact(&ocall_result, path, NULL, 0, &artifact_len)
            != SGX_SUCCESS
        || ocall_result || !artifact_len || artifact_len > UINT32_MAX)
        return 3;

    execution->wasm_bytes = malloc(artifact_len);
    if (!execution->wasm_bytes)
        return 9;
    execution->wasm_len = artifact_len;
    if (ocall_twep_read_artifact(&ocall_result, path, execution->wasm_bytes,
                                 execution->wasm_len, &loaded_len)
            != SGX_SUCCESS
        || ocall_result || loaded_len != execution->wasm_len)
        return 4;
    if (!sgx_wasm_signature_verify(execution->wasm_bytes,
                                   execution->wasm_len,
                                   SGX_WASM_ROLE_TEEP_AGENT)
        || sgx_sha256_msg(execution->wasm_bytes,
                          (uint32_t)execution->wasm_len, &measurement)
                                      != SGX_SUCCESS
        || memcmp(measurement, sgx_teep_agent_measurement(),
                  sizeof(measurement)) != 0)
        return 12;
    return 0;
}

static uint32_t build_resolve_input(uint8_t input[512], const char *command)
{
    uint8_t *cursor = input;

    *cursor++ = 0xa6;
    text(&cursor, "schema_version");
    *cursor++ = 1;
    text(&cursor, "command");
    text(&cursor, "resolve_app");
    text(&cursor, "target_command");
    text(&cursor, command);
    text(&cursor, "resolver_mode");
    text(&cursor, sgx_resolver_mode());
    text(&cursor, "state_dir");
    text(&cursor, "");
    text(&cursor, "attestam_url");
    text(&cursor, sgx_attestam_url());
    return (uint32_t)(cursor - input);
}

static int prepare_teep_agent(struct teep_agent_execution *execution,
                              char error[128])
{
    if (!sgx_wamr_ensure_initialized())
        return 2;
    if (!wasm_runtime_register_natives("twep_teep_env", symbols,
            sizeof(symbols) / sizeof(symbols[0])))
        return 2;
    execution->natives_registered = 1;
    execution->module = wasm_runtime_load(execution->wasm_bytes,
        (uint32_t)execution->wasm_len, error, 128);
    if (!execution->module)
        return 4;
    execution->instance = wasm_runtime_instantiate(execution->module,
        TEEP_STACK, TEEP_HEAP, error, 128);
    if (!execution->instance)
        return 9;
    execution->exec_env = wasm_runtime_create_exec_env(execution->instance,
                                                       TEEP_STACK);
    if (!execution->exec_env)
        return 9;

    /* The capability is Enclave-owned and scoped to this exec-env.  The REE
     * remains byte/HTTP transport and cannot authorize protected actions. */
    execution->host.capability = TEEP_CAPABILITY;
    wasm_runtime_set_user_data(execution->exec_env, &execution->host);
    return 0;
}

static int call_teep_agent(struct teep_agent_execution *execution,
                           const uint8_t *input, uint32_t input_len)
{
    wasm_function_inst_t function;
    uint32_t arguments[3] = {0};

    function = wasm_runtime_lookup_function(execution->instance,
                                            "twep_app_abi_version");
    if (!function
        || !wasm_runtime_call_wasm(execution->exec_env, function, 0,
                                   arguments)
        || arguments[0] != 1)
        return 6;

    execution->input_addr = (uint32_t)wasm_runtime_module_malloc(
        execution->instance, input_len, (void **)&execution->input_native);
    execution->descriptor_addr = (uint32_t)wasm_runtime_module_malloc(
        execution->instance, 8, (void **)&execution->descriptor_native);
    if (!execution->input_addr || !execution->descriptor_addr)
        return 9;
    memcpy(execution->input_native, input, input_len);
    memset(execution->descriptor_native, 0, 8);

    function = wasm_runtime_lookup_function(execution->instance,
                                            "twep_app_main");
    arguments[0] = execution->input_addr;
    arguments[1] = input_len;
    arguments[2] = execution->descriptor_addr;
    if (!function
        || !wasm_runtime_call_wasm(execution->exec_env, function, 3,
                                   arguments)
        || (int32_t)arguments[0] != 0) {
        const char *exception = wasm_runtime_get_exception(execution->instance);
        (void)ocall_twep_log(exception ? "TEEP Agent trapped"
                                       : "TEEP Agent failed");
        return 4;
    }
    return 0;
}

#ifdef TWEP_WR_SGX_TEST_HOOKS
static void log_teep_agent_heap_peak(struct teep_agent_execution *execution)
{
    wasm_function_inst_t function = wasm_runtime_lookup_function(
        execution->instance, "twep_test_heap_peak_bytes");
    uint32_t arguments[1] = {0};
    char diagnostic[64];

    if (function
        && wasm_runtime_call_wasm(execution->exec_env, function, 0, arguments)) {
        (void)snprintf(diagnostic, sizeof(diagnostic),
                       "TEEP Agent heap peak=%u", arguments[0]);
        (void)ocall_twep_log(diagnostic);
    }
}
#endif

static int read_teep_agent_output(struct teep_agent_execution *execution)
{
    const uint8_t *descriptor = execution->descriptor_native;

    /* The Enclave decodes the little-endian descriptor and validates the
     * entire Wasm address range before treating resolver bytes as trusted. */
    execution->output_addr = (uint32_t)descriptor[0]
        | (uint32_t)descriptor[1] << 8
        | (uint32_t)descriptor[2] << 16
        | (uint32_t)descriptor[3] << 24;
    execution->output_len = (uint32_t)descriptor[4]
        | (uint32_t)descriptor[5] << 8
        | (uint32_t)descriptor[6] << 16
        | (uint32_t)descriptor[7] << 24;
    if (!execution->output_addr || !execution->output_len
        || !wasm_runtime_validate_app_addr(execution->instance,
                                           execution->output_addr,
                                           execution->output_len))
        return 4;
    execution->output_native = wasm_runtime_addr_app_to_native(
        execution->instance, execution->output_addr);
    return 0;
}

static int classify_teep_agent_output(struct teep_agent_execution *execution,
                                      const char *command,
                                      struct sgx_catalog_app *app)
{
    char diagnostic[160];
    size_t i;
    size_t diagnostic_len;

    /* Resolver parsing, status classification, and protected-state effects
     * remain Enclave decisions; REE-visible diagnostics grant no authority. */
    if (sgx_resolve_output_parse(execution->output_native,
                                 execution->output_len, command, app))
        return 0;
    if (contains(execution->output_native, execution->output_len,
                 "app.hash_mismatch"))
        return 8;
    if (contains(execution->output_native, execution->output_len,
                 "app.signature_unverified"))
        return 12;
    if (contains(execution->output_native, execution->output_len, "catalog."))
        return 3;

    diagnostic_len = execution->output_len < sizeof(diagnostic) - 1
        ? execution->output_len : sizeof(diagnostic) - 1;
    for (i = 0; i < diagnostic_len; ++i) {
        uint8_t byte = execution->output_native[i];
        diagnostic[i] = byte >= 0x20 && byte <= 0x7e ? (char)byte : '.';
    }
    diagnostic[diagnostic_len] = '\0';
    (void)ocall_twep_log(diagnostic);
    return 4;
}

static void cleanup_teep_agent(struct teep_agent_execution *execution)
{
    if (execution->descriptor_addr && execution->instance)
        wasm_runtime_module_free(execution->instance,
                                 execution->descriptor_addr);
    if (execution->input_addr && execution->instance)
        wasm_runtime_module_free(execution->instance, execution->input_addr);
    if (execution->exec_env)
        wasm_runtime_destroy_exec_env(execution->exec_env);
    if (execution->instance)
        wasm_runtime_deinstantiate(execution->instance);
    if (execution->module)
        wasm_runtime_unload(execution->module);
    if (execution->natives_registered)
        (void)wasm_runtime_unregister_natives("twep_teep_env", symbols);
    memset(&execution->host, 0, sizeof(execution->host));
    free(execution->wasm_bytes);
}

int sgx_teep_agent_resolve(const char *request_id, const char *command,
                           struct sgx_catalog_app *app)
{
    struct teep_agent_execution execution = {0};
    uint8_t input[512];
    uint32_t input_len;
    int status;
    char error[128] = {0};

    if (!request_id || !*request_id || strlen(request_id) > UINT32_MAX)
        return 1;
    status = load_teep_agent(&execution);
    if (status)
        goto out;
    input_len = build_resolve_input(input, command);
    status = prepare_teep_agent(&execution, error);
    if (status)
        goto out;
    status = call_teep_agent(&execution, input, input_len);
    if (status)
        goto out;
#ifdef TWEP_WR_SGX_TEST_HOOKS
    log_teep_agent_heap_peak(&execution);
#endif
    status = read_teep_agent_output(&execution);
    if (status)
        goto out;
    status = classify_teep_agent_output(&execution, command, app);
out:
    cleanup_teep_agent(&execution);
    return status;
}
