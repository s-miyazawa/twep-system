/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */
#include "runtime_internal.h"
#include "twep_wr_sgx_u.h"

#include <sgx_urts.h>
#include <sgx_report.h>
#ifdef TWEP_WR_SGX_HW
#include <sgx_dcap_ql_wrapper.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define SGX_SEALED_DIR "platform/sgx-sealed"
#define SGX_SEALED_MAX (256u * 1024u)

typedef struct {
    sgx_enclave_id_t enclave_id;
    bool initialized;
    bool enclave_ready;
    const twep_wr_context_t *active_ctx;
} sgx_backend_state_t;

static _Thread_local sgx_backend_state_t *active_ocall_state;

/* Keep the request's OCALL transport context live only around an ECALL that
 * may call out, so an unrelated call cannot inherit stale REE context. */
static void activate_ocall_context(sgx_backend_state_t *state,
                                   const twep_wr_context_t *ctx)
{
    state->active_ctx = ctx;
    active_ocall_state = state;
}

static void clear_ocall_context(sgx_backend_state_t *state)
{
    active_ocall_state = NULL;
    state->active_ctx = NULL;
}

#ifdef TWEP_WR_SGX_TEST_HOOKS
enum {
    SGX_DCAP_FAULT_TARGET = 1u << 0,
    SGX_DCAP_FAULT_SIZE = 1u << 1,
    SGX_DCAP_FAULT_QUOTE = 1u << 2,
    SGX_DCAP_FAULT_VERSION = 1u << 3,
    SGX_DCAP_FAULT_SIGNATURE_LEN = 1u << 4,
    SGX_DCAP_FAULT_REPORT_DATA = 1u << 5,
    SGX_DCAP_FAULT_ZERO_TAIL = 1u << 6,
};
static uint32_t test_quote_size = 1024;
static uint32_t test_dcap_faults;
static char test_artifact_replacement[TWEP_WR_MAX_PATH_LEN];

void twep_wr_sgx_test_dcap_configure(uint32_t quote_size, uint32_t faults)
{
    test_quote_size = quote_size;
    test_dcap_faults = faults;
}

void twep_wr_sgx_test_artifact_replacement(const char *path)
{
    if (path == NULL) {
        test_artifact_replacement[0] = '\0';
        return;
    }
    size_t len = strlen(path);
    if (len >= sizeof(test_artifact_replacement)) {
        test_artifact_replacement[0] = '\0';
        return;
    }
    memcpy(test_artifact_replacement, path, len + 1);
}

int twep_wr_sgx_test_evidence(const twep_wr_context_t *ctx,
                              const uint8_t *challenge, size_t challenge_len,
                              const uint8_t *agent_key, size_t agent_key_len,
                              uint8_t *output, size_t output_cap,
                              size_t *output_len)
{
    sgx_backend_state_t *state;
    int result = 7;
    if (!ctx || !(state = ctx->backend_state) || !state->enclave_ready)
        return 1;
    activate_ocall_context(state, ctx);
    sgx_status_t status = ecall_test_evidence(
        state->enclave_id, &result, challenge, challenge_len, agent_key,
        agent_key_len, output, output_cap, output_len);
    clear_ocall_context(state);
    return status == SGX_SUCCESS ? result : 7;
}

int twep_wr_sgx_test_transaction(const twep_wr_context_t *ctx,
                                 uint32_t operation,
                                 const uint8_t query_digest[32],
                                 const uint8_t *component,
                                 size_t component_len, uint64_t sequence,
                                 uint64_t expected_generation,
                                 const uint8_t *payload, size_t payload_len,
                                 const uint8_t payload_digest[32],
                                 uint64_t *new_generation)
{
    sgx_backend_state_t *state;
    int result = 7;
    if (!ctx || !(state = ctx->backend_state) || !state->enclave_ready)
        return 1;
    activate_ocall_context(state, ctx);
    sgx_status_t status = ecall_test_transaction(
        state->enclave_id, &result, operation, query_digest, component,
        component_len, sequence, expected_generation, payload, payload_len,
        payload_digest, new_generation);
    clear_ocall_context(state);
    return status == SGX_SUCCESS ? result : 7;
}

int twep_wr_sgx_test_transcript(const twep_wr_context_t *ctx,
                                uint32_t scenario)
{
    sgx_backend_state_t *state;
    int result = 7;
    if (!ctx || !(state = ctx->backend_state) || !state->enclave_ready)
        return 1;
    sgx_status_t status = ecall_test_transcript(
        state->enclave_id, &result, scenario);
    return status == SGX_SUCCESS ? result : 7;
}

int twep_wr_sgx_test_agent_measurement(const twep_wr_context_t *ctx,
                                       uint8_t measurement[32])
{
    sgx_backend_state_t *state;
    if (!ctx || !measurement || !(state = ctx->backend_state)
        || !state->enclave_ready)
        return 1;
    return ecall_test_agent_measurement(state->enclave_id, measurement)
        == SGX_SUCCESS ? 0 : 7;
}
#endif

static bool sealed_object_allowed(const char *name)
{
    static const char *const exact[] = {
        "acceptance-generation", "catalog-generation",
        "app-generation", "credential-store", "issuer-allowlist",
        "sequence-freshness", "store-freshness", "revocation",
        "agent-identity",
        "acceptance-slot-0", "acceptance-slot-1",
        "catalog-slot-0", "catalog-slot-1", "app-slot-0", "app-slot-1",
    };
    if (name == NULL || name[0] == '\0')
        return false;
    for (size_t i = 0; i < sizeof(exact) / sizeof(exact[0]); ++i)
        if (strcmp(name, exact[i]) == 0)
            return true;
    return false;
}

static bool sealed_path(const char *name, char path[TWEP_WR_MAX_PATH_LEN])
{
    char relative[TWEP_WR_MAX_PATH_LEN];
    int n;
    if (active_ocall_state == NULL || active_ocall_state->active_ctx == NULL
        || !sealed_object_allowed(name))
        return false;
    n = snprintf(relative, sizeof(relative), SGX_SEALED_DIR "/%s.blob", name);
    return n > 0 && (size_t)n < sizeof(relative)
        && twep_wr_state_relative_path(active_ocall_state->active_ctx, relative,
                                       path, TWEP_WR_MAX_PATH_LEN);
}

int ocall_twep_sealed_read(const char *object_name, uint8_t *buffer,
                           size_t buffer_cap, size_t *blob_len)
{
    char path[TWEP_WR_MAX_PATH_LEN];
    struct stat st;
    int fd;
    size_t off = 0;
    if (blob_len == NULL || !sealed_path(object_name, path))
        return 1;
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return errno == ENOENT ? 2 : 1;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0
        || (uintmax_t)st.st_size > SGX_SEALED_MAX) {
        (void)close(fd);
        return 1;
    }
    *blob_len = (size_t)st.st_size;
    if (buffer == NULL && buffer_cap == 0) {
        (void)close(fd);
        return 0;
    }
    if ((size_t)st.st_size > buffer_cap) {
        (void)close(fd);
        return 1;
    }
    while (off < (size_t)st.st_size) {
        ssize_t n = read(fd, buffer + off, (size_t)st.st_size - off);
        if (n <= 0) { (void)close(fd); return 1; }
        off += (size_t)n;
    }
    if (close(fd) != 0)
        return 1;
    return 0;
}

int ocall_twep_sealed_write_atomic(const char *object_name,
                                   const uint8_t *blob, size_t blob_len)
{
    char path[TWEP_WR_MAX_PATH_LEN], tmp[TWEP_WR_MAX_PATH_LEN];
    int fd, dir_fd, n;
    size_t off = 0;
    if (blob == NULL || blob_len == 0 || blob_len > SGX_SEALED_MAX
        || !sealed_path(object_name, path))
        return 1;
    n = snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    if (n <= 0 || (size_t)n >= sizeof(tmp))
        return 1;
    fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
              0600);
    if (fd < 0)
        return 1;
    while (off < blob_len) {
        ssize_t written = write(fd, blob + off, blob_len - off);
        if (written <= 0) {
            (void)close(fd);
            (void)unlink(tmp);
            return 1;
        }
        off += (size_t)written;
    }
    if (fchmod(fd, 0600) != 0 || fsync(fd) != 0 || close(fd) != 0
        || rename(tmp, path) != 0) {
        (void)unlink(tmp);
        return 1;
    }
    n = snprintf(tmp, sizeof(tmp), "%s", path);
    if (n <= 0 || (size_t)n >= sizeof(tmp))
        return 1;
    char *slash = strrchr(tmp, '/');
    if (slash == NULL)
        return 1;
    *slash = '\0';
    dir_fd = open(tmp, O_RDONLY | O_DIRECTORY);
    if (dir_fd < 0)
        return 1;
    if (fsync(dir_fd) != 0 || close(dir_fd) != 0)
        return 1;
    return 0;
}

static bool artifact_name_allowed(const char *relative)
{
    if (relative == NULL) {
        return false;
    }
    if (strcmp(relative, "catalog/catalog.cbor") == 0
        || strcmp(relative, "teep-agent/teep-agent.wasm") == 0
        || strcmp(relative, "teep-agent/dev-agent-public-key.cbor") == 0
        || strcmp(relative, "personalization/protected-credential-store.cbor") == 0
        || strcmp(relative, "personalization/protected-issuer-allowlist.cbor") == 0
        || strcmp(relative, "personalization/protected-sequence-freshness.cbor") == 0
        || strcmp(relative, "personalization/protected-store-freshness.cbor") == 0
        || strcmp(relative, "personalization/protected-revocation-state.cbor") == 0) {
        return true;
    }
    static const char prefix[] = "apps/";
    if (strncmp(relative, prefix, sizeof(prefix) - 1) != 0) {
        return false;
    }
    const char *name = relative + sizeof(prefix) - 1;
    size_t len = strlen(name);
    if (len < 6 || len >= TWEP_WR_MAX_WASM_FILE_LEN
        || strcmp(name + len - 5, ".wasm") != 0) {
        return false;
    }
    for (size_t i = 0; i < len; ++i) {
        if (!((name[i] >= 'a' && name[i] <= 'z')
              || (name[i] >= 'A' && name[i] <= 'Z')
              || (name[i] >= '0' && name[i] <= '9')
              || name[i] == '.' || name[i] == '_' || name[i] == '-')) {
            return false;
        }
    }
    return true;
}

int ocall_twep_read_artifact(const char *relative_path, uint8_t *buffer,
                             size_t buffer_cap, size_t *artifact_len)
{
    char path[TWEP_WR_MAX_PATH_LEN];
    FILE *file = NULL;
    long size;
    if (artifact_len == NULL || active_ocall_state == NULL
        || active_ocall_state->active_ctx == NULL
        || !artifact_name_allowed(relative_path)
        || !twep_wr_state_relative_path(active_ocall_state->active_ctx,
                                        relative_path, path, sizeof(path))) {
        return 1;
    }
#ifdef TWEP_WR_SGX_TEST_HOOKS
    if (buffer != NULL && strcmp(relative_path,
                                 "teep-agent/teep-agent.wasm") == 0
        && test_artifact_replacement[0] != '\0') {
        FILE *source = fopen(test_artifact_replacement, "rb");
        FILE *target = fopen(path, "wb");
        uint8_t chunk[4096];
        size_t count;
        test_artifact_replacement[0] = '\0';
        if (source == NULL || target == NULL) {
            if (source != NULL) (void)fclose(source);
            if (target != NULL) (void)fclose(target);
            return 1;
        }
        while ((count = fread(chunk, 1, sizeof(chunk), source)) != 0)
            if (fwrite(chunk, 1, count, target) != count) break;
        if (ferror(source) || ferror(target) || fclose(source) != 0
            || fclose(target) != 0 || count != 0)
            return 1;
    }
#endif
    file = fopen(path, "rb");
    if (file == NULL || fseek(file, 0, SEEK_END) != 0
        || (size = ftell(file)) <= 0 || fseek(file, 0, SEEK_SET) != 0) {
        if (file != NULL) (void)fclose(file);
        return 1;
    }
    *artifact_len = (size_t)size;
    if (buffer == NULL && buffer_cap == 0) {
        (void)fclose(file);
        return 0;
    }
    if ((size_t)size > buffer_cap
        || fread(buffer, 1, (size_t)size, file) != (size_t)size) {
        (void)fclose(file);
        return 2;
    }
    return fclose(file) == 0 ? 0 : 1;
}

void ocall_twep_log(const char *message)
{
    if (message != NULL)
        (void)fprintf(stderr, "twep-wr SGX Enclave: %s\n", message);
}

int ocall_get_qe_target_info(uint8_t *target_info, size_t target_info_len)
{
#ifdef TWEP_WR_SGX_HW
    if (target_info == NULL || target_info_len != sizeof(sgx_target_info_t))
        return 1;
    return (int)sgx_qe_get_target_info((sgx_target_info_t *)target_info);
#else
#ifdef TWEP_WR_SGX_TEST_HOOKS
    if (!target_info || target_info_len != sizeof(sgx_target_info_t)
        || (test_dcap_faults & SGX_DCAP_FAULT_TARGET))
        return 1;
    memset(target_info, 0, target_info_len);
    return 0;
#else
    (void)target_info; (void)target_info_len;
    return 8;
#endif
#endif
}

int ocall_get_quote_size(uint32_t *quote_size)
{
#ifdef TWEP_WR_SGX_HW
    return quote_size ? (int)sgx_qe_get_quote_size(quote_size) : 1;
#else
#ifdef TWEP_WR_SGX_TEST_HOOKS
    if (!quote_size || (test_dcap_faults & SGX_DCAP_FAULT_SIZE))
        return 1;
    *quote_size = test_quote_size;
    return 0;
#else
    (void)quote_size;
    return 8;
#endif
#endif
}

int ocall_get_quote(const uint8_t *report, size_t report_len,
                    uint8_t *quote, uint32_t quote_cap)
{
#ifdef TWEP_WR_SGX_HW
    if (report == NULL || report_len != sizeof(sgx_report_t)
        || quote == NULL || quote_cap == 0)
        return 1;
    return (int)sgx_qe_get_quote((const sgx_report_t *)report, quote_cap,
                                 quote);
#else
#ifdef TWEP_WR_SGX_TEST_HOOKS
    uint32_t signature_len;
    const sgx_report_t *sgx_report = (const sgx_report_t *)report;
    if (!report || report_len != sizeof(*sgx_report) || !quote
        || quote_cap != test_quote_size || quote_cap < 436
        || (test_dcap_faults & SGX_DCAP_FAULT_QUOTE))
        return 1;
    memset(quote, 0, quote_cap);
    quote[0] = (test_dcap_faults & SGX_DCAP_FAULT_VERSION) ? 2 : 3;
    signature_len = quote_cap - 436;
    if (test_dcap_faults & SGX_DCAP_FAULT_SIGNATURE_LEN)
        ++signature_len;
    quote[432] = (uint8_t)signature_len;
    quote[433] = (uint8_t)(signature_len >> 8);
    quote[434] = (uint8_t)(signature_len >> 16);
    quote[435] = (uint8_t)(signature_len >> 24);
    memcpy(quote + 368, sgx_report->body.report_data.d, 48);
    if (test_dcap_faults & SGX_DCAP_FAULT_REPORT_DATA)
        quote[368] ^= 1;
    if (test_dcap_faults & SGX_DCAP_FAULT_ZERO_TAIL)
        quote[416] = 1;
    return 0;
#else
    (void)report; (void)report_len; (void)quote; (void)quote_cap;
    return 8;
#endif
#endif
}

int ocall_twep_http_post(const uint8_t *url, size_t url_len,
                         const uint8_t *body, size_t body_len,
                         uint8_t *response, size_t response_cap,
                         size_t *response_len)
{
    const twep_wr_context_t *ctx;
    if (active_ocall_state == NULL
        || (ctx = active_ocall_state->active_ctx) == NULL
        || response_len == NULL || url == NULL || (!body && body_len)
        || body_len > 32u * 1024u || response_cap > 128u * 1024u
        || ctx->host_io.http_post == NULL)
        return 1;
    return ctx->host_io.http_post(ctx->host_io.user_data, url, url_len, body,
                                  body_len, response, response_cap,
                                  response_len);
}

int ocall_twep_write_diagnostic(const uint8_t *path, size_t path_len,
                                const uint8_t *data, size_t data_len)
{
#ifdef TWEP_WR_SGX_HW
    const twep_wr_context_t *ctx;
    char relative[160], full[TWEP_WR_MAX_PATH_LEN];
    int fd;
    size_t off = 0;
    if (active_ocall_state == NULL
        || (ctx = active_ocall_state->active_ctx) == NULL || path == NULL
        || data == NULL || path_len < sizeof("teep-agent/") - 1
        || path_len >= sizeof(relative) || data_len > 128u * 1024u
        || memcmp(path, "teep-agent/", sizeof("teep-agent/") - 1) != 0)
        return 1;
    for (size_t i = sizeof("teep-agent/") - 1; i < path_len; ++i)
        if (!((path[i] >= 'a' && path[i] <= 'z')
              || (path[i] >= '0' && path[i] <= '9')
              || path[i] == '-' || path[i] == '.'))
            return 1;
    memcpy(relative, path, path_len);
    relative[path_len] = '\0';
    if (!twep_wr_state_relative_path(ctx, relative, full, sizeof(full)))
        return 1;
    fd = open(full, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
              0600);
    if (fd < 0)
        return 1;
    while (off < data_len) {
        ssize_t n = write(fd, data + off, data_len - off);
        if (n <= 0) {
            (void)close(fd);
            return 1;
        }
        off += (size_t)n;
    }
    int result = 0;
    if (fchmod(fd, 0600) != 0 || fsync(fd) != 0)
        result = 1;
    if (close(fd) != 0)
        result = 1;
    return result;
#else
    (void)path; (void)path_len; (void)data; (void)data_len;
    return 8;
#endif
}

static const twep_wr_platform_info_t SGX_PLATFORM_INFO = {
    .backend_name = "sgx",
    .sealed_storage_security = TWEP_WR_PLATFORM_SEALED_TEE_PROTECTED,
    .supports_file_io = false,
    .supports_random = false,
    .supports_time = false,
};

twep_wr_status_t twep_wr_sgx_init(twep_wr_context_t *ctx,
                                  void **out_backend_state)
{
    sgx_backend_state_t *state = calloc(1, sizeof(*state));
    int enclave_result = 1;
    char path[TWEP_WR_MAX_PATH_LEN];
    if (state == NULL) {
        return TWEP_WR_ERR_NO_MEMORY;
    }
    *out_backend_state = state;
    sgx_launch_token_t token = { 0 };
    int updated = 0;
    sgx_status_t create_status = sgx_create_enclave(
        TWEP_WR_SGX_ENCLAVE_PATH, TWEP_WR_SGX_DEBUG ? SGX_DEBUG_FLAG : 0,
        &token, &updated, &state->enclave_id, NULL);
    if (create_status != SGX_SUCCESS) {
        (void)fprintf(stderr, "twep-wr SGX create_enclave failed: 0x%08x\n",
                      (unsigned)create_status);
        goto fail;
    }
    state->initialized = true;
    if (!twep_wr_state_relative_path(ctx, "platform", path, sizeof(path))
        || (mkdir(path, 0700) != 0 && errno != EEXIST)
        || !twep_wr_state_relative_path(ctx, SGX_SEALED_DIR, path, sizeof(path))
        || (mkdir(path, 0700) != 0 && errno != EEXIST))
        goto fail;
    state->active_ctx = ctx;
    active_ocall_state = state;
    sgx_status_t init_status = ecall_initialize(
        state->enclave_id, &enclave_result, ctx->resolver_mode,
        ctx->attestam_url, ctx->insecure_demo_mode ? 1 : 0);
    active_ocall_state = NULL;
    state->active_ctx = NULL;
    if (init_status != SGX_SUCCESS
        || enclave_result != 0) {
        goto fail;
    }
    state->enclave_ready = true;
    return TWEP_WR_OK;
fail:
    clear_ocall_context(state);
    if (state->initialized)
        (void)sgx_destroy_enclave(state->enclave_id);
    free(state);
    *out_backend_state = NULL;
    return TWEP_WR_ERR_INIT;
}

twep_wr_status_t twep_wr_sgx_execute(const twep_wr_context_t *ctx,
                                     void *backend_state,
                                     const twep_wr_normalized_request_t *request,
                                     twep_wr_owned_bytes_t *out_response_cbor)
{
    sgx_backend_state_t *state = backend_state;
    int enclave_result = TWEP_WR_ERR_INIT;
    size_t response_len = 0;
    uint8_t *response;
    if (ctx == NULL || state == NULL || !state->initialized
        || request == NULL || out_response_cbor == NULL) {
        return TWEP_WR_ERR_INVALID_ARGUMENT;
    }
    response = malloc(ctx->max_response_bytes);
    if (response == NULL) {
        return TWEP_WR_ERR_NO_MEMORY;
    }
    activate_ocall_context(state, ctx);
    sgx_status_t sgx_status = ecall_execute(
        state->enclave_id, &enclave_result, request->request_id,
        request->command, (uint8_t *)request->app_input_cbor.ptr,
        request->app_input_cbor.len, request->request_timeout_ms, response,
        ctx->max_response_bytes, &response_len);
    clear_ocall_context(state);
    if (sgx_status != SGX_SUCCESS || enclave_result != TWEP_WR_OK) {
        memset(response, 0, ctx->max_response_bytes);
        free(response);
        return sgx_status == SGX_SUCCESS
            ? (twep_wr_status_t)enclave_result : TWEP_WR_ERR_INIT;
    }
    out_response_cbor->ptr = response;
    out_response_cbor->len = response_len;
    return TWEP_WR_OK;
}

void twep_wr_sgx_shutdown(void *backend_state)
{
    sgx_backend_state_t *state = backend_state;
    if (state != NULL && state->initialized) {
        if (state->enclave_ready)
            (void)ecall_shutdown(state->enclave_id);
        (void)sgx_destroy_enclave(state->enclave_id);
    }
    free(state);
}

const twep_wr_platform_info_t *twep_wr_platform_info(void)
{
    return &SGX_PLATFORM_INFO;
}
