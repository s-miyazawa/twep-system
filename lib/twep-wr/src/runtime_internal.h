/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef TWEP_WR_RUNTIME_INTERNAL_H
#define TWEP_WR_RUNTIME_INTERNAL_H

#include "twep_wr.h"
#include "platform/platform.h"
#include "wasm_export.h"

#include <openssl/sha.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TWEP_WR_DEFAULT_STACK_SIZE (64u * 1024u)
#define TWEP_WR_DEFAULT_HEAP_SIZE (1024u * 1024u)
#define TWEP_WR_DEFAULT_MAX_OUTPUT_SIZE (16u * 1024u * 1024u)
#define TWEP_WR_GLOBAL_MAX_STACK_SIZE (1024u * 1024u)
#define TWEP_WR_GLOBAL_MAX_HEAP_SIZE (16u * 1024u * 1024u)
#define TWEP_WR_GLOBAL_MAX_OUTPUT_SIZE (16u * 1024u * 1024u)
#define TWEP_WR_ERROR_BUF_SIZE 256u
#define TWEP_WR_MAX_COMMAND_LEN 32u
#define TWEP_WR_MAX_WASM_FILE_LEN 128u
#define TWEP_WR_MAX_PATH_LEN 512u
#define TWEP_WR_TEEP_AGENT_CAPABILITY 0x54454550u

typedef struct {
    char command[TWEP_WR_MAX_COMMAND_LEN];
    char wasm_file[TWEP_WR_MAX_WASM_FILE_LEN];
    uint8_t sha256[SHA256_DIGEST_LENGTH];
    uint32_t stack_bytes;
    uint32_t heap_bytes;
    uint32_t timeout_ms;
    uint32_t max_output_bytes;
} catalog_entry_t;

typedef struct {
    const uint8_t *ptr;
    size_t len;
} bytes_view_t;

typedef struct {
    const twep_wr_context_t *ctx;
    const uint8_t *teep_agent_wasm;
    size_t teep_agent_wasm_len;
    uint32_t capability;
} teep_agent_exec_context_t;

typedef enum {
    TWEP_WR_WASM_SIGNATURE_ROLE_TEEP_AGENT = 1,
    TWEP_WR_WASM_SIGNATURE_ROLE_APP = 2,
} twep_wr_wasm_signature_role_t;

struct twep_wr_context {
    uint32_t abi_version;
    void *backend_state;
    char *state_dir;
    char *resolver_mode;
    char *attestam_url;
    bool insecure_demo_mode;
    uint32_t default_timeout_ms;
    uint32_t max_request_bytes;
    uint32_t max_response_bytes;
    twep_wr_host_io_t host_io;
};

#if (defined(TWEP_WR_PLATFORM_BACKEND_LINUX) + defined(TWEP_WR_PLATFORM_BACKEND_OPTEE) \
     + defined(TWEP_WR_PLATFORM_BACKEND_SGX) + defined(TWEP_WR_PLATFORM_BACKEND_KEYSTONE)) != 1
#error "exactly one TWEP_WR_PLATFORM_BACKEND_* definition is required"
#endif

#ifdef TWEP_WR_PLATFORM_BACKEND_SGX
twep_wr_status_t twep_wr_sgx_init(twep_wr_context_t *ctx, void **out_backend_state);
twep_wr_status_t twep_wr_sgx_execute(const twep_wr_context_t *ctx, void *backend_state,
                                     const twep_wr_normalized_request_t *request,
                                     twep_wr_owned_bytes_t *out_response_cbor);
void twep_wr_sgx_shutdown(void *backend_state);
#endif

twep_wr_status_t twep_wr_register_teep_agent_hostcalls(void);
const twep_wr_context_t *twep_wr_teep_agent_context_from_exec_env(wasm_exec_env_t exec_env);

uint8_t *twep_wr_read_file(const char *path, size_t *out_len);
bool twep_wr_file_exists(const char *path);
twep_wr_status_t twep_wr_copy_file(const char *src, const char *dst);
twep_wr_status_t twep_wr_mkdir_if_needed(const char *path);
char *twep_wr_string_dup(const char *s);
bool twep_wr_is_valid_resolver_mode(const char *mode);
bool twep_wr_relative_state_file_path(const char *path, size_t path_len, char *out, size_t out_cap);
bool twep_wr_protected_object_name(const char *name, size_t name_len, char *out, size_t out_cap);
bool twep_wr_platform_supports_protected_storage(void);
const char *twep_wr_platform_sealed_security_label(twep_wr_platform_sealed_security_t security);
const char *twep_wr_bool_label(bool value);
bool twep_wr_state_relative_path(const twep_wr_context_t *ctx, const char *relative, char *out, size_t out_cap);
twep_wr_status_t twep_wr_ensure_state_layout(const twep_wr_context_t *ctx);
twep_wr_status_t twep_wr_ensure_state_catalog(const twep_wr_context_t *ctx);
twep_wr_status_t twep_wr_ensure_state_app(const twep_wr_context_t *ctx, const char *wasm_file);
twep_wr_status_t twep_wr_ensure_teep_agent(const twep_wr_context_t *ctx);
bool twep_wr_state_path(const twep_wr_context_t *ctx, const char *subdir, const char *name, char *out, size_t out_cap);
bool twep_wr_build_path(const char *name, char *out, size_t out_cap);
twep_wr_status_t twep_wr_lookup_catalog_entry(const twep_wr_context_t *ctx, const char *command,
                                              catalog_entry_t *entry);

bool twep_wr_cbor_read_head(const uint8_t *buf, size_t len, size_t *off, uint8_t *major, uint64_t *value);
bool twep_wr_cbor_read_text_view(const uint8_t *buf, size_t len, size_t *off, bytes_view_t *view);
bool twep_wr_cbor_read_bytes_view(const uint8_t *buf, size_t len, size_t *off, bytes_view_t *view);
bool twep_wr_cbor_read_uint32(const uint8_t *buf, size_t len, size_t *off, uint32_t *out);
bool twep_wr_cbor_skip_value(const uint8_t *buf, size_t len, size_t *off);
bool twep_wr_bytes_equal_text(bytes_view_t view, const char *text);
bool twep_wr_copy_text_view(bytes_view_t view, char *out, size_t out_cap);
bool twep_wr_sha256_matches(const uint8_t *bytes, size_t len, const uint8_t expected[SHA256_DIGEST_LENGTH]);
bool twep_wr_verify_wasm_signature(const uint8_t *wasm, size_t wasm_len, twep_wr_wasm_signature_role_t role);

twep_wr_status_t twep_wr_call_u32_no_args(wasm_exec_env_t exec_env, wasm_module_inst_t module_inst,
                                          const char *name, uint32_t *out_value);
twep_wr_status_t twep_wr_call_free(wasm_exec_env_t exec_env, wasm_module_inst_t module_inst,
                                   uint32_t ptr, uint32_t len);

twep_wr_status_t twep_wr_run_app_wasm(const twep_wr_context_t *ctx, const twep_wr_normalized_request_t *request,
                                      twep_wr_owned_bytes_t *out_response_cbor);

twep_wr_status_t twep_wr_optee_execute(const twep_wr_context_t *ctx, const twep_wr_normalized_request_t *request,
                                           twep_wr_owned_bytes_t *out_response_cbor);

twep_wr_status_t twep_wr_make_response(const char *request_id, const uint8_t *stdout_bytes, size_t stdout_len,
                                       const uint8_t *app_output, size_t app_output_len,
                                       twep_wr_owned_bytes_t *out_response_cbor);
twep_wr_status_t twep_wr_make_app_error_response(const char *request_id, int32_t app_status, const char *command,
                                                 const char *wasm_file,
                                                 twep_wr_owned_bytes_t *out_response_cbor);

#endif
