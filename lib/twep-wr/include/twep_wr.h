/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef TWEP_WR_H
#define TWEP_WR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TWEP_WR_ABI_VERSION 3u

typedef struct twep_wr_context twep_wr_context_t;

typedef struct {
    /* Borrowed bytes; the caller retains ownership for the duration of the call. */
    const uint8_t *ptr;
    size_t len;
} twep_wr_bytes_t;

typedef struct {
    /* Owned by twep-wr; release with twep_wr_free_bytes. */
    uint8_t *ptr;
    size_t len;
} twep_wr_owned_bytes_t;

typedef struct {
    const char *request_id;
    const char *command;
    twep_wr_bytes_t app_input_cbor;
    uint32_t request_timeout_ms;
} twep_wr_normalized_request_t;

typedef enum {
    TWEP_WR_OK = 0,
    TWEP_WR_ERR_INVALID_ARGUMENT = 1,
    TWEP_WR_ERR_INIT = 2,
    TWEP_WR_ERR_CATALOG = 3,
    TWEP_WR_ERR_TEEP = 4,
    TWEP_WR_ERR_WASM_LOAD = 5,
    TWEP_WR_ERR_WASM_ABI = 6,
    TWEP_WR_ERR_WASM_RUNTIME = 7,
    TWEP_WR_ERR_SECURITY = 8,
    TWEP_WR_ERR_NO_MEMORY = 9,
    TWEP_WR_ERR_TEEP_NETWORK = 10,
    TWEP_WR_ERR_TEEP_ATTESTATION_UNSUPPORTED = 11,
    TWEP_WR_ERR_WASM_SIGNATURE = 12,
} twep_wr_status_t;

typedef struct {
    const char *state_dir;
    const char *resolver_mode;
    const char *attestam_url;
    bool insecure_demo_mode;
    uint32_t default_timeout_ms;
    /* Maximum combined bytes of request_id, command, and app_input_cbor. */
    uint32_t max_request_bytes;
    /* Maximum owned response bytes returned by twep_wr_execute. */
    uint32_t max_response_bytes;
} twep_wr_config_t;

typedef int32_t (*twep_wr_http_post_fn)(
    void *user_data,
    const uint8_t *url,
    size_t url_len,
    const uint8_t *body,
    size_t body_len,
    uint8_t *buf,
    size_t buf_cap,
    size_t *out_len);

typedef int32_t (*twep_wr_create_evidence_fn)(
    void *user_data,
    const uint8_t *challenge,
    size_t challenge_len,
    const uint8_t *agent_public_key_cose,
    size_t agent_public_key_cose_len,
    uint8_t *buf,
    size_t buf_cap,
    size_t *out_len);

typedef struct {
    twep_wr_http_post_fn http_post;
    twep_wr_create_evidence_fn create_evidence;
    void *user_data;
} twep_wr_host_io_t;

uint32_t twep_wr_get_abi_version(void);

twep_wr_status_t twep_wr_init(
    const twep_wr_config_t *config,
    twep_wr_context_t **out_ctx);

twep_wr_status_t twep_wr_execute(
    twep_wr_context_t *ctx,
    const twep_wr_normalized_request_t *request,
    twep_wr_owned_bytes_t *out_response_cbor);

twep_wr_status_t twep_wr_set_host_io(
    twep_wr_context_t *ctx,
    const twep_wr_host_io_t *host_io);

void twep_wr_free_bytes(twep_wr_owned_bytes_t bytes);

void twep_wr_shutdown(twep_wr_context_t *ctx);

const char *twep_wr_status_string(twep_wr_status_t status);

#ifdef __cplusplus
}
#endif

#endif
