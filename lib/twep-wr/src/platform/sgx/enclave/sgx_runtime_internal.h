/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef SGX_RUNTIME_INTERNAL_H
#define SGX_RUNTIME_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#define SGX_AGENT_COSE_KEY_LEN 77u
#define SGX_AGENT_WASM_MAX (4u * 1024u * 1024u)
#define SGX_SEALED_BLOB_MAX (256u * 1024u)
#define SGX_ACCEPTANCE_MAX 4096u
#define SGX_CATALOG_MAX (64u * 1024u)
#define SGX_PROTECTED_APP_MAX (128u * 1024u)
#define SGX_APP_STACK_DEFAULT (64u * 1024u)
#define SGX_APP_HEAP_DEFAULT (1024u * 1024u)
#define SGX_APP_OUTPUT_DEFAULT (16u * 1024u * 1024u)
#define SGX_DCAP_QUOTE_MAX (28u * 1024u)
#define SGX_EVIDENCE_BUNDLE_MAX (30u * 1024u)

struct sgx_cbor_cursor {
    const uint8_t *buf;
    size_t len;
    size_t off;
};

struct sgx_catalog_app {
    char wasm_file[128];
    uint8_t digest[32];
    uint32_t stack_bytes;
    uint32_t heap_bytes;
    uint32_t timeout_ms;
    uint32_t max_output_bytes;
};

enum sgx_wasm_role {
    SGX_WASM_ROLE_TEEP_AGENT,
    SGX_WASM_ROLE_APP,
};

int sgx_cbor_len(struct sgx_cbor_cursor *cur, uint8_t want, uint64_t *value);
int sgx_cbor_view(struct sgx_cbor_cursor *cur, uint8_t major,
                  const uint8_t **ptr, size_t *len);
int sgx_cbor_skip(struct sgx_cbor_cursor *cur, unsigned depth);
int sgx_cbor_text_eq(const uint8_t *p, size_t n, const char *s);

int sgx_resolve_output_parse(const uint8_t *buf, size_t len,
                             const char *command,
                             struct sgx_catalog_app *app);
int sgx_catalog_safe_wasm_basename(const char *name);
int sgx_wasm_signature_verify(const uint8_t *wasm, size_t wasm_len,
                              enum sgx_wasm_role expected_role);
int sgx_teep_agent_resolve(const char *request_id, const char *command,
                           struct sgx_catalog_app *app);
#ifdef TWEP_WR_SGX_TEST_HOOKS
int sgx_teep_transcript_test(uint32_t scenario);
#endif
int sgx_wamr_ensure_initialized(void);
const char *sgx_resolver_mode(void);
const char *sgx_attestam_url(void);
int sgx_verified_mode(void);
const uint8_t *sgx_teep_agent_measurement(void);

int sgx_dcap_create_evidence(const uint8_t *challenge, size_t challenge_len,
                             const uint8_t *agent_key, size_t agent_key_len,
                             uint8_t *output, size_t output_cap,
                             size_t *output_len);

enum sgx_store_status {
    SGX_STORE_OK = 0,
    SGX_STORE_INVALID = 1,
    SGX_STORE_SHORT_BUFFER = 2,
    SGX_STORE_NOT_FOUND = 3,
    SGX_STORE_CORRUPT = 4,
    SGX_STORE_PLATFORM = 7,
    SGX_STORE_UNSUPPORTED = 8,
};

/* Existing private hostcall value for a stale generation, replayed digest,
 * or non-increasing component sequence. */
#define SGX_PROTECTED_STATE_CONFLICT 9
int sgx_store_read(const char *physical_name, const char *object_type,
                   uint8_t *payload, size_t payload_cap, size_t *payload_len);
int sgx_store_write_verified(const char *physical_name,
                             const char *object_type,
                             const uint8_t *payload, size_t payload_len);
int sgx_provision_demo_policy(void);
int sgx_provision_agent_identity(void);
int sgx_store_read_protected(const char *logical_name, size_t logical_name_len,
                             uint8_t *payload, size_t payload_cap,
                             size_t *payload_len);
int sgx_acceptance_generation(uint64_t *generation);
int sgx_acceptance_commit(const uint8_t digest[32], const uint8_t *component,
                          size_t component_len, uint64_t sequence,
                          uint64_t expected_generation,
                          uint64_t *new_generation);
int sgx_catalog_commit(const uint8_t digest[32], const uint8_t *component,
                       size_t component_len, uint64_t sequence,
                       uint64_t expected_generation, const uint8_t *catalog,
                       size_t catalog_len, const uint8_t catalog_digest[32],
                       uint64_t *new_generation);
int sgx_catalog_read_active(uint8_t *catalog, size_t catalog_cap,
                            size_t *catalog_len);
int sgx_app_commit(const uint8_t digest[32], const uint8_t *component,
                   size_t component_len, uint64_t sequence,
                   uint64_t expected_generation, const uint8_t *wasm,
                   size_t wasm_len, const uint8_t wasm_digest[32],
                   uint64_t *new_generation);
int sgx_app_read_active(uint8_t *wasm, size_t wasm_cap, size_t *wasm_len,
                        uint8_t digest[32], uint8_t *component,
                        size_t component_cap, size_t *component_len,
                        uint64_t *sequence);

int sgx_app_execute(const char *request_id, const char *command,
                    const uint8_t *input, size_t input_len,
                    uint32_t timeout_ms, uint8_t *output, size_t output_cap,
                    size_t *output_len);

#endif
