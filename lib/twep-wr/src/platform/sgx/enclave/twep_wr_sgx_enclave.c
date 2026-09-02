/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */
#include "sgx_runtime_internal.h"
#include "twep_wr_sgx_t.h"

#include <limits.h>
#include <sgx_tcrypto.h>
#include <stdlib.h>
#include <string.h>

static char configured_mode[24];
static char configured_url[256];
static uint8_t configured_measurement[32];
void ecall_shutdown(void);

/* OCALLs provide bytes and availability only.  Signatures, measurements,
 * resolver policy, and execution authorization remain Enclave decisions. */

const char *sgx_resolver_mode(void) { return configured_mode; }
const char *sgx_attestam_url(void) { return configured_url; }
int sgx_verified_mode(void)
{
    return strcmp(configured_mode, "attestam-verified") == 0;
}
const uint8_t *sgx_teep_agent_measurement(void)
{
    return configured_measurement;
}

int ecall_initialize(const char *resolver_mode, const char *attestam_url,
                     int insecure_demo_mode)
{
    uint8_t *wasm = NULL;
    size_t wasm_len = 0;
    sgx_sha256_hash_t measurement;
    int result = 1;
    (void)attestam_url;
    if (resolver_mode == NULL || attestam_url == NULL
        || strlen(resolver_mode) >= sizeof(configured_mode)
        || strlen(attestam_url) >= sizeof(configured_url)
        || (strcmp(resolver_mode, "mock") != 0
            && strcmp(resolver_mode, "attestam-insecure") != 0
            && strcmp(resolver_mode, "attestam-verified") != 0)
        || (strcmp(resolver_mode, "attestam-verified") == 0
            && insecure_demo_mode))
        return 1;
    if (ocall_twep_read_artifact(&result, "teep-agent/teep-agent.wasm",
                                 NULL, 0, &wasm_len) != SGX_SUCCESS
        || result != 0 || wasm_len == 0 || wasm_len > SGX_AGENT_WASM_MAX)
        return 1;
    wasm = malloc(wasm_len);
    if (wasm == NULL)
        return 1;
    if (ocall_twep_read_artifact(&result, "teep-agent/teep-agent.wasm",
                                 wasm, wasm_len, &wasm_len) != SGX_SUCCESS
        || result != 0
        || !sgx_wasm_signature_verify(wasm, wasm_len,
                                      SGX_WASM_ROLE_TEEP_AGENT)
        || sgx_sha256_msg(wasm, (uint32_t)wasm_len, &measurement)
                                      != SGX_SUCCESS) {
        memset(wasm, 0, wasm_len);
        free(wasm);
        return 1;
    }
    memset(wasm, 0, wasm_len);
    free(wasm);
    memcpy(configured_mode, resolver_mode, strlen(resolver_mode) + 1);
    memcpy(configured_url, attestam_url, strlen(attestam_url) + 1);
    memcpy(configured_measurement, measurement, sizeof(configured_measurement));
    if (sgx_verified_mode()
        && (sgx_provision_demo_policy() != 0
            || sgx_provision_agent_identity() != 0)) {
        ecall_shutdown();
        return 1;
    }
    return 0;
}

void ecall_shutdown(void)
{
    memset(configured_mode, 0, sizeof(configured_mode));
    memset(configured_url, 0, sizeof(configured_url));
    memset(configured_measurement, 0, sizeof(configured_measurement));
}

#ifdef TWEP_WR_SGX_TEST_HOOKS
int ecall_test_evidence(const uint8_t *challenge, size_t challenge_len,
                        const uint8_t *agent_key, size_t agent_key_len,
                        uint8_t *output, size_t output_cap, size_t *output_len)
{
    return sgx_dcap_create_evidence(challenge, challenge_len, agent_key,
                                    agent_key_len, output, output_cap,
                                    output_len);
}

int ecall_test_transaction(uint32_t operation, const uint8_t *query_digest,
                           const uint8_t *component, size_t component_len,
                           uint64_t sequence, uint64_t expected_generation,
                           const uint8_t *payload, size_t payload_len,
                           const uint8_t *payload_digest,
                           uint64_t *new_generation)
{
    if (operation == 1)
        return sgx_acceptance_commit(query_digest, component, component_len,
                                     sequence, expected_generation,
                                     new_generation);
    if (operation == 2)
        return sgx_catalog_commit(query_digest, component, component_len,
                                  sequence, expected_generation, payload,
                                  payload_len, payload_digest, new_generation);
    if (operation == 3)
        return sgx_app_commit(query_digest, component, component_len, sequence,
                              expected_generation, payload, payload_len,
                              payload_digest, new_generation);
    return SGX_STORE_INVALID;
}

int ecall_test_transcript(uint32_t scenario)
{
    return sgx_teep_transcript_test(scenario);
}

void ecall_test_agent_measurement(uint8_t measurement[32])
{
    memcpy(measurement, sgx_teep_agent_measurement(), 32);
}
#endif

int ecall_execute(const char *request_id, const char *command, uint8_t *input,
                  size_t input_len, uint32_t timeout_ms, uint8_t *output,
                  size_t output_cap, size_t *output_len)
{
    if (!request_id || !command || !output_len || !output
        || (!input && input_len))
        return 1;
    *output_len = 0;
    return sgx_app_execute(request_id, command, input, input_len, timeout_ms,
                           output, output_cap, output_len);
}
