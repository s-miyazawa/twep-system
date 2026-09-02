/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */
#include "sgx_runtime_internal.h"
#include "twep_wr_sgx_t.h"

#include <sgx_report.h>
#include <sgx_tcrypto.h>
#include <sgx_trts.h>
#include <sgx_utils.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define QUOTE3_FIXED_LEN 436u

struct evidence_cache {
    uint8_t bundle[SGX_EVIDENCE_BUNDLE_MAX];
    uint8_t challenge[64];
    uint8_t key[SGX_AGENT_COSE_KEY_LEN];
    size_t bundle_len;
    size_t challenge_len;
};

static struct evidence_cache cache;

static void clear_cache(void)
{
    memset(&cache, 0, sizeof(cache));
}

static size_t cbor_bytes_header(uint8_t out[3], size_t len)
{
    if (len < 24) {
        out[0] = (uint8_t)(0x40u | len);
        return 1;
    }
    if (len <= 255) {
        out[0] = 0x58;
        out[1] = (uint8_t)len;
        return 2;
    }
    out[0] = 0x59;
    out[1] = (uint8_t)(len >> 8);
    out[2] = (uint8_t)len;
    return 3;
}

static uint32_t load_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8
        | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static int canonical_agent_key(const uint8_t *key, size_t key_len)
{
    static const uint8_t prefix[] = {
        0xa5, 0x01, 0x02, 0x03, 0x28, 0x20, 0x01, 0x21, 0x58, 0x20
    };
    static const uint8_t y_header[] = { 0x22, 0x58, 0x20 };
    sgx_ec256_public_t point;
    sgx_ecc_state_handle_t ecc = NULL;
    int valid = 0;

    if (!key || key_len != SGX_AGENT_COSE_KEY_LEN
        || memcmp(key, prefix, sizeof(prefix)) != 0
        || memcmp(key + 42, y_header, sizeof(y_header)) != 0)
        return 0;
    for (size_t i = 0; i < 32; ++i) {
        point.gx[i] = key[10 + 31 - i];
        point.gy[i] = key[45 + 31 - i];
    }
    if (sgx_ecc256_open_context(&ecc) != SGX_SUCCESS
        || sgx_ecc256_check_point(&point, ecc, &valid) != SGX_SUCCESS)
        valid = 0;
    if (ecc) (void)sgx_ecc256_close_context(ecc);
    memset(&point, 0, sizeof(point));
    return valid == 1;
}

int sgx_dcap_create_evidence(const uint8_t *challenge, size_t challenge_len,
                             const uint8_t *agent_key, size_t agent_key_len,
                             uint8_t *output, size_t output_cap,
                             size_t *output_len)
{
#if !defined(TWEP_WR_SGX_HW) && !defined(TWEP_WR_SGX_TEST_HOOKS)
    (void)challenge; (void)challenge_len; (void)agent_key;
    (void)agent_key_len; (void)output; (void)output_cap;
    if (output_len) *output_len = 0;
    return 8;
#else
    uint8_t raw[128], hash[48];
    uint8_t quote_header[3], raw_header[3];
    size_t raw_len, qh_len, rh_len, total;
    sgx_target_info_t target;
    sgx_report_data_t report_data;
    sgx_report_t report;
    sgx_sha_state_handle_t sha = NULL;
    uint8_t *quote = NULL, *p;
    uint32_t quote_len = 0, signature_len;
    int ocall_result = 1, result = 7;

    if (!output_len || !challenge || challenge_len < 8 || challenge_len > 64
        || !canonical_agent_key(agent_key, agent_key_len)) {
        clear_cache();
        return 1;
    }
    *output_len = 0;
    if (output != NULL && cache.bundle_len != 0) {
        if (challenge_len != cache.challenge_len
            || memcmp(challenge, cache.challenge, challenge_len) != 0
            || memcmp(agent_key, cache.key, agent_key_len) != 0) {
            clear_cache();
            return 1;
        }
        *output_len = cache.bundle_len;
        if (output_cap < cache.bundle_len)
            return 2;
        memcpy(output, cache.bundle, cache.bundle_len);
        clear_cache();
        return 0;
    }
    if (output == NULL && cache.bundle_len != 0)
        clear_cache();
    memcpy(raw, agent_key + 10, 32);
    memcpy(raw + 32, agent_key + 45, 32);
    memcpy(raw + 64, challenge, challenge_len);
    raw_len = 64 + challenge_len;
    memset(&report_data, 0, sizeof(report_data));
    if (sgx_sha384_init(&sha) != SGX_SUCCESS
        || sgx_sha384_update(raw, (uint32_t)raw_len, sha) != SGX_SUCCESS
        || sgx_sha384_get_hash(sha, (sgx_sha384_hash_t *)hash)
                                      != SGX_SUCCESS)
        goto out;
    if (sgx_sha384_close(sha) != SGX_SUCCESS) goto out;
    sha = NULL;
    memcpy(report_data.d, hash, sizeof(hash));
    if (ocall_get_qe_target_info(&ocall_result, (uint8_t *)&target,
                                 sizeof(target)) != SGX_SUCCESS
        || ocall_result != 0
#ifdef TWEP_WR_SGX_TEST_HOOKS
        || sgx_create_report(NULL, &report_data, &report) != SGX_SUCCESS
#else
        || sgx_create_report(&target, &report_data, &report) != SGX_SUCCESS
#endif
        || ocall_get_quote_size(&ocall_result, &quote_len) != SGX_SUCCESS
        || ocall_result != 0 || quote_len < QUOTE3_FIXED_LEN
        || quote_len > SGX_DCAP_QUOTE_MAX)
        goto out;
    qh_len = cbor_bytes_header(quote_header, quote_len);
    rh_len = cbor_bytes_header(raw_header, raw_len);
    total = 1 + qh_len + quote_len + rh_len + raw_len;
    if (total > SGX_EVIDENCE_BUNDLE_MAX) goto out;
    quote = malloc(quote_len);
    if (!quote) goto out;
    if (ocall_get_quote(&ocall_result, (const uint8_t *)&report,
                        sizeof(report), quote, quote_len) != SGX_SUCCESS
        || ocall_result != 0 || quote[0] != 3 || quote[1] != 0)
        goto out;
    signature_len = load_le32(quote + 432);
    if (signature_len != quote_len - QUOTE3_FIXED_LEN
        || memcmp(quote + 368, hash, sizeof(hash)) != 0) goto out;
    for (size_t i = 416; i < 432; ++i)
        if (quote[i] != 0) goto out;
    p = output != NULL && output_cap >= total ? output : cache.bundle;
    *p++ = 0x82;
    memcpy(p, quote_header, qh_len); p += qh_len;
    memcpy(p, quote, quote_len); p += quote_len;
    memcpy(p, raw_header, rh_len); p += rh_len;
    memcpy(p, raw, raw_len);
    *output_len = total;
    if (output == NULL || output_cap < total) {
        memcpy(cache.challenge, challenge, challenge_len);
        memcpy(cache.key, agent_key, agent_key_len);
        cache.challenge_len = challenge_len;
        cache.bundle_len = total;
        result = 2;
    } else {
        result = 0;
    }
out:
    if (result != 0 && result != 2)
        clear_cache();
    if (sha) (void)sgx_sha384_close(sha);
    if (quote) { memset(quote, 0, quote_len); free(quote); }
    memset(&target, 0, sizeof(target));
    memset(&report, 0, sizeof(report));
    memset(&report_data, 0, sizeof(report_data));
    memset(raw, 0, sizeof(raw));
    memset(hash, 0, sizeof(hash));
    return result;
#endif
}
