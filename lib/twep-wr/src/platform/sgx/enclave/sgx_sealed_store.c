/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */
#include "sgx_runtime_internal.h"
#include "twep_wr_sgx_t.h"

#include <sgx_tcrypto.h>
#include <sgx_tseal.h>
#include <stdlib.h>
#include <string.h>

/* The REE stores opaque blobs under allowlisted names.  The Enclave binds
 * each sealed envelope to its type, policy, Agent measurement, payload, and
 * physical name before accepting bytes returned by that transport. */
#define STORE_SCHEMA 1u
#define STORE_PAYLOAD_MAX (SGX_PROTECTED_APP_MAX + 512u)

struct store_aad {
    uint8_t magic[8];
    uint32_t schema;
    uint8_t physical_name[32];
    uint8_t object_type[32];
    uint8_t backend[8];
    uint8_t key_policy[20];
    uint8_t agent_measurement[32];
    uint64_t payload_len;
    uint8_t payload_sha256[32];
};

struct protected_name {
    const char *logical;
    const char *physical;
    const char *type;
};

static const struct protected_name protected_names[] = {
    { "protected-credential-store.cbor", "credential-store",
      "credential-store" },
    { "protected-issuer-allowlist.cbor", "issuer-allowlist",
      "issuer-allowlist" },
    { "protected-sequence-freshness.cbor", "sequence-freshness",
      "sequence-freshness" },
    { "protected-store-freshness.cbor", "store-freshness",
      "store-freshness" },
    { "protected-revocation-state.cbor", "revocation", "revocation" },
    { "protected-agent-identity.cbor", "agent-identity", "agent-identity" },
    { "verified-evidence-result.cbor", "acceptance-generation",
      "acceptance-result" },
};

struct demo_policy {
    const char *artifact;
    const char *physical;
    const char *type;
    size_t max_len;
    uint8_t sha256[32];
};

static const struct demo_policy demo_policy[] = {
    {
        "personalization/protected-credential-store.cbor",
        "credential-store", "credential-store", 16384,
        { 0x05,0x89,0xfe,0x0a,0xe1,0x91,0x62,0xa6,
          0x3d,0x55,0xb7,0xec,0x0a,0x28,0x64,0x55,
          0x98,0x74,0xc6,0x13,0xee,0x62,0x88,0xcd,
          0xe8,0xa9,0x1c,0x30,0x6e,0x75,0xec,0x44 }
    },
    {
        "personalization/protected-issuer-allowlist.cbor",
        "issuer-allowlist", "issuer-allowlist", 4096,
        { 0xa1,0x7a,0xef,0xce,0x38,0x3b,0x80,0x84,
          0x81,0xe6,0xfd,0x45,0xf9,0x7d,0x80,0x04,
          0xc9,0xc3,0x62,0xc5,0x9e,0x4d,0x8f,0x6f,
          0xa8,0xee,0x40,0x56,0x49,0x85,0x65,0x98 }
    },
    {
        "personalization/protected-store-freshness.cbor",
        "store-freshness", "store-freshness", 4096,
        { 0xe0,0x56,0xf9,0xbf,0x3f,0xdd,0x00,0x87,
          0xcb,0xc3,0x89,0xda,0xff,0x39,0x5b,0x6d,
          0xad,0xa4,0x07,0xff,0x3d,0xf5,0xe7,0x49,
          0xec,0xda,0x38,0x12,0x09,0xfd,0x49,0xab }
    },
    {
        "personalization/protected-revocation-state.cbor",
        "revocation", "revocation", 4096,
        { 0x5b,0x96,0x5a,0x4c,0x22,0xf2,0x11,0x92,
          0x46,0x3f,0xc2,0x0d,0xbe,0xc7,0x01,0x60,
          0x19,0x16,0xa6,0xc9,0x60,0x7a,0x18,0x64,
          0xec,0xf7,0x75,0x71,0xba,0x31,0x82,0x03 }
    },
    {
        "personalization/protected-sequence-freshness.cbor",
        "sequence-freshness", "sequence-freshness", 4096,
        { 0xc1,0x9a,0x79,0x7f,0xa1,0xfd,0x59,0x0c,
          0xd2,0xe5,0xb4,0x2d,0x1c,0xf5,0xf2,0x46,
          0xe2,0x9b,0x91,0x68,0x4e,0x2f,0x87,0x40,
          0x4b,0x81,0xdc,0x34,0x5c,0x7a,0x56,0xa0 }
    }
};

static int bounded_string(uint8_t *out, size_t cap, const char *value)
{
    size_t len;
    if (value == NULL || (len = strlen(value)) == 0 || len >= cap)
        return 0;
    memset(out, 0, cap);
    memcpy(out, value, len);
    return 1;
}

static int make_aad(struct store_aad *aad, const char *physical_name,
                    const char *object_type, const uint8_t *payload,
                    size_t payload_len)
{
    static const uint8_t magic[8] = { 'T','W','E','P','S','G','X','S' };
    sgx_sha256_hash_t digest;
    if (payload == NULL || payload_len == 0 || payload_len > STORE_PAYLOAD_MAX
        || payload_len > UINT32_MAX
        || !bounded_string(aad->physical_name,
                           sizeof(aad->physical_name), physical_name)
        || !bounded_string(aad->object_type,
                           sizeof(aad->object_type), object_type)
        || sgx_sha256_msg(payload, (uint32_t)payload_len, &digest)
                                                        != SGX_SUCCESS)
        return 0;
    memcpy(aad->magic, magic, sizeof(magic));
    aad->schema = STORE_SCHEMA;
    (void)bounded_string(aad->backend, sizeof(aad->backend), "sgx");
    (void)bounded_string(aad->key_policy, sizeof(aad->key_policy),
                         "mrsigner-isvsvn");
    memcpy(aad->agent_measurement, sgx_teep_agent_measurement(), 32);
    aad->payload_len = payload_len;
    memcpy(aad->payload_sha256, digest, sizeof(digest));
    return 1;
}

static int aad_valid(const struct store_aad *aad, const char *physical_name,
                     const char *object_type, const uint8_t *payload,
                     size_t payload_len)
{
    struct store_aad expected;
    static const uint8_t magic[8] = { 'T','W','E','P','S','G','X','S' };
    memset(&expected, 0, sizeof(expected));
    if (!make_aad(&expected, physical_name, object_type, payload, payload_len))
        return 0;
    return memcmp(aad->magic, magic, sizeof(magic)) == 0
        && aad->schema == STORE_SCHEMA
        && memcmp(aad, &expected, sizeof(expected)) == 0;
}

int sgx_store_read(const char *physical_name, const char *object_type,
                   uint8_t *payload, size_t payload_cap, size_t *payload_len)
{
    uint8_t *blob = NULL, *plain = NULL;
    struct store_aad aad;
    size_t blob_len = 0, returned_len = 0;
    uint32_t aad_len = sizeof(aad), plain_len;
    int result = 1, status = SGX_STORE_CORRUPT;
    if (payload_len == NULL || physical_name == NULL || object_type == NULL)
        return SGX_STORE_INVALID;
    *payload_len = 0;
    if (ocall_twep_sealed_read(&result, physical_name, NULL, 0, &blob_len)
                                                        != SGX_SUCCESS)
        return SGX_STORE_PLATFORM;
    if (result == 2)
        return SGX_STORE_NOT_FOUND;
    if (result != 0 || blob_len < sizeof(sgx_sealed_data_t)
        || blob_len > SGX_SEALED_BLOB_MAX)
        return result == 0 ? SGX_STORE_CORRUPT : SGX_STORE_PLATFORM;
    blob = malloc(blob_len);
    if (blob == NULL)
        return SGX_STORE_PLATFORM;
    if (ocall_twep_sealed_read(&result, physical_name, blob, blob_len,
                               &returned_len) != SGX_SUCCESS || result != 0
        || returned_len != blob_len)
        { status = SGX_STORE_PLATFORM; goto out; }
    plain_len = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)blob);
    if (plain_len == UINT32_MAX || plain_len == 0
        || plain_len > STORE_PAYLOAD_MAX
        || sgx_get_add_mac_txt_len((const sgx_sealed_data_t *)blob)
                                                        != sizeof(aad))
        goto out;
    plain = malloc(plain_len);
    if (plain == NULL) { status = SGX_STORE_PLATFORM; goto out; }
    memset(&aad, 0, sizeof(aad));
    if (sgx_unseal_data((const sgx_sealed_data_t *)blob, (uint8_t *)&aad,
                        &aad_len, plain, &plain_len) != SGX_SUCCESS
        || aad_len != sizeof(aad)
        || !aad_valid(&aad, physical_name, object_type, plain, plain_len))
        goto out;
    *payload_len = plain_len;
    if (payload == NULL && payload_cap == 0) { status = SGX_STORE_OK; goto out; }
    if (payload == NULL || payload_cap < plain_len)
        { status = SGX_STORE_SHORT_BUFFER; goto out; }
    memcpy(payload, plain, plain_len);
    status = SGX_STORE_OK;
out:
    memset(&aad, 0, sizeof(aad));
    if (plain != NULL) { memset(plain, 0, plain_len); free(plain); }
    if (blob != NULL) { memset(blob, 0, blob_len); free(blob); }
    return status;
}

int sgx_store_write_verified(const char *physical_name,
                             const char *object_type,
                             const uint8_t *payload, size_t payload_len)
{
    struct store_aad aad;
    uint8_t *blob = NULL, *check = NULL;
    uint32_t blob_len;
    size_t check_len = 0;
    int result = 1, status = SGX_STORE_PLATFORM;
    memset(&aad, 0, sizeof(aad));
    if (!make_aad(&aad, physical_name, object_type, payload, payload_len))
        return SGX_STORE_INVALID;
    blob_len = sgx_calc_sealed_data_size(sizeof(aad), (uint32_t)payload_len);
    if (blob_len == UINT32_MAX || blob_len > SGX_SEALED_BLOB_MAX
        || (blob = malloc(blob_len)) == NULL)
        goto out;
    const sgx_attributes_t mask = { SGX_FLAGS_INITTED | SGX_FLAGS_DEBUG, 0 };
    if (sgx_seal_data_ex(SGX_KEYPOLICY_MRSIGNER, mask, UINT32_MAX,
                         sizeof(aad), (const uint8_t *)&aad,
                         (uint32_t)payload_len, payload, blob_len,
                         (sgx_sealed_data_t *)blob) != SGX_SUCCESS
        || ocall_twep_sealed_write_atomic(&result, physical_name, blob,
                                          blob_len) != SGX_SUCCESS
        || result != 0)
        goto out;
    check = malloc(payload_len);
    if (check == NULL)
        goto out;
    status = sgx_store_read(physical_name, object_type, check, payload_len,
                            &check_len);
    if (status != SGX_STORE_OK || check_len != payload_len
        || memcmp(check, payload, payload_len) != 0)
        status = SGX_STORE_CORRUPT;
out:
    memset(&aad, 0, sizeof(aad));
    if (check != NULL) { memset(check, 0, payload_len); free(check); }
    if (blob != NULL) { memset(blob, 0, blob_len); free(blob); }
    return status;
}

int sgx_provision_demo_policy(void)
{
    uint8_t *payload = NULL;
    size_t i, len = 0, returned = 0;
    int result = 1, status;
    sgx_sha256_hash_t digest;

    status = sgx_store_read(demo_policy[0].physical, demo_policy[0].type,
                            NULL, 0, &len);
    if (status == SGX_STORE_OK || status == SGX_STORE_SHORT_BUFFER) {
        for (i = 1; i < sizeof(demo_policy) / sizeof(demo_policy[0]); ++i) {
            status = sgx_store_read(demo_policy[i].physical,
                                    demo_policy[i].type, NULL, 0, &len);
            if (status != SGX_STORE_OK && status != SGX_STORE_SHORT_BUFFER)
                return status;
        }
        return SGX_STORE_OK;
    }
    if (status != SGX_STORE_NOT_FOUND)
        return status;
    if (ocall_twep_read_artifact(&result, demo_policy[0].artifact,
                                 NULL, 0, &len) != SGX_SUCCESS
        || result != 0)
        return SGX_STORE_OK;

    for (i = 0; i < sizeof(demo_policy) / sizeof(demo_policy[0]); ++i) {
        len = 0;
        if (ocall_twep_read_artifact(&result, demo_policy[i].artifact,
                                     NULL, 0, &len) != SGX_SUCCESS
            || result != 0 || len == 0 || len > demo_policy[i].max_len)
            return SGX_STORE_INVALID;
        payload = malloc(len);
        if (payload == NULL)
            return SGX_STORE_PLATFORM;
        returned = len;
        if (ocall_twep_read_artifact(&result, demo_policy[i].artifact,
                                     payload, len, &returned) != SGX_SUCCESS
            || result != 0 || returned != len
            || len > UINT32_MAX
            || sgx_sha256_msg(payload, (uint32_t)len, &digest) != SGX_SUCCESS
            || memcmp(digest, demo_policy[i].sha256, sizeof(digest)) != 0) {
            memset(payload, 0, len);
            free(payload);
            return SGX_STORE_INVALID;
        }
        status = sgx_store_write_verified(demo_policy[i].physical,
                                          demo_policy[i].type, payload, len);
        memset(payload, 0, len);
        free(payload);
        payload = NULL;
        memset(&digest, 0, sizeof(digest));
        if (status != SGX_STORE_OK)
            return status;
    }
    return SGX_STORE_OK;
}

int sgx_provision_agent_identity(void)
{
    static const uint8_t prefix[] = {
        0xa5,
        0x6e,'s','c','h','e','m','a','_','v','e','r','s','i','o','n',0x01,
        0x70,'p','l','a','t','f','o','r','m','_','b','a','c','k','e','n','d',
        0x63,'s','g','x',
        0x70,'r','u','n','t','i','m','e','_','l','o','c','a','t','i','o','n',
        0x6b,'s','g','x','-','e','n','c','l','a','v','e',
        0x72,'m','e','a','s','u','r','e','m','e','n','t','_','s','h','a','2','5','6',
        0x58,0x20
    };
    static const uint8_t suffix[] = {
        0x73,'t','e','e','p','_','a','g','e','n','t','_','l','o','c','a','t','i','o','n',
        0x6b,'s','g','x','-','e','n','c','l','a','v','e'
    };
    uint8_t object[sizeof(prefix) + 32 + sizeof(suffix)];
    size_t len = 0;
    int status = sgx_store_read("agent-identity", "agent-identity",
                                NULL, 0, &len);
    if (status == SGX_STORE_OK || status == SGX_STORE_SHORT_BUFFER)
        return SGX_STORE_OK;
    if (status != SGX_STORE_NOT_FOUND)
        return status;
    memcpy(object, prefix, sizeof(prefix));
    memcpy(object + sizeof(prefix), sgx_teep_agent_measurement(), 32);
    memcpy(object + sizeof(prefix) + 32, suffix, sizeof(suffix));
    status = sgx_store_write_verified("agent-identity", "agent-identity",
                                      object, sizeof(object));
    memset(object, 0, sizeof(object));
    return status;
}

static void evidence_put_len(uint8_t **out, unsigned major, uint64_t value)
{
    if (value < 24) {
        *(*out)++ = (uint8_t)(major << 5 | value);
    } else if (value <= UINT8_MAX) {
        *(*out)++ = (uint8_t)(major << 5 | 24);
        *(*out)++ = (uint8_t)value;
    } else if (value <= UINT16_MAX) {
        *(*out)++ = (uint8_t)(major << 5 | 25);
        *(*out)++ = (uint8_t)(value >> 8);
        *(*out)++ = (uint8_t)value;
    } else if (value <= UINT32_MAX) {
        *(*out)++ = (uint8_t)(major << 5 | 26);
        *(*out)++ = (uint8_t)(value >> 24);
        *(*out)++ = (uint8_t)(value >> 16);
        *(*out)++ = (uint8_t)(value >> 8);
        *(*out)++ = (uint8_t)value;
    } else {
        *(*out)++ = (uint8_t)(major << 5 | 27);
        for (int shift = 56; shift >= 0; shift -= 8)
            *(*out)++ = (uint8_t)(value >> shift);
    }
}

static void evidence_put_text(uint8_t **out, const char *text)
{
    size_t len = strlen(text);
    evidence_put_len(out, 3, len);
    memcpy(*out, text, len);
    *out += len;
}

static int read_acceptance_evidence_result(uint8_t *payload,
                                           size_t payload_cap,
                                           size_t *payload_len)
{
    uint8_t encoded[192], *out = encoded;
    uint64_t generation;
    int status = sgx_acceptance_generation(&generation);
    if (status != SGX_STORE_OK)
        return status;
    evidence_put_len(&out, 5, 5);
    evidence_put_text(&out, "schema_version");
    evidence_put_len(&out, 0, 2);
    evidence_put_text(&out, "decision_source");
    evidence_put_text(&out, "attestam-signed-update");
    evidence_put_text(&out, "tam_response_verified");
    *out++ = 0xf5;
    evidence_put_text(&out, "challenge_response_bound");
    *out++ = 0xf5;
    evidence_put_text(&out, "acceptance_generation");
    evidence_put_len(&out, 0, generation);
    *payload_len = (size_t)(out - encoded);
    if (payload == NULL || payload_cap < *payload_len)
        return SGX_STORE_SHORT_BUFFER;
    memcpy(payload, encoded, *payload_len);
    return SGX_STORE_OK;
}

int sgx_store_read_protected(const char *logical_name, size_t logical_name_len,
                             uint8_t *payload, size_t payload_cap,
                             size_t *payload_len)
{
    size_t i;
    if (logical_name == NULL || logical_name_len == 0 || payload_len == NULL)
        return SGX_STORE_INVALID;
    if (logical_name_len == sizeof("verified-evidence-result.cbor") - 1
        && memcmp(logical_name, "verified-evidence-result.cbor",
                  logical_name_len) == 0)
        return read_acceptance_evidence_result(payload, payload_cap,
                                               payload_len);
    for (i = 0; i < sizeof(protected_names) / sizeof(protected_names[0]); ++i)
        if (strlen(protected_names[i].logical) == logical_name_len
            && memcmp(logical_name, protected_names[i].logical,
                      logical_name_len) == 0)
            return sgx_store_read(protected_names[i].physical,
                                  protected_names[i].type, payload,
                                  payload_cap, payload_len);
    *payload_len = 0;
    return SGX_STORE_INVALID;
}
