/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */
#include "runtime_internal.h"

#include <assert.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define KEY_LEN 77u
#define TEMP_PATH_LEN 1024u

static uint8_t *load_file(const char *path, size_t *len);
static void save_file(const char *path, const uint8_t *bytes, size_t len);
static void prepare_artifacts(const char *root);
static void assert_helloworld_success(twep_wr_context_t *ctx);

static void make_temp_dir(char path[TEMP_PATH_LEN], const char *name)
{
    const char *root = getenv("TMPDIR");
    if (root == NULL || root[0] == '\0')
        root = "/tmp";
    assert(snprintf(path, TEMP_PATH_LEN, "%s/%s-XXXXXX", root, name) > 0);
    assert(mkdtemp(path) != NULL);
}


static twep_wr_context_t *init_at(const char *state_dir)
{
    twep_wr_config_t config = {
        .state_dir = state_dir,
        .resolver_mode = "mock",
        .attestam_url = "",
        .max_request_bytes = 16u * 1024u * 1024u,
        .max_response_bytes = 16u * 1024u * 1024u,
    };
    twep_wr_context_t *ctx = NULL;
    assert(twep_wr_init(&config, &ctx) == TWEP_WR_OK);
    assert(ctx != NULL);
    return ctx;
}

#ifdef TWEP_WR_SGX_TEST_HOOKS
static twep_wr_context_t *init_verified_at(const char *state_dir);

extern void twep_wr_sgx_test_dcap_configure(uint32_t, uint32_t);
extern int twep_wr_sgx_test_evidence(
    const twep_wr_context_t *, const uint8_t *, size_t, const uint8_t *,
    size_t, uint8_t *, size_t, size_t *);

enum {
    SGX_DCAP_FAULT_TARGET = 1u << 0,
    SGX_DCAP_FAULT_SIZE = 1u << 1,
    SGX_DCAP_FAULT_QUOTE = 1u << 2,
    SGX_DCAP_FAULT_VERSION = 1u << 3,
    SGX_DCAP_FAULT_SIGNATURE_LEN = 1u << 4,
    SGX_DCAP_FAULT_REPORT_DATA = 1u << 5,
    SGX_DCAP_FAULT_ZERO_TAIL = 1u << 6,
};

static size_t read_bstr(const uint8_t *buf, size_t cap, size_t *header_len)
{
    assert(cap != 0 && (buf[0] >> 5) == 2);
    if ((buf[0] & 31) < 24) {
        *header_len = 1;
        return buf[0] & 31;
    }
    if ((buf[0] & 31) == 24) {
        assert(cap >= 2 && buf[1] >= 24);
        *header_len = 2;
        return buf[1];
    }
    assert((buf[0] & 31) == 25 && cap >= 3);
    *header_len = 3;
    return (size_t)buf[1] << 8 | buf[2];
}

static void assert_evidence_bundle(const uint8_t *bundle, size_t bundle_len,
                                   const uint8_t key[KEY_LEN],
                                   const uint8_t *challenge,
                                   size_t challenge_len, size_t quote_len)
{
    uint8_t expected[SHA384_DIGEST_LENGTH];
    size_t qh, rh, qlen, raw_len, off;
    assert(bundle_len != 0 && bundle[0] == 0x82);
    qlen = read_bstr(bundle + 1, bundle_len - 1, &qh);
    assert(qlen == quote_len && 1 + qh + qlen < bundle_len);
    off = 1 + qh + qlen;
    raw_len = read_bstr(bundle + off, bundle_len - off, &rh);
    assert(raw_len == 64 + challenge_len
           && off + rh + raw_len == bundle_len);
    const uint8_t *raw = bundle + off + rh;
    assert(memcmp(raw, key + 10, 32) == 0);
    assert(memcmp(raw + 32, key + 45, 32) == 0);
    assert(memcmp(raw + 64, challenge, challenge_len) == 0);
    SHA384(raw, raw_len, expected);
    assert(memcmp(bundle + 1 + qh + 368, expected, sizeof(expected)) == 0);
    for (size_t i = 416; i < 432; ++i)
        assert(bundle[1 + qh + i] == 0);
}

static void exercise_dcap_evidence(void)
{
    static const uint8_t challenge[] =
        "0123456789abcdef0123456789abcdef";
    static const uint8_t wasm_agent_key[KEY_LEN] = {
        0xa5,0x01,0x02,0x03,0x28,0x20,0x01,0x21,0x58,0x20,
        0x0e,0x90,0x8a,0xa8,0xf0,0x66,0xdb,0x1f,0x08,0x4e,0x0c,0x36,0x52,0xc6,0x39,0x52,0xbd,0x99,0xf2,0xa5,0xbd,0xb2,0x2f,0x9e,0x01,0x36,0x7a,0xad,0x03,0xab,0xa6,0x8b,
        0x22,0x58,0x20,
        0x77,0xda,0x1b,0xd8,0xac,0x4f,0x0c,0xb4,0x90,0xba,0x21,0x06,0x48,0xbf,0x79,0xab,0x16,0x4d,0x49,0xad,0x35,0x51,0xd7,0x1d,0x31,0x4b,0x27,0x49,0xee,0x42,0xd2,0x9a,
    };
    uint8_t changed[sizeof(challenge) - 1], key[KEY_LEN], bundle[31u * 1024u];
    char state_dir[TEMP_PATH_LEN];
    size_t bundle_len = 0;
    make_temp_dir(state_dir, "twep-sgx-dcap");
    prepare_artifacts(state_dir);
    twep_wr_context_t *ctx = init_verified_at(state_dir);
    memcpy(key, wasm_agent_key, sizeof(key));

    twep_wr_sgx_test_dcap_configure(1024, 0);
    assert(twep_wr_sgx_test_evidence(
               ctx, challenge, sizeof(challenge) - 1, wasm_agent_key,
               sizeof(wasm_agent_key),
               NULL, 0, &bundle_len) == 2);
    assert(bundle_len > 1024);
    assert(twep_wr_sgx_test_evidence(
               ctx, challenge, sizeof(challenge) - 1, wasm_agent_key,
               sizeof(wasm_agent_key),
               bundle, bundle_len, &bundle_len) == 0);
    assert_evidence_bundle(bundle, bundle_len, wasm_agent_key, challenge,
                           sizeof(challenge) - 1, 1024);
    assert(twep_wr_sgx_test_evidence(
               ctx, challenge, sizeof(challenge) - 1, key, sizeof(key),
               NULL, 0, &bundle_len) == 2);
    assert(twep_wr_sgx_test_evidence(
               ctx, challenge, sizeof(challenge) - 1, key, sizeof(key),
               bundle, bundle_len - 1, &bundle_len) == 2);
    assert(twep_wr_sgx_test_evidence(
               ctx, challenge, sizeof(challenge) - 1, key, sizeof(key),
               bundle, bundle_len, &bundle_len) == 0);

    /* A size query is bound to exactly the same challenge and Agent key. */
    assert(twep_wr_sgx_test_evidence(
               ctx, challenge, sizeof(challenge) - 1, key, sizeof(key),
               NULL, 0, &bundle_len) == 2);
    memcpy(changed, challenge, sizeof(changed));
    changed[0] ^= 1;
    assert(twep_wr_sgx_test_evidence(
               ctx, changed, sizeof(changed), key, sizeof(key),
               bundle, sizeof(bundle), &bundle_len) == 1);

    /* Any invalid call also destroys a pending short-buffer cache. */
    assert(twep_wr_sgx_test_evidence(
               ctx, challenge, sizeof(challenge) - 1, key, sizeof(key),
               NULL, 0, &bundle_len) == 2);
    assert(twep_wr_sgx_test_evidence(
               ctx, challenge, 7, key, sizeof(key),
               bundle, sizeof(bundle), &bundle_len) == 1);
    twep_wr_sgx_test_dcap_configure(1024, SGX_DCAP_FAULT_TARGET);
    assert(twep_wr_sgx_test_evidence(
               ctx, challenge, sizeof(challenge) - 1, key, sizeof(key),
               bundle, sizeof(bundle), &bundle_len) == 7);
    twep_wr_sgx_test_dcap_configure(1024, 0);
    assert(twep_wr_sgx_test_evidence(
               ctx, challenge, sizeof(challenge) - 1, key, sizeof(key),
               bundle, sizeof(bundle), &bundle_len) == 0);

    const uint32_t valid_sizes[] = {436, 28u * 1024u};
    for (size_t i = 0; i < sizeof(valid_sizes) / sizeof(valid_sizes[0]); ++i) {
        twep_wr_sgx_test_dcap_configure(valid_sizes[i], 0);
        assert(twep_wr_sgx_test_evidence(
                   ctx, challenge, sizeof(challenge) - 1, key, sizeof(key),
                   bundle, sizeof(bundle), &bundle_len) == 0);
        assert_evidence_bundle(bundle, bundle_len, key, challenge,
                               sizeof(challenge) - 1, valid_sizes[i]);
    }
    twep_wr_sgx_test_dcap_configure(30u * 1024u, 0);
    assert(twep_wr_sgx_test_evidence(
               ctx, challenge, sizeof(challenge) - 1, key, sizeof(key),
               bundle, sizeof(bundle), &bundle_len) == 7);
    twep_wr_sgx_test_dcap_configure(435, 0);
    assert(twep_wr_sgx_test_evidence(
               ctx, challenge, sizeof(challenge) - 1, key, sizeof(key),
               bundle, sizeof(bundle), &bundle_len) == 7);
    twep_wr_sgx_test_dcap_configure(32u * 1024u, 0);
    assert(twep_wr_sgx_test_evidence(
               ctx, challenge, sizeof(challenge) - 1, key, sizeof(key),
               bundle, sizeof(bundle), &bundle_len) == 7);

    const uint32_t faults[] = {
        SGX_DCAP_FAULT_TARGET, SGX_DCAP_FAULT_SIZE, SGX_DCAP_FAULT_QUOTE,
        SGX_DCAP_FAULT_VERSION, SGX_DCAP_FAULT_SIGNATURE_LEN,
        SGX_DCAP_FAULT_REPORT_DATA, SGX_DCAP_FAULT_ZERO_TAIL,
    };
    for (size_t i = 0; i < sizeof(faults) / sizeof(faults[0]); ++i) {
        twep_wr_sgx_test_dcap_configure(1024, faults[i]);
        assert(twep_wr_sgx_test_evidence(
                   ctx, challenge, sizeof(challenge) - 1, key, sizeof(key),
                   bundle, sizeof(bundle), &bundle_len) == 7);
    }
    key[10] ^= 1;
    twep_wr_sgx_test_dcap_configure(1024, 0);
    assert(twep_wr_sgx_test_evidence(
               ctx, challenge, sizeof(challenge) - 1, key, sizeof(key),
               bundle, sizeof(bundle), &bundle_len) == 1);
    twep_wr_shutdown(ctx);
}

static twep_wr_context_t *init_verified_at(const char *state_dir)
{
    twep_wr_config_t config = {
        .state_dir = state_dir,
        .resolver_mode = "attestam-verified",
        .attestam_url = "http://127.0.0.1:1",
        .max_request_bytes = 16u * 1024u * 1024u,
        .max_response_bytes = 16u * 1024u * 1024u,
    };
    twep_wr_context_t *ctx = NULL;
    assert(twep_wr_init(&config, &ctx) == TWEP_WR_OK);
    return ctx;
}

extern int twep_wr_sgx_test_transaction(
    const twep_wr_context_t *, uint32_t, const uint8_t[32],
    const uint8_t *, size_t, uint64_t, uint64_t, const uint8_t *, size_t,
    const uint8_t[32], uint64_t *);
extern int twep_wr_sgx_test_transcript(const twep_wr_context_t *, uint32_t);
extern void twep_wr_sgx_test_artifact_replacement(const char *);
extern int twep_wr_sgx_test_agent_measurement(const twep_wr_context_t *,
                                               uint8_t[32]);

static void exercise_transcript_commit(void)
{
    char state_dir[TEMP_PATH_LEN];
    make_temp_dir(state_dir, "twep-sgx-transcript");
    prepare_artifacts(state_dir);
    twep_wr_context_t *ctx = init_verified_at(state_dir);
    for (uint32_t scenario = 1; scenario <= 4; ++scenario)
        assert(twep_wr_sgx_test_transcript(ctx, scenario) == 0);
    twep_wr_shutdown(ctx);
}

static void assert_agent_execute_fails(twep_wr_context_t *ctx)
{
    twep_wr_normalized_request_t request = {
        .request_id = "sgx-agent-measurement", .command = "helloworld",
    };
    twep_wr_owned_bytes_t response = {0};
    assert(twep_wr_execute(ctx, &request, &response) != TWEP_WR_OK);
    assert(response.ptr == NULL && response.len == 0);
}

static void exercise_agent_measurement(void)
{
    char state_dir[TEMP_PATH_LEN], rollback_dir[TEMP_PATH_LEN];
    char agent_path[512], original_path[512], alternate_path[512];
    char corrupt_path[512];
    uint8_t expected[SHA256_DIGEST_LENGTH], reported[SHA256_DIGEST_LENGTH];
    size_t original_len, alternate_len;

    assert(snprintf(original_path, sizeof(original_path), "%s/teep-agent.wasm",
                    TWEP_WR_TEST_ARTIFACT_DIR) > 0);
    assert(snprintf(alternate_path, sizeof(alternate_path),
                    "%s/teep-agent-512k.wasm",
                    TWEP_WR_TEST_ARTIFACT_DIR) > 0);
    uint8_t *original = load_file(original_path, &original_len);
    uint8_t *alternate = load_file(alternate_path, &alternate_len);

    make_temp_dir(state_dir, "twep-sgx-agent-measurement");
    prepare_artifacts(state_dir);
    assert(snprintf(agent_path, sizeof(agent_path),
                    "%s/teep-agent/teep-agent.wasm", state_dir) > 0);
    twep_wr_context_t *ctx = init_at(state_dir);
    SHA256(original, original_len, expected);
    assert(twep_wr_sgx_test_agent_measurement(ctx, reported) == 0);
    assert(memcmp(reported, expected, sizeof(expected)) == 0);

    /* A distinct, correctly role-signed Agent cannot replace the measured one. */
    save_file(agent_path, alternate, alternate_len);
    assert_agent_execute_fails(ctx);
    save_file(agent_path, original, original_len);
    assert_helloworld_success(ctx);

    /* Reject a same-size content change between the size and data reads. */
    assert(snprintf(corrupt_path, sizeof(corrupt_path), "%s/corrupt-agent.wasm",
                    state_dir) > 0);
    original[0] ^= 1;
    save_file(corrupt_path, original, original_len);
    original[0] ^= 1;
    twep_wr_sgx_test_artifact_replacement(corrupt_path);
    assert_agent_execute_fails(ctx);
    save_file(agent_path, original, original_len);

    /* Reject a size change between the size and data reads. */
    twep_wr_sgx_test_artifact_replacement(alternate_path);
    assert_agent_execute_fails(ctx);
    save_file(agent_path, original, original_len);
    assert_helloworld_success(ctx);
    twep_wr_shutdown(ctx);

    /* Initializing with the newer Agent must also reject rollback to the old one. */
    make_temp_dir(rollback_dir, "twep-sgx-agent-rollback");
    prepare_artifacts(rollback_dir);
    assert(snprintf(agent_path, sizeof(agent_path),
                    "%s/teep-agent/teep-agent.wasm", rollback_dir) > 0);
    save_file(agent_path, alternate, alternate_len);
    ctx = init_at(rollback_dir);
    SHA256(alternate, alternate_len, expected);
    assert(twep_wr_sgx_test_agent_measurement(ctx, reported) == 0);
    assert(memcmp(reported, expected, sizeof(expected)) == 0);
    save_file(agent_path, original, original_len);
    assert_agent_execute_fails(ctx);
    twep_wr_shutdown(ctx);

    free(alternate);
    free(original);
}

static void exercise_protected_offline(void)
{
    static const uint8_t catalog_component[] = {
        0x82,0x4f,'t','w','e','p','-','c','a','t','a','l','o','g','-','v','1',
        0x47,'d','e','f','a','u','l','t'
    };
    static const uint8_t app_component[] = {
        0x82,0x4b,'t','w','e','p','-','a','p','p','-','v','1',
        0x4a,'h','e','l','l','o','w','o','r','l','d'
    };
    uint8_t q1[32] = {1}, q2[32] = {2}, q3[32] = {3};
    uint8_t catalog_digest[32], app_digest[32], wrong_digest[32];
    uint8_t noncanonical_component[sizeof(app_component)];
    char state_dir[TEMP_PATH_LEN], path[512];
    size_t catalog_len, app_len;
    uint64_t generation = UINT64_MAX;
    uint64_t rejected_generation = UINT64_MAX;
    make_temp_dir(state_dir, "twep-sgx-protected");
    prepare_artifacts(state_dir);
    uint8_t *catalog = load_file(TWEP_WR_TEST_ARTIFACT_DIR "/catalog.dev.cbor",
                                 &catalog_len);
    uint8_t *app = load_file(TWEP_WR_TEST_ARTIFACT_DIR "/helloworld.wasm",
                             &app_len);
    SHA256(catalog, catalog_len, catalog_digest);
    SHA256(app, app_len, app_digest);
    twep_wr_context_t *ctx = init_verified_at(state_dir);
    assert(twep_wr_sgx_test_transaction(
               ctx, 2, q1, catalog_component, sizeof(catalog_component),
               1, 0, catalog, catalog_len, catalog_digest, &generation) == 0);
    assert(generation == 1);
    assert(twep_wr_sgx_test_transaction(
               ctx, 3, q2, app_component, sizeof(app_component),
               1, generation, app, app_len, app_digest, &generation) == 0);
    assert(generation == 2);
    /*
     * Every rejected app transaction must preserve generation 2 and the
     * already active, executable app.
     */
    memcpy(wrong_digest, app_digest, sizeof(wrong_digest));
    wrong_digest[0] ^= 1;
    assert(twep_wr_sgx_test_transaction(
               ctx, 3, q3, app_component, sizeof(app_component),
               2, 2, app, app_len, wrong_digest, &rejected_generation) != 0);
    memcpy(noncanonical_component, app_component, sizeof(app_component));
    noncanonical_component[1] = 0x58;
    assert(twep_wr_sgx_test_transaction(
               ctx, 3, q3, noncanonical_component,
               sizeof(noncanonical_component), 2, 2, app, app_len,
               app_digest, &rejected_generation) != 0);
    assert(twep_wr_sgx_test_transaction(
               ctx, 3, q3, app_component, sizeof(app_component),
               0, 2, app, app_len, app_digest, &rejected_generation) != 0);
    assert(twep_wr_sgx_test_transaction(
               ctx, 3, q3, app_component, sizeof(app_component),
               2, 1, app, app_len, app_digest, &rejected_generation) == 9);
    assert(twep_wr_sgx_test_transaction(
               ctx, 3, q3, app_component, sizeof(app_component),
               2, 2, app, 128u * 1024u + 1, app_digest,
               &rejected_generation) != 0);
    /* Same digest and non-increasing sequence are replay conflicts. */
    assert(twep_wr_sgx_test_transaction(
               ctx, 1, q2, app_component, sizeof(app_component),
               2, 2, NULL, 0, NULL, &rejected_generation) == 9);
    assert_helloworld_success(ctx);
    twep_wr_shutdown(ctx);
    assert(snprintf(path, sizeof(path), "%s/catalog/catalog.cbor",
                    state_dir) > 0);
    assert(unlink(path) == 0);
    assert(snprintf(path, sizeof(path), "%s/apps/helloworld.wasm",
                    state_dir) > 0);
    assert(unlink(path) == 0);
    ctx = init_verified_at(state_dir);
    assert_helloworld_success(ctx);
    twep_wr_shutdown(ctx);
    free(app);
    free(catalog);
}
#endif


static void assert_init_fails(const char *state_dir)
{
    twep_wr_config_t config = {
        .state_dir = state_dir, .resolver_mode = "mock", .attestam_url = "",
        .max_request_bytes = 1024, .max_response_bytes = 1024,
    };
    twep_wr_context_t *ctx = (twep_wr_context_t *)(uintptr_t)1;
    assert(twep_wr_init(&config, &ctx) == TWEP_WR_ERR_INIT);
    assert(ctx == NULL);
}

static void copy_file(const char *src, const char *dst)
{
    uint8_t buf[8192];
    FILE *in = fopen(src, "rb");
    FILE *out = fopen(dst, "wb");
    assert(in != NULL && out != NULL);
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), in)) != 0)
        assert(fwrite(buf, 1, n, out) == n);
    assert(ferror(in) == 0);
    assert(fclose(in) == 0 && fclose(out) == 0);
}

static bool contains_bytes(const uint8_t *haystack, size_t haystack_len,
                           const char *needle)
{
    size_t needle_len = strlen(needle);
    for (size_t i = 0; i + needle_len <= haystack_len; ++i)
        if (memcmp(haystack + i, needle, needle_len) == 0)
            return true;
    return false;
}

static uint8_t *load_file(const char *path, size_t *len)
{
    FILE *file = fopen(path, "rb");
    assert(file != NULL && fseek(file, 0, SEEK_END) == 0);
    *len = (size_t)ftell(file);
    assert(fseek(file, 0, SEEK_SET) == 0);
    uint8_t *bytes = malloc(*len);
    assert(bytes != NULL && fread(bytes, 1, *len, file) == *len);
    assert(fclose(file) == 0);
    return bytes;
}

static void save_file(const char *path, const uint8_t *bytes, size_t len)
{
    FILE *file = fopen(path, "wb");
    assert(file != NULL && fwrite(bytes, 1, len, file) == len);
    assert(fclose(file) == 0);
}

static void prepare_artifacts(const char *root)
{
    char path[512], src[512];
    assert(snprintf(path, sizeof(path), "%s/catalog", root) > 0);
    assert(mkdir(path, 0700) == 0);
    assert(snprintf(path, sizeof(path), "%s/apps", root) > 0);
    assert(mkdir(path, 0700) == 0);
    assert(snprintf(path, sizeof(path), "%s/teep-agent", root) > 0);
    assert(mkdir(path, 0700) == 0);
    assert(snprintf(src, sizeof(src), "%s/teep-agent.wasm",
                    TWEP_WR_TEST_ARTIFACT_DIR) > 0);
    assert(snprintf(path, sizeof(path), "%s/teep-agent/teep-agent.wasm",
                    root) > 0);
    copy_file(src, path);
    assert(snprintf(src, sizeof(src), "%s/catalog.dev.cbor",
                    TWEP_WR_TEST_ARTIFACT_DIR) > 0);
    assert(snprintf(path, sizeof(path), "%s/catalog/catalog.cbor", root) > 0);
    copy_file(src, path);
    const char *apps[] = { "helloworld.wasm", "calcadd.wasm", "negaposi.wasm" };
    for (size_t i = 0; i < sizeof(apps) / sizeof(apps[0]); ++i) {
        assert(snprintf(src, sizeof(src), "%s/%s",
                        TWEP_WR_TEST_ARTIFACT_DIR, apps[i]) > 0);
        assert(snprintf(path, sizeof(path), "%s/apps/%s", root, apps[i]) > 0);
        copy_file(src, path);
    }
}

static void assert_helloworld_success(twep_wr_context_t *ctx)
{
    static const uint8_t input[] = {
        0xa1, 0x67, 'c','o','m','m','a','n','d',
        0x6a, 'h','e','l','l','o','w','o','r','l','d',
    };
    twep_wr_normalized_request_t request = {
        .request_id = "sgx-recovery",
        .command = "helloworld",
        .app_input_cbor = { input, sizeof(input) },
    };
    twep_wr_owned_bytes_t response = { 0 };
    twep_wr_status_t status = twep_wr_execute(ctx, &request, &response);
    if (status != TWEP_WR_OK)
        fprintf(stderr, "helloworld execution status=%d\n", status);
    assert(status == TWEP_WR_OK);
    assert(response.ptr != NULL && response.len != 0);
    assert(contains_bytes(response.ptr, response.len, "Hello, World!!"));
    twep_wr_free_bytes(response);
}

static size_t replace_digest(uint8_t *catalog, size_t catalog_len,
                             const uint8_t old_digest[SHA256_DIGEST_LENGTH],
                             const uint8_t new_digest[SHA256_DIGEST_LENGTH])
{
    for (size_t i = 0; i + SHA256_DIGEST_LENGTH <= catalog_len; ++i) {
        if (memcmp(catalog + i, old_digest, SHA256_DIGEST_LENGTH) == 0) {
            memcpy(catalog + i, new_digest, SHA256_DIGEST_LENGTH);
            return i;
        }
    }
    assert(!"catalog digest not found");
    return 0;
}

static void install_negaposi_fixture(const char *state_dir,
                                     const char *fixture_name,
                                     uint8_t **original_app,
                                     size_t *original_app_len,
                                     uint8_t **original_catalog,
                                     size_t *original_catalog_len)
{
    char app_path[512], catalog_path[512], fixture_path[512];
    size_t fixture_len;
    uint8_t old_digest[SHA256_DIGEST_LENGTH];
    uint8_t new_digest[SHA256_DIGEST_LENGTH];
    assert(snprintf(app_path, sizeof(app_path), "%s/apps/negaposi.wasm",
                    state_dir) > 0);
    assert(snprintf(catalog_path, sizeof(catalog_path),
                    "%s/catalog/catalog.cbor", state_dir) > 0);
    assert(snprintf(fixture_path, sizeof(fixture_path),
                    "%s/sgx-backend-test-fixtures/%s",
                    TWEP_WR_TEST_ARTIFACT_DIR, fixture_name) > 0);
    *original_app = load_file(app_path, original_app_len);
    *original_catalog = load_file(catalog_path, original_catalog_len);
    uint8_t *fixture = load_file(fixture_path, &fixture_len);
    uint8_t *fixture_catalog = malloc(*original_catalog_len);
    assert(fixture_catalog != NULL);
    memcpy(fixture_catalog, *original_catalog, *original_catalog_len);
    SHA256(*original_app, *original_app_len, old_digest);
    SHA256(fixture, fixture_len, new_digest);
    (void)replace_digest(fixture_catalog, *original_catalog_len,
                         old_digest, new_digest);
    save_file(app_path, fixture, fixture_len);
    save_file(catalog_path, fixture_catalog, *original_catalog_len);
    free(fixture_catalog);
    free(fixture);
}

static void restore_negaposi(const char *state_dir, const uint8_t *app,
                             size_t app_len, const uint8_t *catalog,
                             size_t catalog_len)
{
    char path[512];
    assert(snprintf(path, sizeof(path), "%s/apps/negaposi.wasm",
                    state_dir) > 0);
    save_file(path, app, app_len);
    assert(snprintf(path, sizeof(path), "%s/catalog/catalog.cbor",
                    state_dir) > 0);
    save_file(path, catalog, catalog_len);
}

static void exercise_app_fixture_failure(const char *fixture_name,
                                         twep_wr_status_t expected,
                                         uint32_t timeout_ms,
                                         bool small_output_limit)
{
    char state_dir[TEMP_PATH_LEN];
    uint8_t *app, *catalog;
    size_t app_len, catalog_len;
    make_temp_dir(state_dir, "twep-sgx-negative");
    prepare_artifacts(state_dir);
    install_negaposi_fixture(state_dir, fixture_name, &app, &app_len,
                             &catalog, &catalog_len);
    if (small_output_limit) {
        static const uint8_t encoded_limit[] = {
            0x70, 'm','a','x','_','o','u','t','p','u','t','_','b','y','t','e','s',
            0x1a, 0x01, 0x00, 0x00, 0x00,
        };
        bool patched = false;
        char path[512];
        size_t active_catalog_len;
        assert(snprintf(path, sizeof(path), "%s/catalog/catalog.cbor",
                        state_dir) > 0);
        uint8_t *active_catalog = load_file(path, &active_catalog_len);
        for (size_t i = 0; i + sizeof(encoded_limit) <= active_catalog_len; ++i) {
            if (memcmp(active_catalog + i, encoded_limit,
                       sizeof(encoded_limit)) == 0) {
                memset(active_catalog + i + sizeof(encoded_limit) - 4, 0, 4);
                active_catalog[i + sizeof(encoded_limit) - 1] = 8;
                patched = true;
                break;
            }
        }
        assert(patched);
        save_file(path, active_catalog, active_catalog_len);
        free(active_catalog);
    }
    twep_wr_context_t *ctx = init_at(state_dir);
    twep_wr_normalized_request_t request = {
        .request_id = "sgx-negative",
        .command = "negaposi",
        .request_timeout_ms = timeout_ms,
    };
    twep_wr_owned_bytes_t response = { 0 };
    twep_wr_status_t actual = twep_wr_execute(ctx, &request, &response);
    if (actual != expected)
        fprintf(stderr, "%s: expected %s (%d), got %s (%d)\n",
                fixture_name, twep_wr_status_string(expected), expected,
                twep_wr_status_string(actual), actual);
    assert(actual == expected);
    assert(response.ptr == NULL && response.len == 0);
    restore_negaposi(state_dir, app, app_len, catalog, catalog_len);
    assert_helloworld_success(ctx);
    twep_wr_shutdown(ctx);
    free(catalog);
    free(app);
}

static void exercise_helloworld(void)
{
    static const uint8_t input[] = {
        0xa1, 0x67, 'c','o','m','m','a','n','d',
        0x6a, 'h','e','l','l','o','w','o','r','l','d',
    };
    char state_dir[TEMP_PATH_LEN];
    make_temp_dir(state_dir, "twep-sgx-execute");
    prepare_artifacts(state_dir);
    twep_wr_context_t *ctx = init_at(state_dir);
    twep_wr_normalized_request_t request = {
        .request_id = "sgx-helloworld",
        .command = "helloworld",
        .app_input_cbor = { input, sizeof(input) },
    };
    twep_wr_owned_bytes_t response = { 0 };
    twep_wr_status_t status = twep_wr_execute(ctx, &request, &response);
    if (status != TWEP_WR_OK)
        fprintf(stderr, "SGX helloworld failed: %s (%d)\n",
                twep_wr_status_string(status), status);
    assert(status == TWEP_WR_OK);
    assert(response.ptr != NULL && response.len != 0);
    assert(contains_bytes(response.ptr, response.len, "Hello, World!!"));
    twep_wr_free_bytes(response);

    /* Hash and signature failures must not poison the next request. */
    char app_path[512], catalog_path[512];
    size_t app_len, catalog_len;
    assert(snprintf(app_path, sizeof(app_path), "%s/apps/helloworld.wasm",
                    state_dir) > 0);
    assert(snprintf(catalog_path, sizeof(catalog_path),
                    "%s/catalog/catalog.cbor", state_dir) > 0);
    uint8_t *app = load_file(app_path, &app_len);
    uint8_t *catalog = load_file(catalog_path, &catalog_len);
    uint8_t old_digest[SHA256_DIGEST_LENGTH], new_digest[SHA256_DIGEST_LENGTH];
    SHA256(app, app_len, old_digest);
    app[8] ^= 1;
    save_file(app_path, app, app_len);
    assert(twep_wr_execute(ctx, &request, &response) == TWEP_WR_ERR_SECURITY);
    app[8] ^= 1;
    app[app_len - 1] ^= 1; /* corrupt twep.sig without damaging Wasm sections */
    SHA256(app, app_len, new_digest);
    bool patched = false;
    size_t patch_off = 0;
    for (size_t i = 0; i + sizeof(old_digest) <= catalog_len; ++i) {
        if (memcmp(catalog + i, old_digest, sizeof(old_digest)) == 0) {
            memcpy(catalog + i, new_digest, sizeof(new_digest));
            patched = true;
            patch_off = i;
            break;
        }
    }
    assert(patched);
    save_file(app_path, app, app_len);
    save_file(catalog_path, catalog, catalog_len);
    assert(twep_wr_execute(ctx, &request, &response)
           == TWEP_WR_ERR_WASM_SIGNATURE);
    app[app_len - 1] ^= 1;
    save_file(app_path, app, app_len);
    memcpy(catalog + patch_off, old_digest, sizeof(old_digest));
    save_file(catalog_path, catalog, catalog_len);
    assert(twep_wr_execute(ctx, &request, &response) == TWEP_WR_OK);
    twep_wr_free_bytes(response);
    free(catalog);
    free(app);
    twep_wr_shutdown(ctx);
}

static void exercise_calcadd(void)
{
    static const uint8_t input[] = {
        0xa1, 0x6f, 'i','n','f','e','r','r','e','d','_','p','a','r','a','m','s',
        0x83,
        0xa2,0x64,'t','y','p','e',0x63,'i','n','t',0x65,'v','a','l','u','e',0x03,
        0xa2,0x64,'t','y','p','e',0x63,'i','n','t',0x65,'v','a','l','u','e',0x04,
        0xa2,0x64,'t','y','p','e',0x63,'i','n','t',0x65,'v','a','l','u','e',0x05,
    };
    char state_dir[TEMP_PATH_LEN];
    make_temp_dir(state_dir, "twep-sgx-calcadd");
    prepare_artifacts(state_dir);
    twep_wr_context_t *ctx = init_at(state_dir);
    twep_wr_normalized_request_t request = {
        .request_id = "sgx-calcadd", .command = "calcadd",
        .app_input_cbor = { input, sizeof(input) },
    };
    twep_wr_owned_bytes_t response = { 0 };
    assert(twep_wr_execute(ctx, &request, &response) == TWEP_WR_OK);
    assert(contains_bytes(response.ptr, response.len, "12\n"));
    twep_wr_free_bytes(response);
    twep_wr_shutdown(ctx);
}

static void exercise_negaposi(void)
{
    char state_dir[TEMP_PATH_LEN];
    char image_path[512];
    uint8_t *image, *input, *p;
    size_t image_len;
    FILE *file;
    make_temp_dir(state_dir, "twep-sgx-negaposi");
    prepare_artifacts(state_dir);
    assert(snprintf(image_path, sizeof(image_path), "%s/images/medium.jpg",
                    TWEP_WR_TESTDATA_DIR) > 0);
    file = fopen(image_path, "rb");
    assert(file != NULL && fseek(file, 0, SEEK_END) == 0);
    image_len = (size_t)ftell(file);
    assert(fseek(file, 0, SEEK_SET) == 0);
    image = malloc(image_len);
    input = malloc(image_len + 32);
    assert(image != NULL && input != NULL);
    assert(fread(image, 1, image_len, file) == image_len && fclose(file) == 0);
    p = input;
    *p++ = 0xa1; *p++ = 0x65; memcpy(p, "files", 5); p += 5;
    *p++ = 0xa1; *p++ = 0x65; memcpy(p, "input", 5); p += 5;
    *p++ = 0x5a;
    *p++ = (uint8_t)(image_len >> 24); *p++ = (uint8_t)(image_len >> 16);
    *p++ = (uint8_t)(image_len >> 8); *p++ = (uint8_t)image_len;
    memcpy(p, image, image_len); p += image_len;
    twep_wr_context_t *ctx = init_at(state_dir);
    twep_wr_normalized_request_t request = {
        .request_id = "sgx-negaposi", .command = "negaposi",
        .app_input_cbor = { input, (size_t)(p - input) },
    };
    twep_wr_owned_bytes_t response = { 0 };
    assert(twep_wr_execute(ctx, &request, &response) == TWEP_WR_OK);
    {
        static const uint8_t jpeg_magic[] = { 0xff, 0xd8, 0xff };
        bool found = false;
        for (size_t i = 0; i + sizeof(jpeg_magic) <= response.len; ++i)
            if (memcmp(response.ptr + i, jpeg_magic, sizeof(jpeg_magic)) == 0)
                found = true;
        assert(found);
    }
    twep_wr_free_bytes(response);
    twep_wr_shutdown(ctx);
    free(input);
    free(image);
}

static void exercise_hostcall_negative(void)
{
    exercise_app_fixture_failure("env-import.wasm",
                                 TWEP_WR_ERR_WASM_ABI, 0, false);
    exercise_app_fixture_failure("teep-env-import.wasm",
                                 TWEP_WR_ERR_WASM_ABI, 0, false);
}

static void exercise_cleanup_negative(void)
{
    exercise_app_fixture_failure("nonzero-status.wasm",
                                 TWEP_WR_ERR_WASM_RUNTIME, 0, false);
    exercise_app_fixture_failure("trap.wasm",
                                 TWEP_WR_ERR_WASM_RUNTIME, 0, false);
}

static void exercise_wasm_signature_negative(void)
{
    char state_dir[TEMP_PATH_LEN];
    char agent_path[512], fixture_path[512], app_path[512], catalog_path[512];
    size_t agent_len, app_len, catalog_len, fixture_len;
    make_temp_dir(state_dir, "twep-sgx-signature");
    prepare_artifacts(state_dir);
    assert(snprintf(agent_path, sizeof(agent_path),
                    "%s/teep-agent/teep-agent.wasm", state_dir) > 0);
    uint8_t *agent = load_file(agent_path, &agent_len);
    uint8_t *corrupt = malloc(agent_len);
    assert(corrupt != NULL);
    memcpy(corrupt, agent, agent_len);
    corrupt[agent_len - 1] ^= 1;
    save_file(agent_path, corrupt, agent_len);
    assert_init_fails(state_dir);
    save_file(agent_path, agent, agent_len);
    twep_wr_context_t *ctx = init_at(state_dir);
    twep_wr_normalized_request_t request = {
        .request_id = "sgx-agent-signature", .command = "helloworld",
    };
    twep_wr_owned_bytes_t response = { 0 };
    save_file(agent_path, corrupt, agent_len);
    assert(twep_wr_execute(ctx, &request, &response)
           == TWEP_WR_ERR_WASM_SIGNATURE);
    save_file(agent_path, agent, agent_len);
    assert_helloworld_success(ctx);

    assert(snprintf(fixture_path, sizeof(fixture_path),
                    "%s/sgx-backend-test-fixtures/teep-agent-app-role.wasm",
                    TWEP_WR_TEST_ARTIFACT_DIR) > 0);
    uint8_t *fixture = load_file(fixture_path, &fixture_len);
    save_file(agent_path, fixture, fixture_len);
    assert(twep_wr_execute(ctx, &request, &response)
           == TWEP_WR_ERR_WASM_SIGNATURE);
    save_file(agent_path, agent, agent_len);
    assert_helloworld_success(ctx);
    free(fixture);

    assert(snprintf(app_path, sizeof(app_path), "%s/apps/helloworld.wasm",
                    state_dir) > 0);
    assert(snprintf(catalog_path, sizeof(catalog_path),
                    "%s/catalog/catalog.cbor", state_dir) > 0);
    app_len = 0;
    uint8_t *app = load_file(app_path, &app_len);
    uint8_t *catalog = load_file(catalog_path, &catalog_len);
    assert(snprintf(fixture_path, sizeof(fixture_path),
                    "%s/sgx-backend-test-fixtures/helloworld-agent-role.wasm",
                    TWEP_WR_TEST_ARTIFACT_DIR) > 0);
    fixture = load_file(fixture_path, &fixture_len);
    uint8_t old_digest[SHA256_DIGEST_LENGTH], new_digest[SHA256_DIGEST_LENGTH];
    SHA256(app, app_len, old_digest);
    SHA256(fixture, fixture_len, new_digest);
    (void)replace_digest(catalog, catalog_len, old_digest, new_digest);
    save_file(app_path, fixture, fixture_len);
    save_file(catalog_path, catalog, catalog_len);
    assert(twep_wr_execute(ctx, &request, &response)
           == TWEP_WR_ERR_WASM_SIGNATURE);
    free(fixture);
    save_file(app_path, app, app_len);
    copy_file(TWEP_WR_TEST_ARTIFACT_DIR "/catalog.dev.cbor", catalog_path);
    assert_helloworld_success(ctx);
    twep_wr_shutdown(ctx);
    free(catalog);
    free(app);
    free(corrupt);
    free(agent);
}

int main(int argc, char **argv)
{
    const char *scenario = argc > 1 ? argv[1] : "all";
    bool lifecycle = strcmp(scenario, "all") == 0;
    const twep_wr_platform_info_t *info = twep_wr_platform_info();
    assert(info != NULL && strcmp(info->backend_name, "sgx") == 0);
    assert(info->sealed_storage_security
           == TWEP_WR_PLATFORM_SEALED_TEE_PROTECTED);
    assert(!info->supports_file_io && !info->supports_random
           && !info->supports_time);

    if (!lifecycle) {
#ifdef TWEP_WR_SGX_TEST_HOOKS
        if (strcmp(scenario, "protected-offline") == 0) {
            exercise_protected_offline();
            return 0;
        }
        if (strcmp(scenario, "dcap-evidence") == 0) {
            exercise_dcap_evidence();
            return 0;
        }
        if (strcmp(scenario, "transcript-commit") == 0) {
            exercise_transcript_commit();
            return 0;
        }
        if (strcmp(scenario, "agent-measurement") == 0) {
            exercise_agent_measurement();
            return 0;
        }
#endif
        if (strcmp(scenario, "execute-helloworld") == 0
            || strcmp(scenario, "teep-agent-resolve") == 0
            || strcmp(scenario, "app-hash-negative") == 0) {
            exercise_helloworld();
            return 0;
        }
        if (strcmp(scenario, "execute-calcadd") == 0) {
            exercise_calcadd();
            return 0;
        }
        if (strcmp(scenario, "execute-negaposi") == 0) {
            exercise_negaposi();
            return 0;
        }
        if (strcmp(scenario, "hostcall-negative") == 0) {
            exercise_hostcall_negative();
            return 0;
        }
        if (strcmp(scenario, "resource-limit-negative") == 0) {
            exercise_app_fixture_failure("infinite-loop.wasm",
                                         TWEP_WR_ERR_WASM_RUNTIME, 1, false);
            return 0;
        }
        if (strcmp(scenario, "output-limit-negative") == 0) {
            exercise_app_fixture_failure("oversized-output.wasm",
                                         TWEP_WR_ERR_WASM_RUNTIME, 0, true);
            return 0;
        }
        if (strcmp(scenario, "cleanup-negative") == 0) {
            exercise_cleanup_negative();
            return 0;
        }
        if (strcmp(scenario, "wasm-signature-negative") == 0) {
    exercise_wasm_signature_negative();
#ifdef TWEP_WR_SGX_TEST_HOOKS
    exercise_protected_offline();
#endif
            return 0;
        }
        fprintf(stderr, "unknown SGX backend-test scenario: %s\n", scenario);
        return 2;
    }

    char default_dir[TEMP_PATH_LEN];
    make_temp_dir(default_dir, "twep-sgx-default");
    prepare_artifacts(default_dir);
    char unavailable[1024];
    assert(snprintf(unavailable, sizeof(unavailable), "%s.unavailable",
                    TWEP_WR_SGX_ENCLAVE_PATH) > 0);
    assert(rename(TWEP_WR_SGX_ENCLAVE_PATH, unavailable) == 0);
    twep_wr_config_t config = {
        .state_dir = default_dir, .resolver_mode = "mock", .attestam_url = "",
        .max_request_bytes = 128, .max_response_bytes = 128,
    };
    twep_wr_context_t *failed_ctx = (twep_wr_context_t *)(uintptr_t)1;
    twep_wr_status_t failed_status = twep_wr_init(&config, &failed_ctx);
    assert(rename(unavailable, TWEP_WR_SGX_ENCLAVE_PATH) == 0);
    assert(failed_status == TWEP_WR_ERR_INIT && failed_ctx == NULL);
    twep_wr_context_t *ctx = init_at(default_dir); /* cleanup after load failure */
    twep_wr_shutdown(ctx);
    exercise_helloworld();
    exercise_calcadd();
    exercise_negaposi();
    return 0;
}
