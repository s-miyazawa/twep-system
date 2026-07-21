/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */
#include "trustzone_internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <twep_wr_ta.h>

static bool cbor_text_view_equals(bytes_view_t view, const char *text)
{
    size_t text_len = strlen(text);
    return view.len == text_len && memcmp(view.ptr, text, text_len) == 0;
}
static bool trustzone_measure_wasm(const uint8_t *wasm,
                                   size_t wasm_len,
                                   uint8_t out_sha256[SHA256_DIGEST_LENGTH])
{
    twep_tz_session_t session;
    twep_wr_platform_status_t status;
    TEEC_Operation op;
    TEEC_Result res;
    uint32_t origin = 0;

    if (wasm == NULL || wasm_len == 0 || out_sha256 == NULL) {
        return false;
    }
    status = twep_tz_open(&session);
    if (status != TWEP_WR_PLATFORM_OK) {
        return false;
    }
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = (void *)wasm;
    op.params[0].tmpref.size = wasm_len;
    op.params[1].tmpref.buffer = out_sha256;
    op.params[1].tmpref.size = SHA256_DIGEST_LENGTH;

    res = TEEC_InvokeCommand(&session.sess, TA_TWEP_WR_CMD_MEASURE_WASM,
                             &op, &origin);
    twep_tz_close(&session);
    return res == TEEC_SUCCESS &&
           op.params[1].tmpref.size == SHA256_DIGEST_LENGTH;
}

static const char *trustzone_protected_object_load_status(const char *object_name,
                                                          uint8_t **out,
                                                          size_t *out_len)
{
    twep_wr_platform_status_t status;

    if (out == NULL || out_len == NULL) {
        return "malformed";
    }
    *out = NULL;
    *out_len = 0;
    status = twep_wr_platform_sealed_read(NULL, object_name, out, out_len);
    if (status == TWEP_WR_PLATFORM_OK) {
        return "loaded-unbound";
    }
    return status == TWEP_WR_PLATFORM_ERR_IO ? "absent" : "malformed";
}

static bool cbor_map_uint_field(const uint8_t *buf, size_t len, const char *field, uint32_t *out)
{
    size_t off = 0;
    uint8_t major = 0;
    uint64_t pairs = 0;

    if (buf == NULL || field == NULL || out == NULL ||
        !twep_wr_cbor_read_head(buf, len, &off, &major, &pairs) || major != 5) {
        return false;
    }
    for (uint64_t i = 0; i < pairs; i++) {
        bytes_view_t key = {0};
        uint32_t value = 0;

        if (!twep_wr_cbor_read_text_view(buf, len, &off, &key)) {
            return false;
        }
        if (cbor_text_view_equals(key, field)) {
            if (!twep_wr_cbor_read_uint32(buf, len, &off, &value)) {
                return false;
            }
            *out = value;
            return true;
        }
        if (!twep_wr_cbor_skip_value(buf, len, &off)) {
            return false;
        }
    }
    return false;
}

static bool cbor_map_uint64_field(const uint8_t *buf, size_t len, const char *field, uint64_t *out)
{
    size_t off = 0;
    uint8_t major = 0;
    uint64_t pairs = 0;

    if (buf == NULL || field == NULL || out == NULL ||
        !twep_wr_cbor_read_head(buf, len, &off, &major, &pairs) || major != 5) {
        return false;
    }
    for (uint64_t i = 0; i < pairs; i++) {
        bytes_view_t key = {0};
        uint64_t value = 0;

        if (!twep_wr_cbor_read_text_view(buf, len, &off, &key)) {
            return false;
        }
        if (cbor_text_view_equals(key, field)) {
            if (!twep_wr_cbor_read_head(buf, len, &off, &major, &value) || major != 0) {
                return false;
            }
            *out = value;
            return true;
        }
        if (!twep_wr_cbor_skip_value(buf, len, &off)) {
            return false;
        }
    }
    return false;
}

static bool cbor_top_level_map_well_formed(const uint8_t *buf,
                                           size_t len,
                                           uint64_t *pairs_out)
{
    size_t off = 0;
    size_t verify_off = 0;
    uint8_t major = 0;
    uint64_t pairs = 0;

    if (buf == NULL || len == 0 ||
        !twep_wr_cbor_read_head(buf, len, &off, &major, &pairs) || major != 5 ||
        !twep_wr_cbor_skip_value(buf, len, &verify_off) || verify_off != len) {
        return false;
    }
    if (pairs_out != NULL) {
        *pairs_out = pairs;
    }
    return true;
}

static bool cbor_map_bool_field(const uint8_t *buf, size_t len, const char *field, bool *out);
static bool cbor_map_text_field_equals(const uint8_t *buf, size_t len,
                                       const char *field, const char *expected);
static bool cbor_map_bytes_field(const uint8_t *buf, size_t len,
                                 const char *field, bytes_view_t *out);
static bool cbor_map_optional_bool_field(const uint8_t *buf, size_t len,
                                         const char *field, bool *present, bool *out);
static bool cbor_map_optional_text_field(const uint8_t *buf, size_t len,
                                         const char *field, bool *present, bytes_view_t *out);
static bool cbor_map_optional_bytes_field(const uint8_t *buf, size_t len,
                                          const char *field, bool *present, bytes_view_t *out);

static bool cbor_read_array_len(const uint8_t *buf, size_t len, size_t *off, uint64_t *items)
{
    uint8_t major = 0;

    return twep_wr_cbor_read_head(buf, len, off, &major, items) && major == 4;
}

static bool cose_sign1_unprotected_kid(const uint8_t *buf, size_t len, bytes_view_t *kid)
{
    size_t off = 0;
    uint8_t major = 0;
    uint64_t value = 0;
    uint64_t items = 0;
    uint64_t pairs = 0;

    if (kid != NULL) {
        memset(kid, 0, sizeof(*kid));
    }
    if (buf == NULL || len == 0 || kid == NULL ||
        !twep_wr_cbor_read_head(buf, len, &off, &major, &value) ||
        major != 6 || value != 18 ||
        !cbor_read_array_len(buf, len, &off, &items) || items != 4 ||
        !twep_wr_cbor_skip_value(buf, len, &off) ||
        !twep_wr_cbor_read_head(buf, len, &off, &major, &pairs) ||
        major != 5) {
        return false;
    }
    for (uint64_t i = 0; i < pairs; i++) {
        uint8_t key_major = 0;
        uint64_t key_value = 0;

        if (!twep_wr_cbor_read_head(buf, len, &off, &key_major, &key_value)) {
            return false;
        }
        if (key_major == 0 && key_value == 4) {
            return twep_wr_cbor_read_bytes_view(buf, len, &off, kid) &&
                   kid->len != 0;
        }
        if (!twep_wr_cbor_skip_value(buf, len, &off)) {
            return false;
        }
    }
    return false;
}

static bool cbor_map_text_field(const uint8_t *buf, size_t len,
                                const char *field, bytes_view_t *out)
{
    size_t off = 0;
    uint8_t major = 0;
    uint64_t pairs = 0;

    if (buf == NULL || field == NULL || out == NULL ||
        !twep_wr_cbor_read_head(buf, len, &off, &major, &pairs) || major != 5) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    for (uint64_t i = 0; i < pairs; i++) {
        bytes_view_t key = {0};

        if (!twep_wr_cbor_read_text_view(buf, len, &off, &key)) {
            return false;
        }
        if (cbor_text_view_equals(key, field)) {
            return twep_wr_cbor_read_text_view(buf, len, &off, out);
        }
        if (!twep_wr_cbor_skip_value(buf, len, &off)) {
            return false;
        }
    }
    return false;
}

static bool cbor_map_bytes_array_valid(const uint8_t *buf, size_t len, const char *field)
{
    size_t off = 0;
    uint8_t major = 0;
    uint64_t pairs = 0;

    if (buf == NULL || field == NULL ||
        !twep_wr_cbor_read_head(buf, len, &off, &major, &pairs) || major != 5) {
        return false;
    }
    for (uint64_t i = 0; i < pairs; i++) {
        bytes_view_t key = {0};

        if (!twep_wr_cbor_read_text_view(buf, len, &off, &key)) {
            return false;
        }
        if (cbor_text_view_equals(key, field)) {
            uint64_t items = 0;
            if (!cbor_read_array_len(buf, len, &off, &items)) {
                return false;
            }
            for (uint64_t j = 0; j < items; j++) {
                bytes_view_t value = {0};
                if (!twep_wr_cbor_read_bytes_view(buf, len, &off, &value) || value.len == 0) {
                    return false;
                }
            }
            return true;
        }
        if (!twep_wr_cbor_skip_value(buf, len, &off)) {
            return false;
        }
    }
    return false;
}

static bool cbor_map_bytes_array_contains(const uint8_t *buf, size_t len,
                                          const char *field,
                                          const uint8_t *expected,
                                          size_t expected_len)
{
    size_t off = 0;
    uint8_t major = 0;
    uint64_t pairs = 0;

    if (buf == NULL || field == NULL || expected == NULL ||
        !twep_wr_cbor_read_head(buf, len, &off, &major, &pairs) || major != 5) {
        return false;
    }
    for (uint64_t i = 0; i < pairs; i++) {
        bytes_view_t key = {0};

        if (!twep_wr_cbor_read_text_view(buf, len, &off, &key)) {
            return false;
        }
        if (cbor_text_view_equals(key, field)) {
            uint64_t items = 0;
            if (!cbor_read_array_len(buf, len, &off, &items)) {
                return false;
            }
            for (uint64_t j = 0; j < items; j++) {
                bytes_view_t value = {0};
                if (!twep_wr_cbor_read_bytes_view(buf, len, &off, &value)) {
                    return false;
                }
                if (twep_tz_bytes_view_equals(value, expected, expected_len)) {
                    return true;
                }
            }
            return false;
        }
        if (!twep_wr_cbor_skip_value(buf, len, &off)) {
            return false;
        }
    }
    return false;
}

static bool validate_protected_public_key_credential(const uint8_t *buf,
                                                     size_t len,
                                                     const char *purpose,
                                                     const uint8_t *entry_id,
                                                     size_t entry_id_len,
                                                     bytes_view_t *issuer_id,
                                                     bytes_view_t *kid,
                                                     uint32_t *provisioning_epoch_out)
{
    uint32_t not_before = 0;
    uint32_t not_after = 0;
    uint32_t provisioning_epoch = 0;
    bytes_view_t entry = {0};
    bytes_view_t issuer = {0};
    bytes_view_t credential_kid = {0};
    bytes_view_t x = {0};
    bytes_view_t y = {0};

    if (!cbor_top_level_map_well_formed(buf, len, NULL) ||
        !cbor_map_bytes_field(buf, len, "entry_id", &entry) ||
        !cbor_map_bytes_field(buf, len, "issuer_id", &issuer) ||
        issuer.len == 0 ||
        !cbor_map_bytes_field(buf, len, "kid", &credential_kid) ||
        credential_kid.len == 0 ||
        !cbor_map_text_field_equals(buf, len, "purpose", purpose) ||
        !cbor_map_text_field_equals(buf, len, "alg", "ESP256") ||
        !cbor_map_text_field_equals(buf, len, "crv", "P-256") ||
        !cbor_map_uint_field(buf, len, "not_before", &not_before) ||
        !cbor_map_uint_field(buf, len, "not_after", &not_after) ||
        !cbor_map_uint_field(buf, len, "provisioning_epoch", &provisioning_epoch) ||
        !cbor_map_bytes_field(buf, len, "x", &x) ||
        x.len != SHA256_DIGEST_LENGTH ||
        !cbor_map_bytes_field(buf, len, "y", &y) ||
        y.len != SHA256_DIGEST_LENGTH ||
        not_before > not_after ||
        provisioning_epoch == 0) {
        return false;
    }
    if (entry_id != NULL && entry_id_len != 0u &&
        !twep_tz_bytes_view_equals(entry, entry_id, entry_id_len)) {
        return false;
    }
    if (issuer_id != NULL) {
        *issuer_id = issuer;
    }
    if (kid != NULL) {
        *kid = credential_kid;
    }
    if (provisioning_epoch_out != NULL) {
        *provisioning_epoch_out = provisioning_epoch;
    }
    return true;
}

typedef struct {
    uint32_t total_entries;
    uint32_t matched_entries;
    uint32_t selected_provisioning_epoch;
    bytes_view_t selected_issuer_id;
    bytes_view_t selected_kid;
} twep_wr_tz_credential_array_info_t;

static bool cbor_map_credential_array_valid(const uint8_t *buf,
                                            size_t len,
                                            const char *field,
                                            const char *purpose,
                                            const uint8_t *entry_id,
                                            size_t entry_id_len,
                                            twep_wr_tz_credential_array_info_t *out_info)
{
    size_t off = 0;
    uint8_t major = 0;
    uint64_t pairs = 0;
    bool found_match = false;

    if (out_info != NULL) {
        memset(out_info, 0, sizeof(*out_info));
    }

    if (buf == NULL || field == NULL ||
        !cbor_top_level_map_well_formed(buf, len, NULL) ||
        !twep_wr_cbor_read_head(buf, len, &off, &major, &pairs) || major != 5) {
        return false;
    }
    for (uint64_t i = 0; i < pairs; i++) {
        bytes_view_t key = {0};

        if (!twep_wr_cbor_read_text_view(buf, len, &off, &key)) {
            return false;
        }
        if (cbor_text_view_equals(key, field)) {
            uint64_t items = 0;

            if (!cbor_read_array_len(buf, len, &off, &items) || items == 0) {
                return false;
            }
            if (out_info != NULL) {
                out_info->total_entries = (uint32_t)items;
            }
            for (uint64_t j = 0; j < items; j++) {
                size_t entry_start = off;
                size_t entry_end = 0;
                bytes_view_t issuer_id = {0};
                bytes_view_t kid = {0};
                uint32_t provisioning_epoch = 0;
                bytes_view_t entry = {0};

                if (!twep_wr_cbor_skip_value(buf, len, &off)) {
                    return false;
                }
                entry_end = off;
                if (!validate_protected_public_key_credential(buf + entry_start,
                                                              entry_end - entry_start,
                                                              purpose,
                                                              NULL,
                                                              0,
                                                              &issuer_id,
                                                              &kid,
                                                              &provisioning_epoch)) {
                    return false;
                }
                if (!cbor_map_bytes_field(buf + entry_start, entry_end - entry_start,
                                          "entry_id", &entry)) {
                    return false;
                }
                if (!twep_tz_bytes_view_equals(entry, entry_id, entry_id_len)) {
                    continue;
                }
                found_match = true;
                if (out_info != NULL) {
                    out_info->matched_entries++;
                    if (out_info->selected_kid.ptr == NULL ||
                        provisioning_epoch >= out_info->selected_provisioning_epoch) {
                        out_info->selected_provisioning_epoch = provisioning_epoch;
                        out_info->selected_issuer_id = issuer_id;
                        out_info->selected_kid = kid;
                    }
                }
            }
            return found_match;
        }
        if (!twep_wr_cbor_skip_value(buf, len, &off)) {
            return false;
        }
    }
    return false;
}

static bool validate_protected_credential_store(const uint8_t *buf,
                                                size_t len,
                                                uint32_t *store_epoch,
                                                bytes_view_t *attestam_issuer_id,
                                                bytes_view_t *suit_issuer_id,
                                                bytes_view_t *attestam_kid,
                                                bytes_view_t *suit_kid,
                                                uint32_t *attestam_key_count,
                                                uint32_t *suit_key_count)
{
    static const uint8_t attestam_entry_id[] = {'t', 'a', 'm', '-', 'e', 'n', 't', 'r', 'y'};
    static const uint8_t suit_entry_id[] = {'s', 'u', 'i', 't', '-', 'e', 'n', 't', 'r', 'y'};
    uint32_t schema_version = 0;
    uint32_t epoch = 0;
    twep_wr_tz_credential_array_info_t attestam_info;
    twep_wr_tz_credential_array_info_t suit_info;

    memset(&attestam_info, 0, sizeof(attestam_info));
    memset(&suit_info, 0, sizeof(suit_info));
    if (!cbor_top_level_map_well_formed(buf, len, NULL) ||
        !cbor_map_uint_field(buf, len, "schema_version", &schema_version) ||
        schema_version != 1 ||
        !cbor_map_uint_field(buf, len, "store_epoch", &epoch) ||
        epoch == 0 ||
        !cbor_map_credential_array_valid(buf, len,
                                         "attestam_message_verification_keys",
                                         "attestam-message-verification",
                                         attestam_entry_id,
                                         sizeof(attestam_entry_id),
                                         &attestam_info) ||
        !cbor_map_credential_array_valid(buf, len,
                                         "suit_content_verification_keys",
                                         "suit-content-verification",
                                         suit_entry_id,
                                         sizeof(suit_entry_id),
                                         &suit_info)) {
        return false;
    }
    if (store_epoch != NULL) {
        *store_epoch = epoch;
    }
    if (attestam_issuer_id != NULL) {
        *attestam_issuer_id = attestam_info.selected_issuer_id;
    }
    if (suit_issuer_id != NULL) {
        *suit_issuer_id = suit_info.selected_issuer_id;
    }
    if (attestam_kid != NULL) {
        *attestam_kid = attestam_info.selected_kid;
    }
    if (suit_kid != NULL) {
        *suit_kid = suit_info.selected_kid;
    }
    if (attestam_key_count != NULL) {
        *attestam_key_count = attestam_info.total_entries;
    }
    if (suit_key_count != NULL) {
        *suit_key_count = suit_info.total_entries;
    }
    return true;
}

static bool validate_protected_issuer_allowlist(const uint8_t *buf,
                                                size_t len,
                                                bytes_view_t attestam_issuer_id,
                                                bytes_view_t suit_issuer_id,
                                                bool *issuer_match)
{
    uint32_t schema_version = 0;

    if (issuer_match != NULL) {
        *issuer_match = false;
    }
    if (!cbor_top_level_map_well_formed(buf, len, NULL) ||
        !cbor_map_uint_field(buf, len, "schema_version", &schema_version) ||
        schema_version != 1) {
        return false;
    }
    if (!cbor_map_bytes_array_valid(buf, len, "issuer_ids")) {
        return false;
    }
    if (attestam_issuer_id.ptr != NULL && suit_issuer_id.ptr != NULL &&
        issuer_match != NULL) {
        *issuer_match =
            cbor_map_bytes_array_contains(buf, len, "issuer_ids",
                                          attestam_issuer_id.ptr,
                                          attestam_issuer_id.len) &&
            cbor_map_bytes_array_contains(buf, len, "issuer_ids",
                                          suit_issuer_id.ptr,
                                          suit_issuer_id.len);
    }
    return true;
}

static bool validate_protected_store_freshness(const uint8_t *buf,
                                               size_t len,
                                               uint32_t *max_store_epoch)
{
    uint32_t schema_version = 0;

    return cbor_top_level_map_well_formed(buf, len, NULL) &&
           cbor_map_uint_field(buf, len, "schema_version", &schema_version) &&
           schema_version == 1 &&
           cbor_map_uint_field(buf, len, "max_store_epoch", max_store_epoch);
}

static bool validate_protected_revocation_state(const uint8_t *buf,
                                                size_t len,
                                                bool *attestam_revoked,
                                                bool *suit_revoked)
{
    static const uint8_t attestam_entry_id[] = {'t', 'a', 'm', '-', 'e', 'n', 't', 'r', 'y'};
    static const uint8_t suit_entry_id[] = {'s', 'u', 'i', 't', '-', 'e', 'n', 't', 'r', 'y'};
    uint32_t schema_version = 0;

    if (!cbor_top_level_map_well_formed(buf, len, NULL) ||
        !cbor_map_uint_field(buf, len, "schema_version", &schema_version) ||
        schema_version != 1) {
        return false;
    }
    if (!cbor_map_bytes_array_valid(buf, len, "revoked_entry_ids")) {
        return false;
    }
    if (attestam_revoked != NULL) {
        *attestam_revoked = cbor_map_bytes_array_contains(buf, len, "revoked_entry_ids",
                                                          attestam_entry_id, sizeof(attestam_entry_id));
    }
    if (suit_revoked != NULL) {
        *suit_revoked = cbor_map_bytes_array_contains(buf, len, "revoked_entry_ids",
                                                      suit_entry_id, sizeof(suit_entry_id));
    }
    return true;
}

static bool validate_verified_evidence_result(const uint8_t *buf,
                                              size_t len,
                                              const char **verifier_result,
                                              const char **decision_source,
                                              bool *nonce_match,
                                              bool *cnf_key_match,
                                              bool *platform_match,
                                              bool *tam_response_verified,
                                              bool *challenge_response_bound,
                                              bool *acceptance_generation_present,
                                              uint64_t *acceptance_generation)
{
    uint32_t schema_version = 0;
    uint64_t parsed_acceptance_generation = 0;

    if (verifier_result != NULL) {
        *verifier_result = "none";
    }
    if (decision_source != NULL) {
        *decision_source = "none";
    }
    if (nonce_match != NULL) {
        *nonce_match = false;
    }
    if (cnf_key_match != NULL) {
        *cnf_key_match = false;
    }
    if (platform_match != NULL) {
        *platform_match = false;
    }
    if (tam_response_verified != NULL) {
        *tam_response_verified = false;
    }
    if (challenge_response_bound != NULL) {
        *challenge_response_bound = false;
    }
    if (acceptance_generation_present != NULL) {
        *acceptance_generation_present = false;
    }
    if (acceptance_generation != NULL) {
        *acceptance_generation = 0;
    }
    if (!cbor_top_level_map_well_formed(buf, len, NULL) ||
        !cbor_map_uint_field(buf, len, "schema_version", &schema_version) ||
        (schema_version != 1 && schema_version != 2)) {
        return false;
    }
    if (schema_version == 2) {
        if (!cbor_map_text_field_equals(buf, len, "decision_source", "attestam-signed-update") ||
            !cbor_map_bool_field(buf, len, "tam_response_verified", tam_response_verified) ||
            !cbor_map_bool_field(buf, len, "challenge_response_bound", challenge_response_bound) ||
            !cbor_map_uint64_field(buf, len, "acceptance_generation", &parsed_acceptance_generation)) {
            return false;
        }
        if (decision_source != NULL) {
            *decision_source = "attestam-signed-update";
        }
        if (acceptance_generation_present != NULL) {
            *acceptance_generation_present = true;
        }
        if (acceptance_generation != NULL) {
            *acceptance_generation = parsed_acceptance_generation;
        }
        return true;
    }
    if (decision_source != NULL) {
        *decision_source = "legacy-direct-result";
    }
    if (cbor_map_text_field_equals(buf, len, "verifier_result", "affirming")) {
        if (verifier_result != NULL) {
            *verifier_result = "affirming";
        }
    } else if (cbor_map_text_field_equals(buf, len, "verifier_result", "contraindicated")) {
        if (verifier_result != NULL) {
            *verifier_result = "contraindicated";
        }
    } else if (cbor_map_text_field_equals(buf, len, "verifier_result", "warning")) {
        if (verifier_result != NULL) {
            *verifier_result = "warning";
        }
    } else if (!cbor_map_text_field_equals(buf, len, "verifier_result", "none")) {
        return false;
    }
    return cbor_map_optional_bool_field(buf, len, "nonce_match", NULL, nonce_match) &&
           cbor_map_optional_bool_field(buf, len, "cnf_key_match", NULL, cnf_key_match) &&
           cbor_map_optional_bool_field(buf, len, "platform_match", NULL, platform_match);
}

static bool trustzone_acceptance_slot_generation(const char *object_name,
                                                 uint64_t *generation)
{
    uint8_t *slot = NULL;
    size_t slot_len = 0;
    const char *load_status;
    uint32_t schema_version = 0;
    uint64_t parsed_generation = 0;

    if (object_name == NULL || generation == NULL) {
        return false;
    }
    load_status = trustzone_protected_object_load_status(object_name, &slot, &slot_len);
    if (strcmp(load_status, "loaded-unbound") != 0) {
        free(slot);
        return false;
    }
    if (!cbor_top_level_map_well_formed(slot, slot_len, NULL) ||
        !cbor_map_uint_field(slot, slot_len, "schema_version", &schema_version) ||
        schema_version != 1 ||
        !cbor_map_uint64_field(slot, slot_len, "generation", &parsed_generation)) {
        free(slot);
        return false;
    }
    free(slot);
    if (parsed_generation == 0) {
        return false;
    }
    *generation = parsed_generation;
    return true;
}

static bool trustzone_acceptance_slot_generation_bytes(const uint8_t *slot,
                                                       size_t slot_len,
                                                       uint64_t *generation)
{
    uint32_t schema_version = 0;
    uint64_t parsed_generation = 0;

    if (slot == NULL || slot_len == 0u || generation == NULL ||
        !cbor_top_level_map_well_formed(slot, slot_len, NULL) ||
        !cbor_map_uint_field(slot, slot_len, "schema_version", &schema_version) ||
        schema_version != 1 ||
        !cbor_map_uint64_field(slot, slot_len, "generation", &parsed_generation) ||
        parsed_generation == 0u) {
        return false;
    }
    *generation = parsed_generation;
    return true;
}

static bool trustzone_acceptance_generation(uint64_t *generation)
{
    uint64_t slot_generation = 0;
    bool found = false;

    if (generation == NULL) {
        return false;
    }
    *generation = 0;
    if (trustzone_acceptance_slot_generation("teep-acceptance-state.0.cbor", &slot_generation)) {
        *generation = slot_generation;
        found = true;
    }
    if (trustzone_acceptance_slot_generation("teep-acceptance-state.1.cbor", &slot_generation) &&
        (!found || slot_generation > *generation)) {
        *generation = slot_generation;
        found = true;
    }
    return found;
}

static bool validate_protected_agent_identity(const uint8_t *buf,
                                              size_t len,
                                              bool *backend_match,
                                              bool *runtime_match,
                                              bool *teep_agent_match,
                                              bytes_view_t *measurement)
{
    uint32_t schema_version = 0;
    bool runtime_location_present = false;
    bool teep_agent_location_present = false;
    bool measurement_present = false;
    bytes_view_t platform_backend = {0};
    bytes_view_t runtime_location = {0};
    bytes_view_t teep_agent_location = {0};
    bytes_view_t measurement_sha256 = {0};

    if (backend_match != NULL) {
        *backend_match = false;
    }
    if (runtime_match != NULL) {
        *runtime_match = false;
    }
    if (teep_agent_match != NULL) {
        *teep_agent_match = false;
    }
    if (measurement != NULL) {
        memset(measurement, 0, sizeof(*measurement));
    }
    if (!cbor_top_level_map_well_formed(buf, len, NULL) ||
        !cbor_map_uint_field(buf, len, "schema_version", &schema_version) ||
        schema_version != 1 ||
        !cbor_map_text_field(buf, len, "platform_backend", &platform_backend) ||
        !cbor_map_optional_text_field(buf, len, "runtime_location",
                                      &runtime_location_present, &runtime_location) ||
        !cbor_map_optional_text_field(buf, len, "teep_agent_location",
                                      &teep_agent_location_present, &teep_agent_location) ||
        !cbor_map_optional_bytes_field(buf, len, "measurement_sha256",
                                       &measurement_present, &measurement_sha256) ||
        (measurement_present && measurement_sha256.len != SHA256_DIGEST_LENGTH)) {
        return false;
    }
    if (backend_match != NULL) {
        *backend_match = cbor_text_view_equals(platform_backend, "trustzone");
    }
    if (runtime_match != NULL && runtime_location_present) {
        *runtime_match = cbor_text_view_equals(runtime_location, "trustzone-ta");
    }
    if (teep_agent_match != NULL && teep_agent_location_present) {
        *teep_agent_match = cbor_text_view_equals(teep_agent_location, "trustzone-ta");
    }
    if (measurement != NULL && measurement_present) {
        *measurement = measurement_sha256;
    }
    return true;
}

static bool cbor_map_bool_field(const uint8_t *buf, size_t len, const char *field, bool *out)
{
    size_t off = 0;
    uint8_t major = 0;
    uint64_t pairs = 0;

    if (buf == NULL || field == NULL || out == NULL ||
        !twep_wr_cbor_read_head(buf, len, &off, &major, &pairs) || major != 5) {
        return false;
    }
    for (uint64_t i = 0; i < pairs; i++) {
        bytes_view_t key = {0};
        uint8_t value_major = 0;
        uint64_t value = 0;

        if (!twep_wr_cbor_read_text_view(buf, len, &off, &key)) {
            return false;
        }
        if (cbor_text_view_equals(key, field)) {
            if (!twep_wr_cbor_read_head(buf, len, &off, &value_major, &value) ||
                value_major != 7 || (value != 20u && value != 21u)) {
                return false;
            }
            *out = value == 21u;
            return true;
        }
        if (!twep_wr_cbor_skip_value(buf, len, &off)) {
            return false;
        }
    }
    return false;
}

static bool cbor_map_optional_bool_field(const uint8_t *buf, size_t len,
                                         const char *field, bool *present, bool *out)
{
    size_t off = 0;
    uint8_t major = 0;
    uint64_t pairs = 0;

    if (present != NULL) {
        *present = false;
    }
    if (out != NULL) {
        *out = false;
    }
    if (buf == NULL || field == NULL || out == NULL ||
        !twep_wr_cbor_read_head(buf, len, &off, &major, &pairs) || major != 5) {
        return false;
    }
    for (uint64_t i = 0; i < pairs; i++) {
        bytes_view_t key = {0};
        uint8_t value_major = 0;
        uint64_t value = 0;

        if (!twep_wr_cbor_read_text_view(buf, len, &off, &key)) {
            return false;
        }
        if (cbor_text_view_equals(key, field)) {
            if (!twep_wr_cbor_read_head(buf, len, &off, &value_major, &value) ||
                value_major != 7 || (value != 20u && value != 21u)) {
                return false;
            }
            if (present != NULL) {
                *present = true;
            }
            *out = value == 21u;
            return true;
        }
        if (!twep_wr_cbor_skip_value(buf, len, &off)) {
            return false;
        }
    }
    return true;
}

static bool cbor_map_text_field_equals(const uint8_t *buf, size_t len,
                                       const char *field, const char *expected)
{
    size_t off = 0;
    uint8_t major = 0;
    uint64_t pairs = 0;

    if (buf == NULL || field == NULL || expected == NULL ||
        !twep_wr_cbor_read_head(buf, len, &off, &major, &pairs) || major != 5) {
        return false;
    }
    for (uint64_t i = 0; i < pairs; i++) {
        bytes_view_t key = {0};
        bytes_view_t value = {0};

        if (!twep_wr_cbor_read_text_view(buf, len, &off, &key)) {
            return false;
        }
        if (cbor_text_view_equals(key, field)) {
            return twep_wr_cbor_read_text_view(buf, len, &off, &value) &&
                   cbor_text_view_equals(value, expected);
        }
        if (!twep_wr_cbor_skip_value(buf, len, &off)) {
            return false;
        }
    }
    return false;
}

static bool cbor_map_bytes_field(const uint8_t *buf, size_t len,
                                 const char *field, bytes_view_t *out)
{
    size_t off = 0;
    uint8_t major = 0;
    uint64_t pairs = 0;

    if (buf == NULL || field == NULL || out == NULL ||
        !twep_wr_cbor_read_head(buf, len, &off, &major, &pairs) || major != 5) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    for (uint64_t i = 0; i < pairs; i++) {
        bytes_view_t key = {0};

        if (!twep_wr_cbor_read_text_view(buf, len, &off, &key)) {
            return false;
        }
        if (cbor_text_view_equals(key, field)) {
            return twep_wr_cbor_read_bytes_view(buf, len, &off, out);
        }
        if (!twep_wr_cbor_skip_value(buf, len, &off)) {
            return false;
        }
    }
    return false;
}

static bool cbor_map_optional_text_field(const uint8_t *buf, size_t len,
                                         const char *field, bool *present, bytes_view_t *out)
{
    size_t off = 0;
    uint8_t major = 0;
    uint64_t pairs = 0;

    if (present != NULL) {
        *present = false;
    }
    if (buf == NULL || field == NULL || out == NULL ||
        !twep_wr_cbor_read_head(buf, len, &off, &major, &pairs) || major != 5) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    for (uint64_t i = 0; i < pairs; i++) {
        bytes_view_t key = {0};

        if (!twep_wr_cbor_read_text_view(buf, len, &off, &key)) {
            return false;
        }
        if (cbor_text_view_equals(key, field)) {
            if (!twep_wr_cbor_read_text_view(buf, len, &off, out)) {
                return false;
            }
            if (present != NULL) {
                *present = true;
            }
            return true;
        }
        if (!twep_wr_cbor_skip_value(buf, len, &off)) {
            return false;
        }
    }
    return true;
}

static bool cbor_map_optional_bytes_field(const uint8_t *buf, size_t len,
                                          const char *field, bool *present, bytes_view_t *out)
{
    size_t off = 0;
    uint8_t major = 0;
    uint64_t pairs = 0;

    if (present != NULL) {
        *present = false;
    }
    if (buf == NULL || field == NULL || out == NULL ||
        !twep_wr_cbor_read_head(buf, len, &off, &major, &pairs) || major != 5) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    for (uint64_t i = 0; i < pairs; i++) {
        bytes_view_t key = {0};

        if (!twep_wr_cbor_read_text_view(buf, len, &off, &key)) {
            return false;
        }
        if (cbor_text_view_equals(key, field)) {
            if (!twep_wr_cbor_read_bytes_view(buf, len, &off, out)) {
                return false;
            }
            if (present != NULL) {
                *present = true;
            }
            return true;
        }
        if (!twep_wr_cbor_skip_value(buf, len, &off)) {
            return false;
        }
    }
    return true;
}

void twep_tz_write_verified_diagnostics(const twep_wr_context_t *ctx)
{
    static const uint8_t platform_status[] =
        "platform-backend=trustzone\n"
        "runtime-location=trustzone-ta\n"
        "teep-agent-location=trustzone-ta\n"
        "catalog-resolution-location=trustzone-ta\n"
        "sealed-storage-security=tee-ree-fs-secure-storage\n"
        "sealed-storage-rollback-protected=false\n"
        "protected-storage-supported=true\n"
        "file-io=false\n"
        "random=true\n"
        "time=true\n";
    uint8_t *protected_store = NULL;
    uint8_t *issuer_allowlist = NULL;
    uint8_t *store_freshness = NULL;
    uint8_t *revocation_state = NULL;
    uint8_t *agent_identity = NULL;
    uint8_t *evidence_result = NULL;
    uint8_t *verified_input = NULL;
    size_t protected_store_len = 0;
    size_t issuer_allowlist_len = 0;
    size_t store_freshness_len = 0;
    size_t revocation_state_len = 0;
    size_t agent_identity_len = 0;
    size_t evidence_result_len = 0;
    size_t verified_input_len = 0;
    const char *protected_store_load;
    const char *issuer_allowlist_load;
    const char *store_freshness_load;
    const char *revocation_state_load;
    const char *agent_identity_load;
    const char *evidence_result_load;
    const char *evidence_verifier_result = "none";
    const char *evidence_decision_source = "none";
    const char *evidence_source = "none";
    const char *evidence_binding = "unbound";
    bool has_verified_input = false;
    bool evidence_nonce_match = false;
    bool evidence_cnf_key_match = false;
    bool evidence_platform_match = false;
    bool evidence_tam_response_verified = false;
    bool evidence_challenge_response_bound = false;
    bool evidence_acceptance_generation_present = false;
    bool evidence_acceptance_generation_current = false;
    uint64_t evidence_acceptance_generation = 0;
    uint64_t current_acceptance_generation = 0;
    bool evidence_affirming = false;
    bool issuer_allowlist_match = false;
    bool protected_store_kid_match = false;
    bool protected_store_epoch_fresh = false;
    bool protected_credentials_not_revoked = false;
    bool protected_store_bound = false;
    bool issuer_allowlist_bound = false;
    bool store_freshness_bound = false;
    bool revocation_state_bound = false;
    bool trust_anchor_bound = false;
    bool agent_identity_backend_match = false;
    bool agent_identity_runtime_match = false;
    bool agent_identity_teep_agent_match = false;
    const char *agent_identity_measurement = "absent";
    const char *agent_identity_measurement_source = "none";
    bool agent_identity_bound = false;
    bytes_view_t expected_agent_measurement = {0};
    bytes_view_t protected_store_issuer_id = {0};
    bytes_view_t protected_store_suit_issuer_id = {0};
    bytes_view_t protected_store_attestam_kid = {0};
    bytes_view_t protected_store_suit_kid = {0};
    bytes_view_t observed_attestam_kid = {0};
    bool attestam_revoked = false;
    bool suit_revoked = false;
    bool fixture_verified = false;
    bool trust_anchor_ready = false;
    bool final_verified = false;
    const char *missing_step = "teep.cose_outer_unverified";
    const char *final_missing_step = "teep.cose_outer_unverified";
    uint8_t *teep_agent_wasm = NULL;
    size_t teep_agent_wasm_len = 0;
    uint8_t teep_agent_wasm_sha256[SHA256_DIGEST_LENGTH] = {0};
    const char *agent_identity_binding = "unbound";
    uint32_t store_epoch = 0;
    uint32_t max_store_epoch = 0;
    uint32_t protected_store_attestam_key_count = 0;
    uint32_t protected_store_suit_key_count = 0;
    char verified_state[512];
    char credential_status[2048];
    char evidence_status[768];
    char agent_identity_status[1024];
    char path[TWEP_WR_MAX_PATH_LEN];

    if (ctx == NULL || ctx->resolver_mode == NULL ||
        strcmp(ctx->resolver_mode, "attestam-verified") != 0) {
        return;
    }
    protected_store_load = trustzone_protected_object_load_status("protected-credential-store.cbor",
                                                                  &protected_store,
                                                                  &protected_store_len);
    issuer_allowlist_load = trustzone_protected_object_load_status("protected-issuer-allowlist.cbor",
                                                                   &issuer_allowlist,
                                                                   &issuer_allowlist_len);
    store_freshness_load = trustzone_protected_object_load_status("protected-store-freshness.cbor",
                                                                  &store_freshness,
                                                                  &store_freshness_len);
    revocation_state_load = trustzone_protected_object_load_status("protected-revocation-state.cbor",
                                                                   &revocation_state,
                                                                   &revocation_state_len);
    agent_identity_load = trustzone_protected_object_load_status("protected-agent-identity.cbor",
                                                                 &agent_identity,
                                                                 &agent_identity_len);
    evidence_result_load = trustzone_protected_object_load_status("verified-evidence-result.cbor",
                                                                  &evidence_result,
                                                                  &evidence_result_len);
    if (twep_wr_state_path(ctx, "teep-agent", "verified-input.cose", path, sizeof(path))) {
        has_verified_input = twep_wr_file_exists(path);
        if (has_verified_input) {
            verified_input = twep_wr_read_file(path, &verified_input_len);
            if (verified_input == NULL ||
                !cose_sign1_unprotected_kid(verified_input, verified_input_len,
                                            &observed_attestam_kid)) {
                memset(&observed_attestam_kid, 0, sizeof(observed_attestam_kid));
            }
        }
    }
    if (strcmp(protected_store_load, "loaded-unbound") == 0 &&
        !validate_protected_credential_store(protected_store, protected_store_len,
                                             &store_epoch,
                                             &protected_store_issuer_id,
                                             &protected_store_suit_issuer_id,
                                             &protected_store_attestam_kid,
                                             &protected_store_suit_kid,
                                             &protected_store_attestam_key_count,
                                             &protected_store_suit_key_count)) {
        protected_store_load = "malformed";
    }
    if (strcmp(issuer_allowlist_load, "loaded-unbound") == 0 &&
        !validate_protected_issuer_allowlist(issuer_allowlist, issuer_allowlist_len,
                                             protected_store_issuer_id,
                                             protected_store_suit_issuer_id,
                                             &issuer_allowlist_match)) {
        issuer_allowlist_load = "malformed";
        issuer_allowlist_match = false;
    }
    if (strcmp(store_freshness_load, "loaded-unbound") == 0 &&
        !validate_protected_store_freshness(store_freshness, store_freshness_len,
                                            &max_store_epoch)) {
        store_freshness_load = "malformed";
    }
    if (strcmp(revocation_state_load, "loaded-unbound") == 0 &&
        !validate_protected_revocation_state(revocation_state, revocation_state_len,
                                             &attestam_revoked, &suit_revoked)) {
        revocation_state_load = "malformed";
    }
    if (strcmp(evidence_result_load, "loaded-unbound") == 0 &&
        !validate_verified_evidence_result(evidence_result, evidence_result_len,
                                           &evidence_verifier_result,
                                           &evidence_decision_source,
                                           &evidence_nonce_match,
                                           &evidence_cnf_key_match,
                                           &evidence_platform_match,
                                           &evidence_tam_response_verified,
                                           &evidence_challenge_response_bound,
                                           &evidence_acceptance_generation_present,
                                           &evidence_acceptance_generation)) {
        evidence_result_load = "malformed";
        evidence_verifier_result = "none";
        evidence_decision_source = "none";
        evidence_nonce_match = false;
        evidence_cnf_key_match = false;
        evidence_platform_match = false;
        evidence_tam_response_verified = false;
        evidence_challenge_response_bound = false;
        evidence_acceptance_generation_present = false;
        evidence_acceptance_generation_current = false;
        evidence_acceptance_generation = 0;
    }
    if (strcmp(agent_identity_load, "loaded-unbound") == 0 &&
        !validate_protected_agent_identity(agent_identity, agent_identity_len,
                                           &agent_identity_backend_match,
                                           &agent_identity_runtime_match,
                                           &agent_identity_teep_agent_match,
                                           &expected_agent_measurement)) {
        agent_identity_load = "malformed";
        agent_identity_backend_match = false;
        agent_identity_runtime_match = false;
        agent_identity_teep_agent_match = false;
        memset(&expected_agent_measurement, 0, sizeof(expected_agent_measurement));
    }
    if (strcmp(evidence_result_load, "loaded-unbound") == 0) {
        evidence_source = "verified-evidence-result";
        if (evidence_acceptance_generation_present &&
            trustzone_acceptance_generation(&current_acceptance_generation)) {
            evidence_acceptance_generation_current =
                evidence_acceptance_generation == current_acceptance_generation;
        }
        if (strcmp(evidence_verifier_result, "affirming") == 0 &&
            evidence_nonce_match &&
            evidence_cnf_key_match &&
            evidence_platform_match) {
            evidence_binding = "matched-unbound";
        }
        if (strcmp(evidence_decision_source, "attestam-signed-update") == 0 &&
            evidence_tam_response_verified &&
            evidence_challenge_response_bound &&
            evidence_acceptance_generation_current) {
            evidence_binding = "bound";
            evidence_affirming = true;
        }
    }
    if (has_verified_input &&
        observed_attestam_kid.ptr != NULL &&
        observed_attestam_kid.len != 0u &&
        protected_store_attestam_kid.ptr != NULL &&
        protected_store_attestam_kid.len != 0u &&
        protected_store_suit_kid.ptr != NULL &&
        protected_store_suit_kid.len != 0u) {
        protected_store_kid_match = twep_tz_bytes_view_equals(protected_store_attestam_kid,
                                                            observed_attestam_kid.ptr,
                                                            observed_attestam_kid.len);
    }
    protected_store_epoch_fresh =
        strcmp(protected_store_load, "loaded-unbound") == 0 &&
        strcmp(store_freshness_load, "loaded-unbound") == 0 &&
        store_epoch >= max_store_epoch;
    protected_credentials_not_revoked =
        strcmp(protected_store_load, "loaded-unbound") == 0 &&
        strcmp(revocation_state_load, "loaded-unbound") == 0 &&
        !attestam_revoked &&
        !suit_revoked;
    protected_store_bound =
        has_verified_input &&
        strcmp(protected_store_load, "loaded-unbound") == 0 &&
        protected_store_kid_match;
    issuer_allowlist_bound =
        protected_store_bound &&
        strcmp(issuer_allowlist_load, "loaded-unbound") == 0 &&
        issuer_allowlist_match;
    store_freshness_bound = protected_store_bound && protected_store_epoch_fresh;
    revocation_state_bound = protected_store_bound && protected_credentials_not_revoked;
    /*
     * The individual credential/policy checks can be bound independently, but
     * trust-anchor-bound is a final-boundary claim. This diagnostic path still
     * has unverified COSE/SUIT/session fixture steps, so keep the aggregate
     * trust anchor blocked until fixture verification is wired into the TA path.
     */
    trust_anchor_bound = false;
    if (strcmp(agent_identity_load, "loaded-unbound") == 0) {
        if (expected_agent_measurement.len == SHA256_DIGEST_LENGTH) {
            agent_identity_measurement = "mismatch";
            agent_identity_measurement_source = "trustzone-ta-measure-wasm";
            if (twep_tz_read_teep_agent_wasm(ctx, &teep_agent_wasm, &teep_agent_wasm_len) == TWEP_WR_OK) {
                if (!trustzone_measure_wasm(teep_agent_wasm, teep_agent_wasm_len,
                                            teep_agent_wasm_sha256)) {
                    agent_identity_measurement_source = "trustzone-ta-measure-unavailable";
                } else if (memcmp(teep_agent_wasm_sha256, expected_agent_measurement.ptr,
                                  SHA256_DIGEST_LENGTH) == 0) {
                    agent_identity_measurement = "matched";
                }
            } else {
                agent_identity_measurement_source = "trustzone-ta-measure-unavailable";
            }
        }
    }
    if (agent_identity_backend_match &&
        agent_identity_runtime_match &&
        agent_identity_teep_agent_match) {
        agent_identity_bound = strcmp(agent_identity_measurement, "matched") == 0;
        agent_identity_binding = agent_identity_bound ? "bound" : "matched-unbound";
    }
    trust_anchor_ready =
        fixture_verified &&
        protected_store_bound &&
        issuer_allowlist_bound &&
        store_freshness_bound &&
        revocation_state_bound &&
        evidence_affirming &&
        agent_identity_bound;
    trust_anchor_bound = trust_anchor_ready;
    final_verified = trust_anchor_bound;
    if (fixture_verified) {
        missing_step = "none";
        final_missing_step = final_verified ? "none" : "teep.trust_anchor_unbound";
    }

    (void)snprintf(verified_state, sizeof(verified_state),
                   "cose-outer-verified=false\n"
                   "session-token-bound=false\n"
                   "suit-auth-verified=false\n"
                   "sequence-fresh=false\n"
                   "evidence-affirming=%s\n"
                   "agent-identity-bound=%s\n"
                   "fixture-verified=false\n"
                   "trust-anchor-bound=%s\n"
                   "final-verified=%s\n"
                   "missing-step=%s\n"
                   "final-missing-step=%s\n",
                   twep_wr_bool_label(evidence_affirming),
                   twep_wr_bool_label(agent_identity_bound),
                   twep_wr_bool_label(trust_anchor_bound),
                   twep_wr_bool_label(final_verified),
                   missing_step,
                   final_missing_step);
    (void)snprintf(credential_status, sizeof(credential_status),
                   "credential-model-ready=true\n"
                   "verified-teep-required-credentials=2\n"
                   "attestam-message-verification-key=unbound\n"
                   "suit-content-verification-key=unbound\n"
                   "attestam-message-verification-key-binding=%s\n"
                   "observed-attestam-kid=%s\n"
                   "trust-anchor-load=absent\n"
                   "protected-credential-store-load=%s\n"
                   "protected-credential-store-attestam-message-verification-keys=%d\n"
                   "protected-credential-store-suit-content-verification-keys=%d\n"
                   "protected-credential-store-attestam-key-binding=%s\n"
                   "protected-credential-store-issuer-binding=%s\n"
                   "protected-credential-store-issuer-allowlist-match=%s\n"
                   "protected-credential-store-rotation-policy=%s\n"
                   "protected-credential-store-revocation-status=%s\n"
                   "protected-revocation-state-match=%s\n"
                   "protected-credential-store-freshness=%s\n"
                   "protected-store-freshness-epoch-match=%s\n"
                   "platform-issuer-allowlist-load=%s\n"
                   "platform-store-freshness-load=%s\n"
                   "platform-revocation-state-load=%s\n"
                   "protected-storage-binding=tee-ree-fs-secure-storage\n"
                   "protected-credential-store-bound=%s\n"
                   "issuer-allowlist-bound=%s\n"
                   "store-freshness-bound=%s\n"
                   "revocation-state-bound=%s\n"
                   "trust-anchor-bound=%s\n",
                   has_verified_input ? "observed-kid-unbound" : "no-kid",
                   has_verified_input ? "present" : "none",
                   protected_store_load,
                   protected_store_attestam_key_count,
                   protected_store_suit_key_count,
                   has_verified_input
                       ? (protected_store_bound ? "observed-kid-entry-protected-storage-bound"
                                                : "observed-kid-unbound")
                       : "no-kid",
                   issuer_allowlist_bound ? "bound" : "unverified",
                   twep_wr_bool_label(issuer_allowlist_match),
                   store_freshness_bound
                       ? "bound"
                       : (protected_store_epoch_fresh ? "matched-unbound" : "unverified"),
                   revocation_state_bound
                       ? "bound"
                       : (protected_credentials_not_revoked ? "matched-unbound" : "unverified"),
                   twep_wr_bool_label(protected_credentials_not_revoked),
                   store_freshness_bound
                       ? "bound"
                       : (protected_store_epoch_fresh ? "matched-unbound" : "unverified"),
                   twep_wr_bool_label(protected_store_epoch_fresh),
                   issuer_allowlist_load,
                   store_freshness_load,
                   revocation_state_load,
                   twep_wr_bool_label(protected_store_bound),
                   twep_wr_bool_label(issuer_allowlist_bound),
                   twep_wr_bool_label(store_freshness_bound),
                   twep_wr_bool_label(revocation_state_bound),
                   twep_wr_bool_label(trust_anchor_bound));
    (void)snprintf(evidence_status, sizeof(evidence_status),
                   "evidence-model-ready=true\n"
                   "evidence-source=%s\n"
                   "evidence-result-load=%s\n"
                   "evidence-verifier-result=%s\n"
                   "evidence-decision-source=%s\n"
                   "evidence-nonce-match=%s\n"
                   "evidence-cnf-key-match=%s\n"
                   "evidence-platform-match=%s\n"
                   "evidence-tam-response-verified=%s\n"
                   "evidence-challenge-response-bound=%s\n"
                   "evidence-acceptance-generation-current=%s\n"
                   "evidence-binding=%s\n"
                   "evidence-affirming=%s\n",
                   evidence_source,
                   evidence_result_load,
                   evidence_verifier_result,
                   evidence_decision_source,
                   twep_wr_bool_label(evidence_nonce_match),
                   twep_wr_bool_label(evidence_cnf_key_match),
                   twep_wr_bool_label(evidence_platform_match),
                   twep_wr_bool_label(evidence_tam_response_verified),
                   twep_wr_bool_label(evidence_challenge_response_bound),
                   twep_wr_bool_label(evidence_acceptance_generation_present &&
                                      evidence_acceptance_generation_current),
                   evidence_binding,
                   twep_wr_bool_label(evidence_affirming));
    (void)snprintf(agent_identity_status, sizeof(agent_identity_status),
                   "agent-identity-model-ready=true\n"
                   "platform-backend=trustzone\n"
                   "runtime-location=trustzone-ta\n"
                   "teep-agent-location=trustzone-ta\n"
                   "sealed-storage-rollback-protected=false\n"
                   "agent-identity-source=platform-status-ta-local\n"
                   "agent-identity-observed=true\n"
                   "protected-agent-identity-load=%s\n"
                   "protected-agent-identity-backend-match=%s\n"
                   "protected-agent-identity-runtime-match=%s\n"
                   "protected-agent-identity-teep-agent-match=%s\n"
                   "protected-agent-identity-measurement=%s\n"
                   "protected-agent-identity-measurement-source=%s\n"
                   "agent-identity-binding=%s\n"
                   "agent-identity-bound=%s\n",
                   agent_identity_load,
                   twep_wr_bool_label(agent_identity_backend_match),
                   twep_wr_bool_label(agent_identity_runtime_match),
                   twep_wr_bool_label(agent_identity_teep_agent_match),
                   agent_identity_measurement,
                   agent_identity_measurement_source,
                   agent_identity_binding,
                   twep_wr_bool_label(agent_identity_bound));
    if (twep_wr_state_path(ctx, "teep-agent", "verified-state.txt", path, sizeof(path))) {
        (void)twep_wr_platform_write_file_atomic(path, (const uint8_t *)verified_state, strlen(verified_state));
    }
    if (twep_wr_state_path(ctx, "teep-agent", "credential-status.txt", path, sizeof(path))) {
        (void)twep_wr_platform_write_file_atomic(path, (const uint8_t *)credential_status, strlen(credential_status));
    }
    if (twep_wr_state_path(ctx, "teep-agent", "platform-status.txt", path, sizeof(path))) {
        (void)twep_wr_platform_write_file_atomic(path, platform_status, sizeof(platform_status) - 1);
    }
    if (twep_wr_state_path(ctx, "teep-agent", "evidence-status.txt", path, sizeof(path))) {
        (void)twep_wr_platform_write_file_atomic(path, (const uint8_t *)evidence_status, strlen(evidence_status));
    }
    if (twep_wr_state_path(ctx, "teep-agent", "agent-identity-status.txt", path, sizeof(path))) {
        (void)twep_wr_platform_write_file_atomic(path, (const uint8_t *)agent_identity_status, strlen(agent_identity_status));
    }
    free(protected_store);
    free(issuer_allowlist);
    free(store_freshness);
    free(revocation_state);
    free(agent_identity);
    free(evidence_result);
    free(verified_input);
    free(teep_agent_wasm);
}

void twep_tz_write_verified_evidence_snapshot(
    const twep_wr_context_t *ctx,
    const uint8_t *evidence_result,
    size_t evidence_result_len,
    const uint8_t *slot0,
    size_t slot0_len,
    const uint8_t *slot1,
    size_t slot1_len)
{
    const char *verifier_result = "none";
    const char *decision_source = "none";
    const char *evidence_binding = "unbound";
    bool nonce_match = false;
    bool cnf_key_match = false;
    bool platform_match = false;
    bool tam_response_verified = false;
    bool challenge_response_bound = false;
    bool acceptance_generation_present = false;
    bool acceptance_generation_current = false;
    bool evidence_affirming = false;
    uint64_t acceptance_generation = 0;
    uint64_t current_generation = 0;
    uint64_t slot_generation = 0;
    bool current_generation_present = false;
    char evidence_status[768];
    char path[TWEP_WR_MAX_PATH_LEN];

    if (ctx == NULL || evidence_result == NULL || evidence_result_len == 0u ||
        !validate_verified_evidence_result(evidence_result, evidence_result_len,
                                           &verifier_result,
                                           &decision_source,
                                           &nonce_match,
                                           &cnf_key_match,
                                           &platform_match,
                                           &tam_response_verified,
                                           &challenge_response_bound,
                                           &acceptance_generation_present,
                                           &acceptance_generation)) {
        return;
    }
    if (trustzone_acceptance_slot_generation_bytes(slot0, slot0_len,
                                                   &slot_generation)) {
        current_generation = slot_generation;
        current_generation_present = true;
    }
    if (trustzone_acceptance_slot_generation_bytes(slot1, slot1_len,
                                                   &slot_generation) &&
        (!current_generation_present || slot_generation > current_generation)) {
        current_generation = slot_generation;
        current_generation_present = true;
    }
    acceptance_generation_current =
        acceptance_generation_present && current_generation_present &&
        acceptance_generation == current_generation;
    if (strcmp(decision_source, "attestam-signed-update") == 0 &&
        tam_response_verified && challenge_response_bound &&
        acceptance_generation_current) {
        evidence_binding = "bound";
        evidence_affirming = true;
    }

    (void)snprintf(evidence_status, sizeof(evidence_status),
                   "evidence-model-ready=true\n"
                   "evidence-source=verified-evidence-result\n"
                   "evidence-result-load=loaded-session-snapshot\n"
                   "evidence-verifier-result=%s\n"
                   "evidence-decision-source=%s\n"
                   "evidence-nonce-match=%s\n"
                   "evidence-cnf-key-match=%s\n"
                   "evidence-platform-match=%s\n"
                   "evidence-tam-response-verified=%s\n"
                   "evidence-challenge-response-bound=%s\n"
                   "evidence-acceptance-generation-current=%s\n"
                   "evidence-binding=%s\n"
                   "evidence-affirming=%s\n",
                   verifier_result,
                   decision_source,
                   twep_wr_bool_label(nonce_match),
                   twep_wr_bool_label(cnf_key_match),
                   twep_wr_bool_label(platform_match),
                   twep_wr_bool_label(tam_response_verified),
                   twep_wr_bool_label(challenge_response_bound),
                   twep_wr_bool_label(acceptance_generation_current),
                   evidence_binding,
                   twep_wr_bool_label(evidence_affirming));
    if (twep_wr_state_path(ctx, "teep-agent", "evidence-status.txt", path,
                           sizeof(path))) {
        (void)twep_wr_platform_write_file_atomic(
            path, (const uint8_t *)evidence_status, strlen(evidence_status));
    }
}
