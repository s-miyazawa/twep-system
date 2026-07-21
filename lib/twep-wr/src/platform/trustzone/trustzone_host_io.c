/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */
#include "trustzone_internal.h"

#include <stdlib.h>
#include <string.h>

#define TWEP_WR_TZ_HOST_IO_CAP (128u * 1024u)

static size_t cbor_len_size(uint64_t n)
{
    if (n < 24u) {
        return 1u;
    }
    if (n <= 0xffu) {
        return 2u;
    }
    if (n <= 0xffffu) {
        return 3u;
    }
    if (n <= 0xffffffffu) {
        return 5u;
    }
    return 9u;
}
static void cbor_write_type_len(uint8_t **p, uint8_t major, uint64_t n)
{
    if (n < 24u) {
        *(*p)++ = (uint8_t)((major << 5) | n);
    } else if (n <= 0xffu) {
        *(*p)++ = (uint8_t)((major << 5) | 24u);
        *(*p)++ = (uint8_t)n;
    } else if (n <= 0xffffu) {
        *(*p)++ = (uint8_t)((major << 5) | 25u);
        *(*p)++ = (uint8_t)(n >> 8);
        *(*p)++ = (uint8_t)n;
    } else if (n <= 0xffffffffu) {
        *(*p)++ = (uint8_t)((major << 5) | 26u);
        *(*p)++ = (uint8_t)(n >> 24);
        *(*p)++ = (uint8_t)(n >> 16);
        *(*p)++ = (uint8_t)(n >> 8);
        *(*p)++ = (uint8_t)n;
    } else {
        *(*p)++ = (uint8_t)((major << 5) | 27u);
        for (int shift = 56; shift >= 0; shift -= 8) {
            *(*p)++ = (uint8_t)(n >> shift);
        }
    }
}

static void cbor_write_text(uint8_t **p, const char *text)
{
    size_t len = strlen(text);
    cbor_write_type_len(p, 3, len);
    memcpy(*p, text, len);
    *p += len;
}

static void cbor_write_bytes(uint8_t **p, const uint8_t *bytes, size_t len)
{
    cbor_write_type_len(p, 2, len);
    if (len != 0u) {
        memcpy(*p, bytes, len);
        *p += len;
    }
}

static void cbor_write_bool(uint8_t **p, bool value)
{
    *(*p)++ = value ? 0xf5 : 0xf4;
}

static size_t cbor_text_field_len(const char *key, const char *value)
{
    size_t key_len = strlen(key);
    size_t value_len = strlen(value);
    return cbor_len_size(key_len) + key_len + cbor_len_size(value_len) + value_len;
}

static size_t cbor_bytes_field_len(const char *key, size_t value_len)
{
    size_t key_len = strlen(key);
    return cbor_len_size(key_len) + key_len + cbor_len_size(value_len) + value_len;
}

static bool cbor_text_view_equals(bytes_view_t view, const char *text)
{
    size_t text_len = strlen(text);
    return view.len == text_len && memcmp(view.ptr, text, text_len) == 0;
}

static void cbor_write_text_view(uint8_t **p, bytes_view_t view)
{
    cbor_write_type_len(p, 3, view.len);
    if (view.len != 0u) {
        memcpy(*p, view.ptr, view.len);
        *p += view.len;
    }
}

bool twep_tz_parse_response(const uint8_t *buf,
                                     size_t len,
                                     twep_wr_tz_response_kind_t *out_kind,
                                     bytes_view_t *out_final_response,
                                     twep_wr_tz_need_host_io_t *out_need)
{
    size_t off = 0;
    uint8_t major = 0;
    uint64_t map_len = 0;
    bool have_final = false;
    bool have_need = false;

    if (buf == NULL || out_kind == NULL || out_final_response == NULL || out_need == NULL
        || !twep_wr_cbor_read_head(buf, len, &off, &major, &map_len) || major != 5) {
        return false;
    }
    memset(out_final_response, 0, sizeof(*out_final_response));
    memset(out_need, 0, sizeof(*out_need));

    for (uint64_t i = 0; i < map_len; i++) {
        bytes_view_t key = {0};
        if (!twep_wr_cbor_read_text_view(buf, len, &off, &key)) {
            return false;
        }
        if (cbor_text_view_equals(key, "request_id")) {
            if (!twep_wr_cbor_read_text_view(buf, len, &off, &out_need->request_id)) {
                return false;
            }
        } else if (cbor_text_view_equals(key, "final_response_cbor")) {
            if (!twep_wr_cbor_read_bytes_view(buf, len, &off, out_final_response)) {
                return false;
            }
            have_final = true;
        } else if (cbor_text_view_equals(key, "need_host_io")) {
            uint64_t need_pairs = 0;
            if (!twep_wr_cbor_read_head(buf, len, &off, &major, &need_pairs) || major != 5) {
                return false;
            }
            have_need = true;
            for (uint64_t j = 0; j < need_pairs; j++) {
                bytes_view_t need_key = {0};
                if (!twep_wr_cbor_read_text_view(buf, len, &off, &need_key)) {
                    return false;
                }
                if (cbor_text_view_equals(need_key, "io_id")) {
                    if (!twep_wr_cbor_read_text_view(buf, len, &off, &out_need->io_id)) {
                        return false;
                    }
                } else if (cbor_text_view_equals(need_key, "kind")) {
                    if (!twep_wr_cbor_read_text_view(buf, len, &off, &out_need->kind)) {
                        return false;
                    }
                } else if (cbor_text_view_equals(need_key, "url")) {
                    if (!twep_wr_cbor_read_text_view(buf, len, &off, &out_need->url)) {
                        return false;
                    }
                } else if (cbor_text_view_equals(need_key, "body")) {
                    if (!twep_wr_cbor_read_bytes_view(buf, len, &off, &out_need->body)) {
                        return false;
                    }
                } else if (cbor_text_view_equals(need_key, "challenge")) {
                    if (!twep_wr_cbor_read_bytes_view(buf, len, &off, &out_need->challenge)) {
                        return false;
                    }
                } else if (cbor_text_view_equals(need_key, "agent_public_key_cose")) {
                    if (!twep_wr_cbor_read_bytes_view(buf, len, &off, &out_need->agent_public_key_cose)) {
                        return false;
                    }
                } else if (cbor_text_view_equals(need_key, "sequence")) {
                    if (!twep_wr_cbor_read_uint32(buf, len, &off, &out_need->sequence)) {
                        return false;
                    }
                } else if (cbor_text_view_equals(need_key, "request_body_sha256")) {
                    if (!twep_wr_cbor_read_bytes_view(buf, len, &off, &out_need->request_body_sha256)) {
                        return false;
                    }
                } else if (cbor_text_view_equals(need_key, "normalized_input_sha256")) {
                    if (!twep_wr_cbor_read_bytes_view(buf, len, &off, &out_need->normalized_input_sha256)) {
                        return false;
                    }
                } else if (!twep_wr_cbor_skip_value(buf, len, &off)) {
                    return false;
                }
            }
        } else if (!twep_wr_cbor_skip_value(buf, len, &off)) {
            return false;
        }
    }
    if (off != len || (have_final && have_need) || (!have_final && !have_need)) {
        return false;
    }
    if (have_final) {
        *out_kind = TWEP_WR_TZ_RESPONSE_FINAL;
        return true;
    }
    if (out_need->request_id.ptr == NULL || out_need->io_id.ptr == NULL || out_need->kind.ptr == NULL
        || out_need->sequence == 0 || out_need->request_body_sha256.len != 32
        || out_need->normalized_input_sha256.len != 32) {
        return false;
    }
    *out_kind = TWEP_WR_TZ_RESPONSE_NEED_HOST_IO;
    return true;
}

static uint8_t *make_host_io_result_cbor(const twep_wr_tz_need_host_io_t *need,
                                         const char *result_key,
                                         const uint8_t *result,
                                         size_t result_len,
                                         uint32_t status,
                                         size_t *out_len)
{
    size_t result_key_len = strlen(result_key);
    size_t len;
    uint8_t *buf;
    uint8_t *p;

    if (need == NULL || result_key == NULL || out_len == NULL || (result == NULL && result_len != 0u)) {
        return NULL;
    }
    len = 1u
          + cbor_len_size(strlen("io_id")) + strlen("io_id") + cbor_len_size(need->io_id.len) + need->io_id.len
          + cbor_len_size(strlen("kind")) + strlen("kind") + cbor_len_size(need->kind.len) + need->kind.len
          + cbor_len_size(strlen("status")) + strlen("status") + cbor_len_size(status)
          + cbor_len_size(result_key_len) + result_key_len + cbor_len_size(result_len) + result_len
          + cbor_len_size(strlen("sequence")) + strlen("sequence") + cbor_len_size(need->sequence)
          + cbor_len_size(strlen("request_body_sha256")) + strlen("request_body_sha256") + cbor_len_size(32) + 32
          + cbor_len_size(strlen("normalized_input_sha256")) + strlen("normalized_input_sha256") + cbor_len_size(32) + 32;
    buf = (uint8_t *)malloc(len);
    if (buf == NULL) {
        return NULL;
    }
    p = buf;
    *p++ = 0xa7;
    cbor_write_text(&p, "io_id");
    cbor_write_text_view(&p, need->io_id);
    cbor_write_text(&p, "kind");
    cbor_write_text_view(&p, need->kind);
    cbor_write_text(&p, "status");
    cbor_write_type_len(&p, 0, status);
    cbor_write_text(&p, result_key);
    cbor_write_bytes(&p, result, result_len);
    cbor_write_text(&p, "sequence");
    cbor_write_type_len(&p, 0, need->sequence);
    cbor_write_text(&p, "request_body_sha256");
    cbor_write_bytes(&p, need->request_body_sha256.ptr, need->request_body_sha256.len);
    cbor_write_text(&p, "normalized_input_sha256");
    cbor_write_bytes(&p, need->normalized_input_sha256.ptr, need->normalized_input_sha256.len);
    *out_len = (size_t)(p - buf);
    return buf;
}

uint8_t *twep_tz_make_resume_envelope(bytes_view_t request_id,
                                               const uint8_t *host_io_result,
                                               size_t host_io_result_len,
                                               size_t *out_len)
{
    size_t len;
    uint8_t *buf;
    uint8_t *p;

    if (request_id.ptr == NULL || host_io_result == NULL || out_len == NULL) {
        return NULL;
    }
    len = 1u
          + cbor_len_size(strlen("request_id")) + strlen("request_id") + cbor_len_size(request_id.len) + request_id.len
          + cbor_len_size(strlen("host_io_result_cbor")) + strlen("host_io_result_cbor")
          + cbor_len_size(host_io_result_len) + host_io_result_len;
    buf = (uint8_t *)malloc(len);
    if (buf == NULL) {
        return NULL;
    }
    p = buf;
    *p++ = 0xa2;
    cbor_write_text(&p, "request_id");
    cbor_write_text_view(&p, request_id);
    cbor_write_text(&p, "host_io_result_cbor");
    cbor_write_bytes(&p, host_io_result, host_io_result_len);
    *out_len = (size_t)(p - buf);
    return buf;
}

twep_wr_status_t twep_tz_perform_host_io(const twep_wr_context_t *ctx,
                                                  const twep_wr_tz_need_host_io_t *need,
                                                  uint8_t **out_result,
                                                  size_t *out_result_len)
{
    uint8_t *material = NULL;
    size_t material_len = 0;
    int32_t host_status;
    const char *result_key;

    if (ctx == NULL || need == NULL || out_result == NULL || out_result_len == NULL) {
        return TWEP_WR_ERR_INVALID_ARGUMENT;
    }
    *out_result = NULL;
    *out_result_len = 0;

    material = (uint8_t *)malloc(TWEP_WR_TZ_HOST_IO_CAP);
    if (material == NULL) {
        return TWEP_WR_ERR_NO_MEMORY;
    }
    if (cbor_text_view_equals(need->kind, "http_post")) {
        if (ctx->host_io.http_post == NULL || need->url.ptr == NULL || need->body.ptr == NULL) {
            free(material);
            return TWEP_WR_ERR_TEEP;
        }
        host_status = ctx->host_io.http_post(ctx->host_io.user_data, need->url.ptr, need->url.len,
                                             need->body.ptr, need->body.len, material,
                                             TWEP_WR_TZ_HOST_IO_CAP, &material_len);
        result_key = "response_body";
    } else if (cbor_text_view_equals(need->kind, "create_evidence")) {
        if (ctx->host_io.create_evidence == NULL || need->challenge.ptr == NULL
            || need->agent_public_key_cose.ptr == NULL) {
            free(material);
            return TWEP_WR_ERR_TEEP_ATTESTATION_UNSUPPORTED;
        }
        host_status = ctx->host_io.create_evidence(ctx->host_io.user_data, need->challenge.ptr, need->challenge.len,
                                                   need->agent_public_key_cose.ptr,
                                                   need->agent_public_key_cose.len, material,
                                                   TWEP_WR_TZ_HOST_IO_CAP, &material_len);
        result_key = "evidence";
    } else {
        free(material);
        return TWEP_WR_ERR_TEEP;
    }
    if (material_len > TWEP_WR_TZ_HOST_IO_CAP) {
        free(material);
        return TWEP_WR_ERR_TEEP;
    }
    *out_result = make_host_io_result_cbor(need, result_key, material, material_len,
                                           host_status < 0 ? 1u : (uint32_t)host_status,
                                           out_result_len);
    free(material);
    if (*out_result == NULL) {
        return TWEP_WR_ERR_NO_MEMORY;
    }
    if (host_status != 0) {
        return TWEP_WR_ERR_TEEP_NETWORK;
    }
    return TWEP_WR_OK;
}
