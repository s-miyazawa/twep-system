/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */
#include "runtime_internal.h"

#include <stdlib.h>
#include <string.h>

static bool write_text(uint8_t **p, const char *text);
static bool write_text_view(uint8_t **p, const char *text, size_t len);
static size_t cbor_type_len_size(uint64_t n);
static void write_type_len(uint8_t **p, uint8_t major, uint64_t n);

twep_wr_status_t twep_wr_make_response(const char *request_id, const uint8_t *stdout_bytes, size_t stdout_len,
                                       const uint8_t *app_output, size_t app_output_len,
                                       twep_wr_owned_bytes_t *out_response_cbor)
{
    if (stdout_len > UINT32_MAX || app_output_len > UINT32_MAX) {
        return TWEP_WR_ERR_WASM_RUNTIME;
    }
    size_t request_id_len = strlen(request_id);

    size_t len = 1
                 + 1 + 14 + 1
                 + 1 + 10 + cbor_type_len_size(request_id_len) + request_id_len
                 + 1 + 6 + 1 + 2
                 + 1 + 9 + 1
                 + 1 + 6 + cbor_type_len_size(stdout_len) + stdout_len;
    len += 1 + 10 + cbor_type_len_size(app_output_len) + app_output_len;
    uint8_t *buf = (uint8_t *)malloc(len);
    if (buf == NULL) {
        return TWEP_WR_ERR_NO_MEMORY;
    }

    uint8_t *p = buf;
    *p++ = 0xa6;
    *p++ = 0x6e;
    memcpy(p, "schema_version", 14);
    p += 14;
    *p++ = 0x01;
    *p++ = 0x6a;
    memcpy(p, "request_id", 10);
    p += 10;
    write_type_len(&p, 3, request_id_len);
    memcpy(p, request_id, request_id_len);
    p += request_id_len;
    *p++ = 0x66;
    memcpy(p, "status", 6);
    p += 6;
    *p++ = 0x62;
    memcpy(p, "ok", 2);
    p += 2;
    *p++ = 0x69;
    memcpy(p, "exit_code", 9);
    p += 9;
    *p++ = 0x00;
    *p++ = 0x66;
    memcpy(p, "stdout", 6);
    p += 6;
    write_type_len(&p, 2, stdout_len);
    if (stdout_len != 0) {
        memcpy(p, stdout_bytes, stdout_len);
        p += stdout_len;
    }
    *p++ = 0x6a;
    memcpy(p, "app_output", 10);
    p += 10;
    write_type_len(&p, 2, app_output_len);
    if (app_output_len != 0) {
        memcpy(p, app_output, app_output_len);
        p += app_output_len;
    }

    out_response_cbor->ptr = buf;
    out_response_cbor->len = (size_t)(p - buf);
    return TWEP_WR_OK;
}

twep_wr_status_t twep_wr_make_app_error_response(const char *request_id, int32_t app_status, const char *command,
                                                 const char *wasm_file,
                                                 twep_wr_owned_bytes_t *out_response_cbor)
{
    const char *code = "app.runtime";
    const char *message = "runtime error";
    if (app_status == 1) {
        code = "app.input_cbor";
        message = "invalid input";
    } else if (app_status == 2) {
        code = "app.invalid_argument";
        message = "invalid argument";
    } else if (app_status == 4) {
        code = "app.no_memory";
        message = "no memory";
    } else if (app_status == 5) {
        code = "app.unsupported_command";
        message = "unsupported command";
    } else if (app_status == 6) {
        code = "app.unsupported_format";
        message = "unsupported format";
    } else if (app_status == 3) {
        code = "app.output_generation";
        message = "output generation error";
    } else if (app_status == 7) {
        code = "app.resource_limit";
        message = "resource limit exceeded";
    } else if (app_status == 127) {
        code = "app.internal";
        message = "internal app error";
    }

    size_t request_id_len = strlen(request_id);
    size_t command_len = command == NULL ? 0 : strlen(command);
    size_t wasm_file_len = wasm_file == NULL ? 0 : strlen(wasm_file);
    size_t len = 1
                 + 1 + 14 + 1
                 + 1 + 10 + cbor_type_len_size(request_id_len) + request_id_len
                 + 1 + 6 + 1 + 5
                 + 1 + 9 + 1
                 + 1 + 5
                 + 1 + 4 + 1 + strlen(code)
                 + 1 + 7 + 1 + strlen(message)
                 + 1 + 7
                 + 1
                 + 1 + 11 + cbor_type_len_size((uint64_t)(app_status < 0 ? -1 - app_status : app_status))
                 + 1 + 7 + cbor_type_len_size(command_len) + command_len
                 + 1 + 9 + cbor_type_len_size(wasm_file_len) + wasm_file_len;
    if (strlen(code) > 23 || strlen(message) > 23) {
        return TWEP_WR_ERR_WASM_RUNTIME;
    }
    uint8_t *buf = (uint8_t *)malloc(len);
    if (buf == NULL) {
        return TWEP_WR_ERR_NO_MEMORY;
    }
    uint8_t *p = buf;
    *p++ = 0xa5;
    (void)write_text(&p, "schema_version");
    *p++ = 0x01;
    (void)write_text(&p, "request_id");
    (void)write_text_view(&p, request_id, request_id_len);
    (void)write_text(&p, "status");
    (void)write_text(&p, "error");
    (void)write_text(&p, "exit_code");
    *p++ = 0x01;
    (void)write_text(&p, "error");
    *p++ = 0xa3;
    (void)write_text(&p, "code");
    (void)write_text(&p, code);
    (void)write_text(&p, "message");
    (void)write_text(&p, message);
    (void)write_text(&p, "details");
    *p++ = 0xa3;
    (void)write_text(&p, "return_code");
    if (app_status >= 0) {
        write_type_len(&p, 0, (uint64_t)app_status);
    } else {
        write_type_len(&p, 1, (uint64_t)(-1 - app_status));
    }
    (void)write_text(&p, "command");
    (void)write_text_view(&p, command == NULL ? "" : command, command_len);
    (void)write_text(&p, "wasm_file");
    (void)write_text_view(&p, wasm_file == NULL ? "" : wasm_file, wasm_file_len);

    out_response_cbor->ptr = buf;
    out_response_cbor->len = (size_t)(p - buf);
    return TWEP_WR_OK;
}

static bool write_text(uint8_t **p, const char *text)
{
    size_t len = strlen(text);
    if (len > 23) {
        return false;
    }
    *(*p)++ = 0x60 | (uint8_t)len;
    memcpy(*p, text, len);
    *p += len;
    return true;
}

static bool write_text_view(uint8_t **p, const char *text, size_t len)
{
    if (p == NULL || text == NULL) {
        return false;
    }
    write_type_len(p, 3, len);
    memcpy(*p, text, len);
    *p += len;
    return true;
}

static size_t cbor_type_len_size(uint64_t n)
{
    if (n < 24) {
        return 1;
    }
    if (n <= 0xff) {
        return 2;
    }
    if (n <= 0xffff) {
        return 3;
    }
    if (n <= 0xffffffff) {
        return 5;
    }
    return 9;
}

static void write_type_len(uint8_t **p, uint8_t major, uint64_t n)
{
    uint8_t head = (uint8_t)(major << 5);
    if (n < 24) {
        *(*p)++ = head | (uint8_t)n;
    } else if (n <= 0xff) {
        *(*p)++ = head | 24;
        *(*p)++ = (uint8_t)n;
    } else if (n <= 0xffff) {
        *(*p)++ = head | 25;
        *(*p)++ = (uint8_t)(n >> 8);
        *(*p)++ = (uint8_t)n;
    } else if (n <= 0xffffffff) {
        *(*p)++ = head | 26;
        *(*p)++ = (uint8_t)(n >> 24);
        *(*p)++ = (uint8_t)(n >> 16);
        *(*p)++ = (uint8_t)(n >> 8);
        *(*p)++ = (uint8_t)n;
    } else {
        *(*p)++ = head | 27;
        *(*p)++ = (uint8_t)(n >> 56);
        *(*p)++ = (uint8_t)(n >> 48);
        *(*p)++ = (uint8_t)(n >> 40);
        *(*p)++ = (uint8_t)(n >> 32);
        *(*p)++ = (uint8_t)(n >> 24);
        *(*p)++ = (uint8_t)(n >> 16);
        *(*p)++ = (uint8_t)(n >> 8);
        *(*p)++ = (uint8_t)n;
    }
}
