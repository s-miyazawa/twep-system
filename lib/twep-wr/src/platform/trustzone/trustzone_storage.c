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

#define TWEP_WR_TZ_READ_CAP (64u * 1024u)

static void trustzone_debug_io(const char *op, const char *path, int err)
{
    if (getenv("TWEP_WR_PLATFORM_DEBUG") == NULL) {
        return;
    }
    fprintf(stderr, "twep-wr trustzone %s path=%s errno=%d\n",
            op != NULL ? op : "io",
            path != NULL ? path : "(null)",
            err);
}


twep_wr_platform_status_t twep_wr_platform_read_file(
    const char *path,
    uint8_t **out,
    size_t *out_len)
{
    if (path == NULL || out == NULL || out_len == NULL) {
        return TWEP_WR_PLATFORM_ERR_IO;
    }
    *out = NULL;
    *out_len = 0;

    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
        trustzone_debug_io("fopen-read", path, errno);
        return TWEP_WR_PLATFORM_ERR_IO;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return TWEP_WR_PLATFORM_ERR_IO;
    }
    long len = ftell(fp);
    if (len < 0) {
        fclose(fp);
        return TWEP_WR_PLATFORM_ERR_IO;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return TWEP_WR_PLATFORM_ERR_IO;
    }

    size_t alloc_len = len == 0 ? 1u : (size_t)len;
    uint8_t *buf = (uint8_t *)malloc(alloc_len);
    if (buf == NULL) {
        fclose(fp);
        return TWEP_WR_PLATFORM_ERR_NO_MEMORY;
    }
    if (len != 0 && fread(buf, 1, (size_t)len, fp) != (size_t)len) {
        free(buf);
        fclose(fp);
        return TWEP_WR_PLATFORM_ERR_IO;
    }
    if (fclose(fp) != 0) {
        free(buf);
        return TWEP_WR_PLATFORM_ERR_IO;
    }

    *out = buf;
    *out_len = (size_t)len;
    return TWEP_WR_PLATFORM_OK;
}

twep_wr_platform_status_t twep_wr_platform_write_file(
    const char *path,
    const uint8_t *data,
    size_t data_len)
{
    if (path == NULL || (data == NULL && data_len != 0)) {
        return TWEP_WR_PLATFORM_ERR_IO;
    }
    FILE *fp = fopen(path, "wb");
    if (fp == NULL) {
        trustzone_debug_io("fopen-write", path, errno);
        return TWEP_WR_PLATFORM_ERR_IO;
    }
    if (data_len != 0 && fwrite(data, 1, data_len, fp) != data_len) {
        trustzone_debug_io("fwrite", path, errno);
        fclose(fp);
        return TWEP_WR_PLATFORM_ERR_IO;
    }
    if (fflush(fp) != 0 || fsync(fileno(fp)) != 0) {
        trustzone_debug_io("flush-write", path, errno);
        fclose(fp);
        return TWEP_WR_PLATFORM_ERR_IO;
    }
    if (fclose(fp) != 0) {
        trustzone_debug_io("fclose-write", path, errno);
        return TWEP_WR_PLATFORM_ERR_IO;
    }
    trustzone_debug_io("write-ok", path, 0);
    return TWEP_WR_PLATFORM_OK;
}

twep_wr_platform_status_t twep_wr_platform_write_file_atomic(
    const char *path,
    const uint8_t *data,
    size_t data_len)
{
    if (path == NULL) {
        return TWEP_WR_PLATFORM_ERR_IO;
    }
    char tmp_path[1024];
    int n = snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path);
    if (n <= 0 || (size_t)n >= sizeof(tmp_path)) {
        return TWEP_WR_PLATFORM_ERR_IO;
    }
    twep_wr_platform_status_t status = twep_wr_platform_write_file(tmp_path, data, data_len);
    if (status != TWEP_WR_PLATFORM_OK) {
        unlink(tmp_path);
        return status;
    }
    if (rename(tmp_path, path) != 0) {
        trustzone_debug_io("rename", path, errno);
        unlink(tmp_path);
        return TWEP_WR_PLATFORM_ERR_IO;
    }
    trustzone_debug_io("rename-ok", path, 0);
    return TWEP_WR_PLATFORM_OK;
}

bool twep_wr_platform_file_exists(const char *path)
{
    if (path == NULL) {
        return false;
    }
    return access(path, F_OK) == 0;
}

twep_wr_platform_status_t twep_wr_platform_mkdir_if_needed(const char *path)
{
    if (path == NULL || path[0] == '\0') {
        return TWEP_WR_PLATFORM_ERR_IO;
    }
    if (mkdir(path, 0700) == 0) {
        return TWEP_WR_PLATFORM_OK;
    }
    if (errno == EEXIST) {
        struct stat st;
        if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
            return TWEP_WR_PLATFORM_OK;
        }
    }
    return TWEP_WR_PLATFORM_ERR_IO;
}

twep_wr_platform_status_t twep_wr_platform_random(
    uint8_t *buf,
    uint32_t buf_len)
{
    (void)buf;
    (void)buf_len;
    return TWEP_WR_PLATFORM_ERR_UNSUPPORTED;
}

uint64_t twep_wr_platform_unix_time_ms(void)
{
    return 0;
}

twep_wr_platform_status_t twep_wr_platform_sealed_init(const char *state_dir)
{
    (void)state_dir;
    return TWEP_WR_PLATFORM_OK;
}

bool twep_wr_platform_sealed_exists(
    const char *state_dir,
    const char *object_name)
{
    uint8_t *bytes = NULL;
    size_t bytes_len = 0;
    bool exists = false;

    (void)state_dir;
    if (twep_wr_platform_sealed_read(NULL, object_name, &bytes, &bytes_len) == TWEP_WR_PLATFORM_OK) {
        exists = true;
    }
    free(bytes);
    return exists;
}

twep_wr_platform_status_t twep_wr_platform_sealed_read(
    const char *state_dir,
    const char *object_name,
    uint8_t **out,
    size_t *out_len)
{
    twep_tz_session_t session;
    twep_wr_platform_status_t status;
    TEEC_Operation op;
    TEEC_Result res;
    uint32_t origin = 0;
    size_t object_name_len;
    uint8_t *buf;

    (void)state_dir;
    if (object_name == NULL || out == NULL || out_len == NULL) {
        return TWEP_WR_PLATFORM_ERR_IO;
    }
    *out = NULL;
    *out_len = 0;
    object_name_len = strlen(object_name);
    if (object_name_len == 0) {
        return TWEP_WR_PLATFORM_ERR_IO;
    }

    buf = (uint8_t *)malloc(TWEP_WR_TZ_READ_CAP);
    if (buf == NULL) {
        return TWEP_WR_PLATFORM_ERR_NO_MEMORY;
    }

    status = twep_tz_open(&session);
    if (status != TWEP_WR_PLATFORM_OK) {
        free(buf);
        return status;
    }

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = (void *)object_name;
    op.params[0].tmpref.size = object_name_len;
    op.params[1].tmpref.buffer = buf;
    op.params[1].tmpref.size = TWEP_WR_TZ_READ_CAP;

    res = TEEC_InvokeCommand(&session.sess, TA_TWEP_WR_CMD_SECURE_STORAGE_GET,
                             &op, &origin);
    twep_tz_close(&session);
    if (res != TEEC_SUCCESS) {
        free(buf);
        return twep_tz_platform_status(res);
    }

    *out_len = op.params[1].tmpref.size;
    *out = buf;
    return TWEP_WR_PLATFORM_OK;
}

twep_wr_platform_status_t twep_wr_platform_sealed_write_atomic(
    const char *state_dir,
    const char *object_name,
    const uint8_t *data,
    size_t data_len)
{
    twep_tz_session_t session;
    twep_wr_platform_status_t status;
    TEEC_Operation op;
    TEEC_Result res;
    uint32_t origin = 0;
    size_t object_name_len;

    (void)state_dir;
    if (object_name == NULL || data == NULL || data_len == 0) {
        return TWEP_WR_PLATFORM_ERR_IO;
    }
    if (strcmp(object_name, "twep-catalog-state.cbor") == 0 ||
        strcmp(object_name, "twep-catalog-state.0.cbor") == 0 ||
        strcmp(object_name, "twep-catalog-state.1.cbor") == 0) {
        return TWEP_WR_PLATFORM_ERR_IO;
    }
    object_name_len = strlen(object_name);
    if (object_name_len == 0) {
        return TWEP_WR_PLATFORM_ERR_IO;
    }

    status = twep_tz_open(&session);
    if (status != TWEP_WR_PLATFORM_OK) {
        return status;
    }

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = (void *)object_name;
    op.params[0].tmpref.size = object_name_len;
    op.params[1].tmpref.buffer = (void *)data;
    op.params[1].tmpref.size = data_len;

    res = TEEC_InvokeCommand(&session.sess, TA_TWEP_WR_CMD_SECURE_STORAGE_PUT,
                             &op, &origin);
    twep_tz_close(&session);
    return twep_tz_platform_status(res);
}

