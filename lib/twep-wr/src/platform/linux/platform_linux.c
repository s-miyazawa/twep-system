/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */
#include "platform/platform.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define TWEP_WR_LINUX_SEALED_NAME_MAX 128u

static const twep_wr_platform_info_t LINUX_PLATFORM_INFO = {
    .backend_name = "linux",
    .sealed_storage_security = TWEP_WR_PLATFORM_SEALED_OBSERVATION_ONLY,
    .supports_file_io = true,
    .supports_random = true,
    .supports_time = true,
};

const twep_wr_platform_info_t *twep_wr_platform_info(void)
{
    return &LINUX_PLATFORM_INFO;
}

static bool sealed_object_name_is_safe(const char *object_name)
{
    if (object_name == NULL || object_name[0] == '\0') {
        return false;
    }
    if (object_name[0] == '.') {
        return false;
    }
    for (size_t i = 0; object_name[i] != '\0'; i++) {
        char ch = object_name[i];
        bool ok = (ch >= 'A' && ch <= 'Z')
                  || (ch >= 'a' && ch <= 'z')
                  || (ch >= '0' && ch <= '9')
                  || ch == '-' || ch == '_' || ch == '.';
        if (!ok || i >= TWEP_WR_LINUX_SEALED_NAME_MAX) {
            return false;
        }
    }
    return true;
}

static twep_wr_platform_status_t join_path2(
    const char *base,
    const char *child,
    char *out,
    size_t out_cap)
{
    if (base == NULL || child == NULL || out == NULL || out_cap == 0) {
        return TWEP_WR_PLATFORM_ERR_IO;
    }
    int n = snprintf(out, out_cap, "%s/%s", base, child);
    return n > 0 && (size_t)n < out_cap ? TWEP_WR_PLATFORM_OK : TWEP_WR_PLATFORM_ERR_IO;
}

static twep_wr_platform_status_t linux_sealed_dir(
    const char *state_dir,
    char *out,
    size_t out_cap)
{
    char platform_dir[1024];
    char linux_dir[1024];
    if (join_path2(state_dir, "platform", platform_dir, sizeof(platform_dir)) != TWEP_WR_PLATFORM_OK
        || join_path2(platform_dir, "linux", linux_dir, sizeof(linux_dir)) != TWEP_WR_PLATFORM_OK
        || join_path2(linux_dir, "sealed", out, out_cap) != TWEP_WR_PLATFORM_OK) {
        return TWEP_WR_PLATFORM_ERR_IO;
    }
    return TWEP_WR_PLATFORM_OK;
}

static twep_wr_platform_status_t linux_sealed_path(
    const char *state_dir,
    const char *object_name,
    char *out,
    size_t out_cap)
{
    char sealed_dir[1024];
    if (!sealed_object_name_is_safe(object_name)
        || linux_sealed_dir(state_dir, sealed_dir, sizeof(sealed_dir)) != TWEP_WR_PLATFORM_OK) {
        return TWEP_WR_PLATFORM_ERR_IO;
    }
    return join_path2(sealed_dir, object_name, out, out_cap);
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
        return TWEP_WR_PLATFORM_ERR_IO;
    }
    if (data_len != 0 && fwrite(data, 1, data_len, fp) != data_len) {
        fclose(fp);
        return TWEP_WR_PLATFORM_ERR_IO;
    }
    if (fclose(fp) != 0) {
        return TWEP_WR_PLATFORM_ERR_IO;
    }
    return TWEP_WR_PLATFORM_OK;
}

twep_wr_platform_status_t twep_wr_platform_write_file_atomic(
    const char *path,
    const uint8_t *data,
    size_t data_len)
{
    if (path == NULL || (data == NULL && data_len != 0)) {
        return TWEP_WR_PLATFORM_ERR_IO;
    }

    size_t path_len = strlen(path);
    if (path_len > ((size_t)-1) - 5u) {
        return TWEP_WR_PLATFORM_ERR_IO;
    }
    char *tmp_path = (char *)malloc(path_len + 5u);
    if (tmp_path == NULL) {
        return TWEP_WR_PLATFORM_ERR_NO_MEMORY;
    }
    memcpy(tmp_path, path, path_len);
    memcpy(tmp_path + path_len, ".tmp", 5u);

    twep_wr_platform_status_t status = twep_wr_platform_write_file(tmp_path, data, data_len);
    if (status != TWEP_WR_PLATFORM_OK) {
        free(tmp_path);
        return status;
    }
    if (rename(tmp_path, path) != 0) {
        free(tmp_path);
        return TWEP_WR_PLATFORM_ERR_IO;
    }
    free(tmp_path);
    return TWEP_WR_PLATFORM_OK;
}

bool twep_wr_platform_file_exists(const char *path)
{
    struct stat st;
    return path != NULL && stat(path, &st) == 0;
}

twep_wr_platform_status_t twep_wr_platform_mkdir_if_needed(const char *path)
{
    if (path == NULL) {
        return TWEP_WR_PLATFORM_ERR_IO;
    }
    if (mkdir(path, 0700) == 0 || errno == EEXIST) {
        return TWEP_WR_PLATFORM_OK;
    }
    return TWEP_WR_PLATFORM_ERR_IO;
}

twep_wr_platform_status_t twep_wr_platform_random(
    uint8_t *buf,
    uint32_t buf_len)
{
    if (buf == NULL && buf_len != 0) {
        return TWEP_WR_PLATFORM_ERR_IO;
    }

    uint32_t off = 0;
    while (off < buf_len) {
        ssize_t n = getrandom(buf + off, buf_len - off, 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return TWEP_WR_PLATFORM_ERR_IO;
        }
        if (n == 0) {
            return TWEP_WR_PLATFORM_ERR_IO;
        }
        off += (uint32_t)n;
    }
    return TWEP_WR_PLATFORM_OK;
}

uint64_t twep_wr_platform_unix_time_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        return 0;
    }
    return ((uint64_t)ts.tv_sec * 1000u) + ((uint64_t)ts.tv_nsec / 1000000u);
}

twep_wr_platform_status_t twep_wr_platform_sealed_init(const char *state_dir)
{
    char platform_dir[1024];
    char linux_dir[1024];
    char sealed_dir[1024];
    if (join_path2(state_dir, "platform", platform_dir, sizeof(platform_dir)) != TWEP_WR_PLATFORM_OK
        || join_path2(platform_dir, "linux", linux_dir, sizeof(linux_dir)) != TWEP_WR_PLATFORM_OK
        || join_path2(linux_dir, "sealed", sealed_dir, sizeof(sealed_dir)) != TWEP_WR_PLATFORM_OK) {
        return TWEP_WR_PLATFORM_ERR_IO;
    }
    if (twep_wr_platform_mkdir_if_needed(platform_dir) != TWEP_WR_PLATFORM_OK
        || twep_wr_platform_mkdir_if_needed(linux_dir) != TWEP_WR_PLATFORM_OK
        || twep_wr_platform_mkdir_if_needed(sealed_dir) != TWEP_WR_PLATFORM_OK) {
        return TWEP_WR_PLATFORM_ERR_IO;
    }
    return TWEP_WR_PLATFORM_OK;
}

bool twep_wr_platform_sealed_exists(
    const char *state_dir,
    const char *object_name)
{
    char path[1024];
    if (linux_sealed_path(state_dir, object_name, path, sizeof(path)) != TWEP_WR_PLATFORM_OK) {
        return false;
    }
    return twep_wr_platform_file_exists(path);
}

twep_wr_platform_status_t twep_wr_platform_sealed_read(
    const char *state_dir,
    const char *object_name,
    uint8_t **out,
    size_t *out_len)
{
    char path[1024];
    if (linux_sealed_path(state_dir, object_name, path, sizeof(path)) != TWEP_WR_PLATFORM_OK) {
        return TWEP_WR_PLATFORM_ERR_IO;
    }
    return twep_wr_platform_read_file(path, out, out_len);
}

twep_wr_platform_status_t twep_wr_platform_sealed_write_atomic(
    const char *state_dir,
    const char *object_name,
    const uint8_t *data,
    size_t data_len)
{
    char path[1024];
    twep_wr_platform_status_t status = twep_wr_platform_sealed_init(state_dir);
    if (status != TWEP_WR_PLATFORM_OK) {
        return status;
    }
    if (linux_sealed_path(state_dir, object_name, path, sizeof(path)) != TWEP_WR_PLATFORM_OK) {
        return TWEP_WR_PLATFORM_ERR_IO;
    }
    return twep_wr_platform_write_file_atomic(path, data, data_len);
}
