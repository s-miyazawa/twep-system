/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */
#include "platform/platform.h"

static const twep_wr_platform_info_t SGX_PLATFORM_INFO = {
    .backend_name = "sgx",
    .sealed_storage_security = TWEP_WR_PLATFORM_SEALED_UNSUPPORTED,
    .supports_file_io = false,
    .supports_random = false,
    .supports_time = false,
};

const twep_wr_platform_info_t *twep_wr_platform_info(void)
{
    return &SGX_PLATFORM_INFO;
}

twep_wr_platform_status_t twep_wr_platform_read_file(
    const char *path,
    uint8_t **out,
    size_t *out_len)
{
    (void)path;
    if (out != NULL) {
        *out = NULL;
    }
    if (out_len != NULL) {
        *out_len = 0;
    }
    return TWEP_WR_PLATFORM_ERR_UNSUPPORTED;
}

twep_wr_platform_status_t twep_wr_platform_write_file(
    const char *path,
    const uint8_t *data,
    size_t data_len)
{
    (void)path;
    (void)data;
    (void)data_len;
    return TWEP_WR_PLATFORM_ERR_UNSUPPORTED;
}

twep_wr_platform_status_t twep_wr_platform_write_file_atomic(
    const char *path,
    const uint8_t *data,
    size_t data_len)
{
    (void)path;
    (void)data;
    (void)data_len;
    return TWEP_WR_PLATFORM_ERR_UNSUPPORTED;
}

bool twep_wr_platform_file_exists(const char *path)
{
    (void)path;
    return false;
}

twep_wr_platform_status_t twep_wr_platform_mkdir_if_needed(const char *path)
{
    (void)path;
    return TWEP_WR_PLATFORM_ERR_UNSUPPORTED;
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
    return TWEP_WR_PLATFORM_ERR_UNSUPPORTED;
}

bool twep_wr_platform_sealed_exists(
    const char *state_dir,
    const char *object_name)
{
    (void)state_dir;
    (void)object_name;
    return false;
}

twep_wr_platform_status_t twep_wr_platform_sealed_read(
    const char *state_dir,
    const char *object_name,
    uint8_t **out,
    size_t *out_len)
{
    (void)state_dir;
    (void)object_name;
    if (out != NULL) {
        *out = NULL;
    }
    if (out_len != NULL) {
        *out_len = 0;
    }
    return TWEP_WR_PLATFORM_ERR_UNSUPPORTED;
}

twep_wr_platform_status_t twep_wr_platform_sealed_write_atomic(
    const char *state_dir,
    const char *object_name,
    const uint8_t *data,
    size_t data_len)
{
    (void)state_dir;
    (void)object_name;
    (void)data;
    (void)data_len;
    return TWEP_WR_PLATFORM_ERR_UNSUPPORTED;
}
