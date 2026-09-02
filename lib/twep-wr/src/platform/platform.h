/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef TWEP_WR_PLATFORM_H
#define TWEP_WR_PLATFORM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct twep_wr_context;

typedef enum {
    TWEP_WR_PLATFORM_OK = 0,
    TWEP_WR_PLATFORM_ERR_IO = 1,
    TWEP_WR_PLATFORM_ERR_NO_MEMORY = 2,
    TWEP_WR_PLATFORM_ERR_UNSUPPORTED = 3,
} twep_wr_platform_status_t;

typedef enum {
    TWEP_WR_PLATFORM_SEALED_UNSUPPORTED = 0,
    TWEP_WR_PLATFORM_SEALED_OBSERVATION_ONLY = 1,
    TWEP_WR_PLATFORM_SEALED_TEE_PROTECTED = 2,
    TWEP_WR_PLATFORM_SEALED_TEE_SECURE_STORAGE_SMOKE = 3,
    TWEP_WR_PLATFORM_SEALED_TEE_REE_FS_SECURE_STORAGE = 4,
} twep_wr_platform_sealed_security_t;

typedef struct {
    const char *backend_name;
    twep_wr_platform_sealed_security_t sealed_storage_security;
    bool supports_file_io;
    bool supports_random;
    bool supports_time;
} twep_wr_platform_info_t;

const twep_wr_platform_info_t *twep_wr_platform_info(void);

twep_wr_platform_status_t twep_wr_platform_read_file(
    const char *path,
    uint8_t **out,
    size_t *out_len);

twep_wr_platform_status_t twep_wr_platform_write_file(
    const char *path,
    const uint8_t *data,
    size_t data_len);

twep_wr_platform_status_t twep_wr_platform_write_file_atomic(
    const char *path,
    const uint8_t *data,
    size_t data_len);

bool twep_wr_platform_file_exists(const char *path);

twep_wr_platform_status_t twep_wr_platform_mkdir_if_needed(const char *path);

twep_wr_platform_status_t twep_wr_platform_random(
    uint8_t *buf,
    uint32_t buf_len);

uint64_t twep_wr_platform_unix_time_ms(void);

twep_wr_platform_status_t twep_wr_platform_sealed_init(const char *state_dir);

bool twep_wr_platform_sealed_exists(
    const char *state_dir,
    const char *object_name);

twep_wr_platform_status_t twep_wr_platform_sealed_read(
    const char *state_dir,
    const char *object_name,
    uint8_t **out,
    size_t *out_len);

twep_wr_platform_status_t twep_wr_platform_sealed_write_atomic(
    const char *state_dir,
    const char *object_name,
    const uint8_t *data,
    size_t data_len);

#endif
