/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */

/* Public runtime primitives unavailable on SGX. Enclave code uses its private
 * ECALL/OCALL boundary instead. */
#include "runtime_internal.h"

twep_wr_platform_status_t twep_wr_platform_read_file(
    const char *path, uint8_t **output, size_t *output_len)
{
    (void)path;
    if (output != NULL) *output = NULL;
    if (output_len != NULL) *output_len = 0;
    return TWEP_WR_PLATFORM_ERR_UNSUPPORTED;
}
twep_wr_platform_status_t twep_wr_platform_write_file(
    const char *path, const uint8_t *data, size_t data_len)
{ (void)path; (void)data; (void)data_len; return TWEP_WR_PLATFORM_ERR_UNSUPPORTED; }
twep_wr_platform_status_t twep_wr_platform_write_file_atomic(
    const char *path, const uint8_t *data, size_t data_len)
{ (void)path; (void)data; (void)data_len; return TWEP_WR_PLATFORM_ERR_UNSUPPORTED; }
bool twep_wr_platform_file_exists(const char *path)
{ (void)path; return false; }
twep_wr_platform_status_t twep_wr_platform_mkdir_if_needed(const char *path)
{ (void)path; return TWEP_WR_PLATFORM_ERR_UNSUPPORTED; }
twep_wr_platform_status_t twep_wr_platform_random(uint8_t *buffer, uint32_t len)
{ (void)buffer; (void)len; return TWEP_WR_PLATFORM_ERR_UNSUPPORTED; }
uint64_t twep_wr_platform_unix_time_ms(void) { return 0; }
twep_wr_platform_status_t twep_wr_platform_sealed_init(const char *path)
{ (void)path; return TWEP_WR_PLATFORM_ERR_UNSUPPORTED; }
bool twep_wr_platform_sealed_exists(const char *path, const char *name)
{ (void)path; (void)name; return false; }
twep_wr_platform_status_t twep_wr_platform_sealed_read(
    const char *path, const char *name, uint8_t **output, size_t *output_len)
{
    (void)path; (void)name;
    if (output != NULL) *output = NULL;
    if (output_len != NULL) *output_len = 0;
    return TWEP_WR_PLATFORM_ERR_UNSUPPORTED;
}
twep_wr_platform_status_t twep_wr_platform_sealed_write_atomic(
    const char *path, const char *name, const uint8_t *data, size_t data_len)
{ (void)path; (void)name; (void)data; (void)data_len; return TWEP_WR_PLATFORM_ERR_UNSUPPORTED; }
