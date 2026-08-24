/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */
#include "platform/platform.h"

static const twep_wr_platform_info_t RISCV_OPTEE_PLATFORM_INFO = {
    .backend_name = "riscv-optee",
    .sealed_storage_security = TWEP_WR_PLATFORM_SEALED_TEE_REE_FS_SECURE_STORAGE,
    .supports_file_io = true,
    .supports_random = false,
    .supports_time = false,
};

const twep_wr_platform_info_t *twep_wr_platform_info(void)
{
    return &RISCV_OPTEE_PLATFORM_INFO;
}
