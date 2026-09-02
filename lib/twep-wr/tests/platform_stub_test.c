/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */
#include "platform/platform.h"
#include "twep_wr.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>

int main(void)
{
    const twep_wr_platform_info_t *info = twep_wr_platform_info();
    assert(info != NULL);
    assert(strcmp(info->backend_name, "keystone") == 0);
    assert(info->sealed_storage_security == TWEP_WR_PLATFORM_SEALED_UNSUPPORTED);
    assert(!info->supports_file_io);
    assert(!info->supports_random);
    assert(!info->supports_time);

    twep_wr_config_t config = {
        .state_dir = ".",
        .resolver_mode = "mock",
        .attestam_url = "",
        .max_request_bytes = 1,
        .max_response_bytes = 1,
    };
    twep_wr_context_t *ctx = (twep_wr_context_t *)(uintptr_t)1;
    assert(twep_wr_init(&config, &ctx) == TWEP_WR_ERR_INIT);
    assert(ctx == NULL);
    assert(twep_wr_init(&config, &ctx) == TWEP_WR_ERR_INIT);
    assert(ctx == NULL);
    return 0;
}
