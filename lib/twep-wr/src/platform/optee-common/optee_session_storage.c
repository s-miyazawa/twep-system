/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */
#include "optee_internal.h"

#include <stdlib.h>
#include <string.h>

#include <twep_wr_ta.h>

#define TWEP_WR_OPTEE_READ_CAP (64u * 1024u)

twep_wr_platform_status_t twep_optee_session_secure_storage_get(
    twep_optee_session_t *session,
    const char *object_name,
    uint8_t **out,
    size_t *out_len)
{
    TEEC_Operation op;
    TEEC_Result res;
    uint32_t origin = 0;
    uint8_t *buf;

    if (session == NULL || object_name == NULL || object_name[0] == '\0' ||
        out == NULL || out_len == NULL) {
        return TWEP_WR_PLATFORM_ERR_IO;
    }
    *out = NULL;
    *out_len = 0;
    buf = (uint8_t *)malloc(TWEP_WR_OPTEE_READ_CAP);
    if (buf == NULL) {
        return TWEP_WR_PLATFORM_ERR_NO_MEMORY;
    }
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = (void *)object_name;
    op.params[0].tmpref.size = strlen(object_name);
    op.params[1].tmpref.buffer = buf;
    op.params[1].tmpref.size = TWEP_WR_OPTEE_READ_CAP;
    res = TEEC_InvokeCommand(&session->sess, TA_TWEP_WR_CMD_SECURE_STORAGE_GET,
                             &op, &origin);
    if (res != TEEC_SUCCESS) {
        free(buf);
        return twep_optee_platform_status(res);
    }
    *out = buf;
    *out_len = op.params[1].tmpref.size;
    return TWEP_WR_PLATFORM_OK;
}
