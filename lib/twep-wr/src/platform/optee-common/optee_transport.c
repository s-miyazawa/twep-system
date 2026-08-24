/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */

/* Transporting bytes does not authorize Catalog publication or app execution. */
#include "optee_internal.h"

#include <string.h>

#include <twep_wr_ta.h>

twep_wr_platform_status_t twep_optee_platform_status(TEEC_Result result)
{
    switch (result) {
    case TEEC_SUCCESS: return TWEP_WR_PLATFORM_OK;
    case TEEC_ERROR_OUT_OF_MEMORY: return TWEP_WR_PLATFORM_ERR_NO_MEMORY;
    case TEEC_ERROR_NOT_SUPPORTED: return TWEP_WR_PLATFORM_ERR_UNSUPPORTED;
    default: return TWEP_WR_PLATFORM_ERR_IO;
    }
}

twep_wr_status_t twep_optee_wr_status(TEEC_Result result)
{
    switch (result) {
    case TEEC_SUCCESS: return TWEP_WR_OK;
    case TEEC_ERROR_OUT_OF_MEMORY: return TWEP_WR_ERR_NO_MEMORY;
    case TEEC_ERROR_BAD_PARAMETERS:
    case TEEC_ERROR_BAD_FORMAT:
    case TEEC_ERROR_SHORT_BUFFER: return TWEP_WR_ERR_INVALID_ARGUMENT;
    case TEEC_ERROR_SECURITY: return TWEP_WR_ERR_SECURITY;
    default: return TWEP_WR_ERR_TEEP;
    }
}

twep_wr_platform_status_t twep_optee_open(twep_optee_session_t *session)
{
    TEEC_UUID uuid = TA_TWEP_WR_UUID;
    uint32_t origin = 0;
    TEEC_Result result;

    if (session == NULL) return TWEP_WR_PLATFORM_ERR_IO;
    memset(session, 0, sizeof(*session));
    result = TEEC_InitializeContext(NULL, &session->ctx);
    if (result != TEEC_SUCCESS) return twep_optee_platform_status(result);
    session->context_open = true;
    result = TEEC_OpenSession(&session->ctx, &session->sess, &uuid,
                              TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
    if (result != TEEC_SUCCESS) {
        TEEC_FinalizeContext(&session->ctx);
        memset(session, 0, sizeof(*session));
        return twep_optee_platform_status(result);
    }
    session->session_open = true;
    return TWEP_WR_PLATFORM_OK;
}

void twep_optee_close(twep_optee_session_t *session)
{
    if (session == NULL) return;
    if (session->session_open) TEEC_CloseSession(&session->sess);
    if (session->context_open) TEEC_FinalizeContext(&session->ctx);
    memset(session, 0, sizeof(*session));
}
