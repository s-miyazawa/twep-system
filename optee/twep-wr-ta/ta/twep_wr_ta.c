/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
// SPDX-License-Identifier: BSD-2-Clause

#include <twep_wr_ta.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "ta_internal.h"

TEE_Result TA_CreateEntryPoint(void)
{
	IMSG("twep-wr-ta create");
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	twep_ta_runtime_destroy();
	IMSG("twep-wr-ta destroy");
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
				    TEE_Param params[4],
				    void **session)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	(void)param_types;
	(void)params;
	res = twep_ta_session_open(session);
	if (res != TEE_SUCCESS)
		return res;

	IMSG("twep-wr-ta open session");
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *session)
{
	twep_ta_session_close(session);
	IMSG("twep-wr-ta close session");
}

TEE_Result TA_InvokeCommandEntryPoint(void *session, uint32_t command,
				      uint32_t param_types,
				      TEE_Param params[4])
{
	return twep_ta_session_invoke(session, command, param_types, params);
}
