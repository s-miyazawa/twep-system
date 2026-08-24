/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */

#include "ta_internal.h"

#include <tee_internal_api_extensions.h>

#define PLATFORM_STATUS \
	"platform-backend=" TWEP_TA_PLATFORM_BACKEND "\n" \
	"sealed-storage-security=tee-ree-fs-secure-storage\n" \
	"sealed-storage-rollback-protected=false\n" \
	"protected-storage=true\n" \
	"file-io=false\n" \
	"random=false\n" \
	"time=false\n" \
	"final-verified=false\n"

static const uint8_t cbor_dry_run_response[] = {
	0xa2, 0x64, 'm', 'o', 'd', 'e',
	0x6c, 'c', 'b', 'o', 'r', '-', 'd', 'r', 'y', '-', 'r', 'u', 'n',
	0x66, 's', 't', 'a', 't', 'u', 's', 0x62, 'o', 'k',
};

TEE_Result twep_ta_cmd_ping(uint32_t param_types, TEE_Param params[4])
{
	const uint32_t expected = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
						 TEE_PARAM_TYPE_NONE,
						 TEE_PARAM_TYPE_NONE,
						 TEE_PARAM_TYPE_NONE);

	if (param_types != expected)
		return TEE_ERROR_BAD_PARAMETERS;
	params[0].value.a++;
	IMSG("twep-wr-ta ping");
	return TEE_SUCCESS;
}

TEE_Result twep_ta_cmd_get_platform_status(uint32_t param_types,
					  TEE_Param params[4])
{
	const uint32_t expected = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
						 TEE_PARAM_TYPE_NONE,
						 TEE_PARAM_TYPE_NONE,
						 TEE_PARAM_TYPE_NONE);
	const size_t status_size = sizeof(PLATFORM_STATUS);

	if (param_types != expected)
		return TEE_ERROR_BAD_PARAMETERS;
	if (params[0].memref.size < status_size) {
		params[0].memref.size = status_size;
		return TEE_ERROR_SHORT_BUFFER;
	}
	TEE_MemMove(params[0].memref.buffer, PLATFORM_STATUS, status_size);
	params[0].memref.size = status_size;
	IMSG("twep-wr-ta platform status");
	return TEE_SUCCESS;
}

TEE_Result twep_ta_cmd_get_random(uint32_t param_types, TEE_Param params[4])
{
	const uint32_t expected = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
						 TEE_PARAM_TYPE_NONE,
						 TEE_PARAM_TYPE_NONE,
						 TEE_PARAM_TYPE_NONE);

	if (param_types != expected || params[0].memref.size == 0)
		return TEE_ERROR_BAD_PARAMETERS;
	TEE_GenerateRandom(params[0].memref.buffer, params[0].memref.size);
	IMSG("twep-wr-ta random");
	return TEE_SUCCESS;
}

TEE_Result twep_ta_cmd_get_time(uint32_t param_types, TEE_Param params[4])
{
	const uint32_t expected = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
						 TEE_PARAM_TYPE_NONE,
						 TEE_PARAM_TYPE_NONE,
						 TEE_PARAM_TYPE_NONE);
	TEE_Time time = { };

	if (param_types != expected)
		return TEE_ERROR_BAD_PARAMETERS;
	TEE_GetSystemTime(&time);
	params[0].value.a = time.seconds;
	params[0].value.b = time.millis;
	IMSG("twep-wr-ta time");
	return TEE_SUCCESS;
}

TEE_Result twep_ta_cmd_cbor_dry_run(uint32_t param_types,
				   TEE_Param params[4])
{
	const uint32_t expected = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						 TEE_PARAM_TYPE_MEMREF_OUTPUT,
						 TEE_PARAM_TYPE_NONE,
						 TEE_PARAM_TYPE_NONE);

	if (param_types != expected || params[0].memref.size == 0)
		return TEE_ERROR_BAD_PARAMETERS;
	if (params[1].memref.size < sizeof(cbor_dry_run_response)) {
		params[1].memref.size = sizeof(cbor_dry_run_response);
		return TEE_ERROR_SHORT_BUFFER;
	}
	TEE_MemMove(params[1].memref.buffer, cbor_dry_run_response,
		    sizeof(cbor_dry_run_response));
	params[1].memref.size = sizeof(cbor_dry_run_response);
	IMSG("twep-wr-ta cbor dry-run");
	return TEE_SUCCESS;
}
