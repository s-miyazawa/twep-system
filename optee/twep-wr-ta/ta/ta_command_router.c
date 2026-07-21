/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */

#include <twep_wr_ta.h>
#include <trace.h>

#include "ta_internal.h"

struct command_route {
	uint32_t command;
	TEE_Result (*handler)(uint32_t, TEE_Param[4]);
};

static TEE_Result command_init(uint32_t types, TEE_Param params[4])
{
	return twep_ta_cmd_production_envelope(types, params,
					       TWEP_TA_ENVELOPE_INIT, "init");
}

static TEE_Result command_execute(uint32_t types, TEE_Param params[4])
{
	return twep_ta_cmd_production_envelope(types, params,
					       TWEP_TA_ENVELOPE_EXECUTE,
					       "execute");
}

static TEE_Result command_resume(uint32_t types, TEE_Param params[4])
{
	return twep_ta_cmd_production_envelope(
		types, params, TWEP_TA_ENVELOPE_RESUME_HOST_IO, "resume-host-io");
}

static const struct command_route routes[] = {
	{ TA_TWEP_WR_CMD_PING, twep_ta_cmd_ping },
	{ TA_TWEP_WR_CMD_GET_PLATFORM_STATUS, twep_ta_cmd_get_platform_status },
	{ TA_TWEP_WR_CMD_MEASURE_WASM, twep_ta_cmd_measure_wasm },
	{ TA_TWEP_WR_CMD_SECURE_STORAGE_PUT, twep_ta_cmd_secure_storage_put },
	{ TA_TWEP_WR_CMD_SECURE_STORAGE_GET, twep_ta_cmd_secure_storage_get },
	{ TA_TWEP_WR_CMD_GET_RANDOM, twep_ta_cmd_get_random },
	{ TA_TWEP_WR_CMD_GET_TIME, twep_ta_cmd_get_time },
	{ TA_TWEP_WR_CMD_CBOR_DRY_RUN, twep_ta_cmd_cbor_dry_run },
	{ TA_TWEP_WR_CMD_WAMR_SPIKE_EXEC, twep_ta_cmd_wamr_spike_exec },
	{ TA_TWEP_WR_CMD_INIT, command_init },
	{ TA_TWEP_WR_CMD_EXECUTE, command_execute },
	{ TA_TWEP_WR_CMD_RESUME_HOST_IO, command_resume },
#ifdef TWEP_TA_D043_TEST_HOOKS
	{ TA_TWEP_WR_CMD_D043_TEST, twep_ta_cmd_d043_test },
#endif
};

TEE_Result twep_ta_dispatch_command(uint32_t command, uint32_t param_types,
				    TEE_Param params[4])
{
	size_t i = 0;

	for (i = 0; i < sizeof(routes) / sizeof(routes[0]); ++i) {
		if (routes[i].command == command)
			return routes[i].handler(param_types, params);
	}
	EMSG("twep-wr-ta unsupported command 0x%x", command);
	return TEE_ERROR_NOT_SUPPORTED;
}
