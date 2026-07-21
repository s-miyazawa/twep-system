/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */

#include "ta_internal.h"

#include <stdint.h>
#include <tee_internal_api_extensions.h>

#ifdef TWEP_TA_WAMR_LINK
#include <wasm_export.h>
#endif

#define WAMR_SPIKE_STACK_SIZE (16 * 1024)
#define WAMR_SPIKE_HEAP_SIZE (16 * 1024)
#define WAMR_SPIKE_MAX_INPUT_SIZE 64
#define WAMR_SPIKE_MAX_OUTPUT_SIZE 128

static const uint8_t wamr_spike_expected_input[] = {
	0xa1, 0x67, 'c', 'o', 'm', 'm', 'a', 'n', 'd',
	0x6a, 'h', 'e', 'l', 'l', 'o', 'w', 'o', 'r', 'l', 'd',
};

static TEE_Result validate_wamr_spike_input(const TEE_Param *param)
{
	if (param->memref.size == 0) {
		IMSG("twep-wr-ta WAMR spike rejected empty app input");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	if (param->memref.size > WAMR_SPIKE_MAX_INPUT_SIZE) {
		IMSG("twep-wr-ta WAMR spike rejected oversized app input");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	if (param->memref.size != sizeof(wamr_spike_expected_input) ||
	    TEE_MemCompare(param->memref.buffer, wamr_spike_expected_input,
			   sizeof(wamr_spike_expected_input)) != 0) {
		IMSG("twep-wr-ta WAMR spike rejected malformed app input");
		return TEE_ERROR_BAD_FORMAT;
	}
	return TEE_SUCCESS;
}

#ifdef TWEP_TA_WAMR_LINK
static bool read_leb_u32(const uint8_t *bytes, size_t len, size_t *pos,
			 uint32_t *value)
{
	uint32_t result = 0;
	uint32_t shift = 0;

	while (*pos < len && shift <= 28) {
		uint8_t byte = bytes[*pos];

		(*pos)++;
		result |= (uint32_t)(byte & 0x7f) << shift;
		if ((byte & 0x80) == 0) {
			*value = result;
			return true;
		}
		shift += 7;
	}
	return false;
}

bool twep_ta_wasm_has_import_section(const void *wasm, size_t wasm_len)
{
	const uint8_t *bytes = wasm;
	size_t pos = 8;

	if (wasm_len < 8)
		return false;
	if (bytes[0] != 0x00 || bytes[1] != 0x61 || bytes[2] != 0x73 ||
	    bytes[3] != 0x6d)
		return false;

	while (pos < wasm_len) {
		uint8_t section_id = bytes[pos++];
		uint32_t payload_len = 0;

		if (!read_leb_u32(bytes, wasm_len, &pos, &payload_len))
			return false;
		if (payload_len > wasm_len - pos)
			return false;
		if (section_id == 2)
			return true;
		pos += payload_len;
	}
	return false;
}
#endif

TEE_Result twep_ta_cmd_wamr_spike_exec(uint32_t param_types,
				      TEE_Param params[4])
{
	const uint32_t expected = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						 TEE_PARAM_TYPE_MEMREF_INPUT,
						 TEE_PARAM_TYPE_MEMREF_OUTPUT,
						 TEE_PARAM_TYPE_NONE);
#ifdef TWEP_TA_WAMR_LINK
	char error_buf[128] = { };
	wasm_module_t module = NULL;
	wasm_module_inst_t module_inst = NULL;
	wasm_exec_env_t exec_env = NULL;
	wasm_function_inst_t main_func = NULL;
	wasm_function_inst_t free_func = NULL;
	uint32_t input_ptr = 0;
	uint32_t desc_ptr = 0;
	void *input_native = NULL;
	void *desc_native = NULL;
	uint32_t argv[3] = { };
	uint32_t output_ptr = 0;
	uint32_t output_len = 0;
	uint8_t *output_native = NULL;
	TEE_Result res = TEE_SUCCESS;
#endif

	if (param_types != expected)
		return TEE_ERROR_BAD_PARAMETERS;
	if (params[0].memref.size == 0 || params[2].memref.size == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	{
		TEE_Result input_res = validate_wamr_spike_input(&params[1]);

		if (input_res != TEE_SUCCESS)
			return input_res;
	}

#ifdef TWEP_TA_WAMR_LINK
	if (!twep_ta_ensure_wamr_runtime()) {
		EMSG("twep-wr-ta WAMR spike init failed");
		return TEE_ERROR_GENERIC;
	}

	if (twep_ta_wasm_has_import_section(params[0].memref.buffer,
					    params[0].memref.size)) {
		IMSG("twep-wr-ta WAMR spike rejected unsupported Wasm import section");
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	module = wasm_runtime_load(params[0].memref.buffer,
				   (uint32_t)params[0].memref.size,
				   error_buf, sizeof(error_buf));
	if (!module) {
		EMSG("twep-wr-ta WAMR spike load failed: %s", error_buf);
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	module_inst = wasm_runtime_instantiate(module, WAMR_SPIKE_STACK_SIZE,
					       WAMR_SPIKE_HEAP_SIZE, error_buf,
					       sizeof(error_buf));
	if (!module_inst) {
		EMSG("twep-wr-ta WAMR spike instantiate failed: %s", error_buf);
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	exec_env = wasm_runtime_create_exec_env(module_inst, WAMR_SPIKE_STACK_SIZE);
	if (!exec_env) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	input_ptr = (uint32_t)wasm_runtime_module_malloc(module_inst,
							 params[1].memref.size,
							 &input_native);
	if (!input_ptr || !input_native) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	TEE_MemMove(input_native, params[1].memref.buffer, params[1].memref.size);

	desc_ptr = (uint32_t)wasm_runtime_module_malloc(module_inst, 8,
						       &desc_native);
	if (!desc_ptr || !desc_native) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	TEE_MemFill(desc_native, 0, 8);

	main_func = wasm_runtime_lookup_function(module_inst, "twep_app_main");
	if (!main_func) {
		IMSG("twep-wr-ta WAMR spike rejected missing twep_app_main");
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	argv[0] = input_ptr;
	argv[1] = (uint32_t)params[1].memref.size;
	argv[2] = desc_ptr;
	if (!wasm_runtime_call_wasm(exec_env, main_func, 3, argv)) {
		EMSG("twep-wr-ta WAMR spike call failed: %s",
		     wasm_runtime_get_exception(module_inst));
		res = TEE_ERROR_GENERIC;
		goto out;
	}
	if ((int32_t)argv[0] != 0) {
		IMSG("twep-wr-ta WAMR spike rejected app failure status");
		res = TEE_ERROR_GENERIC;
		goto out;
	}

	output_ptr = (uint32_t)((uint8_t *)desc_native)[0] |
		     ((uint32_t)((uint8_t *)desc_native)[1] << 8) |
		     ((uint32_t)((uint8_t *)desc_native)[2] << 16) |
		     ((uint32_t)((uint8_t *)desc_native)[3] << 24);
	output_len = (uint32_t)((uint8_t *)desc_native)[4] |
		     ((uint32_t)((uint8_t *)desc_native)[5] << 8) |
		     ((uint32_t)((uint8_t *)desc_native)[6] << 16) |
		     ((uint32_t)((uint8_t *)desc_native)[7] << 24);
	if (!output_ptr || !output_len) {
		IMSG("twep-wr-ta WAMR spike rejected invalid app output descriptor");
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}
	if (output_len > WAMR_SPIKE_MAX_OUTPUT_SIZE) {
		IMSG("twep-wr-ta WAMR spike rejected oversized app output");
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}
	if (!wasm_runtime_validate_app_addr(module_inst, output_ptr, output_len)) {
		IMSG("twep-wr-ta WAMR spike rejected invalid app output address");
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}
	if (params[2].memref.size < output_len) {
		IMSG("twep-wr-ta WAMR spike rejected short output buffer");
		params[2].memref.size = output_len;
		res = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}

	output_native = wasm_runtime_addr_app_to_native(module_inst, output_ptr);
	if (!output_native) {
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}
	TEE_MemMove(params[2].memref.buffer, output_native, output_len);
	params[2].memref.size = output_len;
	IMSG("twep-wr-ta WAMR spike executed helloworld");

out:
	if (output_ptr) {
		free_func = wasm_runtime_lookup_function(module_inst, "twep_app_free");
		if (free_func) {
			uint32_t free_argv[2] = { output_ptr, output_len };
			(void)wasm_runtime_call_wasm(exec_env, free_func, 2, free_argv);
		}
	}
	if (desc_ptr)
		wasm_runtime_module_free(module_inst, desc_ptr);
	if (input_ptr)
		wasm_runtime_module_free(module_inst, input_ptr);
	if (exec_env)
		wasm_runtime_destroy_exec_env(exec_env);
	if (module_inst)
		wasm_runtime_deinstantiate(module_inst);
	if (module)
		wasm_runtime_unload(module);
	twep_ta_wamr_cleanup_if_idle();
	return res;
#else
	IMSG("twep-wr-ta WAMR spike blocker: WAMR runtime is not linked into the TA");
	return TEE_ERROR_NOT_SUPPORTED;
#endif
}
