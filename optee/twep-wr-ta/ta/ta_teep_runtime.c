/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */
#include "ta_runtime_internal.h"

#ifdef TWEP_TA_WAMR_LINK
bool twep_ta_ensure_wamr_runtime(void)
{
	if (g_wamr_runtime_initialized)
		return true;
	if (!wasm_runtime_init())
		return false;
	g_wamr_runtime_initialized = true;
	return true;
}

void twep_ta_wamr_cleanup_if_idle(void)
{
	if (!g_teep_agent_live_session_count) {
		wasm_runtime_destroy();
		g_wamr_runtime_initialized = false;
		g_teep_agent_natives_registered = false;
	}
}

TEE_Result execute_teep_agent_resolve(
	const struct bytes_view *request_id, const struct bytes_view *wasm,
	const struct bytes_view *input, const struct bytes_view *catalog,
	const struct bytes_view *app_wasm,
	const struct bytes_view *dev_agent_public_key,
	enum teep_agent_pending_hostcall replay, const uint8_t *replay_payload,
	size_t replay_payload_len, uint8_t *out, size_t out_size,
	size_t *out_len)
{
	char error_buf[128] = {};
	wasm_module_t module = NULL;
	wasm_module_inst_t module_inst = NULL;
	wasm_exec_env_t exec_env = NULL;
	wasm_function_inst_t main_func = NULL;
	wasm_function_inst_t free_func = NULL;
	wasm_function_inst_t abi_func = NULL;
	uint8_t *load_wasm = NULL;
	uint32_t input_ptr = 0;
	uint8_t *input_native = NULL;
	uint32_t desc_ptr = 0;
	uint8_t *desc_native = NULL;
	uint32_t argv[3] = {};
	uint32_t output_ptr = 0;
	uint32_t output_len = 0;
	uint8_t *output_native = NULL;
	struct teep_resolve_input resolve_input = {};
	struct teep_agent_hostcall_context host_ctx = {
		.teep_agent_wasm = *wasm,
		.catalog = *catalog,
		.app_wasm = *app_wasm,
		.request_id = request_id,
		.input = *input,
		.replay = replay,
		.replay_payload = replay_payload,
		.replay_payload_len = replay_payload_len,
	};
	TEE_Result res = TEE_SUCCESS;
	bool using_live_module = false;
	bool verified_acceptance;

	res = parse_teep_resolve_input(input, &resolve_input);
	if (res != TEE_SUCCESS) {
		IMSG("twep-wr-ta teep-agent resolve input rejected 0x%08x",
		     res);
		return res;
	}
	res = twep_ta_verify_teep_agent_wasm_signature(wasm);
	if (res != TEE_SUCCESS) {
		EMSG("twep-wr-ta teep-agent code signature rejected");
		return TEE_ERROR_SECURITY;
	}
	host_ctx.resolver_mode = resolve_input.resolver_mode;
	if (dev_agent_public_key && dev_agent_public_key->len) {
		res = teep_transient_object_write(
			&host_ctx, "teep-agent/dev-agent-public-key.cbor",
			sizeof("teep-agent/dev-agent-public-key.cbor") - 1,
			dev_agent_public_key->ptr,
			(uint32_t)dev_agent_public_key->len);
		if (res != TEE_SUCCESS)
			return res;
	}
	host_ctx.command = resolve_input.command;
	verified_acceptance = bytes_view_eq(&resolve_input.resolver_mode,
					    "attestam-verified");
	if (bytes_view_eq(&resolve_input.command, "resolve_app")) {
		if (verified_acceptance) {
			if (catalog->len || app_wasm->len)
				return TEE_ERROR_SECURITY;
		} else if (!catalog->ptr || !catalog->len ||
			   !wasm_magic_valid(app_wasm)) {
			return TEE_ERROR_BAD_FORMAT;
		}
	}
	if (!twep_ta_ensure_wamr_runtime())
		return TEE_ERROR_GENERIC;
	if (!g_teep_agent_natives_registered) {
		if (!wasm_runtime_register_natives(
			    "twep_teep_env", teep_agent_native_symbols,
			    sizeof(teep_agent_native_symbols) /
				    sizeof(teep_agent_native_symbols[0]))) {
			res = TEE_ERROR_GENERIC;
			goto out;
		}
		g_teep_agent_natives_registered = true;
	}
	if (g_teep_agent_live_session.active &&
	    g_teep_agent_live_session.module) {
		if (!g_teep_agent_live_session.module_wasm ||
		    !g_teep_agent_live_session.module_wasm_len) {
			res = TEE_ERROR_GENERIC;
			goto out;
		}
		module = g_teep_agent_live_session.module;
		using_live_module = true;
	} else {
		load_wasm = TEE_Malloc(wasm->len, 0);
		if (!load_wasm) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}
		TEE_MemMove(load_wasm, wasm->ptr, wasm->len);
		module = wasm_runtime_load(load_wasm, (uint32_t)wasm->len,
					   error_buf, sizeof(error_buf));
		if (!module) {
			EMSG("twep-wr-ta teep-agent load failed: %s",
			     error_buf);
			res = TEE_ERROR_BAD_FORMAT;
			goto out;
		}
	}
	module_inst = wasm_runtime_instantiate(module, PRODUCTION_STACK_SIZE,
					       PRODUCTION_HEAP_SIZE, error_buf,
					       sizeof(error_buf));
	if (!module_inst) {
		EMSG("twep-wr-ta teep-agent instantiate failed: %s", error_buf);
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	exec_env = wasm_runtime_create_exec_env(module_inst,
						PRODUCTION_STACK_SIZE);
	if (!exec_env) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	wasm_runtime_set_user_data(exec_env, &host_ctx);
	abi_func = wasm_runtime_lookup_function(module_inst,
						"twep_app_abi_version");
	if (!abi_func) {
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}
	if (!wasm_runtime_call_wasm(exec_env, abi_func, 0, argv) ||
	    argv[0] != 1) {
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}
	if (input->len) {
		void *native = NULL;

		input_ptr = (uint32_t)wasm_runtime_module_malloc(
			module_inst, input->len, &native);
		input_native = native;
		if (!input_ptr || !input_native) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}
		TEE_MemMove(input_native, input->ptr, input->len);
	}
	{
		void *native = NULL;

		desc_ptr = (uint32_t)wasm_runtime_module_malloc(module_inst, 8,
								&native);
		desc_native = native;
	}
	if (!desc_ptr || !desc_native) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	TEE_MemFill(desc_native, 0, 8);
	main_func = wasm_runtime_lookup_function(module_inst, "twep_app_main");
	if (!main_func) {
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}
	argv[0] = input_ptr;
	argv[1] = (uint32_t)input->len;
	argv[2] = desc_ptr;
	if (!wasm_runtime_call_wasm(exec_env, main_func, 3, argv)) {
		if (host_ctx.pending != TEEP_AGENT_PENDING_NONE) {
			res = teep_agent_pending_to_need_host_io(
				&host_ctx, out, out_size, out_len);
			if (res == TEE_SUCCESS && !using_live_module) {
				teep_agent_live_session_release();
				g_teep_agent_live_session.active = true;
				g_teep_agent_live_session.module = module;
				g_teep_agent_live_session.module_wasm =
					load_wasm;
				g_teep_agent_live_session.module_wasm_len =
					wasm->len;
				g_teep_agent_live_session_count++;
				module = NULL;
				load_wasm = NULL;
			}
			goto out;
		}
		EMSG("twep-wr-ta teep-agent call failed: %s",
		     wasm_runtime_get_exception(module_inst));
		res = TEE_ERROR_GENERIC;
		goto out;
	}
	if ((int32_t)argv[0] != 0) {
		if (host_ctx.pending != TEEP_AGENT_PENDING_NONE) {
			res = teep_agent_pending_to_need_host_io(
				&host_ctx, out, out_size, out_len);
			if (res == TEE_SUCCESS && !using_live_module) {
				teep_agent_live_session_release();
				g_teep_agent_live_session.active = true;
				g_teep_agent_live_session.module = module;
				g_teep_agent_live_session.module_wasm =
					load_wasm;
				g_teep_agent_live_session.module_wasm_len =
					wasm->len;
				g_teep_agent_live_session_count++;
				module = NULL;
				load_wasm = NULL;
			}
			goto out;
		}
		res = TEE_ERROR_GENERIC;
		goto out;
	}
	output_ptr = (uint32_t)desc_native[0] |
		     ((uint32_t)desc_native[1] << 8) |
		     ((uint32_t)desc_native[2] << 16) |
		     ((uint32_t)desc_native[3] << 24);
	output_len = (uint32_t)desc_native[4] |
		     ((uint32_t)desc_native[5] << 8) |
		     ((uint32_t)desc_native[6] << 16) |
		     ((uint32_t)desc_native[7] << 24);
	if (!output_ptr || !output_len || output_len > out_size ||
	    !wasm_runtime_validate_app_addr(module_inst, output_ptr,
					    output_len)) {
		res = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}
	output_native =
		wasm_runtime_addr_app_to_native(module_inst, output_ptr);
	if (!output_native) {
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}
	TEE_MemMove(out, output_native, output_len);
	*out_len = output_len;

out:
	if (output_ptr) {
		free_func = wasm_runtime_lookup_function(module_inst,
							 "twep_app_free");
		if (free_func) {
			uint32_t free_argv[2] = {output_ptr, output_len};

			(void)wasm_runtime_call_wasm(exec_env, free_func, 2,
						     free_argv);
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
	if (module && !using_live_module)
		wasm_runtime_unload(module);
	if (load_wasm)
		TEE_Free(load_wasm);
	if (g_wamr_runtime_initialized && !g_teep_agent_live_session_count) {
		wasm_runtime_destroy();
		g_wamr_runtime_initialized = false;
		g_teep_agent_natives_registered = false;
	}
	teep_hostcall_context_free(&host_ctx);
	return res;
}

TEE_Result resume_pending_teep_live(const struct bytes_view *request_id,
				    const struct bytes_view *host_io_result,
				    uint8_t *out, size_t out_size,
				    size_t *out_len)
{
	enum teep_agent_pending_hostcall replay_kind = TEEP_AGENT_PENDING_NONE;
	struct bytes_view replay_payload = {};
	struct bytes_view saved_request_id = {
		.ptr = (const uint8_t *)g_pending_teep_live.request_id_storage,
		.len = g_pending_teep_live.request_id_len,
	};
	struct bytes_view saved_command = {
		.ptr = (const uint8_t *)g_pending_teep_live.command_storage,
		.len = g_pending_teep_live.command_len,
	};
	struct bytes_view wasm = {
		.ptr = g_pending_teep_live.wasm,
		.len = g_pending_teep_live.wasm_len,
	};
	struct bytes_view input = {
		.ptr = g_pending_teep_live.input,
		.len = g_pending_teep_live.input_len,
	};
	struct bytes_view app_input = {
		.ptr = g_pending_teep_live.app_input,
		.len = g_pending_teep_live.app_input_len,
	};
	struct bytes_view catalog = {
		.ptr = g_pending_teep_live.catalog,
		.len = g_pending_teep_live.catalog_len,
	};
	struct bytes_view app_wasm = {
		.ptr = g_pending_teep_live.app_wasm,
		.len = g_pending_teep_live.app_wasm_len,
	};
	struct bytes_view dev_agent_public_key = {
		.ptr = g_pending_teep_live.dev_agent_public_key,
		.len = g_pending_teep_live.dev_agent_public_key_len,
	};
	uint8_t *teep_output = NULL;
	uint8_t *protected_app_owned = NULL;
	uint8_t authorized_app_digest[32] = {};
	uint8_t protected_app_digest[32] = {};
	uint8_t execute_output[4096] = {};
	struct bytes_view teep_result = {};
	struct bytes_view teep_code = {};
	struct bytes_view teep_message = {};
	struct bytes_view final_response = {};
	struct teep_resolve_input resolve_input = {};
	struct production_resource_limits resource_limits = {};
	size_t response_len = 0;
	size_t execute_len = 0;
	TEE_Result res = TEE_SUCCESS;

	if (!g_pending_teep_live.active ||
	    !pending_request_matches(request_id) ||
	    request_id->len != saved_request_id.len ||
	    TEE_MemCompare(request_id->ptr, saved_request_id.ptr,
			   request_id->len) != 0 ||
	    !host_io_result_ok(host_io_result))
		return TEE_ERROR_BAD_FORMAT;
	teep_output = TEE_Malloc(TEEP_AGENT_HOST_IO_RESPONSE_SIZE_MAX,
				 TEE_MALLOC_FILL_ZERO);
	if (!teep_output)
		return TEE_ERROR_OUT_OF_MEMORY;
	res = parse_host_io_result_payload(host_io_result, &replay_kind,
					   &replay_payload);
	if (res != TEE_SUCCESS)
		goto terminal_failure;
	res = pending_teep_live_append_history(replay_kind, &replay_payload);
	if (res != TEE_SUCCESS)
		goto terminal_failure;
	res = execute_teep_agent_resolve(
		&saved_request_id, &wasm, &input, &catalog, &app_wasm,
		&dev_agent_public_key, TEEP_AGENT_PENDING_NONE, NULL, 0,
		teep_output, TEEP_AGENT_HOST_IO_RESPONSE_SIZE_MAX,
		&response_len);
	if (res != TEE_SUCCESS)
		goto terminal_failure;
	teep_result.ptr = teep_output;
	teep_result.len = response_len;
	if (teep_output_is_need_host_io(&teep_result)) {
		if (response_len > out_size) {
			res = TEE_ERROR_SHORT_BUFFER;
			goto terminal_failure;
		}
		TEE_MemMove(out, teep_output, response_len);
		*out_len = response_len;
		IMSG("twep-wr-ta production teep-agent resumed to next host io "
		     "request");
		TEE_Free(teep_output);
		return TEE_SUCCESS;
	}
	if (parse_teep_error_output(&teep_result, &teep_code, &teep_message) ==
	    TEE_SUCCESS) {
		res = build_teep_error_execute_response(
			&saved_request_id, &teep_code, &teep_message,
			&saved_command, out, out_size, out_len);
		pending_host_io_clear(&g_pending_host_io);
		teep_agent_live_session_release();
		pending_teep_live_clear();
		if (res == TEE_SUCCESS)
			IMSG("twep-wr-ta production teep-agent resumed with "
			     "error");
		TEE_Free(teep_output);
		return res;
	}
	res = parse_teep_resolve_input(&input, &resolve_input);
	if (res == TEE_SUCCESS &&
	    !bytes_view_eq(&resolve_input.command, "resolve_app")) {
		res = build_final_response_wrapper(&saved_request_id,
						   &teep_result, out, out_size,
						   out_len);
		if (res == TEE_SUCCESS) {
			pending_host_io_clear(&g_pending_host_io);
			teep_agent_live_session_release();
			pending_teep_live_clear();
			IMSG("twep-wr-ta production teep-agent hostcall probe "
			     "resumed");
		}
		if (res != TEE_SUCCESS)
			goto terminal_failure;
		TEE_Free(teep_output);
		return TEE_SUCCESS;
	}
	if (res != TEE_SUCCESS)
		goto terminal_failure;
	production_resource_limits_default(&resource_limits);
	res = parse_teep_resource_limits_output(&teep_result, &resource_limits,
						authorized_app_digest);
	if (res != TEE_SUCCESS && res != TEE_ERROR_ITEM_NOT_FOUND)
		goto terminal_failure;
	if (bytes_view_eq(&resolve_input.resolver_mode, "attestam-verified")) {
		res = twep_load_protected_app(&app_wasm, &protected_app_owned,
					      protected_app_digest);
		if (res != TEE_SUCCESS)
			goto terminal_failure;
		if (TEE_MemCompare(authorized_app_digest, protected_app_digest,
				   32) != 0) {
			res = TEE_ERROR_SECURITY;
			goto terminal_failure;
		}
	}
	res = execute_production_app_wasm(&saved_request_id, &saved_command,
					  &app_input, &app_wasm,
					  &resource_limits, execute_output,
					  sizeof(execute_output), &execute_len);
	if (res != TEE_SUCCESS)
		goto terminal_failure;
	final_response.ptr = execute_output;
	final_response.len = execute_len;
	res = build_final_response_wrapper(&saved_request_id, &final_response,
					   out, out_size, out_len);
	if (res == TEE_SUCCESS) {
		pending_host_io_clear(&g_pending_host_io);
		teep_agent_live_session_release();
		pending_teep_live_clear();
		IMSG("twep-wr-ta production host io resumed and executed app");
	}
	if (protected_app_owned) {
		TEE_Free(protected_app_owned);
		protected_app_owned = NULL;
	}
	if (res != TEE_SUCCESS)
		goto terminal_failure;
	TEE_Free(teep_output);
	return TEE_SUCCESS;

terminal_failure:
	if (protected_app_owned)
		TEE_Free(protected_app_owned);
	pending_host_io_clear(&g_pending_host_io);
	teep_agent_live_session_release();
	pending_teep_live_clear();
	TEE_Free(teep_output);
	return res;
}
#endif
