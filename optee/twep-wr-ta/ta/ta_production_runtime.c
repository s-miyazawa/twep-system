/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */
#include "ta_runtime_internal.h"

static const uint8_t production_skeleton_response[] = {
	0xa2, 0x66, 's', 't',  'a',  't', 'u', 's', 0x6b, 'u', 'n', 's',
	'u',  'p',  'p', 'o',  'r',  't', 'e', 'd', 0x66, 'd', 'e', 't',
	'a',  'i',  'l', 0x78, 0x1e, 't', 'a', '-', 'p',  'r', 'o', 'd',
	'u',  'c',  't', 'i',  'o',  'n', '-', 'r', 'u',  'n', 't', 'i',
	'm',  'e',  '-', 's',  'k',  'e', 'l', 'e', 't',  'o', 'n',
};

struct twep_wr_session *g_session;
size_t g_pending_http_transcript_count;
size_t g_pending_http_transcript_bytes;
#ifdef TWEP_TA_WAMR_LINK
bool g_wamr_runtime_initialized;
bool g_teep_agent_natives_registered;
size_t g_teep_agent_live_session_count;
#endif

TEE_Result
twep_ta_cmd_production_envelope(uint32_t param_types, TEE_Param params[4],
				enum twep_ta_production_envelope_kind kind,
				const char *label)
{
	const uint32_t expected = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT,
		TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
	struct production_envelope_seen seen = {};
	TEE_Result res = TEE_SUCCESS;

	if (param_types != expected)
		return TEE_ERROR_BAD_PARAMETERS;
	if (params[0].memref.size == 0)
		return TEE_ERROR_BAD_PARAMETERS;
	if (params[1].memref.size < sizeof(production_skeleton_response)) {
		params[1].memref.size = sizeof(production_skeleton_response);
		IMSG("twep-wr-ta production %s rejected short output buffer",
		     label);
		return TEE_ERROR_SHORT_BUFFER;
	}

	res = parse_production_envelope(params[0].memref.buffer,
					params[0].memref.size, kind, &seen);
	if (res != TEE_SUCCESS) {
		IMSG("twep-wr-ta production %s rejected malformed envelope",
		     label);
		return res;
	}

	if (kind == TWEP_TA_ENVELOPE_EXECUTE &&
	    bytes_view_eq(&seen.command_view, "teep-agent-host-io")) {
		static const uint8_t body[] = {0xa1, 0x66, 'p', 'r',
					       'o',  'b',  'e', 0x01};
		size_t response_len = 0;

		res = build_need_host_io_response(
			&seen.request_id_view, &seen.command_view,
			&seen.app_input_view, "io-1",
			"https://ta.example.invalid/teep", body, sizeof(body),
			params[1].memref.buffer, params[1].memref.size,
			&response_len);
		params[1].memref.size = response_len;
		if (res == TEE_SUCCESS)
			IMSG("twep-wr-ta production host io requested");
		return res;
	}

	if (kind == TWEP_TA_ENVELOPE_EXECUTE &&
	    bytes_view_eq(&seen.command_view, "teep-agent-transcript-limit")) {
		size_t response_len = 0;

		res = build_need_host_io_response(
			&seen.request_id_view, &seen.command_view,
			&seen.app_input_view, "teep-http-limit-1",
			"https://ta.example.invalid/transcript-limit",
			seen.app_input_view.ptr, seen.app_input_view.len,
			params[1].memref.buffer, params[1].memref.size,
			&response_len);
		params[1].memref.size = response_len;
		if (res == TEE_SUCCESS)
			IMSG("twep-wr-ta pending HTTP transcript limit probe "
			     "requested");
		return res;
	}

	if (kind == TWEP_TA_ENVELOPE_EXECUTE &&
	    bytes_view_eq(&seen.command_view, "teep-agent-hostcall-http")) {
		static const uint8_t body[] = {
			0xa2, 0x64, 't', 'e', 'e', 'p', 0x6e, 'q', 'u', 'e',
			'r',  'y',  '-', 'r', 'e', 's', 'p',  'o', 'n', 's',
			'e',  0x67, 'p', 'u', 'r', 'p', 'o',  's', 'e', 0x77,
			't',  'e',  'e', 'p', '-', 'a', 'g',  'e', 'n', 't',
			'-',  'h',  'o', 's', 't', 'c', 'a',  'l', 'l', '-',
			's',  'm',  'o', 'k', 'e',
		};
		size_t response_len = 0;

		res = build_need_host_io_response(
			&seen.request_id_view, &seen.command_view,
			&seen.app_input_view, "teep-http-1",
			"https://ta.example.invalid/tam", body, sizeof(body),
			params[1].memref.buffer, params[1].memref.size,
			&response_len);
		params[1].memref.size = response_len;
		if (res == TEE_SUCCESS)
			IMSG("twep-wr-ta production teep-agent hostcall http "
			     "requested");
		return res;
	}

	if (kind == TWEP_TA_ENVELOPE_EXECUTE &&
	    bytes_view_eq(&seen.command_view, "teep-agent-hostcall-evidence")) {
		size_t response_len = 0;

		res = build_need_evidence_response(
			&seen.request_id_view, &seen.command_view,
			&seen.app_input_view, params[1].memref.buffer,
			params[1].memref.size, &response_len);
		params[1].memref.size = response_len;
		if (res == TEE_SUCCESS)
			IMSG("twep-wr-ta production teep-agent hostcall "
			     "evidence requested");
		return res;
	}

	if (kind == TWEP_TA_ENVELOPE_RESUME_HOST_IO) {
		size_t response_len = 0;

#ifdef TWEP_TA_WAMR_LINK
		if (g_pending_teep_live.active)
			res = resume_pending_teep_live(
				&seen.request_id_view,
				&seen.host_io_result_view,
				params[1].memref.buffer, params[1].memref.size,
				&response_len);
		else
#endif
			res = build_resume_final_response(
				&seen.request_id_view,
				&seen.host_io_result_view,
				params[1].memref.buffer, params[1].memref.size,
				&response_len);
		params[1].memref.size = response_len;
		if (res == TEE_SUCCESS)
			IMSG("twep-wr-ta production host io resumed");
		return res;
	}

	if (kind == TWEP_TA_ENVELOPE_EXECUTE && seen.wasm_view.ptr &&
	    seen.wasm_view.len) {
#ifdef TWEP_TA_WAMR_LINK
		struct production_resource_limits resource_limits = {};
		size_t response_len = 0;

		bool command_is_helloworld =
			seen.command_view.len == strlen("helloworld") &&
			TEE_MemCompare(seen.command_view.ptr, "helloworld",
				       strlen("helloworld")) == 0;
		bool command_is_remotehello =
			seen.command_view.len == strlen("remotehello") &&
			TEE_MemCompare(seen.command_view.ptr, "remotehello",
				       strlen("remotehello")) == 0;
		bool command_is_calcadd =
			seen.command_view.len == strlen("calcadd") &&
			TEE_MemCompare(seen.command_view.ptr, "calcadd",
				       strlen("calcadd")) == 0;
		bool command_is_negaposi =
			seen.command_view.len == strlen("negaposi") &&
			TEE_MemCompare(seen.command_view.ptr, "negaposi",
				       strlen("negaposi")) == 0;
		bool command_is_teep_agent_resolve =
			bytes_view_eq(&seen.command_view, "teep-agent-resolve");
		bool command_is_teep_agent_resolve_wrapped = bytes_view_eq(
			&seen.command_view, "teep-agent-resolve-wrapped");
		bool resolver_is_attestam_verified = bytes_view_eq(
			&seen.resolver_mode_view, "attestam-verified");

		production_resource_limits_default(&resource_limits);
		if (command_is_teep_agent_resolve ||
		    command_is_teep_agent_resolve_wrapped) {
			uint8_t *teep_output =
				TEE_Malloc(TEEP_AGENT_HOST_IO_RESPONSE_SIZE_MAX,
					   TEE_MALLOC_FILL_ZERO);
			if (!teep_output)
				return TEE_ERROR_OUT_OF_MEMORY;
			uint8_t *resolve_out =
				command_is_teep_agent_resolve_wrapped
					? teep_output
					: params[1].memref.buffer;
			size_t resolve_out_size =
				command_is_teep_agent_resolve_wrapped
					? TEEP_AGENT_HOST_IO_RESPONSE_SIZE_MAX
					: params[1].memref.size;

			res = execute_teep_agent_resolve(
				&seen.request_id_view, &seen.wasm_view,
				&seen.app_input_view, &seen.catalog_view,
				&seen.app_wasm_view,
				&seen.dev_agent_public_key_view,
				TEEP_AGENT_PENDING_NONE, NULL, 0, resolve_out,
				resolve_out_size, &response_len);
			if (res == TEE_SUCCESS &&
			    command_is_teep_agent_resolve_wrapped) {
				struct bytes_view teep_result = {
					.ptr = teep_output,
					.len = response_len,
				};
				struct bytes_view teep_code = {};
				struct bytes_view teep_message = {};

				if (parse_teep_error_output(
					    &teep_result, &teep_code,
					    &teep_message) == TEE_SUCCESS)
					res = build_teep_error_execute_response(
						&seen.request_id_view,
						&teep_code, &teep_message,
						&seen.command_view,
						params[1].memref.buffer,
						params[1].memref.size,
						&response_len);
				else if (response_len <= params[1].memref.size)
					TEE_MemMove(params[1].memref.buffer,
						    teep_output, response_len);
				else
					res = TEE_ERROR_SHORT_BUFFER;
			}
			if (res == TEE_SUCCESS) {
				struct bytes_view teep_result = {
					.ptr = resolve_out,
					.len = response_len,
				};

				if (teep_output_is_need_host_io(&teep_result)) {
					res = pending_teep_live_save(
						&seen.request_id_view,
						&seen.command_view,
						&seen.wasm_view,
						&seen.app_input_view,
						&seen.app_input_view,
						&seen.catalog_view,
						&seen.app_wasm_view,
						&seen.dev_agent_public_key_view);
					if (res != TEE_SUCCESS) {
						teep_agent_live_abort();
						TEE_Free(teep_output);
						return res;
					}
				}
			}
			if (res != TEE_SUCCESS)
				teep_agent_live_abort();
			params[1].memref.size = response_len;
			if (res == TEE_SUCCESS)
				IMSG("twep-wr-ta production teep-agent resolve "
				     "executed");
			TEE_Free(teep_output);
			return res;
		}
		if (!command_is_helloworld && !command_is_remotehello &&
		    !command_is_calcadd && !command_is_negaposi)
			return TEE_ERROR_NOT_SUPPORTED;
		struct bytes_view app_runtime_wasm = seen.wasm_view;
		if (resolver_is_attestam_verified ||
		    (seen.catalog_view.ptr && seen.catalog_view.len &&
		     seen.app_wasm_view.ptr && seen.app_wasm_view.len)) {
			uint8_t resolve_input_buf[256];
			uint8_t *teep_output =
				TEE_Malloc(TEEP_AGENT_HOST_IO_RESPONSE_SIZE_MAX,
					   TEE_MALLOC_FILL_ZERO);
			struct bytes_view resolve_input = {};
			struct bytes_view teep_result = {};
			struct bytes_view teep_code = {};
			struct bytes_view teep_message = {};
			if (!teep_output)
				return TEE_ERROR_OUT_OF_MEMORY;

			res = build_teep_resolve_input_for_command(
				&seen.command_view, &seen.resolver_mode_view,
				&seen.attestam_url_view, resolve_input_buf,
				sizeof(resolve_input_buf), &resolve_input);
			if (res != TEE_SUCCESS) {
				TEE_Free(teep_output);
				return res;
			}
			res = execute_teep_agent_resolve(
				&seen.request_id_view, &seen.wasm_view,
				&resolve_input, &seen.catalog_view,
				&seen.app_wasm_view,
				&seen.dev_agent_public_key_view,
				TEEP_AGENT_PENDING_NONE, NULL, 0, teep_output,
				TEEP_AGENT_HOST_IO_RESPONSE_SIZE_MAX,
				&response_len);
			if (res != TEE_SUCCESS) {
				teep_agent_live_abort();
				TEE_Free(teep_output);
				return res;
			}
			teep_result.ptr = teep_output;
			teep_result.len = response_len;
			if (teep_output_is_need_host_io(&teep_result)) {
				res = pending_teep_live_save(
					&seen.request_id_view,
					&seen.command_view, &seen.wasm_view,
					&resolve_input, &seen.app_input_view,
					&seen.catalog_view, &seen.app_wasm_view,
					&seen.dev_agent_public_key_view);
				if (res != TEE_SUCCESS) {
					teep_agent_live_abort();
					TEE_Free(teep_output);
					return res;
				}
				if (response_len > params[1].memref.size) {
					teep_agent_live_abort();
					TEE_Free(teep_output);
					return TEE_ERROR_SHORT_BUFFER;
				}
				TEE_MemMove(params[1].memref.buffer,
					    teep_output, response_len);
				params[1].memref.size = response_len;
				IMSG("twep-wr-ta production teep-agent "
				     "returned host io request");
				TEE_Free(teep_output);
				return TEE_SUCCESS;
			}
			if (parse_teep_error_output(&teep_result, &teep_code,
						    &teep_message) ==
			    TEE_SUCCESS) {
				res = build_teep_error_execute_response(
					&seen.request_id_view, &teep_code,
					&teep_message, &seen.command_view,
					params[1].memref.buffer,
					params[1].memref.size, &response_len);
				params[1].memref.size = response_len;
				TEE_Free(teep_output);
				return res;
			}
			if (resolver_is_attestam_verified) {
				TEE_Free(teep_output);
				return TEE_ERROR_SECURITY;
			}
			res = parse_teep_resource_limits_output(
				&teep_result, &resource_limits);
			if (res != TEE_SUCCESS &&
			    res != TEE_ERROR_ITEM_NOT_FOUND) {
				TEE_Free(teep_output);
				return res;
			}
			res = TEE_SUCCESS;
			app_runtime_wasm = seen.app_wasm_view;
			IMSG("twep-wr-ta production teep-agent resolved app");
			TEE_Free(teep_output);
		}
		res = execute_production_app_wasm(
			&seen.request_id_view, &seen.command_view,
			&seen.app_input_view, &app_runtime_wasm,
			&resource_limits, params[1].memref.buffer,
			params[1].memref.size, &response_len);
		params[1].memref.size = response_len;
		if (res == TEE_SUCCESS) {
			if (command_is_calcadd)
				IMSG("twep-wr-ta production executed calcadd");
			else if (command_is_negaposi)
				IMSG("twep-wr-ta production executed negaposi");
			else
				IMSG("twep-wr-ta production executed "
				     "helloworld");
		}
		return res;
#else
		IMSG("twep-wr-ta production blocker: WAMR runtime is not "
		     "linked into the "
		     "TA");
		return TEE_ERROR_NOT_SUPPORTED;
#endif
	}

	TEE_MemMove(params[1].memref.buffer, production_skeleton_response,
		    sizeof(production_skeleton_response));
	params[1].memref.size = sizeof(production_skeleton_response);
	IMSG("twep-wr-ta production %s envelope parsed", label);
	return TEE_SUCCESS;
}

void twep_ta_runtime_destroy(void)
{
#ifdef TWEP_TA_D043_TEST_HOOKS
	twep_ta_d043_runtime_test_reset();
	twep_acceptance_test_reset_fault();
#endif
#ifdef TWEP_TA_WAMR_LINK
	if (g_wamr_runtime_initialized) {
		wasm_runtime_destroy();
		g_wamr_runtime_initialized = false;
		g_teep_agent_natives_registered = false;
		g_teep_agent_live_session_count = 0;
	}
#endif
	g_session = NULL;
	g_pending_http_transcript_count = 0;
	g_pending_http_transcript_bytes = 0;
}

TEE_Result twep_ta_session_open(void **session)
{
	struct twep_wr_session *ctx = NULL;

	if (!session)
		return TEE_ERROR_BAD_STATE;
	ctx = TEE_Malloc(sizeof(*ctx), TEE_MALLOC_FILL_ZERO);
	if (!ctx)
		return TEE_ERROR_OUT_OF_MEMORY;
	*session = ctx;
	return TEE_SUCCESS;
}

void twep_ta_session_close(void *session)
{
	struct twep_wr_session *ctx = session;

	if (!ctx || g_session)
		return;
	g_session = ctx;
#ifdef TWEP_TA_WAMR_LINK
	teep_agent_live_session_release();
	pending_teep_live_clear();
#endif
	pending_host_io_clear(&g_pending_host_io);
	TEE_MemFill(ctx, 0, sizeof(*ctx));
	TEE_Free(ctx);
	g_session = NULL;
}

TEE_Result twep_ta_session_invoke(void *session, uint32_t command,
				  uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res = TEE_ERROR_NOT_SUPPORTED;

	if (!session || g_session)
		return TEE_ERROR_BAD_STATE;
	g_session = session;
	res = twep_ta_dispatch_command(command, param_types, params);
	g_session = NULL;
	return res;
}
