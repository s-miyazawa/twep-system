/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */
#include "ta_runtime_internal.h"

#ifdef TWEP_TA_WAMR_LINK
void cbor_write_uint64(uint8_t **p, uint64_t n)
{
	if (n < 24) {
		*(*p)++ = (uint8_t)n;
	} else if (n <= 0xff) {
		*(*p)++ = 0x18;
		*(*p)++ = (uint8_t)n;
	} else if (n <= 0xffff) {
		*(*p)++ = 0x19;
		*(*p)++ = (uint8_t)(n >> 8);
		*(*p)++ = (uint8_t)n;
	} else if (n <= 0xffffffff) {
		*(*p)++ = 0x1a;
		*(*p)++ = (uint8_t)(n >> 24);
		*(*p)++ = (uint8_t)(n >> 16);
		*(*p)++ = (uint8_t)(n >> 8);
		*(*p)++ = (uint8_t)n;
	} else {
		*(*p)++ = 0x1b;
		*(*p)++ = (uint8_t)(n >> 56);
		*(*p)++ = (uint8_t)(n >> 48);
		*(*p)++ = (uint8_t)(n >> 40);
		*(*p)++ = (uint8_t)(n >> 32);
		*(*p)++ = (uint8_t)(n >> 24);
		*(*p)++ = (uint8_t)(n >> 16);
		*(*p)++ = (uint8_t)(n >> 8);
		*(*p)++ = (uint8_t)n;
	}
}

TEE_Result extract_stdout_view(const uint8_t *app_output, size_t app_output_len,
			       struct bytes_view *stdout_view)
{
	struct cbor_cursor cur = {
		.buf = app_output,
		.len = app_output_len,
		.off = 0,
	};
	uint64_t map_len = 0;
	size_t i = 0;

	stdout_view->ptr = NULL;
	stdout_view->len = 0;
	if (!cbor_read_len(&cur, 5, &map_len))
		return TEE_ERROR_BAD_FORMAT;
	for (i = 0; i < map_len; i++) {
		const uint8_t *key = NULL;
		size_t key_len = 0;

		if (!cbor_read_text_key(&cur, &key, &key_len))
			return TEE_ERROR_BAD_FORMAT;
		if (key_eq(key, key_len, "stdout")) {
			TEE_Result res =
				parse_bstr_value_view(&cur, stdout_view);

			if (res != TEE_SUCCESS)
				return res;
		} else if (!cbor_skip_item(&cur, 0)) {
			return TEE_ERROR_BAD_FORMAT;
		}
	}
	if (cur.off != cur.len)
		return TEE_ERROR_BAD_FORMAT;
	return TEE_SUCCESS;
}

TEE_Result build_execute_response(const struct bytes_view *request_id,
				  const struct bytes_view *stdout_view,
				  const struct bytes_view *app_output,
				  uint8_t *out, size_t out_size,
				  size_t *out_len)
{
	size_t len =
		1 + 1 + 14 + 1 + 1 + 10 + cbor_type_len_size(request_id->len) +
		request_id->len + 1 + 6 + 1 + 2 + 1 + 9 + 1 + 1 + 6 +
		cbor_type_len_size(stdout_view->len) + stdout_view->len + 1 +
		10 + cbor_type_len_size(app_output->len) + app_output->len;
	uint8_t *p = out;

	*out_len = len;
	if (out_size < len)
		return TEE_ERROR_SHORT_BUFFER;

	*p++ = 0xa6;
	cbor_write_text(&p, "schema_version");
	*p++ = 0x01;
	cbor_write_text(&p, "request_id");
	cbor_write_type_len(&p, 3, request_id->len);
	TEE_MemMove(p, request_id->ptr, request_id->len);
	p += request_id->len;
	cbor_write_text(&p, "status");
	cbor_write_text(&p, "ok");
	cbor_write_text(&p, "exit_code");
	*p++ = 0x00;
	cbor_write_text(&p, "stdout");
	cbor_write_type_len(&p, 2, stdout_view->len);
	if (stdout_view->len) {
		TEE_MemMove(p, stdout_view->ptr, stdout_view->len);
		p += stdout_view->len;
	}
	cbor_write_text(&p, "app_output");
	cbor_write_type_len(&p, 2, app_output->len);
	if (app_output->len) {
		TEE_MemMove(p, app_output->ptr, app_output->len);
		p += app_output->len;
	}
	return TEE_SUCCESS;
}

TEE_Result build_final_response_wrapper(const struct bytes_view *request_id,
					const struct bytes_view *final_response,
					uint8_t *out, size_t out_size,
					size_t *out_len)
{
	size_t len = 1 + 1 + 14 + 1 + 1 + 10 +
		     cbor_type_len_size(request_id->len) + request_id->len + 1 +
		     19 + cbor_type_len_size(final_response->len) +
		     final_response->len;
	uint8_t *p = out;

	*out_len = len;
	if (out_size < len)
		return TEE_ERROR_SHORT_BUFFER;
	*p++ = 0xa3;
	cbor_write_text(&p, "schema_version");
	*p++ = 0x01;
	cbor_write_text(&p, "request_id");
	cbor_write_view_text(&p, request_id);
	cbor_write_text(&p, "final_response_cbor");
	cbor_write_bstr(&p, final_response->ptr, final_response->len);
	return TEE_SUCCESS;
}

TEE_Result execute_production_app_wasm(
	const struct bytes_view *request_id, const struct bytes_view *command,
	const struct bytes_view *app_input, const struct bytes_view *app_wasm,
	const struct production_resource_limits *limits, uint8_t *out,
	size_t out_size, size_t *out_len)
{
	char error_buf[128] = {};
	wasm_module_t module = NULL;
	wasm_module_inst_t module_inst = NULL;
	wasm_exec_env_t exec_env = NULL;
	wasm_function_inst_t main_func = NULL;
	wasm_function_inst_t free_func = NULL;
	wasm_function_inst_t abi_func = NULL;
	uint32_t input_ptr = 0;
	uint8_t *input_native = NULL;
	uint32_t desc_ptr = 0;
	uint8_t *desc_native = NULL;
	uint32_t argv[3] = {};
	uint32_t output_ptr = 0;
	uint32_t output_len = 0;
	uint8_t *output_native = NULL;
	struct bytes_view stdout_view = {};
	struct bytes_view app_output = {};
	size_t response_len = 0;
	TEE_Result res = TEE_SUCCESS;

	if (!twep_ta_ensure_wamr_runtime())
		return TEE_ERROR_GENERIC;
	if (twep_ta_wasm_has_import_section(app_wasm->ptr, app_wasm->len)) {
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}
	module = wasm_runtime_load((uint8_t *)app_wasm->ptr,
				   (uint32_t)app_wasm->len, error_buf,
				   sizeof(error_buf));
	if (!module) {
		EMSG("twep-wr-ta production live load failed: %s", error_buf);
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}
	module_inst = wasm_runtime_instantiate(module, limits->stack_bytes,
					       limits->heap_bytes, error_buf,
					       sizeof(error_buf));
	if (!module_inst) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	exec_env =
		wasm_runtime_create_exec_env(module_inst, limits->stack_bytes);
	if (!exec_env) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	abi_func = wasm_runtime_lookup_function(module_inst,
						"twep_app_abi_version");
	if (!abi_func || !wasm_runtime_call_wasm(exec_env, abi_func, 0, argv) ||
	    argv[0] != 1) {
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}
	if (app_input->len) {
		void *native = NULL;

		input_ptr = (uint32_t)wasm_runtime_module_malloc(
			module_inst, app_input->len, &native);
		input_native = native;
		if (!input_ptr || !input_native) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}
		TEE_MemMove(input_native, app_input->ptr, app_input->len);
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
	argv[1] = (uint32_t)app_input->len;
	argv[2] = desc_ptr;
	if (!wasm_runtime_call_wasm(exec_env, main_func, 3, argv) ||
	    (int32_t)argv[0] != 0) {
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
	if (!output_ptr || !output_len ||
	    !wasm_runtime_validate_app_addr(module_inst, output_ptr,
					    output_len)) {
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}
	if (output_len > limits->max_output_bytes) {
		res = build_app_runtime_error_execute_response(
			request_id, command, "app.resource_limit",
			"resource limit exceeded", "max_output_bytes", out,
			out_size, &response_len);
		*out_len = response_len;
		goto out;
	}
	output_native =
		wasm_runtime_addr_app_to_native(module_inst, output_ptr);
	if (!output_native) {
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}
	app_output.ptr = output_native;
	app_output.len = output_len;
	res = extract_stdout_view(output_native, output_len, &stdout_view);
	if (res != TEE_SUCCESS)
		goto out;
	res = build_execute_response(request_id, &stdout_view, &app_output, out,
				     out_size, &response_len);
	*out_len = response_len;

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
	if (module)
		wasm_runtime_unload(module);
	return res;
}

TEE_Result twep_load_protected_app(struct bytes_view *app, uint8_t **owned,
				   uint8_t digest[32])
{
	size_t app_len = 0;
	uint8_t *bytes;
	TEE_Result res;

	if (!app || !owned)
		return TEE_ERROR_BAD_PARAMETERS;
	*owned = NULL;
	app->ptr = NULL;
	app->len = 0;
	res = twep_app_read_active(NULL, 0, &app_len, NULL);
	if (res != TEE_ERROR_SHORT_BUFFER || !app_len ||
	    app_len > TWEP_PROTECTED_APP_MAX_SIZE)
		return res == TEE_SUCCESS ? TEE_ERROR_BAD_FORMAT : res;
	bytes = TEE_Malloc(app_len, 0);
	if (!bytes)
		return TEE_ERROR_OUT_OF_MEMORY;
	res = twep_app_read_active(bytes, app_len, &app_len, digest);
	if (res != TEE_SUCCESS) {
		TEE_Free(bytes);
		return res;
	}
	app->ptr = bytes;
	app->len = app_len;
	*owned = bytes;
	return TEE_SUCCESS;
}

TEE_Result parse_teep_error_output(const struct bytes_view *output,
				   struct bytes_view *code,
				   struct bytes_view *message)
{
	struct cbor_cursor cur = {
		.buf = output->ptr,
		.len = output->len,
		.off = 0,
	};
	uint64_t map_len = 0;
	size_t i = 0;
	bool status_error = false;
	bool have_code = false;
	bool have_message = false;

	if (!output->ptr || !output->len || !cbor_read_len(&cur, 5, &map_len))
		return TEE_ERROR_BAD_FORMAT;
	for (i = 0; i < map_len; i++) {
		const uint8_t *key = NULL;
		size_t key_len = 0;

		if (!cbor_read_text_key(&cur, &key, &key_len))
			return TEE_ERROR_BAD_FORMAT;
		if (key_eq(key, key_len, "status")) {
			struct bytes_view status = {};

			if (parse_text_value_view(&cur, &status) != TEE_SUCCESS)
				return TEE_ERROR_BAD_FORMAT;
			status_error = bytes_view_eq(&status, "error");
		} else if (key_eq(key, key_len, "error")) {
			uint64_t error_map_len = 0;
			size_t j = 0;

			if (!cbor_read_len(&cur, 5, &error_map_len))
				return TEE_ERROR_BAD_FORMAT;
			for (j = 0; j < error_map_len; j++) {
				const uint8_t *error_key = NULL;
				size_t error_key_len = 0;

				if (!cbor_read_text_key(&cur, &error_key,
							&error_key_len))
					return TEE_ERROR_BAD_FORMAT;
				if (key_eq(error_key, error_key_len, "code")) {
					if (parse_text_value_view(&cur, code) !=
					    TEE_SUCCESS)
						return TEE_ERROR_BAD_FORMAT;
					have_code = true;
				} else if (key_eq(error_key, error_key_len,
						  "message")) {
					if (parse_text_value_view(&cur,
								  message) !=
					    TEE_SUCCESS)
						return TEE_ERROR_BAD_FORMAT;
					have_message = true;
				} else if (!cbor_skip_item(&cur, 0)) {
					return TEE_ERROR_BAD_FORMAT;
				}
			}
		} else if (!cbor_skip_item(&cur, 0)) {
			return TEE_ERROR_BAD_FORMAT;
		}
	}
	if (cur.off != cur.len || !status_error || !have_code || !have_message)
		return TEE_ERROR_BAD_FORMAT;
	return TEE_SUCCESS;
}

bool teep_output_is_need_host_io(const struct bytes_view *output)
{
	struct cbor_cursor cur = {
		.buf = output->ptr,
		.len = output->len,
		.off = 0,
	};
	uint64_t map_len = 0;
	size_t i = 0;
	bool have_need_host_io = false;

	if (!output->ptr || !output->len || !cbor_read_len(&cur, 5, &map_len))
		return false;
	for (i = 0; i < map_len; i++) {
		const uint8_t *key = NULL;
		size_t key_len = 0;

		if (!cbor_read_text_key(&cur, &key, &key_len))
			return false;
		if (key_eq(key, key_len, "need_host_io"))
			have_need_host_io = true;
		if (!cbor_skip_item(&cur, 0))
			return false;
	}
	return cur.off == cur.len && have_need_host_io;
}

void production_resource_limits_default(
	struct production_resource_limits *limits)
{
	limits->stack_bytes = PRODUCTION_STACK_SIZE;
	limits->heap_bytes = PRODUCTION_HEAP_SIZE;
	limits->max_output_bytes = PRODUCTION_MAX_OUTPUT_SIZE;
}

static void
production_resource_limits_clamp(struct production_resource_limits *limits)
{
	if (!limits->stack_bytes || limits->stack_bytes > PRODUCTION_STACK_SIZE)
		limits->stack_bytes = PRODUCTION_STACK_SIZE;
	if (!limits->heap_bytes || limits->heap_bytes > PRODUCTION_HEAP_SIZE)
		limits->heap_bytes = PRODUCTION_HEAP_SIZE;
	if (!limits->max_output_bytes ||
	    limits->max_output_bytes > PRODUCTION_MAX_OUTPUT_SIZE)
		limits->max_output_bytes = PRODUCTION_MAX_OUTPUT_SIZE;
}

static TEE_Result
parse_production_resource_limits_map(struct cbor_cursor *cur,
				     struct production_resource_limits *limits)
{
	uint64_t map_len = 0;
	size_t i = 0;

	if (!cbor_read_len(cur, 5, &map_len))
		return TEE_ERROR_BAD_FORMAT;
	for (i = 0; i < map_len; i++) {
		const uint8_t *key = NULL;
		size_t key_len = 0;

		if (!cbor_read_text_key(cur, &key, &key_len))
			return TEE_ERROR_BAD_FORMAT;
		if (key_eq(key, key_len, "stack_bytes")) {
			TEE_Result res =
				parse_uint32_value(cur, &limits->stack_bytes);

			if (res != TEE_SUCCESS)
				return res;
		} else if (key_eq(key, key_len, "heap_bytes")) {
			TEE_Result res =
				parse_uint32_value(cur, &limits->heap_bytes);

			if (res != TEE_SUCCESS)
				return res;
		} else if (key_eq(key, key_len, "max_output_bytes")) {
			TEE_Result res = parse_uint32_value(
				cur, &limits->max_output_bytes);

			if (res != TEE_SUCCESS)
				return res;
		} else if (!cbor_skip_item(cur, 0)) {
			return TEE_ERROR_BAD_FORMAT;
		}
	}
	production_resource_limits_clamp(limits);
	return TEE_SUCCESS;
}

TEE_Result
parse_teep_resource_limits_output(const struct bytes_view *output,
				  struct production_resource_limits *limits,
				  uint8_t app_digest[32])
{
	struct cbor_cursor cur = {
		.buf = output->ptr,
		.len = output->len,
		.off = 0,
	};
	uint64_t map_len = 0;
	size_t i = 0;
	bool status_ok = false;
	bool have_app = false;
	bool have_limits = false;
	bool have_digest = false;

	if (!output->ptr || !output->len || !cbor_read_len(&cur, 5, &map_len))
		return TEE_ERROR_BAD_FORMAT;
	for (i = 0; i < map_len; i++) {
		const uint8_t *key = NULL;
		size_t key_len = 0;

		if (!cbor_read_text_key(&cur, &key, &key_len))
			return TEE_ERROR_BAD_FORMAT;
		if (key_eq(key, key_len, "status")) {
			struct bytes_view status = {};

			if (parse_text_value_view(&cur, &status) != TEE_SUCCESS)
				return TEE_ERROR_BAD_FORMAT;
			status_ok = bytes_view_eq(&status, "ok");
		} else if (key_eq(key, key_len, "app")) {
			uint64_t app_map_len = 0;
			size_t j = 0;

			if (!cbor_read_len(&cur, 5, &app_map_len))
				return TEE_ERROR_BAD_FORMAT;
			have_app = true;
			for (j = 0; j < app_map_len; j++) {
				const uint8_t *app_key = NULL;
				size_t app_key_len = 0;

				if (!cbor_read_text_key(&cur, &app_key,
							&app_key_len))
					return TEE_ERROR_BAD_FORMAT;
				if (key_eq(app_key, app_key_len,
					   "resource_limits")) {
					TEE_Result res =
						parse_production_resource_limits_map(
							&cur, limits);

					if (res != TEE_SUCCESS)
						return res;
					have_limits = true;
				} else if (key_eq(app_key, app_key_len,
						  "sha256")) {
					struct bytes_view digest = { };

					if (parse_bstr_value_view(&cur, &digest) !=
						    TEE_SUCCESS ||
					    digest.len != 32)
						return TEE_ERROR_BAD_FORMAT;
					if (app_digest)
						TEE_MemMove(app_digest, digest.ptr, 32);
					have_digest = true;
				} else if (!cbor_skip_item(&cur, 0)) {
					return TEE_ERROR_BAD_FORMAT;
				}
			}
		} else if (!cbor_skip_item(&cur, 0)) {
			return TEE_ERROR_BAD_FORMAT;
		}
	}
	if (cur.off != cur.len || !status_ok || !have_app || !have_digest)
		return TEE_ERROR_BAD_FORMAT;
	return have_limits ? TEE_SUCCESS : TEE_ERROR_ITEM_NOT_FOUND;
}

TEE_Result build_teep_error_execute_response(
	const struct bytes_view *request_id, const struct bytes_view *teep_code,
	const struct bytes_view *teep_message, const struct bytes_view *command,
	uint8_t *out, size_t out_size, size_t *out_len)
{
	const char *source = "teep-agent";
	size_t len = 1 + 1 + 14 + 1 + 1 + 10 +
		     cbor_type_len_size(request_id->len) + request_id->len + 1 +
		     6 + 1 + 5 + 1 + 9 + 1 + 1 + 5 + 1 + 1 + 4 +
		     cbor_type_len_size(teep_code->len) + teep_code->len + 1 +
		     7 + cbor_type_len_size(teep_message->len) +
		     teep_message->len + 1 + 7 + 1 + 1 + 6 +
		     cbor_type_len_size(strlen(source)) + strlen(source) + 1 +
		     9 + cbor_type_len_size(teep_code->len) + teep_code->len +
		     1 + 7 + cbor_type_len_size(command->len) + command->len;
	uint8_t *p = out;

	*out_len = len;
	if (out_size < len)
		return TEE_ERROR_SHORT_BUFFER;
	*p++ = 0xa5;
	cbor_write_text(&p, "schema_version");
	*p++ = 0x01;
	cbor_write_text(&p, "request_id");
	cbor_write_view_text(&p, request_id);
	cbor_write_text(&p, "status");
	cbor_write_text(&p, "error");
	cbor_write_text(&p, "exit_code");
	*p++ = 0x01;
	cbor_write_text(&p, "error");
	*p++ = 0xa3;
	cbor_write_text(&p, "code");
	cbor_write_view_text(&p, teep_code);
	cbor_write_text(&p, "message");
	cbor_write_view_text(&p, teep_message);
	cbor_write_text(&p, "details");
	*p++ = 0xa3;
	cbor_write_text(&p, "source");
	cbor_write_text(&p, source);
	cbor_write_text(&p, "teep_code");
	cbor_write_view_text(&p, teep_code);
	cbor_write_text(&p, "command");
	cbor_write_view_text(&p, command);
	return TEE_SUCCESS;
}

TEE_Result build_app_runtime_error_execute_response(
	const struct bytes_view *request_id, const struct bytes_view *command,
	const char *code, const char *message, const char *reason, uint8_t *out,
	size_t out_size, size_t *out_len)
{
	const char *source = "app-runtime";
	size_t code_len = strlen(code);
	size_t message_len = strlen(message);
	size_t reason_len = strlen(reason);
	size_t len =
		1 + 1 + 14 + 1 + 1 + 10 + cbor_type_len_size(request_id->len) +
		request_id->len + 1 + 6 + 1 + 5 + 1 + 9 + 1 + 1 + 5 + 1 + 1 +
		4 + cbor_type_len_size(code_len) + code_len + 1 + 7 +
		cbor_type_len_size(message_len) + message_len + 1 + 7 + 1 + 1 +
		6 + cbor_type_len_size(strlen(source)) + strlen(source) + 1 +
		7 + cbor_type_len_size(command->len) + command->len + 1 + 6 +
		cbor_type_len_size(reason_len) + reason_len;
	uint8_t *p = out;

	*out_len = len;
	if (out_size < len)
		return TEE_ERROR_SHORT_BUFFER;
	*p++ = 0xa5;
	cbor_write_text(&p, "schema_version");
	*p++ = 0x01;
	cbor_write_text(&p, "request_id");
	cbor_write_view_text(&p, request_id);
	cbor_write_text(&p, "status");
	cbor_write_text(&p, "error");
	cbor_write_text(&p, "exit_code");
	*p++ = 0x01;
	cbor_write_text(&p, "error");
	*p++ = 0xa3;
	cbor_write_text(&p, "code");
	cbor_write_text(&p, code);
	cbor_write_text(&p, "message");
	cbor_write_text(&p, message);
	cbor_write_text(&p, "details");
	*p++ = 0xa3;
	cbor_write_text(&p, "source");
	cbor_write_text(&p, source);
	cbor_write_text(&p, "command");
	cbor_write_view_text(&p, command);
	cbor_write_text(&p, "reason");
	cbor_write_text(&p, reason);
	return TEE_SUCCESS;
}

TEE_Result parse_teep_resolve_input(const struct bytes_view *input,
				    struct teep_resolve_input *out)
{
	struct cbor_cursor cur = {
		.buf = input->ptr,
		.len = input->len,
		.off = 0,
	};
	struct teep_resolve_input seen = {};
	uint64_t map_len = 0;
	size_t i = 0;

	if (!input->ptr || input->len == 0)
		return TEE_ERROR_BAD_FORMAT;
	if (!cbor_read_len(&cur, 5, &map_len))
		return TEE_ERROR_BAD_FORMAT;
	for (i = 0; i < map_len; i++) {
		const uint8_t *key = NULL;
		size_t key_len = 0;

		if (!cbor_read_text_key(&cur, &key, &key_len))
			return TEE_ERROR_BAD_FORMAT;
		if (key_eq(key, key_len, "command")) {
			TEE_Result res =
				parse_text_value_view(&cur, &seen.command);

			if (res != TEE_SUCCESS)
				return res;
		} else if (key_eq(key, key_len, "target_command")) {
			TEE_Result res = parse_text_value_view(
				&cur, &seen.target_command);

			if (res != TEE_SUCCESS)
				return res;
		} else if (key_eq(key, key_len, "resolver_mode")) {
			TEE_Result res = parse_text_value_view(
				&cur, &seen.resolver_mode);

			if (res != TEE_SUCCESS)
				return res;
		} else if (!cbor_skip_item(&cur, 0)) {
			return TEE_ERROR_BAD_FORMAT;
		}
	}
	if (cur.off != cur.len)
		return TEE_ERROR_BAD_FORMAT;
	if (bytes_view_eq(&seen.command, "hostcall_http_probe") ||
	    bytes_view_eq(&seen.command, "hostcall_evidence_probe") ||
	    bytes_view_eq(&seen.command, "hostcall_acceptance_probe_1") ||
	    bytes_view_eq(&seen.command, "hostcall_acceptance_probe_2") ||
	    bytes_view_eq(&seen.command, "hostcall_acceptance_probe_3") ||
	    bytes_view_eq(&seen.command, "hostcall_acceptance_probe_stale") ||
	    bytes_view_eq(&seen.command, "hostcall_bad_read_probe") ||
	    bytes_view_eq(&seen.command, "hostcall_bad_write_probe") ||
	    bytes_view_eq(&seen.command,
			  "hostcall_verified_result_write_probe")) {
		*out = seen;
		return TEE_SUCCESS;
	}
#ifdef TWEP_TA_D043_TEST_HOOKS
	if (bytes_view_eq(&seen.command,
			  "hostcall_acceptance_result_stale_probe")) {
		*out = seen;
		return TEE_SUCCESS;
	}
#endif
	if (!bytes_view_eq(&seen.command, "resolve_app") ||
	    !bytes_view_is_safe_command(&seen.target_command) ||
	    (!bytes_view_eq(&seen.resolver_mode, "mock") &&
	     !bytes_view_eq(&seen.resolver_mode, "attestam-insecure") &&
	     !bytes_view_eq(&seen.resolver_mode, "attestam-verified")))
		return TEE_ERROR_NOT_SUPPORTED;
	*out = seen;
	return TEE_SUCCESS;
}

TEE_Result
build_teep_resolve_input_for_command(const struct bytes_view *target_command,
				     const struct bytes_view *resolver_mode,
				     const struct bytes_view *attestam_url,
				     uint8_t *out, size_t out_size,
				     struct bytes_view *out_view)
{
	static const char default_resolver_mode[] = "mock";
	struct bytes_view mode = {
		.ptr = (const uint8_t *)default_resolver_mode,
		.len = sizeof(default_resolver_mode) - 1,
	};
	struct bytes_view url = {};
	size_t len =
		1 + cbor_type_len_size(strlen("schema_version")) +
		strlen("schema_version") + 1 +
		cbor_type_len_size(strlen("command")) + strlen("command") +
		cbor_type_len_size(strlen("resolve_app")) +
		strlen("resolve_app") +
		cbor_type_len_size(strlen("target_command")) +
		strlen("target_command") +
		cbor_type_len_size(target_command->len) + target_command->len +
		cbor_type_len_size(strlen("state_dir")) + strlen("state_dir") +
		1 + cbor_type_len_size(strlen("attestam_url")) +
		strlen("attestam_url") + 1;
	uint8_t *p = out;

	if (resolver_mode && resolver_mode->ptr && resolver_mode->len)
		mode = *resolver_mode;
	if (attestam_url && attestam_url->ptr && attestam_url->len)
		url = *attestam_url;
	len += cbor_type_len_size(strlen("resolver_mode")) +
	       strlen("resolver_mode") + cbor_type_len_size(mode.len) +
	       mode.len;
	len += cbor_type_len_size(strlen("attestam_url")) +
	       strlen("attestam_url") + cbor_type_len_size(url.len) + url.len;

	if (!target_command || !out || !out_view || len > out_size)
		return TEE_ERROR_SHORT_BUFFER;
	*p++ = 0xa6;
	cbor_write_text(&p, "schema_version");
	*p++ = 0x01;
	cbor_write_text(&p, "command");
	cbor_write_text(&p, "resolve_app");
	cbor_write_text(&p, "target_command");
	cbor_write_type_len(&p, 3, target_command->len);
	TEE_MemMove(p, target_command->ptr, target_command->len);
	p += target_command->len;
	cbor_write_text(&p, "resolver_mode");
	cbor_write_type_len(&p, 3, mode.len);
	TEE_MemMove(p, mode.ptr, mode.len);
	p += mode.len;
	cbor_write_text(&p, "state_dir");
	cbor_write_text(&p, "");
	cbor_write_text(&p, "attestam_url");
	cbor_write_type_len(&p, 3, url.len);
	if (url.len) {
		TEE_MemMove(p, url.ptr, url.len);
		p += url.len;
	}
	out_view->ptr = out;
	out_view->len = (size_t)(p - out);
	return TEE_SUCCESS;
}

bool wasm_magic_valid(const struct bytes_view *wasm)
{
	const uint8_t magic[] = {0x00, 0x61, 0x73, 0x6d};

	return wasm->ptr && wasm->len >= 8 &&
	       TEE_MemCompare(wasm->ptr, magic, sizeof(magic)) == 0;
}

#endif /* TWEP_TA_WAMR_LINK */
