/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */
#include "ta_runtime_internal.h"

void pending_host_io_clear(struct pending_host_io_state *pending)
{
	if (!pending)
		return;
	if (pending->http_transcript) {
		if (g_pending_http_transcript_count)
			g_pending_http_transcript_count--;
		else
			EMSG("twep-wr-ta pending HTTP transcript count "
			     "underflow");
		if (g_pending_http_transcript_bytes >=
		    pending->request_body_len)
			g_pending_http_transcript_bytes -=
				pending->request_body_len;
		else {
			EMSG("twep-wr-ta pending HTTP transcript byte "
			     "underflow");
			g_pending_http_transcript_bytes = 0;
		}
	}
	if (pending->request_body) {
		TEE_MemFill(pending->request_body, 0,
			    pending->request_body_len);
		TEE_Free(pending->request_body);
	}
	TEE_MemFill(pending, 0, sizeof(*pending));
}

static TEE_Result save_pending_host_io_request(
	const struct bytes_view *request_id, const struct bytes_view *command,
	const struct bytes_view *input, const char *io_id, const char *kind,
	const uint8_t *request_body, size_t request_body_len)
{
	size_t io_id_len = strlen(io_id);
	size_t kind_len = strlen(kind);
	uint8_t *request_body_copy = NULL;
	TEE_Result res = TEE_SUCCESS;
	bool http_transcript = strcmp(kind, "http_post") == 0;

	pending_host_io_clear(&g_pending_host_io);
	if (http_transcript) {
		if (request_body_len > TEEP_AGENT_TRANSCRIPT_SIZE_MAX ||
		    g_pending_http_transcript_count >=
			    TEEP_AGENT_TRANSCRIPT_COUNT_MAX ||
		    g_pending_http_transcript_bytes >
			    TEEP_AGENT_TRANSCRIPT_AGGREGATE_SIZE_MAX ||
		    request_body_len >
			    TEEP_AGENT_TRANSCRIPT_AGGREGATE_SIZE_MAX -
				    g_pending_http_transcript_bytes)
			return TEE_ERROR_EXCESS_DATA;
	}
	if (!request_id->ptr || request_id->len == 0 ||
	    request_id->len >= sizeof(g_pending_host_io.request_id_storage) ||
	    !command->ptr || command->len == 0 ||
	    command->len >= sizeof(g_pending_host_io.command_storage) ||
	    io_id_len >= sizeof(g_pending_host_io.io_id_storage) ||
	    kind_len >= sizeof(g_pending_host_io.kind_storage))
		return TEE_ERROR_BAD_FORMAT;
	request_body_copy =
		TEE_Malloc(request_body_len ? request_body_len : 1, 0);
	if (!request_body_copy)
		return TEE_ERROR_OUT_OF_MEMORY;
	if (request_body_len)
		TEE_MemMove(request_body_copy, request_body, request_body_len);
	res = twep_ta_sha256_bytes(input->ptr, input->len,
				   g_pending_host_io.normalized_input_sha256);
	if (res != TEE_SUCCESS)
		goto err;
	res = twep_ta_sha256_bytes(request_body, request_body_len,
				   g_pending_host_io.request_body_sha256);
	if (res != TEE_SUCCESS)
		goto err;
	g_pending_host_io.request_body = request_body_copy;
	g_pending_host_io.request_body_len = request_body_len;
	TEE_MemMove(g_pending_host_io.request_id_storage, request_id->ptr,
		    request_id->len);
	TEE_MemMove(g_pending_host_io.command_storage, command->ptr,
		    command->len);
	TEE_MemMove(g_pending_host_io.io_id_storage, io_id, io_id_len);
	TEE_MemMove(g_pending_host_io.kind_storage, kind, kind_len);
	g_pending_host_io.sequence = 1;
	g_pending_host_io.request_id.ptr =
		(const uint8_t *)g_pending_host_io.request_id_storage;
	g_pending_host_io.request_id.len = request_id->len;
	g_pending_host_io.io_id.ptr =
		(const uint8_t *)g_pending_host_io.io_id_storage;
	g_pending_host_io.io_id.len = io_id_len;
	g_pending_host_io.kind.ptr =
		(const uint8_t *)g_pending_host_io.kind_storage;
	g_pending_host_io.kind.len = kind_len;
	g_pending_host_io.http_transcript = http_transcript;
	if (http_transcript) {
		g_pending_http_transcript_count++;
		g_pending_http_transcript_bytes += request_body_len;
	}
	g_pending_host_io.active = true;
	return TEE_SUCCESS;

err:
	TEE_MemFill(request_body_copy, 0, request_body_len);
	TEE_Free(request_body_copy);
	pending_host_io_clear(&g_pending_host_io);
	return res;
}

bool pending_request_matches(const struct bytes_view *request_id)
{
	return g_pending_host_io.active &&
	       request_id->len == g_pending_host_io.request_id.len &&
	       TEE_MemCompare(request_id->ptr, g_pending_host_io.request_id.ptr,
			      request_id->len) == 0;
}

TEE_Result build_need_host_io_response(const struct bytes_view *request_id,
				       const struct bytes_view *command,
				       const struct bytes_view *input,
				       const char *io_id, const char *url,
				       const uint8_t *body, size_t body_len,
				       uint8_t *out, size_t out_size,
				       size_t *out_len)
{
	const char *kind = "http_post";
	TEE_Result res = TEE_SUCCESS;
	size_t len = 1 + 1 + 14 + 1 + 1 + 10 +
		     cbor_type_len_size(request_id->len) + request_id->len + 1 +
		     12 + 1 + 1 + 5 + cbor_type_len_size(strlen(io_id)) +
		     strlen(io_id) + 1 + 4 + cbor_type_len_size(strlen(kind)) +
		     strlen(kind) + 1 + 3 + cbor_type_len_size(strlen(url)) +
		     strlen(url) + 1 + 4 + cbor_type_len_size(body_len) +
		     body_len + 1 + 8 + 1 + 1 + 19 + cbor_type_len_size(32) +
		     32 + 1 + 23 + cbor_type_len_size(32) + 32;
	uint8_t *p = out;

	res = save_pending_host_io_request(request_id, command, input, io_id,
					   kind, body, body_len);

	if (res != TEE_SUCCESS)
		return res;
	*out_len = len;
	if (out_size < len) {
		pending_host_io_clear(&g_pending_host_io);
		return TEE_ERROR_SHORT_BUFFER;
	}
	*p++ = 0xa3;
	cbor_write_text(&p, "schema_version");
	*p++ = 0x01;
	cbor_write_text(&p, "request_id");
	cbor_write_view_text(&p, &g_pending_host_io.request_id);
	cbor_write_text(&p, "need_host_io");
	*p++ = 0xa7;
	cbor_write_text(&p, "io_id");
	cbor_write_text(&p, io_id);
	cbor_write_text(&p, "kind");
	cbor_write_text(&p, kind);
	cbor_write_text(&p, "url");
	cbor_write_text(&p, url);
	cbor_write_text(&p, "body");
	cbor_write_bstr(&p, body, body_len);
	cbor_write_text(&p, "sequence");
	*p++ = (uint8_t)g_pending_host_io.sequence;
	cbor_write_text(&p, "request_body_sha256");
	cbor_write_bstr(&p, g_pending_host_io.request_body_sha256, 32);
	cbor_write_text(&p, "normalized_input_sha256");
	cbor_write_bstr(&p, g_pending_host_io.normalized_input_sha256, 32);
	return TEE_SUCCESS;
}

TEE_Result build_need_evidence_response_with_payload(
	const struct bytes_view *request_id, const struct bytes_view *command,
	const struct bytes_view *input, const uint8_t *challenge,
	size_t challenge_len, const uint8_t *agent_public_key_cose,
	size_t agent_public_key_cose_len, uint8_t *out, size_t out_size,
	size_t *out_len)
{
	const char *io_id = "teep-evidence-1";
	const char *kind = "create_evidence";
	size_t len = 1 + 1 + 14 + 1 + 1 + 10 +
		     cbor_type_len_size(request_id->len) + request_id->len + 1 +
		     12 + 1 + 1 + 5 + cbor_type_len_size(strlen(io_id)) +
		     strlen(io_id) + 1 + 4 + cbor_type_len_size(strlen(kind)) +
		     strlen(kind) + 1 + 9 + cbor_type_len_size(challenge_len) +
		     challenge_len + 1 + 21 +
		     cbor_type_len_size(agent_public_key_cose_len) +
		     agent_public_key_cose_len + 1 + 8 + 1 + 1 + 19 +
		     cbor_type_len_size(32) + 32 + 1 + 23 +
		     cbor_type_len_size(32) + 32;
	uint8_t *p = out;
	TEE_Result res =
		save_pending_host_io_request(request_id, command, input, io_id,
					     kind, challenge, challenge_len);

	if (res != TEE_SUCCESS)
		return res;
	*out_len = len;
	if (out_size < len) {
		pending_host_io_clear(&g_pending_host_io);
		return TEE_ERROR_SHORT_BUFFER;
	}
	*p++ = 0xa3;
	cbor_write_text(&p, "schema_version");
	*p++ = 0x01;
	cbor_write_text(&p, "request_id");
	cbor_write_view_text(&p, request_id);
	cbor_write_text(&p, "need_host_io");
	*p++ = 0xa7;
	cbor_write_text(&p, "io_id");
	cbor_write_text(&p, io_id);
	cbor_write_text(&p, "kind");
	cbor_write_text(&p, kind);
	cbor_write_text(&p, "challenge");
	cbor_write_bstr(&p, challenge, challenge_len);
	cbor_write_text(&p, "agent_public_key_cose");
	cbor_write_bstr(&p, agent_public_key_cose, agent_public_key_cose_len);
	cbor_write_text(&p, "sequence");
	*p++ = (uint8_t)g_pending_host_io.sequence;
	cbor_write_text(&p, "request_body_sha256");
	cbor_write_bstr(&p, g_pending_host_io.request_body_sha256, 32);
	cbor_write_text(&p, "normalized_input_sha256");
	cbor_write_bstr(&p, g_pending_host_io.normalized_input_sha256, 32);
	return TEE_SUCCESS;
}

TEE_Result build_need_evidence_response(const struct bytes_view *request_id,
					const struct bytes_view *command,
					const struct bytes_view *input,
					uint8_t *out, size_t out_size,
					size_t *out_len)
{
	static const uint8_t challenge[] = {0x10, 0x11, 0x12, 0x13,
					    0x14, 0x15, 0x16, 0x17};
	static const uint8_t agent_public_key_cose[] = {0xa1, 0x61, 'k', 0x63,
							'd',  'e',  'v'};

	return build_need_evidence_response_with_payload(
		request_id, command, input, challenge, sizeof(challenge),
		agent_public_key_cose, sizeof(agent_public_key_cose), out,
		out_size, out_len);
}

bool host_io_result_ok(const struct bytes_view *result)
{
	struct cbor_cursor cur = {
		.buf = result->ptr,
		.len = result->len,
		.off = 0,
	};
	bool io_id_ok = false;
	bool kind_ok = false;
	bool status_ok = false;
	bool sequence_ok = false;
	bool request_body_sha_ok = false;
	bool normalized_input_sha_ok = false;
	uint64_t map_len = 0;
	size_t i = 0;

	if (!result->ptr || result->len == 0 ||
	    !cbor_read_len(&cur, 5, &map_len))
		return false;
	for (i = 0; i < map_len; i++) {
		const uint8_t *key = NULL;
		size_t key_len = 0;

		if (!cbor_read_text_key(&cur, &key, &key_len))
			return false;
		if (key_eq(key, key_len, "io_id")) {
			struct bytes_view value = {};

			if (parse_text_value_view(&cur, &value) != TEE_SUCCESS)
				return false;
			io_id_ok = value.len == g_pending_host_io.io_id.len &&
				   TEE_MemCompare(value.ptr,
						  g_pending_host_io.io_id.ptr,
						  value.len) == 0;
		} else if (key_eq(key, key_len, "kind")) {
			struct bytes_view value = {};

			if (parse_text_value_view(&cur, &value) != TEE_SUCCESS)
				return false;
			kind_ok = value.len == g_pending_host_io.kind.len &&
				  TEE_MemCompare(value.ptr,
						 g_pending_host_io.kind.ptr,
						 value.len) == 0;
		} else if (key_eq(key, key_len, "status")) {
			uint64_t value = 0;

			if (!cbor_read_len(&cur, 0, &value))
				return false;
			status_ok = value == 0;
		} else if (key_eq(key, key_len, "sequence")) {
			uint64_t value = 0;

			if (!cbor_read_len(&cur, 0, &value))
				return false;
			sequence_ok = value == g_pending_host_io.sequence;
		} else if (key_eq(key, key_len, "request_body_sha256")) {
			struct bytes_view value = {};

			if (parse_bstr_value_view(&cur, &value) != TEE_SUCCESS)
				return false;
			request_body_sha_ok =
				value.len == 32 &&
				TEE_MemCompare(
					value.ptr,
					g_pending_host_io.request_body_sha256,
					32) == 0;
		} else if (key_eq(key, key_len, "normalized_input_sha256")) {
			struct bytes_view value = {};

			if (parse_bstr_value_view(&cur, &value) != TEE_SUCCESS)
				return false;
			normalized_input_sha_ok =
				value.len == 32 &&
				TEE_MemCompare(value.ptr,
					       g_pending_host_io
						       .normalized_input_sha256,
					       32) == 0;
		} else if (!cbor_skip_item(&cur, 0)) {
			return false;
		}
	}
	return cur.off == cur.len && io_id_ok && kind_ok && status_ok &&
	       sequence_ok && request_body_sha_ok && normalized_input_sha_ok;
}

#ifdef TWEP_TA_WAMR_LINK
void pending_teep_live_clear(void)
{
	size_t i = 0;

	if (g_pending_teep_live.wasm)
		TEE_Free(g_pending_teep_live.wasm);
	if (g_pending_teep_live.input)
		TEE_Free(g_pending_teep_live.input);
	if (g_pending_teep_live.app_input)
		TEE_Free(g_pending_teep_live.app_input);
	if (g_pending_teep_live.catalog)
		TEE_Free(g_pending_teep_live.catalog);
	if (g_pending_teep_live.app_wasm)
		TEE_Free(g_pending_teep_live.app_wasm);
	if (g_pending_teep_live.dev_agent_public_key)
		TEE_Free(g_pending_teep_live.dev_agent_public_key);
	for (i = 0; i < g_pending_teep_live.history_count; i++) {
		if (g_pending_teep_live.history[i].payload)
			TEE_Free(g_pending_teep_live.history[i].payload);
	}
	TEE_MemFill(&g_pending_teep_live, 0, sizeof(g_pending_teep_live));
}

static TEE_Result copy_view_alloc(const struct bytes_view *view, uint8_t **out,
				  size_t *out_len)
{
	uint8_t *copy = NULL;

	if (!view || !out || !out_len || (!view->ptr && view->len))
		return TEE_ERROR_BAD_PARAMETERS;
	copy = TEE_Malloc(view->len ? view->len : 1, 0);
	if (!copy)
		return TEE_ERROR_OUT_OF_MEMORY;
	if (view->len)
		TEE_MemMove(copy, view->ptr, view->len);
	*out = copy;
	*out_len = view->len;
	return TEE_SUCCESS;
}

TEE_Result pending_teep_live_save(const struct bytes_view *request_id,
				  const struct bytes_view *command,
				  const struct bytes_view *wasm,
				  const struct bytes_view *input,
				  const struct bytes_view *app_input,
				  const struct bytes_view *catalog,
				  const struct bytes_view *app_wasm,
				  const struct bytes_view *dev_agent_public_key)
{
	TEE_Result res = TEE_SUCCESS;

	if (!request_id || !request_id->ptr || request_id->len == 0 ||
	    request_id->len >= sizeof(g_pending_teep_live.request_id_storage) ||
	    !command || !command->ptr || command->len == 0 ||
	    command->len >= sizeof(g_pending_teep_live.command_storage))
		return TEE_ERROR_BAD_FORMAT;
	pending_teep_live_clear();
	TEE_MemMove(g_pending_teep_live.request_id_storage, request_id->ptr,
		    request_id->len);
	g_pending_teep_live.request_id_len = request_id->len;
	TEE_MemMove(g_pending_teep_live.command_storage, command->ptr,
		    command->len);
	g_pending_teep_live.command_len = command->len;
	res = copy_view_alloc(wasm, &g_pending_teep_live.wasm,
			      &g_pending_teep_live.wasm_len);
	if (res != TEE_SUCCESS)
		goto err;
#ifdef TWEP_TA_D043_TEST_HOOKS
	if (twep_ta_take_d043_runtime_test_fault(
		    TA_TWEP_WR_D043_FAULT_CONTINUATION_ALLOC)) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}
#endif
	res = copy_view_alloc(input, &g_pending_teep_live.input,
			      &g_pending_teep_live.input_len);
	if (res != TEE_SUCCESS)
		goto err;
	res = copy_view_alloc(app_input, &g_pending_teep_live.app_input,
			      &g_pending_teep_live.app_input_len);
	if (res != TEE_SUCCESS)
		goto err;
	res = copy_view_alloc(catalog, &g_pending_teep_live.catalog,
			      &g_pending_teep_live.catalog_len);
	if (res != TEE_SUCCESS)
		goto err;
	res = copy_view_alloc(app_wasm, &g_pending_teep_live.app_wasm,
			      &g_pending_teep_live.app_wasm_len);
	if (res != TEE_SUCCESS)
		goto err;
	res = copy_view_alloc(dev_agent_public_key,
			      &g_pending_teep_live.dev_agent_public_key,
			      &g_pending_teep_live.dev_agent_public_key_len);
	if (res != TEE_SUCCESS)
		goto err;
	g_pending_teep_live.active = true;
	IMSG("twep-wr-ta teep live saved wasm_len=%zu input_len=%zu "
	     "catalog_len=%zu "
	     "app_wasm_len=%zu",
	     g_pending_teep_live.wasm_len, g_pending_teep_live.input_len,
	     g_pending_teep_live.catalog_len, g_pending_teep_live.app_wasm_len);
	return TEE_SUCCESS;
err:
	pending_teep_live_clear();
	return res;
}

TEE_Result
pending_teep_live_append_history(enum teep_agent_pending_hostcall kind,
				 const struct bytes_view *payload)
{
	uint8_t *copy = NULL;
	size_t idx = g_pending_teep_live.history_count;

	if (!payload || (!payload->ptr && payload->len))
		return TEE_ERROR_BAD_PARAMETERS;
	if (idx >= TEEP_AGENT_HOST_IO_HISTORY_MAX)
		return TEE_ERROR_OUT_OF_MEMORY;
	copy = TEE_Malloc(payload->len ? payload->len : 1, 0);
	if (!copy)
		return TEE_ERROR_OUT_OF_MEMORY;
	if (payload->len)
		TEE_MemMove(copy, payload->ptr, payload->len);
	g_pending_teep_live.history[idx].kind = kind;
	g_pending_teep_live.history[idx].payload = copy;
	g_pending_teep_live.history[idx].payload_len = payload->len;
	g_pending_teep_live.history_count++;
	return TEE_SUCCESS;
}

TEE_Result
parse_host_io_result_payload(const struct bytes_view *result,
			     enum teep_agent_pending_hostcall *out_kind,
			     struct bytes_view *out_payload)
{
	struct cbor_cursor cur = {
		.buf = result->ptr,
		.len = result->len,
		.off = 0,
	};
	uint64_t map_len = 0;
	size_t i = 0;
	struct bytes_view kind = {};
	struct bytes_view response_body = {};
	struct bytes_view evidence = {};

	if (!out_kind || !out_payload || !result->ptr || !result->len ||
	    !cbor_read_len(&cur, 5, &map_len))
		return TEE_ERROR_BAD_FORMAT;
	for (i = 0; i < map_len; i++) {
		const uint8_t *key = NULL;
		size_t key_len = 0;

		if (!cbor_read_text_key(&cur, &key, &key_len))
			return TEE_ERROR_BAD_FORMAT;
		if (key_eq(key, key_len, "kind")) {
			if (parse_text_value_view(&cur, &kind) != TEE_SUCCESS)
				return TEE_ERROR_BAD_FORMAT;
		} else if (key_eq(key, key_len, "response_body")) {
			if (parse_bstr_value_view(&cur, &response_body) !=
			    TEE_SUCCESS)
				return TEE_ERROR_BAD_FORMAT;
		} else if (key_eq(key, key_len, "evidence")) {
			if (parse_bstr_value_view(&cur, &evidence) !=
			    TEE_SUCCESS)
				return TEE_ERROR_BAD_FORMAT;
		} else if (!cbor_skip_item(&cur, 0)) {
			return TEE_ERROR_BAD_FORMAT;
		}
	}
	if (cur.off != cur.len)
		return TEE_ERROR_BAD_FORMAT;
	if (bytes_view_eq(&kind, "http_post")) {
		*out_kind = TEEP_AGENT_PENDING_HTTP_POST;
		*out_payload = response_body;
		return TEE_SUCCESS;
	}
	if (bytes_view_eq(&kind, "create_evidence")) {
		*out_kind = TEEP_AGENT_PENDING_CREATE_EVIDENCE;
		*out_payload = evidence;
		return TEE_SUCCESS;
	}
	return TEE_ERROR_BAD_FORMAT;
}
#endif

TEE_Result build_resume_final_response(const struct bytes_view *request_id,
				       const struct bytes_view *result,
				       uint8_t *out, size_t out_size,
				       size_t *out_len)
{
	static const uint8_t final_response[] = {
		0xa3, 0x6e, 's', 'c', 'h',  'e', 'm',  'a',  '_', 'v',
		'e',  'r',  's', 'i', 'o',  'n', 0x01, 0x66, 's', 't',
		'a',  't',  'u', 's', 0x62, 'o', 'k',  0x66, 'd', 'e',
		't',  'a',  'i', 'l', 0x6e, 'h', 'o',  's',  't', '-',
		'i',  'o',  '-', 'r', 'e',  's', 'u',  'm',  'e',
	};
	size_t len = 1 + 1 + 14 + 1 + 1 + 10 +
		     cbor_type_len_size(request_id->len) + request_id->len + 1 +
		     19 + cbor_type_len_size(sizeof(final_response)) +
		     sizeof(final_response);
	uint8_t *p = out;

	if (!pending_request_matches(request_id) || !host_io_result_ok(result))
		return TEE_ERROR_BAD_FORMAT;
	pending_host_io_clear(&g_pending_host_io);
	*out_len = len;
	if (out_size < len)
		return TEE_ERROR_SHORT_BUFFER;
	*p++ = 0xa3;
	cbor_write_text(&p, "schema_version");
	*p++ = 0x01;
	cbor_write_text(&p, "request_id");
	cbor_write_view_text(&p, request_id);
	cbor_write_text(&p, "final_response_cbor");
	cbor_write_bstr(&p, final_response, sizeof(final_response));
	return TEE_SUCCESS;
}
