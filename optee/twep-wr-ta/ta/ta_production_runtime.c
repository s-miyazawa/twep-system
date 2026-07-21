/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
// SPDX-License-Identifier: BSD-2-Clause

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <twep_wr_ta.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "acceptance_state.h"
#include "ta_internal.h"

#ifdef TWEP_TA_WAMR_LINK
#include <wasm_export.h>
#endif

#define PRODUCTION_STACK_SIZE (64 * 1024)
/* Bounded for a 128 KiB D047 response plus verified Catalog/COSE worksets. */
#define PRODUCTION_HEAP_SIZE (512 * 1024)
#define PRODUCTION_MAX_OUTPUT_SIZE (16 * 1024)
#define TEEP_AGENT_TRANSIENT_OBJECTS_MAX 64
#define TEEP_AGENT_TRANSIENT_OBJECT_NAME_MAX 96
#define TEEP_AGENT_TRANSIENT_OBJECT_SIZE_MAX (16 * 1024)
#define TEEP_AGENT_HOST_IO_HISTORY_MAX 8
#define TEEP_AGENT_TRANSCRIPT_SIZE_MAX (32 * 1024)
#define TEEP_AGENT_TRANSCRIPT_COUNT_MAX 2
#define TEEP_AGENT_TRANSCRIPT_AGGREGATE_SIZE_MAX (64 * 1024)
#define TEEP_AGENT_HOST_IO_RESPONSE_SIZE_MAX \
	(TEEP_AGENT_TRANSCRIPT_SIZE_MAX + 1024)

static const uint8_t production_skeleton_response[] = {
	0xa2,
	0x66, 's', 't', 'a', 't', 'u', 's',
	0x6b, 'u', 'n', 's', 'u', 'p', 'p', 'o', 'r', 't', 'e', 'd',
	0x66, 'd', 'e', 't', 'a', 'i', 'l',
	0x78, 0x1e,
	't', 'a', '-', 'p', 'r', 'o', 'd', 'u', 'c', 't', 'i', 'o', 'n',
	'-', 'r', 'u', 'n', 't', 'i', 'm', 'e', '-', 's', 'k', 'e', 'l',
	'e', 't', 'o', 'n',
};

struct cbor_cursor {
	const uint8_t *buf;
	size_t len;
	size_t off;
};

struct bytes_view {
	const uint8_t *ptr;
	size_t len;
};

struct production_resource_limits {
	uint32_t stack_bytes;
	uint32_t heap_bytes;
	uint32_t max_output_bytes;
};

enum teep_agent_pending_hostcall {
	TEEP_AGENT_PENDING_NONE = 0,
	TEEP_AGENT_PENDING_HTTP_POST,
	TEEP_AGENT_PENDING_CREATE_EVIDENCE,
};

struct production_envelope_seen {
	bool resolver_mode;
	bool attestam_url;
	bool insecure;
	bool default_timeout_ms;
	bool max_request_size;
	bool max_response_size;
	bool request_id;
	bool command;
	bool app_input_cbor;
	bool request_timeout_ms;
	bool host_io_result_cbor;
	struct bytes_view request_id_view;
	struct bytes_view command_view;
	struct bytes_view resolver_mode_view;
	struct bytes_view attestam_url_view;
	struct bytes_view app_input_view;
	struct bytes_view host_io_result_view;
	struct bytes_view wasm_view;
	struct bytes_view catalog_view;
	struct bytes_view app_wasm_view;
	struct bytes_view dev_agent_public_key_view;
};

struct pending_host_io_state {
	bool active;
	bool http_transcript;
	uint64_t sequence;
	struct bytes_view request_id;
	struct bytes_view io_id;
	struct bytes_view kind;
	uint8_t normalized_input_sha256[32];
	uint8_t request_body_sha256[32];
	uint8_t *request_body;
	size_t request_body_len;
	char request_id_storage[64];
	char command_storage[64];
	char io_id_storage[64];
	char kind_storage[32];
};

#ifdef TWEP_TA_WAMR_LINK
struct pending_teep_live_state {
	bool active;
	bool catalog_commit_recorded;
	uint8_t catalog_commit_query_digest[32];
	uint8_t catalog_commit_payload_digest[32];
	uint64_t catalog_commit_sequence;
	uint64_t catalog_commit_expected_generation;
	uint64_t catalog_commit_new_generation;
	uint32_t catalog_commit_payload_len;
	uint8_t *wasm;
	size_t wasm_len;
	uint8_t *input;
	size_t input_len;
	uint8_t *app_input;
	size_t app_input_len;
	uint8_t *catalog;
	size_t catalog_len;
	uint8_t *app_wasm;
	size_t app_wasm_len;
	uint8_t *dev_agent_public_key;
	size_t dev_agent_public_key_len;
	char request_id_storage[64];
	size_t request_id_len;
	char command_storage[64];
	size_t command_len;
	struct {
		enum teep_agent_pending_hostcall kind;
		uint8_t *payload;
		size_t payload_len;
	} history[TEEP_AGENT_HOST_IO_HISTORY_MAX];
	size_t history_count;
};

struct teep_agent_live_session {
	bool active;
	wasm_module_t module;
	uint8_t *module_wasm;
	size_t module_wasm_len;
};
#endif

struct twep_wr_session {
	struct pending_host_io_state pending_host_io;
#ifdef TWEP_TA_WAMR_LINK
	struct pending_teep_live_state pending_teep_live;
	struct teep_agent_live_session teep_agent_live_session;
#endif
};

/*
 * OP-TEE serializes entry to this single-instance, multi-session TA.  Keep
 * this pointer set only while servicing one session entry so native WAMR
 * hostcalls can reach that session's pending state.
 */
static struct twep_wr_session *g_session;
static size_t g_pending_http_transcript_count;
static size_t g_pending_http_transcript_bytes;

#define g_pending_host_io (g_session->pending_host_io)

#ifdef TWEP_TA_WAMR_LINK
#define g_pending_teep_live (g_session->pending_teep_live)
#define g_teep_agent_live_session (g_session->teep_agent_live_session)
static bool g_wamr_runtime_initialized;
static bool g_teep_agent_natives_registered;
static size_t g_teep_agent_live_session_count;
#endif

static bool cbor_read_len(struct cbor_cursor *cur, uint8_t want_major,
			  uint64_t *value)
{
	uint8_t initial = 0;
	uint8_t major = 0;
	uint8_t ai = 0;
	uint64_t out = 0;
	size_t needed = 0;
	size_t i = 0;

	if (cur->off >= cur->len)
		return false;
	initial = cur->buf[cur->off++];
	major = initial >> 5;
	ai = initial & 0x1f;
	if (major != want_major)
		return false;
	if (ai < 24) {
		*value = ai;
		return true;
	}
	if (ai == 24)
		needed = 1;
	else if (ai == 25)
		needed = 2;
	else if (ai == 26)
		needed = 4;
	else if (ai == 27)
		needed = 8;
	else
		return false;
	if (needed > cur->len - cur->off)
		return false;
	for (i = 0; i < needed; i++)
		out = (out << 8) | cur->buf[cur->off++];
	*value = out;
	return true;
}

static bool cbor_skip_item(struct cbor_cursor *cur, unsigned depth)
{
	uint8_t initial = 0;
	uint8_t major = 0;
	uint8_t ai = 0;
	uint64_t n = 0;
	size_t i = 0;

	if (depth > 8 || cur->off >= cur->len)
		return false;
	initial = cur->buf[cur->off];
	major = initial >> 5;
	ai = initial & 0x1f;

	switch (major) {
	case 0:
	case 1:
		return cbor_read_len(cur, major, &n);
	case 2:
	case 3:
		if (!cbor_read_len(cur, major, &n) || n > cur->len - cur->off)
			return false;
		cur->off += (size_t)n;
		return true;
	case 4:
		if (!cbor_read_len(cur, 4, &n))
			return false;
		for (i = 0; i < n; i++) {
			if (!cbor_skip_item(cur, depth + 1))
				return false;
		}
		return true;
	case 5:
		if (!cbor_read_len(cur, 5, &n))
			return false;
		for (i = 0; i < n; i++) {
			if (!cbor_skip_item(cur, depth + 1) ||
			    !cbor_skip_item(cur, depth + 1))
				return false;
		}
		return true;
	case 7:
		if (ai == 20 || ai == 21 || ai == 22 || ai == 23) {
			cur->off++;
			return true;
		}
		return false;
	default:
		return false;
	}
}

static bool cbor_read_text_key(struct cbor_cursor *cur, const uint8_t **key,
			       size_t *key_len)
{
	uint64_t n = 0;

	if (!cbor_read_len(cur, 3, &n) || n > cur->len - cur->off)
		return false;
	*key = cur->buf + cur->off;
	*key_len = (size_t)n;
	cur->off += (size_t)n;
	return true;
}

static bool key_eq(const uint8_t *key, size_t key_len, const char *want)
{
	size_t want_len = strlen(want);

	return key_len == want_len && TEE_MemCompare(key, want, want_len) == 0;
}

static TEE_Result parse_uint_value(struct cbor_cursor *cur)
{
	uint64_t value = 0;

	if (!cbor_read_len(cur, 0, &value))
		return TEE_ERROR_BAD_FORMAT;
	return TEE_SUCCESS;
}

static TEE_Result parse_bool_value(struct cbor_cursor *cur)
{
	if (cur->off >= cur->len)
		return TEE_ERROR_BAD_FORMAT;
	if (cur->buf[cur->off] != 0xf4 && cur->buf[cur->off] != 0xf5)
		return TEE_ERROR_BAD_FORMAT;
	cur->off++;
	return TEE_SUCCESS;
}

#ifdef TWEP_TA_WAMR_LINK
static TEE_Result parse_uint32_value(struct cbor_cursor *cur, uint32_t *out)
{
	uint64_t value = 0;

	if (!cbor_read_len(cur, 0, &value) || value > UINT32_MAX)
		return TEE_ERROR_BAD_FORMAT;
	*out = (uint32_t)value;
	return TEE_SUCCESS;
}
#endif

static TEE_Result parse_text_value_view(struct cbor_cursor *cur,
					struct bytes_view *view)
{
	uint64_t n = 0;

	if (!cbor_read_len(cur, 3, &n) || n > cur->len - cur->off || n == 0)
		return TEE_ERROR_BAD_FORMAT;
	view->ptr = cur->buf + cur->off;
	view->len = (size_t)n;
	cur->off += (size_t)n;
	return TEE_SUCCESS;
}

static TEE_Result parse_text_value_view_allow_empty(struct cbor_cursor *cur,
						    struct bytes_view *view)
{
	uint64_t n = 0;

	if (!cbor_read_len(cur, 3, &n) || n > cur->len - cur->off)
		return TEE_ERROR_BAD_FORMAT;
	view->ptr = cur->buf + cur->off;
	view->len = (size_t)n;
	cur->off += (size_t)n;
	return TEE_SUCCESS;
}

static TEE_Result parse_bstr_value_view(struct cbor_cursor *cur,
					struct bytes_view *view)
{
	uint64_t n = 0;

	if (!cbor_read_len(cur, 2, &n) || n > cur->len - cur->off)
		return TEE_ERROR_BAD_FORMAT;
	view->ptr = cur->buf + cur->off;
	view->len = (size_t)n;
	cur->off += (size_t)n;
	return TEE_SUCCESS;
}

static TEE_Result parse_production_envelope(
	const void *buf, size_t len, enum twep_ta_production_envelope_kind kind,
					    struct production_envelope_seen *out_seen)
{
	struct cbor_cursor cur = { .buf = buf, .len = len, .off = 0 };
	struct production_envelope_seen seen = { };
	uint64_t map_len = 0;
	size_t i = 0;

	if (!buf || len == 0)
		return TEE_ERROR_BAD_PARAMETERS;
	if (!cbor_read_len(&cur, 5, &map_len))
		return TEE_ERROR_BAD_FORMAT;

	for (i = 0; i < map_len; i++) {
		const uint8_t *key = NULL;
		size_t key_len = 0;
		TEE_Result res = TEE_SUCCESS;

		if (!cbor_read_text_key(&cur, &key, &key_len))
			return TEE_ERROR_BAD_FORMAT;
		if (key_eq(key, key_len, "resolver_mode")) {
			res = parse_text_value_view(&cur, &seen.resolver_mode_view);
			seen.resolver_mode = true;
		} else if (key_eq(key, key_len, "attestam_url")) {
			res = parse_text_value_view_allow_empty(
				&cur, &seen.attestam_url_view);
			seen.attestam_url = true;
		} else if (key_eq(key, key_len, "insecure")) {
			res = parse_bool_value(&cur);
			seen.insecure = true;
		} else if (key_eq(key, key_len, "default_timeout_ms")) {
			res = parse_uint_value(&cur);
			seen.default_timeout_ms = true;
		} else if (key_eq(key, key_len, "max_request_size")) {
			res = parse_uint_value(&cur);
			seen.max_request_size = true;
		} else if (key_eq(key, key_len, "max_response_size")) {
			res = parse_uint_value(&cur);
			seen.max_response_size = true;
		} else if (key_eq(key, key_len, "request_id")) {
			res = parse_text_value_view(&cur, &seen.request_id_view);
			seen.request_id = true;
		} else if (key_eq(key, key_len, "command")) {
			res = parse_text_value_view(&cur, &seen.command_view);
			seen.command = true;
		} else if (key_eq(key, key_len, "app_input_cbor")) {
			res = parse_bstr_value_view(&cur, &seen.app_input_view);
			seen.app_input_cbor = true;
		} else if (key_eq(key, key_len, "request_timeout_ms")) {
			res = parse_uint_value(&cur);
			seen.request_timeout_ms = true;
		} else if (key_eq(key, key_len, "host_io_result_cbor")) {
			res = parse_bstr_value_view(&cur,
						    &seen.host_io_result_view);
			seen.host_io_result_cbor = true;
		} else if (key_eq(key, key_len, "wasm_bytes")) {
			res = parse_bstr_value_view(&cur, &seen.wasm_view);
		} else if (key_eq(key, key_len, "catalog_cbor")) {
			res = parse_bstr_value_view(&cur, &seen.catalog_view);
		} else if (key_eq(key, key_len, "app_wasm_bytes")) {
			res = parse_bstr_value_view(&cur, &seen.app_wasm_view);
		} else if (key_eq(key, key_len, "dev_agent_public_key_cbor")) {
			res = parse_bstr_value_view(&cur,
						    &seen.dev_agent_public_key_view);
		} else if (!cbor_skip_item(&cur, 0)) {
			res = TEE_ERROR_BAD_FORMAT;
		}
		if (res != TEE_SUCCESS)
			return res;
	}
	if (cur.off != cur.len)
		return TEE_ERROR_BAD_FORMAT;

	if (kind == TWEP_TA_ENVELOPE_INIT &&
	    (!seen.resolver_mode || !seen.attestam_url || !seen.insecure ||
	     !seen.default_timeout_ms || !seen.max_request_size ||
	     !seen.max_response_size))
		return TEE_ERROR_BAD_FORMAT;
	if (kind == TWEP_TA_ENVELOPE_EXECUTE &&
	    (!seen.request_id || !seen.command || !seen.app_input_cbor ||
	     !seen.request_timeout_ms))
		return TEE_ERROR_BAD_FORMAT;
	if (kind == TWEP_TA_ENVELOPE_RESUME_HOST_IO &&
	    (!seen.request_id || !seen.host_io_result_cbor))
		return TEE_ERROR_BAD_FORMAT;

	if (out_seen)
		*out_seen = seen;
	return TEE_SUCCESS;
}

static size_t cbor_type_len_size(uint64_t n)
{
	if (n < 24)
		return 1;
	if (n <= 0xff)
		return 2;
	if (n <= 0xffff)
		return 3;
	if (n <= 0xffffffff)
		return 5;
	return 9;
}

static void cbor_write_type_len(uint8_t **p, uint8_t major, uint64_t n)
{
	if (n < 24) {
		*(*p)++ = (uint8_t)((major << 5) | n);
	} else if (n <= 0xff) {
		*(*p)++ = (uint8_t)((major << 5) | 24);
		*(*p)++ = (uint8_t)n;
	} else if (n <= 0xffff) {
		*(*p)++ = (uint8_t)((major << 5) | 25);
		*(*p)++ = (uint8_t)(n >> 8);
		*(*p)++ = (uint8_t)n;
	} else {
		*(*p)++ = (uint8_t)((major << 5) | 26);
		*(*p)++ = (uint8_t)(n >> 24);
		*(*p)++ = (uint8_t)(n >> 16);
		*(*p)++ = (uint8_t)(n >> 8);
		*(*p)++ = (uint8_t)n;
	}
}

static void cbor_write_text(uint8_t **p, const char *text)
{
	size_t len = strlen(text);

	cbor_write_type_len(p, 3, len);
	TEE_MemMove(*p, text, len);
	*p += len;
}

static void cbor_write_view_text(uint8_t **p, const struct bytes_view *view)
{
	cbor_write_type_len(p, 3, view->len);
	if (view->len) {
		TEE_MemMove(*p, view->ptr, view->len);
		*p += view->len;
	}
}

static void cbor_write_bstr(uint8_t **p, const uint8_t *bytes, size_t len)
{
	cbor_write_type_len(p, 2, len);
	if (len) {
		TEE_MemMove(*p, bytes, len);
		*p += len;
	}
}

static bool bytes_view_eq(const struct bytes_view *view, const char *want)
{
	size_t want_len = strlen(want);

	return view->len == want_len &&
	       TEE_MemCompare(view->ptr, want, want_len) == 0;
}

#ifdef TWEP_TA_WAMR_LINK
static bool object_name_eq(const char *ptr, uint32_t len, const char *want)
{
	size_t want_len = strlen(want);

	return len == want_len && TEE_MemCompare(ptr, want, want_len) == 0;
}
#endif

#ifdef TWEP_TA_WAMR_LINK
static bool bytes_view_is_safe_command(const struct bytes_view *view)
{
	size_t i = 0;

	if (!view->ptr || view->len == 0 || view->len > 32)
		return false;
	for (i = 0; i < view->len; i++) {
		uint8_t ch = view->ptr[i];

		if ((ch >= 'a' && ch <= 'z') ||
		    (ch >= 'A' && ch <= 'Z') ||
		    (ch >= '0' && ch <= '9') ||
		    ch == '_' || ch == '-')
			continue;
		return false;
	}
	return true;
}
#endif

TEE_Result twep_ta_sha256_bytes(const uint8_t *bytes, size_t len,
				uint8_t out[32])
{
	static const uint8_t empty = 0;
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_Result res = TEE_AllocateOperation(&op, TEE_ALG_SHA256,
					       TEE_MODE_DIGEST, 0);
	uint32_t out_len = 32;

	if (res != TEE_SUCCESS)
		return res;
	if (!bytes && len == 0)
		bytes = &empty;
	res = TEE_DigestDoFinal(op, (void *)bytes, len, out, &out_len);
	TEE_FreeOperation(op);
	if (res != TEE_SUCCESS || out_len != 32)
		return TEE_ERROR_GENERIC;
	return TEE_SUCCESS;
}

static void pending_host_io_clear(struct pending_host_io_state *pending)
{
	if (!pending)
		return;
	if (pending->http_transcript) {
		if (g_pending_http_transcript_count)
			g_pending_http_transcript_count--;
		else
			EMSG("twep-wr-ta pending HTTP transcript count underflow");
		if (g_pending_http_transcript_bytes >= pending->request_body_len)
			g_pending_http_transcript_bytes -= pending->request_body_len;
		else {
			EMSG("twep-wr-ta pending HTTP transcript byte underflow");
			g_pending_http_transcript_bytes = 0;
		}
	}
	if (pending->request_body) {
		TEE_MemFill(pending->request_body, 0, pending->request_body_len);
		TEE_Free(pending->request_body);
	}
	TEE_MemFill(pending, 0, sizeof(*pending));
}

static TEE_Result save_pending_host_io_request(const struct bytes_view *request_id,
					      const struct bytes_view *command,
					      const struct bytes_view *input,
					      const char *io_id,
					      const char *kind,
					      const uint8_t *request_body,
					      size_t request_body_len)
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
	request_body_copy = TEE_Malloc(request_body_len ? request_body_len : 1, 0);
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

static bool pending_request_matches(const struct bytes_view *request_id)
{
	return g_pending_host_io.active &&
	       request_id->len == g_pending_host_io.request_id.len &&
	       TEE_MemCompare(request_id->ptr, g_pending_host_io.request_id.ptr,
			      request_id->len) == 0;
}

static TEE_Result build_need_host_io_response(const struct bytes_view *request_id,
					     const struct bytes_view *command,
					     const struct bytes_view *input,
					     const char *io_id,
					     const char *url,
					     const uint8_t *body,
					     size_t body_len,
					     uint8_t *out, size_t out_size,
					     size_t *out_len)
{
	const char *kind = "http_post";
	TEE_Result res = TEE_SUCCESS;
	size_t len = 1
		     + 1 + 14 + 1
		     + 1 + 10 + cbor_type_len_size(request_id->len) + request_id->len
		     + 1 + 12 + 1
		     + 1 + 5 + cbor_type_len_size(strlen(io_id)) + strlen(io_id)
		     + 1 + 4 + cbor_type_len_size(strlen(kind)) + strlen(kind)
		     + 1 + 3 + cbor_type_len_size(strlen(url)) + strlen(url)
		     + 1 + 4 + cbor_type_len_size(body_len) + body_len
		     + 1 + 8 + 1
		     + 1 + 19 + cbor_type_len_size(32) + 32
		     + 1 + 23 + cbor_type_len_size(32) + 32;
	uint8_t *p = out;

	res = save_pending_host_io_request(request_id, command, input,
					   io_id, kind, body, body_len);

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

static TEE_Result build_need_evidence_response_with_payload(
					       const struct bytes_view *request_id,
					       const struct bytes_view *command,
					       const struct bytes_view *input,
					       const uint8_t *challenge,
					       size_t challenge_len,
					       const uint8_t *agent_public_key_cose,
					       size_t agent_public_key_cose_len,
					       uint8_t *out, size_t out_size,
					       size_t *out_len)
{
	const char *io_id = "teep-evidence-1";
	const char *kind = "create_evidence";
	size_t len = 1
		     + 1 + 14 + 1
		     + 1 + 10 + cbor_type_len_size(request_id->len) + request_id->len
		     + 1 + 12 + 1
		     + 1 + 5 + cbor_type_len_size(strlen(io_id)) + strlen(io_id)
		     + 1 + 4 + cbor_type_len_size(strlen(kind)) + strlen(kind)
		     + 1 + 9 + cbor_type_len_size(challenge_len) + challenge_len
		     + 1 + 21 + cbor_type_len_size(agent_public_key_cose_len) +
		       agent_public_key_cose_len
		     + 1 + 8 + 1
		     + 1 + 19 + cbor_type_len_size(32) + 32
		     + 1 + 23 + cbor_type_len_size(32) + 32;
	uint8_t *p = out;
	TEE_Result res = save_pending_host_io_request(
		request_id, command, input, io_id, kind, challenge,
		challenge_len);

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
	cbor_write_bstr(&p, agent_public_key_cose,
			agent_public_key_cose_len);
	cbor_write_text(&p, "sequence");
	*p++ = (uint8_t)g_pending_host_io.sequence;
	cbor_write_text(&p, "request_body_sha256");
	cbor_write_bstr(&p, g_pending_host_io.request_body_sha256, 32);
	cbor_write_text(&p, "normalized_input_sha256");
	cbor_write_bstr(&p, g_pending_host_io.normalized_input_sha256, 32);
	return TEE_SUCCESS;
}

static TEE_Result build_need_evidence_response(const struct bytes_view *request_id,
					       const struct bytes_view *command,
					       const struct bytes_view *input,
					       uint8_t *out, size_t out_size,
					       size_t *out_len)
{
	static const uint8_t challenge[] = {
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
	};
	static const uint8_t agent_public_key_cose[] = {
		0xa1, 0x61, 'k', 0x63, 'd', 'e', 'v'
	};

	return build_need_evidence_response_with_payload(
		request_id, command, input, challenge, sizeof(challenge),
		agent_public_key_cose, sizeof(agent_public_key_cose), out,
		out_size, out_len);
}

static bool host_io_result_ok(const struct bytes_view *result)
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
			struct bytes_view value = { };

			if (parse_text_value_view(&cur, &value) != TEE_SUCCESS)
				return false;
			io_id_ok = value.len == g_pending_host_io.io_id.len &&
				   TEE_MemCompare(value.ptr,
						  g_pending_host_io.io_id.ptr,
						  value.len) == 0;
		} else if (key_eq(key, key_len, "kind")) {
			struct bytes_view value = { };

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
			struct bytes_view value = { };

			if (parse_bstr_value_view(&cur, &value) != TEE_SUCCESS)
				return false;
			request_body_sha_ok = value.len == 32 &&
					      TEE_MemCompare(value.ptr,
							     g_pending_host_io.request_body_sha256,
							     32) == 0;
		} else if (key_eq(key, key_len, "normalized_input_sha256")) {
			struct bytes_view value = { };

			if (parse_bstr_value_view(&cur, &value) != TEE_SUCCESS)
				return false;
			normalized_input_sha_ok =
				value.len == 32 &&
				TEE_MemCompare(value.ptr,
					       g_pending_host_io.normalized_input_sha256,
					       32) == 0;
		} else if (!cbor_skip_item(&cur, 0)) {
			return false;
		}
	}
	return cur.off == cur.len && io_id_ok && kind_ok && status_ok &&
	       sequence_ok && request_body_sha_ok && normalized_input_sha_ok;
}

#ifdef TWEP_TA_WAMR_LINK
static void pending_teep_live_clear(void)
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

static TEE_Result copy_view_alloc(const struct bytes_view *view,
				  uint8_t **out, size_t *out_len)
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

static TEE_Result pending_teep_live_save(const struct bytes_view *request_id,
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
	IMSG("twep-wr-ta teep live saved wasm_len=%zu input_len=%zu catalog_len=%zu app_wasm_len=%zu",
	     g_pending_teep_live.wasm_len, g_pending_teep_live.input_len,
	     g_pending_teep_live.catalog_len, g_pending_teep_live.app_wasm_len);
	return TEE_SUCCESS;
err:
	pending_teep_live_clear();
	return res;
}

static TEE_Result pending_teep_live_append_history(
			enum teep_agent_pending_hostcall kind,
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

static TEE_Result parse_host_io_result_payload(
				const struct bytes_view *result,
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
	struct bytes_view kind = { };
	struct bytes_view response_body = { };
	struct bytes_view evidence = { };

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
			if (parse_bstr_value_view(&cur, &evidence) != TEE_SUCCESS)
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

static TEE_Result build_resume_final_response(const struct bytes_view *request_id,
					     const struct bytes_view *result,
					     uint8_t *out, size_t out_size,
					     size_t *out_len)
{
	static const uint8_t final_response[] = {
		0xa3,
		0x6e, 's', 'c', 'h', 'e', 'm', 'a', '_', 'v', 'e', 'r', 's', 'i', 'o', 'n',
		0x01,
		0x66, 's', 't', 'a', 't', 'u', 's',
		0x62, 'o', 'k',
		0x66, 'd', 'e', 't', 'a', 'i', 'l',
		0x6e, 'h', 'o', 's', 't', '-', 'i', 'o', '-', 'r', 'e', 's', 'u', 'm', 'e',
	};
	size_t len = 1
		     + 1 + 14 + 1
		     + 1 + 10 + cbor_type_len_size(request_id->len) + request_id->len
		     + 1 + 19 + cbor_type_len_size(sizeof(final_response)) +
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

#ifdef TWEP_TA_WAMR_LINK
static void cbor_write_uint64(uint8_t **p, uint64_t n)
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

static TEE_Result extract_stdout_view(const uint8_t *app_output,
				      size_t app_output_len,
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
			TEE_Result res = parse_bstr_value_view(&cur, stdout_view);

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

static TEE_Result build_execute_response(const struct bytes_view *request_id,
					 const struct bytes_view *stdout_view,
					 const struct bytes_view *app_output,
					 uint8_t *out, size_t out_size,
					 size_t *out_len)
{
	size_t len = 1
		     + 1 + 14 + 1
		     + 1 + 10 + cbor_type_len_size(request_id->len) + request_id->len
		     + 1 + 6 + 1 + 2
		     + 1 + 9 + 1
		     + 1 + 6 + cbor_type_len_size(stdout_view->len) + stdout_view->len
		     + 1 + 10 + cbor_type_len_size(app_output->len) + app_output->len;
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

static TEE_Result build_app_runtime_error_execute_response(
	const struct bytes_view *request_id,
	const struct bytes_view *command,
	const char *code,
	const char *message,
	const char *reason,
	uint8_t *out,
	size_t out_size,
	size_t *out_len);

static TEE_Result build_final_response_wrapper(const struct bytes_view *request_id,
					       const struct bytes_view *final_response,
					       uint8_t *out, size_t out_size,
					       size_t *out_len)
{
	size_t len = 1
		     + 1 + 14 + 1
		     + 1 + 10 + cbor_type_len_size(request_id->len) + request_id->len
		     + 1 + 19 + cbor_type_len_size(final_response->len) +
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

static TEE_Result execute_production_app_wasm(const struct bytes_view *request_id,
					      const struct bytes_view *command,
					      const struct bytes_view *app_input,
					      const struct bytes_view *app_wasm,
					      const struct production_resource_limits *limits,
					      uint8_t *out, size_t out_size,
					      size_t *out_len)
{
	char error_buf[128] = { };
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
	uint32_t argv[3] = { };
	uint32_t output_ptr = 0;
	uint32_t output_len = 0;
	uint8_t *output_native = NULL;
	struct bytes_view stdout_view = { };
	struct bytes_view app_output = { };
	size_t response_len = 0;
	TEE_Result res = TEE_SUCCESS;

	if (!twep_ta_ensure_wamr_runtime())
		return TEE_ERROR_GENERIC;
	if (twep_ta_wasm_has_import_section(app_wasm->ptr, app_wasm->len)) {
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}
	module = wasm_runtime_load((uint8_t *)app_wasm->ptr,
				   (uint32_t)app_wasm->len,
				   error_buf, sizeof(error_buf));
	if (!module) {
		EMSG("twep-wr-ta production live load failed: %s", error_buf);
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}
	module_inst = wasm_runtime_instantiate(module, limits->stack_bytes,
					       limits->heap_bytes,
					       error_buf, sizeof(error_buf));
	if (!module_inst) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	exec_env = wasm_runtime_create_exec_env(module_inst,
						limits->stack_bytes);
	if (!exec_env) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	abi_func = wasm_runtime_lookup_function(module_inst,
						"twep_app_abi_version");
	if (!abi_func ||
	    !wasm_runtime_call_wasm(exec_env, abi_func, 0, argv) ||
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
			"resource limit exceeded", "max_output_bytes",
			out, out_size, &response_len);
		*out_len = response_len;
		goto out;
	}
	output_native = wasm_runtime_addr_app_to_native(module_inst, output_ptr);
	if (!output_native) {
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}
	app_output.ptr = output_native;
	app_output.len = output_len;
	res = extract_stdout_view(output_native, output_len, &stdout_view);
	if (res != TEE_SUCCESS)
		goto out;
	res = build_execute_response(request_id, &stdout_view, &app_output,
				     out, out_size, &response_len);
	*out_len = response_len;

out:
	if (output_ptr) {
		free_func = wasm_runtime_lookup_function(module_inst,
							 "twep_app_free");
		if (free_func) {
			uint32_t free_argv[2] = { output_ptr, output_len };

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

static TEE_Result parse_teep_error_output(const struct bytes_view *output,
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
			struct bytes_view status = { };

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

static bool teep_output_is_need_host_io(const struct bytes_view *output)
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

static void production_resource_limits_default(
				struct production_resource_limits *limits)
{
	limits->stack_bytes = PRODUCTION_STACK_SIZE;
	limits->heap_bytes = PRODUCTION_HEAP_SIZE;
	limits->max_output_bytes = PRODUCTION_MAX_OUTPUT_SIZE;
}

static void production_resource_limits_clamp(
				struct production_resource_limits *limits)
{
	if (!limits->stack_bytes || limits->stack_bytes > PRODUCTION_STACK_SIZE)
		limits->stack_bytes = PRODUCTION_STACK_SIZE;
	if (!limits->heap_bytes || limits->heap_bytes > PRODUCTION_HEAP_SIZE)
		limits->heap_bytes = PRODUCTION_HEAP_SIZE;
	if (!limits->max_output_bytes ||
	    limits->max_output_bytes > PRODUCTION_MAX_OUTPUT_SIZE)
		limits->max_output_bytes = PRODUCTION_MAX_OUTPUT_SIZE;
}

static TEE_Result parse_production_resource_limits_map(
				struct cbor_cursor *cur,
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
			TEE_Result res = parse_uint32_value(
				cur, &limits->stack_bytes);

			if (res != TEE_SUCCESS)
				return res;
		} else if (key_eq(key, key_len, "heap_bytes")) {
			TEE_Result res = parse_uint32_value(
				cur, &limits->heap_bytes);

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

static TEE_Result parse_teep_resource_limits_output(
				const struct bytes_view *output,
				struct production_resource_limits *limits)
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

	if (!output->ptr || !output->len || !cbor_read_len(&cur, 5, &map_len))
		return TEE_ERROR_BAD_FORMAT;
	for (i = 0; i < map_len; i++) {
		const uint8_t *key = NULL;
		size_t key_len = 0;

		if (!cbor_read_text_key(&cur, &key, &key_len))
			return TEE_ERROR_BAD_FORMAT;
		if (key_eq(key, key_len, "status")) {
			struct bytes_view status = { };

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
				} else if (!cbor_skip_item(&cur, 0)) {
					return TEE_ERROR_BAD_FORMAT;
				}
			}
		} else if (!cbor_skip_item(&cur, 0)) {
			return TEE_ERROR_BAD_FORMAT;
		}
	}
	if (cur.off != cur.len || !status_ok || !have_app)
		return TEE_ERROR_BAD_FORMAT;
	return have_limits ? TEE_SUCCESS : TEE_ERROR_ITEM_NOT_FOUND;
}

static TEE_Result build_teep_error_execute_response(
					const struct bytes_view *request_id,
					const struct bytes_view *teep_code,
					const struct bytes_view *teep_message,
					const struct bytes_view *command,
					uint8_t *out, size_t out_size,
					size_t *out_len)
{
	const char *source = "teep-agent";
	size_t len = 1
		     + 1 + 14 + 1
		     + 1 + 10 + cbor_type_len_size(request_id->len) +
		       request_id->len
		     + 1 + 6 + 1 + 5
		     + 1 + 9 + 1
		     + 1 + 5
		     + 1
		     + 1 + 4 + cbor_type_len_size(teep_code->len) +
		       teep_code->len
		     + 1 + 7 + cbor_type_len_size(teep_message->len) +
		       teep_message->len
		     + 1 + 7
		     + 1
		     + 1 + 6 + cbor_type_len_size(strlen(source)) +
		       strlen(source)
		     + 1 + 9 + cbor_type_len_size(teep_code->len) +
		       teep_code->len
		     + 1 + 7 + cbor_type_len_size(command->len) +
		       command->len;
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

static TEE_Result build_app_runtime_error_execute_response(
					const struct bytes_view *request_id,
					const struct bytes_view *command,
					const char *code,
					const char *message,
					const char *reason,
					uint8_t *out, size_t out_size,
					size_t *out_len)
{
	const char *source = "app-runtime";
	size_t code_len = strlen(code);
	size_t message_len = strlen(message);
	size_t reason_len = strlen(reason);
	size_t len = 1
		     + 1 + 14 + 1
		     + 1 + 10 + cbor_type_len_size(request_id->len) +
		       request_id->len
		     + 1 + 6 + 1 + 5
		     + 1 + 9 + 1
		     + 1 + 5
		     + 1
		     + 1 + 4 + cbor_type_len_size(code_len) + code_len
		     + 1 + 7 + cbor_type_len_size(message_len) +
		       message_len
		     + 1 + 7
		     + 1
		     + 1 + 6 + cbor_type_len_size(strlen(source)) +
		       strlen(source)
		     + 1 + 7 + cbor_type_len_size(command->len) +
		       command->len
		     + 1 + 6 + cbor_type_len_size(reason_len) +
		       reason_len;
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

struct teep_resolve_input {
	struct bytes_view command;
	struct bytes_view target_command;
	struct bytes_view resolver_mode;
};

struct teep_agent_hostcall_context {
	struct bytes_view teep_agent_wasm;
	struct bytes_view catalog;
	struct bytes_view app_wasm;
	struct bytes_view resolver_mode;
	const struct bytes_view *request_id;
	struct bytes_view command;
	struct bytes_view input;
	enum teep_agent_pending_hostcall pending;
	enum teep_agent_pending_hostcall replay;
	const uint8_t *replay_payload;
	size_t replay_payload_len;
	bool replay_used;
	size_t replay_history_index;
	char url[128];
	size_t url_len;
	uint8_t body[TEEP_AGENT_TRANSCRIPT_SIZE_MAX];
	size_t body_len;
	uint8_t challenge[64];
	size_t challenge_len;
	uint8_t agent_public_key_cose[128];
	size_t agent_public_key_cose_len;
	struct {
		bool used;
		char name[TEEP_AGENT_TRANSIENT_OBJECT_NAME_MAX];
		size_t name_len;
		uint8_t *data;
		size_t data_len;
	} objects[TEEP_AGENT_TRANSIENT_OBJECTS_MAX];
};

static TEE_Result parse_teep_resolve_input(const struct bytes_view *input,
					   struct teep_resolve_input *out)
{
	struct cbor_cursor cur = {
		.buf = input->ptr,
		.len = input->len,
		.off = 0,
	};
	struct teep_resolve_input seen = { };
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
			TEE_Result res = parse_text_value_view(&cur,
							       &seen.command);

			if (res != TEE_SUCCESS)
				return res;
		} else if (key_eq(key, key_len, "target_command")) {
			TEE_Result res = parse_text_value_view(&cur,
							       &seen.target_command);

			if (res != TEE_SUCCESS)
				return res;
		} else if (key_eq(key, key_len, "resolver_mode")) {
			TEE_Result res = parse_text_value_view(&cur,
							       &seen.resolver_mode);

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

static TEE_Result build_teep_resolve_input_for_command(
	const struct bytes_view *target_command,
	const struct bytes_view *resolver_mode,
	const struct bytes_view *attestam_url,
	uint8_t *out,
	size_t out_size,
	struct bytes_view *out_view)
{
	static const char default_resolver_mode[] = "mock";
	struct bytes_view mode = {
		.ptr = (const uint8_t *)default_resolver_mode,
		.len = sizeof(default_resolver_mode) - 1,
	};
	struct bytes_view url = { };
	size_t len = 1
		     + cbor_type_len_size(strlen("schema_version")) + strlen("schema_version") + 1
		     + cbor_type_len_size(strlen("command")) + strlen("command") + cbor_type_len_size(strlen("resolve_app")) + strlen("resolve_app")
		     + cbor_type_len_size(strlen("target_command")) + strlen("target_command") + cbor_type_len_size(target_command->len) + target_command->len
		     + cbor_type_len_size(strlen("state_dir")) + strlen("state_dir") + 1
		     + cbor_type_len_size(strlen("attestam_url")) + strlen("attestam_url") + 1;
	uint8_t *p = out;

	if (resolver_mode && resolver_mode->ptr && resolver_mode->len)
		mode = *resolver_mode;
	if (attestam_url && attestam_url->ptr && attestam_url->len)
		url = *attestam_url;
	len += cbor_type_len_size(strlen("resolver_mode")) +
	       strlen("resolver_mode") + cbor_type_len_size(mode.len) +
	       mode.len;
	len += cbor_type_len_size(strlen("attestam_url")) +
	       strlen("attestam_url") + cbor_type_len_size(url.len) +
	       url.len;

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

static bool wasm_magic_valid(const struct bytes_view *wasm)
{
	const uint8_t magic[] = { 0x00, 0x61, 0x73, 0x6d };

	return wasm->ptr && wasm->len >= 8 &&
	       TEE_MemCompare(wasm->ptr, magic, sizeof(magic)) == 0;
}

static struct teep_agent_hostcall_context *teep_hostcall_context(wasm_exec_env_t exec_env)
{
	return (struct teep_agent_hostcall_context *)
		wasm_runtime_get_user_data(exec_env);
}

static void teep_hostcall_context_free(struct teep_agent_hostcall_context *ctx)
{
	size_t i = 0;

	if (!ctx)
		return;
	for (i = 0; i < TEEP_AGENT_TRANSIENT_OBJECTS_MAX; i++) {
		if (ctx->objects[i].data) {
			TEE_Free(ctx->objects[i].data);
			ctx->objects[i].data = NULL;
		}
		ctx->objects[i].used = false;
		ctx->objects[i].data_len = 0;
		ctx->objects[i].name_len = 0;
	}
}

static void teep_agent_live_session_release(void)
{
	struct teep_agent_live_session *session = &g_teep_agent_live_session;

	if (session->active && g_teep_agent_live_session_count)
		g_teep_agent_live_session_count--;
	if (session->module)
		wasm_runtime_unload(session->module);
	if (session->module_wasm)
		TEE_Free(session->module_wasm);
	TEE_MemFill(session, 0, sizeof(*session));
}

static void teep_agent_live_abort(void)
{
	pending_host_io_clear(&g_pending_host_io);
	teep_agent_live_session_release();
	pending_teep_live_clear();
}

static struct bytes_view *teep_transient_object_view(
				struct teep_agent_hostcall_context *ctx,
				const char *path, uint32_t path_len,
				struct bytes_view *out)
{
	size_t i = 0;

	if (!ctx || !path || !out)
		return NULL;
	for (i = 0; i < TEEP_AGENT_TRANSIENT_OBJECTS_MAX; i++) {
		if (!ctx->objects[i].used ||
		    ctx->objects[i].name_len != path_len)
			continue;
		if (TEE_MemCompare(ctx->objects[i].name, path, path_len) == 0) {
			out->ptr = ctx->objects[i].data;
			out->len = ctx->objects[i].data_len;
			return out;
		}
	}
	return NULL;
}

static int32_t teep_transient_object_write(
				struct teep_agent_hostcall_context *ctx,
				const char *path, uint32_t path_len,
				const uint8_t *data, uint32_t data_len)
{
	size_t slot = TEEP_AGENT_TRANSIENT_OBJECTS_MAX;
	size_t i = 0;
	uint8_t *copy = NULL;

	if (!ctx || !path || (!data && data_len))
		return 1;
	if (path_len >= TEEP_AGENT_TRANSIENT_OBJECT_NAME_MAX ||
	    data_len > TEEP_AGENT_TRANSIENT_OBJECT_SIZE_MAX)
		return 2;
	for (i = 0; i < TEEP_AGENT_TRANSIENT_OBJECTS_MAX; i++) {
		if (ctx->objects[i].used &&
		    ctx->objects[i].name_len == path_len &&
		    TEE_MemCompare(ctx->objects[i].name, path, path_len) == 0) {
			slot = i;
			break;
		}
		if (!ctx->objects[i].used &&
		    slot == TEEP_AGENT_TRANSIENT_OBJECTS_MAX)
			slot = i;
	}
	if (slot == TEEP_AGENT_TRANSIENT_OBJECTS_MAX)
		return 2;
	copy = TEE_Malloc(data_len ? data_len : 1, 0);
	if (!copy)
		return 1;
	if (data_len)
		TEE_MemMove(copy, data, data_len);
	if (ctx->objects[slot].data)
		TEE_Free(ctx->objects[slot].data);
	ctx->objects[slot].data = copy;
	ctx->objects[slot].data_len = data_len;
	ctx->objects[slot].name_len = path_len;
	TEE_MemMove(ctx->objects[slot].name, path, path_len);
	ctx->objects[slot].used = true;
	return 0;
}

static void teep_host_log(wasm_exec_env_t exec_env, uint32_t level,
			  const char *msg, uint32_t msg_len)
{
	(void)exec_env;
	(void)level;
	(void)msg;
	(void)msg_len;
}

static int32_t teep_host_read_file(wasm_exec_env_t exec_env, const char *path,
				   uint32_t path_len, uint8_t *buf,
				   uint32_t buf_cap, uint32_t *out_len)
{
	struct teep_agent_hostcall_context *ctx = teep_hostcall_context(exec_env);
	const struct bytes_view *source = NULL;
	struct bytes_view transient = { };
	size_t protected_len = 0;
	TEE_Result res;

	if (!ctx || !path || !out_len)
		return 1;
	if (object_name_eq(path, path_len, "catalog/catalog.cbor") &&
	    bytes_view_eq(&ctx->resolver_mode, "attestam-verified")) {
		res = twep_catalog_read_active(buf, buf_cap, &protected_len);
		*out_len = protected_len > UINT32_MAX ? UINT32_MAX :
			(uint32_t)protected_len;
		if (res == TEE_SUCCESS)
			return 0;
		if (res == TEE_ERROR_SHORT_BUFFER)
			return 2;
		if (res == TEE_ERROR_ITEM_NOT_FOUND)
			return 3;
		if (res == TEE_ERROR_BAD_PARAMETERS)
			return 1;
		if (res == TEE_ERROR_CORRUPT_OBJECT ||
		    res == TEE_ERROR_BAD_FORMAT || res == TEE_ERROR_NOT_SUPPORTED ||
		    res == TEE_ERROR_SECURITY)
			return 4;
		return 7;
	}
	if (teep_transient_object_view(ctx, path, path_len, &transient))
		source = &transient;
	else if (object_name_eq(path, path_len, "catalog/catalog.cbor"))
		source = &ctx->catalog;
	else if (object_name_eq(path, path_len, "apps/helloworld.wasm"))
		source = &ctx->app_wasm;
	else {
		return 3;
	}
	*out_len = source->len > UINT32_MAX ? UINT32_MAX : (uint32_t)source->len;
	if (source->len > buf_cap)
		return 2;
	if (source->len && buf)
		TEE_MemMove(buf, source->ptr, source->len);
	return 0;
}

static bool teep_agent_state_object_allowed(const char *path, uint32_t path_len)
{
	static const char teep_agent_prefix[] = "teep-agent/";
	static const char tmp_prefix[] = "tmp/";
	static const char components_prefix[] = "components/";
	static const char apps_prefix[] = "apps/";

	if (!path || path_len == 0)
		return false;
	for (uint32_t i = 0; i < path_len; i++) {
		if (path[i] == '\0')
			return false;
		if (path[i] == '.' && i + 1 < path_len && path[i + 1] == '.')
			return false;
	}
	if (object_name_eq(path, path_len, "catalog/catalog.cbor"))
		return true;
	if (path_len >= sizeof(teep_agent_prefix) - 1 &&
	    TEE_MemCompare(path, teep_agent_prefix,
			   sizeof(teep_agent_prefix) - 1) == 0)
		return true;
	if (path_len >= sizeof(tmp_prefix) - 1 &&
	    TEE_MemCompare(path, tmp_prefix, sizeof(tmp_prefix) - 1) == 0)
		return true;
	if (path_len >= sizeof(components_prefix) - 1 &&
	    TEE_MemCompare(path, components_prefix,
			   sizeof(components_prefix) - 1) == 0)
		return true;
	if (path_len >= sizeof(apps_prefix) - 1 &&
	    TEE_MemCompare(path, apps_prefix, sizeof(apps_prefix) - 1) == 0)
		return object_name_eq(path, path_len, "apps/helloworld.wasm");
	return false;
}

static bool teep_agent_protected_object_allowed(const char *object_name,
						uint32_t object_name_len)
{
	return object_name_eq(object_name, object_name_len,
			      "protected-credential-store.cbor") ||
	       object_name_eq(object_name, object_name_len,
			      "protected-issuer-allowlist.cbor") ||
	       object_name_eq(object_name, object_name_len,
			      "protected-sequence-freshness.cbor") ||
	       object_name_eq(object_name, object_name_len,
			      "protected-store-freshness.cbor") ||
	       object_name_eq(object_name, object_name_len,
			      "protected-revocation-state.cbor") ||
	       object_name_eq(object_name, object_name_len,
			      "protected-agent-identity.cbor") ||
	       object_name_eq(object_name, object_name_len,
			      "verified-evidence-result.cbor");
}

TEE_Result twep_ta_write_persistent_object(const char *object_name,
					   uint32_t object_name_len,
					   const uint8_t *data,
					   uint32_t data_len)
{
	TEE_ObjectHandle object = TEE_HANDLE_NULL;
	uint32_t flags = TEE_DATA_FLAG_ACCESS_READ |
			 TEE_DATA_FLAG_ACCESS_WRITE |
			 TEE_DATA_FLAG_ACCESS_WRITE_META |
			 TEE_DATA_FLAG_OVERWRITE;
	TEE_Result res;

	if (!object_name || object_name_len == 0 || (!data && data_len != 0))
		return TEE_ERROR_BAD_PARAMETERS;

	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, object_name,
					 object_name_len, flags,
					 TEE_HANDLE_NULL, NULL, 0, &object);
	if (res != TEE_SUCCESS)
		return res;

	res = TEE_WriteObjectData(object, data, data_len);
	if (res != TEE_SUCCESS) {
		TEE_CloseAndDeletePersistentObject1(object);
		return res;
	}
	TEE_CloseObject(object);
	return TEE_SUCCESS;
}

static TEE_Result teep_encode_attestam_acceptance_result(uint64_t generation,
							 uint8_t *buf,
							 uint32_t buf_cap,
							 uint32_t *out_len)
{
	uint8_t *p = buf;
	uint32_t need = 1 +
		1 + sizeof("schema_version") - 1 + 1 +
		1 + sizeof("decision_source") - 1 + 1 +
		sizeof("attestam-signed-update") - 1 +
		1 + sizeof("tam_response_verified") - 1 + 1 +
		2 + sizeof("challenge_response_bound") - 1 + 1 +
		1 + sizeof("acceptance_generation") - 1 +
		(uint32_t)cbor_type_len_size(generation);

	if (!buf || !out_len)
		return TEE_ERROR_BAD_PARAMETERS;
	if (buf_cap < need)
		return TEE_ERROR_SHORT_BUFFER;

	*p++ = 0xa5;
	cbor_write_text(&p, "schema_version");
	cbor_write_uint64(&p, 2);
	cbor_write_text(&p, "decision_source");
	cbor_write_text(&p, "attestam-signed-update");
	cbor_write_text(&p, "tam_response_verified");
	*p++ = 0xf5;
	cbor_write_text(&p, "challenge_response_bound");
	*p++ = 0xf5;
	cbor_write_text(&p, "acceptance_generation");
	cbor_write_uint64(&p, generation);
	*out_len = (uint32_t)(p - buf);
	return TEE_SUCCESS;
}

static TEE_Result teep_read_persistent_object(const char *object_name,
					      uint32_t object_name_len,
					      uint8_t *buf, uint32_t buf_cap,
					      uint32_t *out_len)
{
	TEE_ObjectHandle object = TEE_HANDLE_NULL;
	TEE_ObjectInfo object_info = { };
	uint32_t read_bytes = 0;
	TEE_Result res;

	if (!object_name || object_name_len == 0 || !out_len)
		return TEE_ERROR_BAD_PARAMETERS;

	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, object_name,
				       object_name_len,
				       TEE_DATA_FLAG_ACCESS_READ |
				       TEE_DATA_FLAG_SHARE_READ,
				       &object);
	if (res != TEE_SUCCESS)
		return res;

	res = TEE_GetObjectInfo1(object, &object_info);
	if (res != TEE_SUCCESS)
		goto out;

	*out_len = object_info.dataSize;
	if (object_info.dataSize > buf_cap) {
		res = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}
	if (object_info.dataSize != 0 && !buf) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	res = TEE_ReadObjectData(object, buf, object_info.dataSize, &read_bytes);
	if (res != TEE_SUCCESS)
		goto out;
	if (read_bytes != object_info.dataSize)
		res = TEE_ERROR_CORRUPT_OBJECT;

out:
	TEE_CloseObject(object);
	return res;
}

static int32_t teep_host_write_file(wasm_exec_env_t exec_env, const char *path,
				    uint32_t path_len, const uint8_t *data,
				    uint32_t data_len)
{
	struct teep_agent_hostcall_context *ctx = teep_hostcall_context(exec_env);
	int32_t status;

	if (!ctx || !path)
		return 1;
	if (twep_ta_d047_object_name_reserved(path, path_len)) {
		IMSG("twep-wr-ta teep-agent generic catalog-state write rejected");
		return 4;
	}
	if (object_name_eq(path, path_len,
			   "teep-agent/verified-evidence-result.cbor")) {
		IMSG("twep-wr-ta teep-agent generic acceptance-result write rejected");
		return 4;
	}
	if (!teep_agent_state_object_allowed(path, path_len)) {
		IMSG("twep-wr-ta teep-agent write rejected object len=%u", path_len);
		return 4;
	}
	status = teep_transient_object_write(ctx, path, path_len, data, data_len);
	return status;
}

static int32_t teep_host_read_protected(wasm_exec_env_t exec_env,
					const char *object_name,
					uint32_t object_name_len,
					uint8_t *buf, uint32_t buf_cap,
					uint32_t *out_len)
{
	TEE_Result res;

	if (!teep_hostcall_context(exec_env) || !out_len)
		return 1;
	if (!teep_agent_protected_object_allowed(object_name, object_name_len))
		return 8;

	*out_len = 0;
	res = teep_read_persistent_object(object_name, object_name_len, buf,
					  buf_cap, out_len);
	switch (res) {
	case TEE_SUCCESS:
		return 0;
	case TEE_ERROR_SHORT_BUFFER:
		return 2;
	case TEE_ERROR_ITEM_NOT_FOUND:
		return 3;
	case TEE_ERROR_BAD_PARAMETERS:
		return 1;
	case TEE_ERROR_CORRUPT_OBJECT:
	case TEE_ERROR_BAD_FORMAT:
	case TEE_ERROR_NOT_SUPPORTED:
		return 4;
	default:
		return 7;
	}
}

static int32_t teep_host_http_post(wasm_exec_env_t exec_env, const char *url,
				   uint32_t url_len, const uint8_t *body,
				   uint32_t body_len, uint8_t *buf,
				   uint32_t buf_cap, uint32_t *out_len)
{
	{
		struct teep_agent_hostcall_context *ctx =
			teep_hostcall_context(exec_env);

		if (!ctx || !out_len || !url || (!body && body_len))
			return 1;
		if (ctx->replay_history_index <
		    g_pending_teep_live.history_count &&
		    g_pending_teep_live.history[ctx->replay_history_index].kind ==
		    TEEP_AGENT_PENDING_HTTP_POST) {
			const uint8_t *payload =
				g_pending_teep_live.history[ctx->replay_history_index].payload;
			size_t payload_len =
				g_pending_teep_live.history[ctx->replay_history_index].payload_len;

			*out_len = payload_len > UINT32_MAX ?
				UINT32_MAX : (uint32_t)payload_len;
			if (payload_len > buf_cap)
				return 2;
			if (payload_len && buf)
				TEE_MemMove(buf, payload, payload_len);
			ctx->replay_history_index++;
			return 0;
		}
		if (ctx->replay == TEEP_AGENT_PENDING_HTTP_POST &&
		    !ctx->replay_used) {
			*out_len = ctx->replay_payload_len > UINT32_MAX ?
				UINT32_MAX : (uint32_t)ctx->replay_payload_len;
			if (ctx->replay_payload_len > buf_cap)
				return 2;
			if (ctx->replay_payload_len && buf)
				TEE_MemMove(buf, ctx->replay_payload,
					    ctx->replay_payload_len);
			ctx->replay_used = true;
			return 0;
		}
		if (url_len >= sizeof(ctx->url) || body_len > sizeof(ctx->body)) {
			return 2;
		}
		TEE_MemMove(ctx->url, url, url_len);
		ctx->url[url_len] = '\0';
		ctx->url_len = url_len;
		if (body_len)
			TEE_MemMove(ctx->body, body, body_len);
		ctx->body_len = body_len;
		ctx->pending = TEEP_AGENT_PENDING_HTTP_POST;
		*out_len = 0;
	}
	return 11;
}

static int32_t teep_host_create_evidence(wasm_exec_env_t exec_env,
					 const uint8_t *challenge,
					 uint32_t challenge_len,
					 const uint8_t *agent_key,
					 uint32_t agent_key_len,
					 uint8_t *buf, uint32_t buf_cap,
					 uint32_t *out_len)
{
	(void)buf;
	(void)buf_cap;
	{
		struct teep_agent_hostcall_context *ctx =
			teep_hostcall_context(exec_env);

		if (!ctx || !out_len || (!challenge && challenge_len) ||
		    (!agent_key && agent_key_len))
			return 1;
		if (ctx->replay_history_index <
		    g_pending_teep_live.history_count &&
		    g_pending_teep_live.history[ctx->replay_history_index].kind ==
		    TEEP_AGENT_PENDING_CREATE_EVIDENCE) {
			const uint8_t *payload =
				g_pending_teep_live.history[ctx->replay_history_index].payload;
			size_t payload_len =
				g_pending_teep_live.history[ctx->replay_history_index].payload_len;

			*out_len = payload_len > UINT32_MAX ?
				UINT32_MAX : (uint32_t)payload_len;
			if (payload_len > buf_cap)
				return 2;
			if (payload_len && buf)
				TEE_MemMove(buf, payload, payload_len);
			ctx->replay_history_index++;
			return 0;
		}
		if (ctx->replay == TEEP_AGENT_PENDING_CREATE_EVIDENCE &&
		    !ctx->replay_used) {
			*out_len = ctx->replay_payload_len > UINT32_MAX ?
				UINT32_MAX : (uint32_t)ctx->replay_payload_len;
			if (ctx->replay_payload_len > buf_cap)
				return 2;
			if (ctx->replay_payload_len && buf)
				TEE_MemMove(buf, ctx->replay_payload,
					    ctx->replay_payload_len);
			ctx->replay_used = true;
			return 0;
		}
		if (challenge_len > sizeof(ctx->challenge) ||
		    agent_key_len > sizeof(ctx->agent_public_key_cose))
			return 2;
		if (challenge_len)
			TEE_MemMove(ctx->challenge, challenge, challenge_len);
		ctx->challenge_len = challenge_len;
		if (agent_key_len)
			TEE_MemMove(ctx->agent_public_key_cose, agent_key,
				    agent_key_len);
		ctx->agent_public_key_cose_len = agent_key_len;
		ctx->pending = TEEP_AGENT_PENDING_CREATE_EVIDENCE;
		*out_len = 0;
	}
	return 11;
}

static TEE_Result teep_agent_pending_to_need_host_io(
				const struct teep_agent_hostcall_context *ctx,
				uint8_t *out, size_t out_size, size_t *out_len)
{
	if (!ctx || !ctx->request_id)
		return TEE_ERROR_BAD_FORMAT;
	if (ctx->pending == TEEP_AGENT_PENDING_HTTP_POST)
		return build_need_host_io_response(ctx->request_id,
						   &ctx->command,
						   &ctx->input,
						   "teep-http-1", ctx->url,
						   ctx->body, ctx->body_len,
						   out, out_size, out_len);
	if (ctx->pending == TEEP_AGENT_PENDING_CREATE_EVIDENCE)
		return build_need_evidence_response_with_payload(
			ctx->request_id, &ctx->command, &ctx->input,
			ctx->challenge, ctx->challenge_len,
			ctx->agent_public_key_cose,
			ctx->agent_public_key_cose_len, out, out_size,
			out_len);
	return TEE_ERROR_BAD_FORMAT;
}

static int32_t teep_host_platform_status(wasm_exec_env_t exec_env,
					 uint8_t *buf, uint32_t buf_cap,
					 uint32_t *out_len)
{
	static const char status[] =
		"platform-backend=trustzone\n"
		"runtime-location=trustzone-ta\n"
		"teep-agent-location=trustzone-ta\n"
		"catalog-resolution-location=trustzone-ta\n"
		"sealed-storage-security=tee-ree-fs-secure-storage\n"
		"sealed-storage-rollback-protected=false\n";
	size_t len = sizeof(status) - 1;

	if (!teep_hostcall_context(exec_env) || !out_len)
		return 1;
	*out_len = (uint32_t)len;
	if (len > buf_cap)
		return 2;
	if (len && buf)
		TEE_MemMove(buf, status, len);
	return 0;
}

static int32_t teep_host_teep_agent_measurement_sha256(wasm_exec_env_t exec_env,
						       uint8_t *buf, uint32_t buf_cap,
						       uint32_t *out_len)
{
	struct teep_agent_hostcall_context *ctx = teep_hostcall_context(exec_env);
	uint8_t digest[32] = { };
	TEE_Result res = TEE_SUCCESS;

	if (!ctx || !out_len)
		return 1;
	if (!ctx->teep_agent_wasm.ptr || !ctx->teep_agent_wasm.len) {
		*out_len = 0;
		return 8;
	}
	*out_len = sizeof(digest);
	if (buf_cap < sizeof(digest))
		return 2;
	if (!buf)
		return 1;
	res = twep_ta_sha256_bytes(ctx->teep_agent_wasm.ptr,
				   ctx->teep_agent_wasm.len, digest);
	if (res != TEE_SUCCESS)
		return 7;
	TEE_MemMove(buf, digest, sizeof(digest));
	return 0;
}

static int32_t acceptance_host_status(TEE_Result res)
{
	switch (res) {
	case TEE_SUCCESS:
		return 0;
	case TEE_ERROR_BAD_PARAMETERS:
		return 1;
	case TEE_ERROR_EXCESS_DATA:
	case TEE_ERROR_OVERFLOW:
		return 2;
	case TEE_ERROR_ITEM_NOT_FOUND:
		return 3;
	case TEE_ERROR_BAD_FORMAT:
	case TEE_ERROR_CORRUPT_OBJECT:
	case TEE_ERROR_NOT_SUPPORTED:
	case TEE_ERROR_SECURITY:
		return 4;
	case TEE_ERROR_ACCESS_CONFLICT:
		return 9;
	default:
		return 7;
	}
}

static int32_t teep_host_acceptance_generation(wasm_exec_env_t exec_env,
					       uint64_t *generation)
{
	if (!teep_hostcall_context(exec_env) || !generation)
		return 1;
#ifdef TWEP_TA_WAMR_LINK
	if (g_pending_teep_live.active &&
	    g_pending_teep_live.catalog_commit_recorded) {
		*generation =
			g_pending_teep_live.catalog_commit_expected_generation;
		return 0;
	}
#endif
	return acceptance_host_status(twep_acceptance_generation(generation));
}

static TEE_Result teep_publish_acceptance_result(uint64_t generation)
{
	uint8_t result[160] = { };
	uint8_t stored_result[160] = { };
	uint32_t result_len = 0;
	uint32_t stored_result_len = 0;
	TEE_Result res;

	res = teep_encode_attestam_acceptance_result(generation, result,
						     sizeof(result), &result_len);
	if (res != TEE_SUCCESS)
		return res;
#ifdef TWEP_TA_D043_TEST_HOOKS
	if (twep_ta_take_d043_runtime_test_fault(
		    TA_TWEP_WR_D043_FAULT_RESULT_WRITE))
		res = TEE_ERROR_STORAGE_NOT_AVAILABLE;
	else
#endif
		res = twep_ta_write_persistent_object("verified-evidence-result.cbor",
				   sizeof("verified-evidence-result.cbor") - 1,
				   result, result_len);
	if (res != TEE_SUCCESS)
		return res;
	res = teep_read_persistent_object("verified-evidence-result.cbor",
				  sizeof("verified-evidence-result.cbor") - 1,
				  stored_result, sizeof(stored_result),
				  &stored_result_len);
	if (res == TEE_SUCCESS &&
	    (stored_result_len != result_len ||
	     TEE_MemCompare(stored_result, result, result_len) != 0))
		return TEE_ERROR_CORRUPT_OBJECT;
	return res;
}

static int32_t teep_host_commit_acceptance(wasm_exec_env_t exec_env,
					   const uint8_t *digest,
					   uint32_t digest_len,
					   const uint8_t *component_id,
					   uint32_t component_id_len,
					   uint64_t sequence,
					   uint64_t expected_generation,
					   uint64_t *new_generation)
{
	struct teep_agent_hostcall_context *ctx = teep_hostcall_context(exec_env);
	TEE_Result res;

	if (!ctx)
		return 1;
	if (!digest || digest_len != 32 || !component_id ||
	    !component_id_len || !new_generation) {
		pending_host_io_clear(&g_pending_host_io);
		return 1;
	}
	if (!g_pending_host_io.active || !g_pending_host_io.http_transcript ||
	    !bytes_view_eq(&g_pending_host_io.kind, "http_post"))
		return 9;
	if (TEE_MemCompare(g_pending_host_io.request_body_sha256,
			   digest, 32) != 0) {
		pending_host_io_clear(&g_pending_host_io);
		return 9;
	}
	res = twep_acceptance_commit(digest, component_id, component_id_len,
				     sequence, expected_generation,
				     new_generation);
	if (res != TEE_SUCCESS) {
		IMSG("twep-wr-ta acceptance commit failed 0x%x", res);
		goto out;
	}
	res = teep_publish_acceptance_result(*new_generation);
	if (res == TEE_SUCCESS)
		IMSG("twep-wr-ta acceptance result generation %llu stored",
		     (unsigned long long)*new_generation);
	else
		IMSG("twep-wr-ta acceptance result store failed 0x%x", res);
out:
	pending_host_io_clear(&g_pending_host_io);
	return acceptance_host_status(res);
}

static int32_t teep_host_commit_catalog(wasm_exec_env_t exec_env,
					const uint8_t *digest,
					uint32_t digest_len,
					const uint8_t *component_id,
					uint32_t component_id_len,
					uint64_t sequence,
					uint64_t expected_generation,
					const uint8_t *catalog,
					uint32_t catalog_len,
					const uint8_t *catalog_digest,
					uint32_t catalog_digest_len,
					uint64_t *new_generation)
{
	struct teep_agent_hostcall_context *ctx = teep_hostcall_context(exec_env);
	TEE_Result res;

	if (!ctx)
		return 1;
	if (!digest || digest_len != 32 ||
	    !twep_catalog_component_id_is_default(component_id,
						 component_id_len) ||
	    !catalog || !catalog_len || catalog_len > 65536 ||
	    !catalog_digest || catalog_digest_len != 32 || !new_generation) {
		pending_host_io_clear(&g_pending_host_io);
		return 1;
	}
	if (!bytes_view_eq(&ctx->resolver_mode, "attestam-verified")) {
		pending_host_io_clear(&g_pending_host_io);
		return 8;
	}
#ifdef TWEP_TA_WAMR_LINK
	if (g_pending_teep_live.active &&
	    g_pending_teep_live.catalog_commit_recorded) {
		uint64_t current_sequence = 0;
		uint64_t current_generation = 0;
		uint8_t replay_catalog_digest[32] = { };

		res = twep_ta_sha256_bytes(catalog, catalog_len,
					   replay_catalog_digest);
		if (res != TEE_SUCCESS ||
		    sequence != g_pending_teep_live.catalog_commit_sequence ||
		    expected_generation !=
			g_pending_teep_live.catalog_commit_expected_generation ||
		    catalog_len !=
			g_pending_teep_live.catalog_commit_payload_len ||
		    TEE_MemCompare(digest,
				   g_pending_teep_live.catalog_commit_query_digest,
				   32) != 0 ||
		    TEE_MemCompare(catalog_digest,
				   g_pending_teep_live.catalog_commit_payload_digest,
				   32) != 0 ||
		    TEE_MemCompare(replay_catalog_digest,
				   g_pending_teep_live.catalog_commit_payload_digest,
				   32) != 0)
			return 9;
		res = twep_acceptance_component_sequence(
			component_id, component_id_len, &current_generation,
			&current_sequence);
		if (res != TEE_SUCCESS || current_sequence != sequence)
			return 9;
		*new_generation =
			g_pending_teep_live.catalog_commit_new_generation;
		IMSG("twep-wr-ta replayed committed Catalog generation %llu",
		     (unsigned long long)*new_generation);
		return 0;
	}
#endif
	if (!g_pending_host_io.active || !g_pending_host_io.http_transcript ||
	    !bytes_view_eq(&g_pending_host_io.kind, "http_post"))
		return 9;
	if (TEE_MemCompare(g_pending_host_io.request_body_sha256,
			   digest, 32) != 0) {
		pending_host_io_clear(&g_pending_host_io);
		return 9;
	}
	res = twep_catalog_commit(digest, component_id, component_id_len,
				  sequence, expected_generation, catalog,
				  catalog_len, catalog_digest, new_generation);
	if (res == TEE_SUCCESS)
		res = teep_publish_acceptance_result(*new_generation);
	if (res != TEE_SUCCESS)
		IMSG("twep-wr-ta catalog commit failed 0x%x", res);
	else {
#ifdef TWEP_TA_WAMR_LINK
		if (g_pending_teep_live.active) {
			g_pending_teep_live.catalog_commit_recorded = true;
			TEE_MemMove(
				g_pending_teep_live.catalog_commit_query_digest,
				digest, 32);
			TEE_MemMove(
				g_pending_teep_live.catalog_commit_payload_digest,
				catalog_digest, 32);
			g_pending_teep_live.catalog_commit_sequence = sequence;
			g_pending_teep_live.catalog_commit_expected_generation =
				expected_generation;
			g_pending_teep_live.catalog_commit_new_generation =
				*new_generation;
			g_pending_teep_live.catalog_commit_payload_len = catalog_len;
		}
#endif
		IMSG("twep-wr-ta catalog generation %llu committed",
		     (unsigned long long)*new_generation);
	}
	pending_host_io_clear(&g_pending_host_io);
	return acceptance_host_status(res);
}

#ifdef TWEP_TA_D043_TEST_HOOKS
void twep_ta_pending_diagnostics(uint32_t *flags, uint32_t *count,
				 uint32_t *bytes)
{
	uint32_t pending_flags = g_pending_host_io.active ? 1u : 0u;

#ifdef TWEP_TA_WAMR_LINK
	if (g_pending_teep_live.active)
		pending_flags |= 2u;
	if (g_teep_agent_live_session.active)
		pending_flags |= 4u;
#endif
	*flags = pending_flags;
	*count = (uint32_t)g_pending_http_transcript_count;
	*bytes = (uint32_t)g_pending_http_transcript_bytes;
}
#endif
static int32_t teep_host_random(wasm_exec_env_t exec_env, uint8_t *buf,
				uint32_t buf_len)
{
	if (!teep_hostcall_context(exec_env) || (!buf && buf_len))
		return 1;
	if (buf_len)
		TEE_GenerateRandom(buf, buf_len);
	return 0;
}

static uint64_t teep_host_unix_time_ms(wasm_exec_env_t exec_env)
{
	TEE_Time time = { };

	if (!teep_hostcall_context(exec_env))
		return 0;
	TEE_GetSystemTime(&time);
	return ((uint64_t)time.seconds * 1000) + time.millis;
}

static NativeSymbol teep_agent_native_symbols[] = {
	{ "twep_host_log", teep_host_log, "(i*~)", NULL },
	{ "twep_host_read_file", teep_host_read_file, "(*~*~*)i", NULL },
	{ "twep_host_write_file", teep_host_write_file, "(*~*~)i", NULL },
	{ "twep_host_read_protected", teep_host_read_protected, "(*~*~*)i", NULL },
	{ "twep_host_http_post", teep_host_http_post, "(*~*~*~*)i", NULL },
	{ "twep_host_create_evidence", teep_host_create_evidence, "(*~*~*~*)i", NULL },
	{ "twep_host_platform_status", teep_host_platform_status, "(*~*)i", NULL },
	{ "twep_host_teep_agent_measurement_sha256", teep_host_teep_agent_measurement_sha256, "(*~*)i", NULL },
	{ "twep_host_acceptance_generation", teep_host_acceptance_generation, "(*)i", NULL },
	{ "twep_host_commit_acceptance", teep_host_commit_acceptance, "(*~*~II*)i", NULL },
	{ "twep_host_commit_catalog", teep_host_commit_catalog, "(*~*~II*~*~*)i", NULL },
	{ "twep_host_random", teep_host_random, "(*~)i", NULL },
	{ "twep_host_unix_time_ms", teep_host_unix_time_ms, "()I", NULL },
};

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

static TEE_Result execute_teep_agent_resolve(const struct bytes_view *request_id,
					     const struct bytes_view *wasm,
					     const struct bytes_view *input,
					     const struct bytes_view *catalog,
					     const struct bytes_view *app_wasm,
					     const struct bytes_view *dev_agent_public_key,
					     enum teep_agent_pending_hostcall replay,
					     const uint8_t *replay_payload,
					     size_t replay_payload_len,
					     uint8_t *out, size_t out_size,
					     size_t *out_len)
{
	char error_buf[128] = { };
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
	uint32_t argv[3] = { };
	uint32_t output_ptr = 0;
	uint32_t output_len = 0;
	uint8_t *output_native = NULL;
	struct teep_resolve_input resolve_input = { };
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
		IMSG("twep-wr-ta teep-agent resolve input rejected 0x%08x", res);
		return res;
	}
	host_ctx.resolver_mode = resolve_input.resolver_mode;
	if (dev_agent_public_key && dev_agent_public_key->len) {
		res = teep_transient_object_write(&host_ctx,
			"teep-agent/dev-agent-public-key.cbor",
			sizeof("teep-agent/dev-agent-public-key.cbor") - 1,
			dev_agent_public_key->ptr,
			(uint32_t)dev_agent_public_key->len);
		if (res != TEE_SUCCESS)
			return res;
	}
	host_ctx.command = resolve_input.command;
	verified_acceptance = bytes_view_eq(&resolve_input.resolver_mode,
					    "attestam-verified");
	if (!wasm_magic_valid(wasm))
		return TEE_ERROR_BAD_FORMAT;
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
					       PRODUCTION_HEAP_SIZE,
					       error_buf, sizeof(error_buf));
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
				g_teep_agent_live_session.module_wasm = load_wasm;
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
				g_teep_agent_live_session.module_wasm = load_wasm;
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
	output_native = wasm_runtime_addr_app_to_native(module_inst, output_ptr);
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
			uint32_t free_argv[2] = { output_ptr, output_len };

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

static TEE_Result resume_pending_teep_live(const struct bytes_view *request_id,
					   const struct bytes_view *host_io_result,
					   uint8_t *out, size_t out_size,
					   size_t *out_len)
{
	enum teep_agent_pending_hostcall replay_kind = TEEP_AGENT_PENDING_NONE;
	struct bytes_view replay_payload = { };
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
	uint8_t teep_output[TEEP_AGENT_HOST_IO_RESPONSE_SIZE_MAX] = { };
	uint8_t execute_output[4096] = { };
	struct bytes_view teep_result = { };
	struct bytes_view teep_code = { };
	struct bytes_view teep_message = { };
	struct bytes_view final_response = { };
	struct teep_resolve_input resolve_input = { };
	struct production_resource_limits resource_limits = { };
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
	res = parse_host_io_result_payload(host_io_result, &replay_kind,
					   &replay_payload);
	if (res != TEE_SUCCESS)
		goto terminal_failure;
	res = pending_teep_live_append_history(replay_kind, &replay_payload);
	if (res != TEE_SUCCESS)
		goto terminal_failure;
	res = execute_teep_agent_resolve(&saved_request_id, &wasm,
					 &input, &catalog, &app_wasm,
					 &dev_agent_public_key,
					 TEEP_AGENT_PENDING_NONE,
					 NULL, 0,
					 teep_output,
					 sizeof(teep_output),
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
		IMSG("twep-wr-ta production teep-agent resumed to next host io request");
		return TEE_SUCCESS;
	}
	if (parse_teep_error_output(&teep_result, &teep_code,
				    &teep_message) == TEE_SUCCESS) {
		res = build_teep_error_execute_response(
			&saved_request_id, &teep_code, &teep_message,
			&saved_command, out, out_size, out_len);
		pending_host_io_clear(&g_pending_host_io);
		teep_agent_live_session_release();
		pending_teep_live_clear();
		if (res == TEE_SUCCESS)
			IMSG("twep-wr-ta production teep-agent resumed with error");
		return res;
	}
	res = parse_teep_resolve_input(&input, &resolve_input);
	if (res == TEE_SUCCESS &&
	    !bytes_view_eq(&resolve_input.command, "resolve_app")) {
		res = build_final_response_wrapper(&saved_request_id,
						   &teep_result,
						   out, out_size, out_len);
		if (res == TEE_SUCCESS) {
			pending_host_io_clear(&g_pending_host_io);
			teep_agent_live_session_release();
			pending_teep_live_clear();
			IMSG("twep-wr-ta production teep-agent hostcall probe resumed");
		}
		if (res != TEE_SUCCESS)
			goto terminal_failure;
		return TEE_SUCCESS;
	}
	if (res != TEE_SUCCESS)
		goto terminal_failure;
	if (bytes_view_eq(&resolve_input.resolver_mode,
			  "attestam-verified")) {
		pending_host_io_clear(&g_pending_host_io);
		teep_agent_live_session_release();
		pending_teep_live_clear();
		return TEE_ERROR_SECURITY;
	}
	production_resource_limits_default(&resource_limits);
	res = parse_teep_resource_limits_output(&teep_result, &resource_limits);
	if (res != TEE_SUCCESS && res != TEE_ERROR_ITEM_NOT_FOUND)
		goto terminal_failure;
	res = execute_production_app_wasm(&saved_request_id, &saved_command,
					  &app_input, &app_wasm,
					  &resource_limits,
					  execute_output,
					  sizeof(execute_output),
					  &execute_len);
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
	if (res != TEE_SUCCESS)
		goto terminal_failure;
	return TEE_SUCCESS;

terminal_failure:
	pending_host_io_clear(&g_pending_host_io);
	teep_agent_live_session_release();
	pending_teep_live_clear();
	return res;
}
#endif

TEE_Result twep_ta_cmd_production_envelope(uint32_t param_types,
					  TEE_Param params[4],
					  enum twep_ta_production_envelope_kind kind,
					  const char *label)
{
	const uint32_t expected = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						 TEE_PARAM_TYPE_MEMREF_OUTPUT,
						 TEE_PARAM_TYPE_NONE,
						 TEE_PARAM_TYPE_NONE);
	struct production_envelope_seen seen = { };
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
		static const uint8_t body[] = {
			0xa1, 0x66, 'p', 'r', 'o', 'b', 'e', 0x01
		};
		size_t response_len = 0;

		res = build_need_host_io_response(&seen.request_id_view,
						  &seen.command_view,
						  &seen.app_input_view,
						  "io-1",
						  "https://ta.example.invalid/teep",
						  body, sizeof(body),
						  params[1].memref.buffer,
						  params[1].memref.size,
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
			IMSG("twep-wr-ta pending HTTP transcript limit probe requested");
		return res;
	}

	if (kind == TWEP_TA_ENVELOPE_EXECUTE &&
	    bytes_view_eq(&seen.command_view, "teep-agent-hostcall-http")) {
		static const uint8_t body[] = {
			0xa2,
			0x64, 't', 'e', 'e', 'p',
			0x6e, 'q', 'u', 'e', 'r', 'y', '-', 'r', 'e', 's',
			      'p', 'o', 'n', 's', 'e',
			0x67, 'p', 'u', 'r', 'p', 'o', 's', 'e',
			0x77, 't', 'e', 'e', 'p', '-', 'a', 'g', 'e', 'n',
			      't', '-', 'h', 'o', 's', 't', 'c', 'a', 'l',
			      'l', '-', 's', 'm', 'o', 'k', 'e',
		};
		size_t response_len = 0;

		res = build_need_host_io_response(&seen.request_id_view,
						  &seen.command_view,
						  &seen.app_input_view,
						  "teep-http-1",
						  "https://ta.example.invalid/tam",
						  body, sizeof(body),
						  params[1].memref.buffer,
						  params[1].memref.size,
						  &response_len);
		params[1].memref.size = response_len;
		if (res == TEE_SUCCESS)
			IMSG("twep-wr-ta production teep-agent hostcall http requested");
		return res;
	}

	if (kind == TWEP_TA_ENVELOPE_EXECUTE &&
	    bytes_view_eq(&seen.command_view, "teep-agent-hostcall-evidence")) {
		size_t response_len = 0;

		res = build_need_evidence_response(&seen.request_id_view,
						   &seen.command_view,
						   &seen.app_input_view,
						   params[1].memref.buffer,
						   params[1].memref.size,
						   &response_len);
		params[1].memref.size = response_len;
		if (res == TEE_SUCCESS)
			IMSG("twep-wr-ta production teep-agent hostcall evidence requested");
		return res;
	}

	if (kind == TWEP_TA_ENVELOPE_RESUME_HOST_IO) {
		size_t response_len = 0;

#ifdef TWEP_TA_WAMR_LINK
		if (g_pending_teep_live.active)
			res = resume_pending_teep_live(&seen.request_id_view,
						       &seen.host_io_result_view,
						       params[1].memref.buffer,
						       params[1].memref.size,
						       &response_len);
		else
#endif
			res = build_resume_final_response(&seen.request_id_view,
							  &seen.host_io_result_view,
							  params[1].memref.buffer,
							  params[1].memref.size,
							  &response_len);
		params[1].memref.size = response_len;
		if (res == TEE_SUCCESS)
			IMSG("twep-wr-ta production host io resumed");
		return res;
	}

	if (kind == TWEP_TA_ENVELOPE_EXECUTE && seen.wasm_view.ptr &&
	    seen.wasm_view.len) {
#ifdef TWEP_TA_WAMR_LINK
		char error_buf[128] = { };
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
		uint32_t argv[3] = { };
		uint32_t output_ptr = 0;
		uint32_t output_len = 0;
		uint8_t *output_native = NULL;
		struct bytes_view stdout_view = { };
		struct bytes_view app_output = { };
		struct production_resource_limits resource_limits = { };
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
		bool command_is_teep_agent_resolve_wrapped =
			bytes_view_eq(&seen.command_view,
				      "teep-agent-resolve-wrapped");
		bool resolver_is_attestam_verified =
			bytes_view_eq(&seen.resolver_mode_view,
				      "attestam-verified");

		production_resource_limits_default(&resource_limits);
		if (command_is_teep_agent_resolve ||
		    command_is_teep_agent_resolve_wrapped) {
			uint8_t teep_output[TEEP_AGENT_HOST_IO_RESPONSE_SIZE_MAX];
			uint8_t *resolve_out = command_is_teep_agent_resolve_wrapped ?
				teep_output : params[1].memref.buffer;
			size_t resolve_out_size =
				command_is_teep_agent_resolve_wrapped ?
				sizeof(teep_output) : params[1].memref.size;

			res = execute_teep_agent_resolve(&seen.request_id_view,
							 &seen.wasm_view,
							 &seen.app_input_view,
							 &seen.catalog_view,
							 &seen.app_wasm_view,
							 &seen.dev_agent_public_key_view,
							 TEEP_AGENT_PENDING_NONE,
							 NULL, 0,
							 resolve_out,
							 resolve_out_size,
							 &response_len);
			if (res == TEE_SUCCESS &&
			    command_is_teep_agent_resolve_wrapped) {
				struct bytes_view teep_result = {
					.ptr = teep_output,
					.len = response_len,
				};
				struct bytes_view teep_code = { };
				struct bytes_view teep_message = { };

				if (parse_teep_error_output(&teep_result,
							    &teep_code,
							    &teep_message) ==
				    TEE_SUCCESS)
					res = build_teep_error_execute_response(
						&seen.request_id_view,
						&teep_code, &teep_message,
						&seen.command_view,
						params[1].memref.buffer,
						params[1].memref.size,
						&response_len);
				else if (response_len <= params[1].memref.size)
					TEE_MemMove(params[1].memref.buffer,
						    teep_output,
						    response_len);
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
						return res;
					}
				}
			}
			if (res != TEE_SUCCESS)
				teep_agent_live_abort();
			params[1].memref.size = response_len;
			if (res == TEE_SUCCESS)
				IMSG("twep-wr-ta production teep-agent resolve executed");
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
			uint8_t teep_output[TEEP_AGENT_HOST_IO_RESPONSE_SIZE_MAX];
			struct bytes_view resolve_input = { };
			struct bytes_view teep_result = { };
			struct bytes_view teep_code = { };
			struct bytes_view teep_message = { };

			res = build_teep_resolve_input_for_command(
				&seen.command_view, &seen.resolver_mode_view,
				&seen.attestam_url_view,
				resolve_input_buf,
				sizeof(resolve_input_buf), &resolve_input);
			if (res != TEE_SUCCESS)
				return res;
			res = execute_teep_agent_resolve(&seen.request_id_view,
							 &seen.wasm_view,
							 &resolve_input,
							 &seen.catalog_view,
							 &seen.app_wasm_view,
							 &seen.dev_agent_public_key_view,
							 TEEP_AGENT_PENDING_NONE,
							 NULL, 0,
							 teep_output,
							 sizeof(teep_output),
							 &response_len);
			if (res != TEE_SUCCESS) {
				teep_agent_live_abort();
				return res;
			}
			teep_result.ptr = teep_output;
			teep_result.len = response_len;
			if (teep_output_is_need_host_io(&teep_result)) {
				res = pending_teep_live_save(
					&seen.request_id_view, &seen.command_view,
					&seen.wasm_view, &resolve_input,
					&seen.app_input_view, &seen.catalog_view,
					&seen.app_wasm_view,
					&seen.dev_agent_public_key_view);
				if (res != TEE_SUCCESS) {
					teep_agent_live_abort();
					return res;
				}
				if (response_len > params[1].memref.size) {
					teep_agent_live_abort();
					return TEE_ERROR_SHORT_BUFFER;
				}
				TEE_MemMove(params[1].memref.buffer, teep_output,
					    response_len);
				params[1].memref.size = response_len;
				IMSG("twep-wr-ta production teep-agent returned host io request");
				return TEE_SUCCESS;
			}
			if (parse_teep_error_output(&teep_result, &teep_code,
						    &teep_message) ==
			    TEE_SUCCESS) {
				res = build_teep_error_execute_response(
					&seen.request_id_view, &teep_code,
					&teep_message, &seen.command_view,
					params[1].memref.buffer,
					params[1].memref.size,
					&response_len);
				params[1].memref.size = response_len;
				return res;
			}
			if (resolver_is_attestam_verified)
				return TEE_ERROR_SECURITY;
			res = parse_teep_resource_limits_output(&teep_result,
								&resource_limits);
			if (res != TEE_SUCCESS &&
			    res != TEE_ERROR_ITEM_NOT_FOUND)
				return res;
			res = TEE_SUCCESS;
			app_runtime_wasm = seen.app_wasm_view;
			IMSG("twep-wr-ta production teep-agent resolved app");
		}
		if (!twep_ta_ensure_wamr_runtime()) {
			EMSG("twep-wr-ta production WAMR init failed");
			return TEE_ERROR_GENERIC;
		}
		if (twep_ta_wasm_has_import_section(app_runtime_wasm.ptr,
						    app_runtime_wasm.len)) {
			IMSG("twep-wr-ta production rejected unsupported Wasm import section");
			res = TEE_ERROR_BAD_FORMAT;
			goto prod_out;
		}
		module = wasm_runtime_load((uint8_t *)app_runtime_wasm.ptr,
					   (uint32_t)app_runtime_wasm.len,
					   error_buf, sizeof(error_buf));
		if (!module) {
			EMSG("twep-wr-ta production load failed: %s", error_buf);
			res = TEE_ERROR_BAD_FORMAT;
			goto prod_out;
		}
		module_inst = wasm_runtime_instantiate(module,
						       resource_limits.stack_bytes,
						       resource_limits.heap_bytes,
						       error_buf,
						       sizeof(error_buf));
		if (!module_inst) {
			EMSG("twep-wr-ta production instantiate failed: %s",
			     error_buf);
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto prod_out;
		}
		exec_env = wasm_runtime_create_exec_env(module_inst,
							resource_limits.stack_bytes);
		if (!exec_env) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto prod_out;
		}
		abi_func = wasm_runtime_lookup_function(module_inst,
							"twep_app_abi_version");
		if (!abi_func) {
			res = TEE_ERROR_BAD_FORMAT;
			goto prod_out;
		}
		if (!wasm_runtime_call_wasm(exec_env, abi_func, 0, argv) ||
		    argv[0] != 1) {
			IMSG("twep-wr-ta production rejected unsupported app ABI");
			res = TEE_ERROR_BAD_FORMAT;
			goto prod_out;
		}
		if (seen.app_input_view.len) {
			void *native = NULL;

			input_ptr = (uint32_t)wasm_runtime_module_malloc(
				module_inst, seen.app_input_view.len,
				&native);
			input_native = native;
			if (!input_ptr || !input_native) {
				res = TEE_ERROR_OUT_OF_MEMORY;
				goto prod_out;
			}
			TEE_MemMove(input_native, seen.app_input_view.ptr,
				    seen.app_input_view.len);
		}
		{
			void *native = NULL;

			desc_ptr = (uint32_t)wasm_runtime_module_malloc(
				module_inst, 8, &native);
			desc_native = native;
		}
		if (!desc_ptr || !desc_native) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto prod_out;
		}
		TEE_MemFill(desc_native, 0, 8);
		main_func = wasm_runtime_lookup_function(module_inst,
							 "twep_app_main");
		if (!main_func) {
			res = TEE_ERROR_BAD_FORMAT;
			goto prod_out;
		}
		argv[0] = input_ptr;
		argv[1] = (uint32_t)seen.app_input_view.len;
		argv[2] = desc_ptr;
		if (!wasm_runtime_call_wasm(exec_env, main_func, 3, argv)) {
			EMSG("twep-wr-ta production call failed: %s",
			     wasm_runtime_get_exception(module_inst));
			res = TEE_ERROR_GENERIC;
			goto prod_out;
		}
		if ((int32_t)argv[0] != 0) {
			res = TEE_ERROR_GENERIC;
			goto prod_out;
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
			goto prod_out;
		}
		if (output_len > resource_limits.max_output_bytes) {
			IMSG("twep-wr-ta production rejected app output above catalog max_output_bytes");
			res = build_app_runtime_error_execute_response(
				&seen.request_id_view, &seen.command_view,
				"app.resource_limit",
				"resource limit exceeded",
				"max_output_bytes",
				params[1].memref.buffer,
				params[1].memref.size,
				&response_len);
			params[1].memref.size = response_len;
			goto prod_out;
		}
		output_native = wasm_runtime_addr_app_to_native(module_inst,
								output_ptr);
		if (!output_native) {
			res = TEE_ERROR_BAD_FORMAT;
			goto prod_out;
		}
		app_output.ptr = output_native;
		app_output.len = output_len;
		res = extract_stdout_view(output_native, output_len,
					  &stdout_view);
		if (res != TEE_SUCCESS)
			goto prod_out;
		res = build_execute_response(&seen.request_id_view, &stdout_view,
					     &app_output,
					     params[1].memref.buffer,
					     params[1].memref.size,
					     &response_len);
		params[1].memref.size = response_len;
		if (res == TEE_SUCCESS) {
			if (command_is_calcadd)
				IMSG("twep-wr-ta production executed calcadd");
			else if (command_is_negaposi)
				IMSG("twep-wr-ta production executed negaposi");
			else
				IMSG("twep-wr-ta production executed helloworld");
		}

prod_out:
		if (output_ptr) {
			free_func = wasm_runtime_lookup_function(module_inst,
								 "twep_app_free");
			if (free_func) {
				uint32_t free_argv[2] = {
					output_ptr,
					output_len,
				};
				(void)wasm_runtime_call_wasm(exec_env,
							     free_func, 2,
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
#else
		IMSG("twep-wr-ta production blocker: WAMR runtime is not linked into the TA");
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
