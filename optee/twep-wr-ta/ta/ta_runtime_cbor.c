/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */
#include "ta_runtime_internal.h"

bool cbor_read_len(struct cbor_cursor *cur, uint8_t want_major, uint64_t *value)
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

bool cbor_skip_item(struct cbor_cursor *cur, unsigned depth)
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

bool cbor_read_text_key(struct cbor_cursor *cur, const uint8_t **key,
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

bool key_eq(const uint8_t *key, size_t key_len, const char *want)
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

TEE_Result parse_uint32_value(struct cbor_cursor *cur, uint32_t *out)
{
	uint64_t value = 0;

	if (!cbor_read_len(cur, 0, &value) || value > UINT32_MAX)
		return TEE_ERROR_BAD_FORMAT;
	*out = (uint32_t)value;
	return TEE_SUCCESS;
}

TEE_Result parse_text_value_view(struct cbor_cursor *cur,
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

TEE_Result parse_bstr_value_view(struct cbor_cursor *cur,
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

TEE_Result parse_production_envelope(const void *buf, size_t len,
				     enum twep_ta_production_envelope_kind kind,
				     struct production_envelope_seen *out_seen)
{
	struct cbor_cursor cur = {.buf = buf, .len = len, .off = 0};
	struct production_envelope_seen seen = {};
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
			res = parse_text_value_view(&cur,
						    &seen.resolver_mode_view);
			seen.resolver_mode = true;
		} else if (key_eq(key, key_len, "attestam_url")) {
			res = parse_text_value_view_allow_empty(
				&cur, &seen.attestam_url_view);
			seen.attestam_url = true;
		} else if (key_eq(key, key_len, "insecure")) {
			res = parse_bool_value(&cur);
			seen.insecure = true;
		} else if (key_eq(key, key_len, "default_timeout_ms")) {
			res = parse_uint32_value(
				&cur, &seen.default_timeout_ms_value);
			seen.default_timeout_ms = true;
		} else if (key_eq(key, key_len, "max_request_size")) {
			res = parse_uint_value(&cur);
			seen.max_request_size = true;
		} else if (key_eq(key, key_len, "max_response_size")) {
			res = parse_uint_value(&cur);
			seen.max_response_size = true;
		} else if (key_eq(key, key_len, "request_id")) {
			res = parse_text_value_view(&cur,
						    &seen.request_id_view);
			seen.request_id = true;
		} else if (key_eq(key, key_len, "command")) {
			res = parse_text_value_view(&cur, &seen.command_view);
			seen.command = true;
		} else if (key_eq(key, key_len, "app_input_cbor")) {
			res = parse_bstr_value_view(&cur, &seen.app_input_view);
			seen.app_input_cbor = true;
		} else if (key_eq(key, key_len, "request_timeout_ms")) {
			res = parse_uint32_value(
				&cur, &seen.request_timeout_ms_value);
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
			res = parse_bstr_value_view(
				&cur, &seen.dev_agent_public_key_view);
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

size_t cbor_type_len_size(uint64_t n)
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

void cbor_write_type_len(uint8_t **p, uint8_t major, uint64_t n)
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

void cbor_write_text(uint8_t **p, const char *text)
{
	size_t len = strlen(text);

	cbor_write_type_len(p, 3, len);
	TEE_MemMove(*p, text, len);
	*p += len;
}

void cbor_write_view_text(uint8_t **p, const struct bytes_view *view)
{
	cbor_write_type_len(p, 3, view->len);
	if (view->len) {
		TEE_MemMove(*p, view->ptr, view->len);
		*p += view->len;
	}
}

void cbor_write_bstr(uint8_t **p, const uint8_t *bytes, size_t len)
{
	cbor_write_type_len(p, 2, len);
	if (len) {
		TEE_MemMove(*p, bytes, len);
		*p += len;
	}
}

bool bytes_view_eq(const struct bytes_view *view, const char *want)
{
	size_t want_len = strlen(want);

	return view->len == want_len &&
	       TEE_MemCompare(view->ptr, want, want_len) == 0;
}

#ifdef TWEP_TA_WAMR_LINK
bool object_name_eq(const char *ptr, uint32_t len, const char *want)
{
	size_t want_len = strlen(want);

	return len == want_len && TEE_MemCompare(ptr, want, want_len) == 0;
}
#endif

#ifdef TWEP_TA_WAMR_LINK
bool bytes_view_is_safe_command(const struct bytes_view *view)
{
	size_t i = 0;

	if (!view->ptr || view->len == 0 || view->len > 32)
		return false;
	for (i = 0; i < view->len; i++) {
		uint8_t ch = view->ptr[i];

		if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
		    (ch >= '0' && ch <= '9') || ch == '_' || ch == '-')
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
	TEE_Result res =
		TEE_AllocateOperation(&op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
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
