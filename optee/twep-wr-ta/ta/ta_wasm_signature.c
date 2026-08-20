/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */
#include "ta_runtime_internal.h"

#define TEEP_AGENT_P256_BITS 256
#define TEEP_AGENT_SIGNATURE_SIZE 64

/* Public half of the fixed, development-only TEEP Agent signing key. */
static const uint8_t teep_agent_public_x[32] = {
	0x82, 0x82, 0x0a, 0xb9, 0x8d, 0x42, 0x91, 0xc4,
	0x9d, 0x9a, 0x3c, 0x95, 0x07, 0x13, 0x52, 0x1a,
	0xed, 0x4e, 0xb4, 0x7f, 0xf0, 0xd2, 0x3e, 0x9c,
	0xd8, 0xd6, 0x38, 0x8f, 0x23, 0x09, 0x20, 0xc9,
};
static const uint8_t teep_agent_public_y[32] = {
	0x9b, 0x7f, 0xb3, 0x3e, 0x03, 0x5f, 0x63, 0xb7,
	0x9e, 0x9c, 0xcf, 0x53, 0x64, 0x60, 0x55, 0xb8,
	0x38, 0x75, 0x18, 0xae, 0x86, 0x65, 0xd0, 0x2e,
	0x3f, 0x80, 0xba, 0x60, 0x88, 0xe4, 0xa7, 0xa1,
};

struct wasm_signature_payload {
	struct bytes_view signature;
	bool alg;
	bool kid;
	bool sig;
	bool role;
};

static bool read_varuint32(const uint8_t *bytes, size_t len, size_t *off,
			   uint32_t *value)
{
	uint32_t result = 0;
	unsigned shift;

	for (shift = 0; shift < 35; shift += 7) {
		uint8_t byte;

		if (*off >= len)
			return false;
		byte = bytes[(*off)++];
		if (shift == 28 && (byte & 0xf0))
			return false;
		result |= (uint32_t)(byte & 0x7f) << shift;
		if (!(byte & 0x80)) {
			*value = result;
			return true;
		}
	}
	return false;
}

static bool read_cbor_view(struct cbor_cursor *cur, uint8_t major,
			   struct bytes_view *view)
{
	uint64_t len;

	if (!cbor_read_len(cur, major, &len) || len > cur->len - cur->off)
		return false;
	view->ptr = cur->buf + cur->off;
	view->len = (size_t)len;
	cur->off += (size_t)len;
	return true;
}

static bool view_equals(const struct bytes_view *view, const char *text)
{
	size_t len = strlen(text);

	return view->len == len && !TEE_MemCompare(view->ptr, text, len);
}

static bool parse_signature_payload(const uint8_t *bytes, size_t len,
				    struct wasm_signature_payload *payload)
{
	struct cbor_cursor cur = { .buf = bytes, .len = len };
	uint64_t pairs;
	uint64_t i;

	if (!cbor_read_len(&cur, 5, &pairs) || pairs > 16)
		return false;
	for (i = 0; i < pairs; i++) {
		const uint8_t *key;
		size_t key_len;
		struct bytes_view value;

		if (!cbor_read_text_key(&cur, &key, &key_len))
			return false;
		if (key_len == 3 && !TEE_MemCompare(key, "alg", 3)) {
			if (payload->alg || !read_cbor_view(&cur, 3, &value) ||
			    !view_equals(&value, "ESP256"))
				return false;
			payload->alg = true;
		} else if (key_len == 3 && !TEE_MemCompare(key, "kid", 3)) {
			if (payload->kid || !read_cbor_view(&cur, 2, &value) ||
			    !value.len)
				return false;
			payload->kid = true;
		} else if (key_len == 3 && !TEE_MemCompare(key, "sig", 3)) {
			if (payload->sig || !read_cbor_view(&cur, 2, &value) ||
			    value.len != TEEP_AGENT_SIGNATURE_SIZE)
				return false;
			payload->signature = value;
			payload->sig = true;
		} else if (key_len == 4 && !TEE_MemCompare(key, "role", 4)) {
			if (payload->role || !read_cbor_view(&cur, 3, &value) ||
			    !view_equals(&value, "teep-agent"))
				return false;
			payload->role = true;
		} else if (!cbor_skip_item(&cur, 0)) {
			return false;
		}
	}
	return cur.off == cur.len && payload->alg && payload->kid &&
	       payload->sig && payload->role;
}

static bool find_signature(const struct bytes_view *wasm, size_t *prefix_len,
			   struct wasm_signature_payload *payload)
{
	size_t off = 8;

	if (!wasm || !wasm->ptr || wasm->len < 8 ||
	    TEE_MemCompare(wasm->ptr, "\0asm", 4))
		return false;
	while (off < wasm->len) {
		size_t section_start = off;
		size_t payload_start;
		size_t payload_end;
		uint32_t section_size;
		uint8_t section_id = wasm->ptr[off++];

		if (!read_varuint32(wasm->ptr, wasm->len, &off, &section_size) ||
		    section_size > wasm->len - off)
			return false;
		payload_start = off;
		payload_end = off + section_size;
		if (section_id == 0) {
			uint32_t name_len;
			size_t name_off = payload_start;

			if (!read_varuint32(wasm->ptr, payload_end, &name_off,
					    &name_len) ||
			    name_len > payload_end - name_off)
				return false;
			if (name_len == sizeof("twep.sig") - 1 &&
			    !TEE_MemCompare(wasm->ptr + name_off, "twep.sig",
					    sizeof("twep.sig") - 1)) {
				name_off += name_len;
				if (payload_end != wasm->len ||
				    !parse_signature_payload(wasm->ptr + name_off,
							     payload_end - name_off,
							     payload))
					return false;
				*prefix_len = section_start;
				return true;
			}
		}
		off = payload_end;
	}
	return false;
}

TEE_Result twep_ta_verify_teep_agent_wasm_signature(
	const struct bytes_view *wasm)
{
	struct wasm_signature_payload payload = {};
	TEE_Attribute attrs[3];
	TEE_ObjectHandle key = TEE_HANDLE_NULL;
	TEE_OperationHandle operation = TEE_HANDLE_NULL;
	uint8_t digest[32];
	size_t prefix_len;
	TEE_Result res;

	if (!find_signature(wasm, &prefix_len, &payload))
		return TEE_ERROR_SECURITY;
	res = twep_ta_sha256_bytes(wasm->ptr, prefix_len, digest);
	if (res != TEE_SUCCESS)
		return res;
	res = TEE_AllocateTransientObject(TEE_TYPE_ECDSA_PUBLIC_KEY,
					  TEEP_AGENT_P256_BITS, &key);
	if (res != TEE_SUCCESS)
		goto out;
	TEE_InitRefAttribute(&attrs[0], TEE_ATTR_ECC_PUBLIC_VALUE_X,
			     (void *)teep_agent_public_x,
			     sizeof(teep_agent_public_x));
	TEE_InitRefAttribute(&attrs[1], TEE_ATTR_ECC_PUBLIC_VALUE_Y,
			     (void *)teep_agent_public_y,
			     sizeof(teep_agent_public_y));
	TEE_InitValueAttribute(&attrs[2], TEE_ATTR_ECC_CURVE,
			       TEE_ECC_CURVE_NIST_P256, 0);
	res = TEE_PopulateTransientObject(key, attrs, 3);
	if (res != TEE_SUCCESS)
		goto out;
	res = TEE_AllocateOperation(&operation, TEE_ALG_ECDSA_P256,
				    TEE_MODE_VERIFY, TEEP_AGENT_P256_BITS);
	if (res != TEE_SUCCESS)
		goto out;
	res = TEE_SetOperationKey(operation, key);
	if (res != TEE_SUCCESS)
		goto out;
	res = TEE_AsymmetricVerifyDigest(operation, NULL, 0, digest,
					 sizeof(digest), payload.signature.ptr,
					 payload.signature.len);
out:
	if (operation != TEE_HANDLE_NULL)
		TEE_FreeOperation(operation);
	if (key != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(key);
	TEE_MemFill(digest, 0, sizeof(digest));
	return res;
}
