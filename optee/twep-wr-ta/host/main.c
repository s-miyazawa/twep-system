/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
// SPDX-License-Identifier: BSD-2-Clause

#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tee_client_api.h>

#include <twep_wr_ta.h>

struct twep_ta_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
};

struct trustzone_transport_response {
	uint8_t *ptr;
	size_t len;
};

struct host_io_transcript {
	uint64_t sequence;
	uint8_t request_body_sha256[32];
	uint8_t normalized_input_sha256[32];
};

static uint8_t *read_file(const char *path, size_t *out_len);
static int validate_helloworld_app_output(const uint8_t *bytes, size_t len);
static void invoke_abi_vectors(struct twep_ta_ctx *ctx, const char *path);

static const uint8_t wamr_spike_helloworld_input[] = {
	0xa1,
	0x67, 'c', 'o', 'm', 'm', 'a', 'n', 'd',
	0x6a, 'h', 'e', 'l', 'l', 'o', 'w', 'o', 'r', 'l', 'd',
};

static const uint8_t production_init_envelope[] = {
	0xa6,
	0x6d, 'r', 'e', 's', 'o', 'l', 'v', 'e', 'r', '_', 'm', 'o', 'd', 'e',
	0x64, 'm', 'o', 'c', 'k',
	0x6c, 'a', 't', 't', 'e', 's', 't', 'a', 'm', '_', 'u', 'r', 'l',
	0x74, 'h', 't', 't', 'p', ':', '/', '/', '1', '2', '7', '.', '0',
	'.', '0', '.', '1', '/', 't', 'a', 'm',
	0x68, 'i', 'n', 's', 'e', 'c', 'u', 'r', 'e',
	0xf5,
	0x72, 'd', 'e', 'f', 'a', 'u', 'l', 't', '_', 't', 'i', 'm', 'e',
	'o', 'u', 't', '_', 'm', 's',
	0x19, 0x03, 0xe8,
	0x70, 'm', 'a', 'x', '_', 'r', 'e', 'q', 'u', 'e', 's', 't', '_',
	's', 'i', 'z', 'e',
	0x1a, 0x00, 0x01, 0x00, 0x00,
	0x71, 'm', 'a', 'x', '_', 'r', 'e', 's', 'p', 'o', 'n', 's', 'e',
	'_', 's', 'i', 'z', 'e',
	0x1a, 0x00, 0x01, 0x00, 0x00,
};

static const uint8_t production_execute_envelope[] = {
	0xa4,
	0x6a, 'r', 'e', 'q', 'u', 'e', 's', 't', '_', 'i', 'd',
	0x65, 'r', 'e', 'q', '-', '1',
	0x67, 'c', 'o', 'm', 'm', 'a', 'n', 'd',
	0x6a, 'h', 'e', 'l', 'l', 'o', 'w', 'o', 'r', 'l', 'd',
	0x6e, 'a', 'p', 'p', '_', 'i', 'n', 'p', 'u', 't', '_', 'c', 'b',
	'o', 'r',
	0x40,
	0x72, 'r', 'e', 'q', 'u', 'e', 's', 't', '_', 't', 'i', 'm', 'e',
	'o', 'u', 't', '_', 'm', 's',
	0x19, 0x03, 0xe8,
};

static const uint8_t production_resume_envelope[] = {
	0xa2,
	0x6a, 'r', 'e', 'q', 'u', 'e', 's', 't', '_', 'i', 'd',
	0x65, 'r', 'e', 'q', '-', '1',
	0x73, 'h', 'o', 's', 't', '_', 'i', 'o', '_', 'r', 'e', 's', 'u',
	'l', 't', '_', 'c', 'b', 'o', 'r',
	0x40,
};

static const uint8_t calcadd_3_4_5_input[] = {
	0xa1,
	0x6f, 'i', 'n', 'f', 'e', 'r', 'r', 'e', 'd', '_', 'p', 'a', 'r',
	'a', 'm', 's',
	0x83,
	0xa2, 0x64, 't', 'y', 'p', 'e', 0x63, 'i', 'n', 't',
	0x65, 'v', 'a', 'l', 'u', 'e', 0x03,
	0xa2, 0x64, 't', 'y', 'p', 'e', 0x63, 'i', 'n', 't',
	0x65, 'v', 'a', 'l', 'u', 'e', 0x04,
	0xa2, 0x64, 't', 'y', 'p', 'e', 0x63, 'i', 'n', 't',
	0x65, 'v', 'a', 'l', 'u', 'e', 0x05,
};

static void open_ta(struct twep_ta_ctx *ctx)
{
	TEEC_UUID uuid = TA_TWEP_WR_UUID;
	TEEC_Result res;
	uint32_t origin = 0;

	res = TEEC_InitializeContext(NULL, &ctx->ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx->ctx, &ctx->sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_OpenSession failed with code 0x%x origin 0x%x",
		     res, origin);
}

static void close_ta(struct twep_ta_ctx *ctx)
{
	TEEC_CloseSession(&ctx->sess);
	TEEC_FinalizeContext(&ctx->ctx);
}

static void invoke_ping(struct twep_ta_ctx *ctx)
{
	TEEC_Operation op;
	TEEC_Result res;
	uint32_t origin = 0;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = 41;

	res = TEEC_InvokeCommand(&ctx->sess, TA_TWEP_WR_CMD_PING, &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "PING failed with code 0x%x origin 0x%x", res, origin);
	if (op.params[0].value.a != 42)
		errx(1, "PING returned unexpected value %u", op.params[0].value.a);

	puts("TA ping ok");
}

static void invoke_platform_status(struct twep_ta_ctx *ctx)
{
	char status[256];
	TEEC_Operation op;
	TEEC_Result res;
	uint32_t origin = 0;

	memset(status, 0, sizeof(status));
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = status;
	op.params[0].tmpref.size = sizeof(status);

	res = TEEC_InvokeCommand(&ctx->sess, TA_TWEP_WR_CMD_GET_PLATFORM_STATUS,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "GET_PLATFORM_STATUS failed with code 0x%x origin 0x%x",
		     res, origin);

	printf("%s", status);
}

static void secure_storage_put(struct twep_ta_ctx *ctx, const char *name,
			       const void *value, size_t value_len)
{
	TEEC_Operation op;
	TEEC_Result res;
	uint32_t origin = 0;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = (void *)name;
	op.params[0].tmpref.size = strlen(name);
	op.params[1].tmpref.buffer = (void *)value;
	op.params[1].tmpref.size = value_len;

	res = TEEC_InvokeCommand(&ctx->sess, TA_TWEP_WR_CMD_SECURE_STORAGE_PUT,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "SECURE_STORAGE_PUT failed with code 0x%x origin 0x%x",
		     res, origin);
}

static void expect_secure_storage_put_rejected(struct twep_ta_ctx *ctx,
					       const char *name)
{
	const char value[] = "blocked";
	TEEC_Operation op;
	TEEC_Result res;
	uint32_t origin = 0;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = (void *)name;
	op.params[0].tmpref.size = strlen(name);
	op.params[1].tmpref.buffer = (void *)value;
	op.params[1].tmpref.size = sizeof(value) - 1;

	res = TEEC_InvokeCommand(&ctx->sess, TA_TWEP_WR_CMD_SECURE_STORAGE_PUT,
				 &op, &origin);
	if (res != TEEC_ERROR_ACCESS_DENIED)
		errx(1, "SECURE_STORAGE_PUT unexpectedly accepted reserved object %s: code 0x%x origin 0x%x",
		     name, res, origin);
}

static void secure_storage_get(struct twep_ta_ctx *ctx, const char *name,
			       void *value, size_t value_len, size_t *out_len)
{
	TEEC_Operation op;
	TEEC_Result res;
	uint32_t origin = 0;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = (void *)name;
	op.params[0].tmpref.size = strlen(name);
	op.params[1].tmpref.buffer = value;
	op.params[1].tmpref.size = value_len;

	res = TEEC_InvokeCommand(&ctx->sess, TA_TWEP_WR_CMD_SECURE_STORAGE_GET,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "SECURE_STORAGE_GET failed with code 0x%x origin 0x%x",
		     res, origin);
	if (out_len)
		*out_len = op.params[1].tmpref.size;
}

static void secure_storage_get_optional(struct twep_ta_ctx *ctx,
					const char *name, void *value,
					size_t value_len, size_t *out_len)
{
	TEEC_Operation op;
	TEEC_Result res;
	uint32_t origin = 0;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = (void *)name;
	op.params[0].tmpref.size = strlen(name);
	op.params[1].tmpref.buffer = value;
	op.params[1].tmpref.size = value_len;

	res = TEEC_InvokeCommand(&ctx->sess, TA_TWEP_WR_CMD_SECURE_STORAGE_GET,
				 &op, &origin);
	if (res == TEEC_ERROR_ITEM_NOT_FOUND) {
		if (out_len)
			*out_len = 0;
		return;
	}
	if (res != TEEC_SUCCESS)
		errx(1, "optional SECURE_STORAGE_GET failed with code 0x%x origin 0x%x",
		     res, origin);
	if (out_len)
		*out_len = op.params[1].tmpref.size;
}

static void expect_secure_storage_get_rejected(struct twep_ta_ctx *ctx,
					       const char *name,
					       size_t value_len)
{
	uint8_t value[64] = { 0 };
	TEEC_Operation op;
	TEEC_Result res;
	uint32_t origin = 0;

	if (value_len > sizeof(value))
		errx(1, "invalid reserved-object read test size");
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = (void *)name;
	op.params[0].tmpref.size = strlen(name);
	op.params[1].tmpref.buffer = value;
	op.params[1].tmpref.size = value_len;

	res = TEEC_InvokeCommand(&ctx->sess, TA_TWEP_WR_CMD_SECURE_STORAGE_GET,
				 &op, &origin);
	if (res != TEEC_ERROR_ACCESS_DENIED)
		errx(1, "SECURE_STORAGE_GET unexpectedly exposed reserved object %s with %zu-byte buffer: code 0x%x origin 0x%x",
		     name, value_len, res, origin);
}

static void invoke_secure_storage_smoke(struct twep_ta_ctx *ctx)
{
	const char object_name[] = "twep-wr-ta-smoke";
	const char object_value[] = "secure-storage-smoke-value";
	char read_back[64];
	size_t read_len = 0;

	memset(read_back, 0, sizeof(read_back));
	secure_storage_put(ctx, object_name, object_value, strlen(object_value));
	secure_storage_get(ctx, object_name, read_back, sizeof(read_back), &read_len);

	if (read_len != strlen(object_value) || strcmp(read_back, object_value) != 0)
		errx(1, "secure storage readback mismatch: %s", read_back);

	puts("secure storage readback ok");
}

static void invoke_random_smoke(struct twep_ta_ctx *ctx)
{
	uint8_t random[32];
	TEEC_Operation op;
	TEEC_Result res;
	uint32_t origin = 0;
	size_t i;
	int nonzero = 0;

	memset(random, 0, sizeof(random));
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = random;
	op.params[0].tmpref.size = sizeof(random);

	res = TEEC_InvokeCommand(&ctx->sess, TA_TWEP_WR_CMD_GET_RANDOM, &op,
				 &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "GET_RANDOM failed with code 0x%x origin 0x%x", res,
		     origin);
	if (op.params[0].tmpref.size != sizeof(random))
		errx(1, "GET_RANDOM returned unexpected size %zu",
		     op.params[0].tmpref.size);
	for (i = 0; i < sizeof(random); i++) {
		if (random[i] != 0) {
			nonzero = 1;
			break;
		}
	}
	if (!nonzero)
		errx(1, "GET_RANDOM returned all-zero bytes");

	puts("random smoke ok");
}

static void invoke_time_smoke(struct twep_ta_ctx *ctx)
{
	TEEC_Operation op;
	TEEC_Result res;
	uint32_t origin = 0;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(&ctx->sess, TA_TWEP_WR_CMD_GET_TIME, &op,
				 &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "GET_TIME failed with code 0x%x origin 0x%x", res,
		     origin);
	if (op.params[0].value.a == 0 || op.params[0].value.b >= 1000)
		errx(1, "GET_TIME returned unexpected value %u.%03u",
		     op.params[0].value.a, op.params[0].value.b);

	puts("time smoke ok");
}

static void invoke_cbor_dry_run_smoke(struct twep_ta_ctx *ctx)
{
	static const uint8_t request[] = {
		0xa1,
		0x67, 'c', 'o', 'm', 'm', 'a', 'n', 'd',
		0x65, 's', 'm', 'o', 'k', 'e',
	};
	static const uint8_t want_response[] = {
		0xa2,
		0x64, 'm', 'o', 'd', 'e',
		0x6c, 'c', 'b', 'o', 'r', '-', 'd', 'r', 'y', '-', 'r', 'u', 'n',
		0x66, 's', 't', 'a', 't', 'u', 's',
		0x62, 'o', 'k',
	};
	uint8_t response[64];
	TEEC_Operation op;
	TEEC_Result res;
	uint32_t origin = 0;

	memset(response, 0, sizeof(response));
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = (void *)request;
	op.params[0].tmpref.size = sizeof(request);
	op.params[1].tmpref.buffer = response;
	op.params[1].tmpref.size = sizeof(response);

	res = TEEC_InvokeCommand(&ctx->sess, TA_TWEP_WR_CMD_CBOR_DRY_RUN, &op,
				 &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "CBOR_DRY_RUN failed with code 0x%x origin 0x%x", res,
		     origin);
	if (op.params[1].tmpref.size != sizeof(want_response) ||
	    memcmp(response, want_response, sizeof(want_response)) != 0)
		errx(1, "CBOR_DRY_RUN returned unexpected response");

	puts("CBOR dry-run ok");
}

static TEEC_Result invoke_production_raw(struct twep_ta_ctx *ctx,
					 uint32_t command,
					 const uint8_t *request,
					 size_t request_len,
					 uint8_t *response,
					 size_t response_len,
					 size_t *out_response_len,
					 uint32_t *out_origin)
{
	TEEC_Operation op;
	TEEC_Result res;
	uint32_t origin = 0;

	memset(response, 0, response_len);
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = (void *)request;
	op.params[0].tmpref.size = request_len;
	op.params[1].tmpref.buffer = response;
	op.params[1].tmpref.size = response_len;

	res = TEEC_InvokeCommand(&ctx->sess, command, &op, &origin);
	if (out_response_len)
		*out_response_len = op.params[1].tmpref.size;
	if (out_origin)
		*out_origin = origin;
	return res;
}

static TEEC_Result trustzone_transport_execute(struct twep_ta_ctx *ctx,
					       const uint8_t *request,
					       size_t request_len,
					       struct trustzone_transport_response *out,
					       uint32_t *out_origin)
{
	uint8_t response[4096];
	size_t response_len = 0;
	TEEC_Result res;

	if (!out)
		return TEEC_ERROR_BAD_PARAMETERS;
	out->ptr = NULL;
	out->len = 0;

	res = invoke_production_raw(ctx, TA_TWEP_WR_CMD_EXECUTE, request,
				    request_len, response, sizeof(response),
				    &response_len, out_origin);
	if (res != TEEC_SUCCESS)
		return res;

	out->ptr = malloc(response_len);
	if (!out->ptr)
		return TEEC_ERROR_OUT_OF_MEMORY;
	memcpy(out->ptr, response, response_len);
	out->len = response_len;
	return TEEC_SUCCESS;
}

static void trustzone_transport_response_free(
				struct trustzone_transport_response *response)
{
	if (!response)
		return;
	free(response->ptr);
	response->ptr = NULL;
	response->len = 0;
}

static int bytes_contains(const uint8_t *haystack, size_t haystack_len,
			  const char *needle)
{
	size_t needle_len = strlen(needle);
	size_t i;

	if (needle_len == 0 || haystack_len < needle_len)
		return 0;
	for (i = 0; i <= haystack_len - needle_len; i++) {
		if (memcmp(haystack + i, needle, needle_len) == 0)
			return 1;
	}
	return 0;
}

static uint8_t *catalog_with_small_negaposi_output_limit(
				const uint8_t *catalog, size_t catalog_len,
				size_t *out_len)
{
	static const uint8_t max_output_key[] = {
		0x70, 'm', 'a', 'x', '_', 'o', 'u', 't', 'p', 'u', 't',
		'_', 'b', 'y', 't', 'e', 's',
	};
	uint8_t *patched = NULL;
	size_t i = 0;

	if (catalog_len < sizeof(max_output_key) + 5)
		errx(1, "catalog too small to patch max_output_bytes");
	patched = malloc(catalog_len);
	if (!patched)
		err(1, "malloc patched catalog");
	memcpy(patched, catalog, catalog_len);
	for (i = 0; i <= catalog_len - sizeof(max_output_key) - 5; i++) {
		if (memcmp(patched + i, max_output_key,
			   sizeof(max_output_key)) == 0 &&
		    patched[i + sizeof(max_output_key)] == 0x1a) {
			size_t value = i + sizeof(max_output_key) + 1;

			patched[value] = 0x00;
			patched[value + 1] = 0x00;
			patched[value + 2] = 0x00;
			patched[value + 3] = 0x08;
			*out_len = catalog_len;
			return patched;
		}
	}
	free(patched);
	errx(1, "catalog max_output_bytes field not found");
}

static void dump_hex(FILE *stream, const uint8_t *bytes, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		fprintf(stream, "%02x", bytes[i]);
}

static int looks_like_jpeg_bytes(const uint8_t *bytes, size_t len)
{
	return len >= 4 && bytes[0] == 0xff && bytes[1] == 0xd8 &&
	       bytes[len - 2] == 0xff && bytes[len - 1] == 0xd9;
}

static size_t cbor_len_size(uint64_t n)
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
	} else if (n <= 0xffffffff) {
		*(*p)++ = (uint8_t)((major << 5) | 26);
		*(*p)++ = (uint8_t)(n >> 24);
		*(*p)++ = (uint8_t)(n >> 16);
		*(*p)++ = (uint8_t)(n >> 8);
		*(*p)++ = (uint8_t)n;
	} else {
		int shift;

		*(*p)++ = (uint8_t)((major << 5) | 27);
		for (shift = 56; shift >= 0; shift -= 8)
			*(*p)++ = (uint8_t)(n >> shift);
	}
}

static void cbor_write_text(uint8_t **p, const char *text)
{
	size_t len = strlen(text);

	cbor_write_type_len(p, 3, len);
	memcpy(*p, text, len);
	*p += len;
}

static void expect_production_success(struct twep_ta_ctx *ctx, uint32_t command,
				      const char *label,
				      const uint8_t *request,
				      size_t request_len)
{
	uint8_t response[128];
	size_t response_len = 0;
	TEEC_Result res;
	uint32_t origin = 0;

	res = invoke_production_raw(ctx, command, request, request_len, response,
				    sizeof(response), &response_len, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "%s envelope parse failed with code 0x%x origin 0x%x",
		     label, res, origin);
	if (response_len == 0 ||
	    !bytes_contains(response, response_len,
			    "ta-production-runtime-skeleton"))
		errx(1, "%s envelope returned unexpected skeleton response",
		     label);
	printf("TA production %s envelope parsed\n", label);
}

static void invoke_execute_abi_negative(struct twep_ta_ctx *ctx)
{
	static const uint8_t malformed_envelope[] = { 0xff };
	uint8_t short_response[8];
	uint8_t response[128];
	size_t response_len = 0;
	TEEC_Result res;
	uint32_t origin = 0;
	TEEC_Operation op;

	expect_production_success(ctx, TA_TWEP_WR_CMD_INIT, "init",
				  production_init_envelope,
				  sizeof(production_init_envelope));
	expect_production_success(ctx, TA_TWEP_WR_CMD_EXECUTE, "execute",
				  production_execute_envelope,
				  sizeof(production_execute_envelope));
	res = invoke_production_raw(ctx, TA_TWEP_WR_CMD_RESUME_HOST_IO,
				    production_resume_envelope,
				    sizeof(production_resume_envelope), response,
				    sizeof(response), &response_len, &origin);
	if (res != TEEC_ERROR_BAD_FORMAT)
		errx(1, "TA production resume-host-io without pending request returned code 0x%x origin 0x%x",
		     res, origin);
	printf("TA production resume-host-io rejected without pending request: code 0x%x origin 0x%x\n",
	       res, origin);

	res = invoke_production_raw(ctx, TA_TWEP_WR_CMD_INIT,
				    production_init_envelope,
				    sizeof(production_init_envelope),
				    short_response, sizeof(short_response),
				    &response_len, &origin);
	if (res != TEEC_ERROR_SHORT_BUFFER)
		errx(1, "TA production init did not reject short output buffer: code 0x%x origin 0x%x",
		     res, origin);
	if (response_len <= sizeof(short_response))
		errx(1, "TA production init did not report required output length");
	printf("TA production init rejected short output buffer: code 0x%x origin 0x%x needed %zu\n",
	       res, origin, response_len);

	res = invoke_production_raw(ctx, TA_TWEP_WR_CMD_EXECUTE,
				    malformed_envelope,
				    sizeof(malformed_envelope), response,
				    sizeof(response), &response_len, &origin);
	if (res != TEEC_ERROR_BAD_FORMAT)
		errx(1, "TA production execute did not reject malformed envelope: code 0x%x origin 0x%x",
		     res, origin);
	printf("TA production execute rejected malformed envelope: code 0x%x origin 0x%x\n",
	       res, origin);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE,
					 TEEC_NONE);
	res = TEEC_InvokeCommand(&ctx->sess, 0x7fffffff, &op, &origin);
	if (res != TEEC_ERROR_NOT_SUPPORTED)
		errx(1, "TA unsupported command did not return TEEC_ERROR_NOT_SUPPORTED: code 0x%x origin 0x%x",
		     res, origin);
	printf("TA unsupported command rejected: code 0x%x origin 0x%x\n",
	       res, origin);

	/* This value is compiled into the TA only with TWEP_TA_D043_TEST_HOOKS. */
	res = TEEC_InvokeCommand(&ctx->sess, 0x80000043, &op, &origin);
	if (res != TEEC_ERROR_NOT_SUPPORTED)
		errx(1, "TA production build exposed D043 test command: code 0x%x origin 0x%x",
		     res, origin);
	printf("TA production rejected D043 private test command: code 0x%x origin 0x%x\n",
	       res, origin);
	puts("TrustZone TA execute ABI negative ok");
}

static TEEC_Result invoke_wamr_spike_raw(struct twep_ta_ctx *ctx,
					 const char *wasm_path,
					 const uint8_t *app_input,
					 size_t app_input_len,
					 uint8_t *response,
					 size_t response_len,
					 size_t *out_response_len,
					 uint32_t *out_origin)
{
	uint8_t *wasm;
	size_t wasm_len;
	TEEC_Operation op;
	TEEC_Result res;
	uint32_t origin = 0;

	wasm = read_file(wasm_path, &wasm_len);
	if (wasm_len == 0)
		errx(1, "refusing empty Wasm spike payload %s", wasm_path);

	memset(response, 0, response_len);
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);
	op.params[0].tmpref.buffer = wasm;
	op.params[0].tmpref.size = wasm_len;
	op.params[1].tmpref.buffer = (void *)app_input;
	op.params[1].tmpref.size = app_input_len;
	op.params[2].tmpref.buffer = response;
	op.params[2].tmpref.size = response_len;

	res = TEEC_InvokeCommand(&ctx->sess, TA_TWEP_WR_CMD_WAMR_SPIKE_EXEC,
				 &op, &origin);
	free(wasm);
	if (out_response_len)
		*out_response_len = op.params[2].tmpref.size;
	if (out_origin)
		*out_origin = origin;
	return res;
}

static void invoke_wamr_spike(struct twep_ta_ctx *ctx, const char *wasm_path)
{
	uint8_t response[512];
	size_t response_len = 0;
	TEEC_Result res;
	uint32_t origin = 0;

	memset(response, 0, sizeof(response));
	res = invoke_wamr_spike_raw(ctx, wasm_path, wamr_spike_helloworld_input,
				    sizeof(wamr_spike_helloworld_input),
				    response, sizeof(response),
				    &response_len, &origin);
	if (res == TEEC_ERROR_NOT_SUPPORTED) {
		puts("WAMR spike blocker: TA command shape reached, but WAMR runtime is not linked into the TA");
		puts("WAMR spike blocker detail: TA_TWEP_WR_CMD_WAMR_SPIKE_EXEC returned TEEC_ERROR_NOT_SUPPORTED");
		return;
	}
	if (res != TEEC_SUCCESS)
		errx(1, "WAMR_SPIKE_EXEC failed with code 0x%x origin 0x%x",
		     res, origin);
	if (!validate_helloworld_app_output(response, response_len))
		errx(1, "WAMR_SPIKE_EXEC response did not match expected CBOR app output");

	puts("WAMR spike executed helloworld inside TA");
}

static void invoke_wamr_spike_expect_reject(struct twep_ta_ctx *ctx,
					    const char *wasm_path)
{
	uint8_t response[512];
	size_t response_len = 0;
	TEEC_Result res;
	uint32_t origin = 0;

	memset(response, 0, sizeof(response));
	res = invoke_wamr_spike_raw(ctx, wasm_path, wamr_spike_helloworld_input,
				    sizeof(wamr_spike_helloworld_input),
				    response, sizeof(response),
				    &response_len, &origin);
	if (res == TEEC_SUCCESS)
		errx(1, "WAMR_SPIKE_EXEC unexpectedly accepted unsupported payload");
	if (res == TEEC_ERROR_NOT_SUPPORTED)
		errx(1, "WAMR_SPIKE_EXEC did not reach linked WAMR path");

	printf("WAMR spike rejected unsupported import inside TA: code 0x%x origin 0x%x\n",
	       res, origin);
}

static void expect_wamr_spike_input_reject(struct twep_ta_ctx *ctx,
					   const char *wasm_path,
					   const char *label,
					   const uint8_t *app_input,
					   size_t app_input_len)
{
	uint8_t response[512];
	size_t response_len = 0;
	TEEC_Result res;
	uint32_t origin = 0;

	memset(response, 0, sizeof(response));
	res = invoke_wamr_spike_raw(ctx, wasm_path, app_input, app_input_len,
				    response, sizeof(response), &response_len,
				    &origin);
	if (res == TEEC_SUCCESS)
		errx(1, "WAMR_SPIKE_EXEC unexpectedly accepted %s input", label);
	if (res == TEEC_ERROR_NOT_SUPPORTED)
		errx(1, "WAMR_SPIKE_EXEC did not reach input validation for %s input",
		     label);

	printf("WAMR spike rejected %s app input inside TA: code 0x%x origin 0x%x\n",
	       label, res, origin);
}

static void invoke_wamr_spike_input_negative(struct twep_ta_ctx *ctx,
					     const char *wasm_path)
{
	static const uint8_t malformed_input[] = {
		0xa1,
		0x67, 'c', 'o', 'm', 'm', 'a', 'n', 'd',
		0x69, 'n', 'o', 't', '-', 'h', 'e', 'l', 'l', 'o',
	};
	uint8_t oversized_input[80];

	memset(oversized_input, 0xa0, sizeof(oversized_input));
	expect_wamr_spike_input_reject(ctx, wasm_path, "empty", malformed_input, 0);
	expect_wamr_spike_input_reject(ctx, wasm_path, "malformed",
				       malformed_input, sizeof(malformed_input));
	expect_wamr_spike_input_reject(ctx, wasm_path, "oversized",
				       oversized_input, sizeof(oversized_input));
	puts("WAMR spike input boundary rejection ok");
}

static void invoke_wamr_spike_output_negative(struct twep_ta_ctx *ctx,
					      const char *helloworld_wasm_path,
					      const char *oversized_wasm_path)
{
	uint8_t short_response[8];
	uint8_t response[512];
	size_t response_len = 0;
	TEEC_Result res;
	uint32_t origin = 0;

	memset(short_response, 0, sizeof(short_response));
	res = invoke_wamr_spike_raw(ctx, helloworld_wasm_path,
				    wamr_spike_helloworld_input,
				    sizeof(wamr_spike_helloworld_input),
				    short_response, sizeof(short_response),
				    &response_len, &origin);
	if (res != TEEC_ERROR_SHORT_BUFFER)
		errx(1, "WAMR_SPIKE_EXEC did not reject short output buffer: code 0x%x origin 0x%x",
		     res, origin);
	if (response_len <= sizeof(short_response))
		errx(1, "WAMR_SPIKE_EXEC did not report required output length");
	printf("WAMR spike rejected short output buffer inside TA: code 0x%x origin 0x%x needed %zu\n",
	       res, origin, response_len);

	memset(response, 0, sizeof(response));
	response_len = 0;
	origin = 0;
	res = invoke_wamr_spike_raw(ctx, oversized_wasm_path,
				    wamr_spike_helloworld_input,
				    sizeof(wamr_spike_helloworld_input),
				    response, sizeof(response), &response_len,
				    &origin);
	if (res == TEEC_SUCCESS)
		errx(1, "WAMR_SPIKE_EXEC unexpectedly accepted oversized output");
	if (res == TEEC_ERROR_NOT_SUPPORTED)
		errx(1, "WAMR_SPIKE_EXEC did not reach linked output validation");
	printf("WAMR spike rejected oversized app output inside TA: code 0x%x origin 0x%x\n",
	       res, origin);
	puts("WAMR spike output boundary rejection ok");
}

static void expect_wamr_spike_exec_failure(struct twep_ta_ctx *ctx,
					   const char *wasm_path,
					   const char *label,
					   TEEC_Result expected)
{
	uint8_t response[512];
	size_t response_len = 0;
	TEEC_Result res;
	uint32_t origin = 0;

	memset(response, 0, sizeof(response));
	res = invoke_wamr_spike_raw(ctx, wasm_path, wamr_spike_helloworld_input,
				    sizeof(wamr_spike_helloworld_input),
				    response, sizeof(response), &response_len,
				    &origin);
	if (res != expected)
		errx(1, "WAMR_SPIKE_EXEC did not reject %s with expected failure: want 0x%x got 0x%x origin 0x%x",
		     label, expected, res, origin);
	printf("WAMR spike rejected %s inside TA: code 0x%x origin 0x%x\n",
	       label, res, origin);
}

static void invoke_wamr_spike_cleanup_negative(struct twep_ta_ctx *ctx,
					       const char *helloworld_wasm_path,
					       const char *nonzero_wasm_path,
					       const char *trap_wasm_path)
{
	expect_wamr_spike_exec_failure(ctx, nonzero_wasm_path,
				       "nonzero app status",
				       TEEC_ERROR_GENERIC);
	expect_wamr_spike_exec_failure(ctx, trap_wasm_path, "trap app",
				       TEEC_ERROR_BAD_FORMAT);
	invoke_wamr_spike(ctx, helloworld_wasm_path);
	puts("WAMR spike cleanup after failures ok");
}

static int cbor_read_type_len(const uint8_t *bytes, size_t len, size_t *off,
			      uint8_t want_major, uint64_t *out_value)
{
	uint8_t initial;
	uint8_t major;
	uint8_t ai;
	uint64_t value = 0;
	size_t needed = 0;
	size_t i;

	if (*off >= len)
		return 0;
	initial = bytes[(*off)++];
	major = initial >> 5;
	ai = initial & 0x1f;
	if (major != want_major)
		return 0;
	if (ai < 24) {
		*out_value = ai;
		return 1;
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
		return 0;
	if (needed > len - *off)
		return 0;
	for (i = 0; i < needed; i++)
		value = (value << 8) | bytes[(*off)++];
	*out_value = value;
	return 1;
}

static int cbor_read_text_key(const uint8_t *bytes, size_t len, size_t *off,
			      const char *want)
{
	uint64_t text_len = 0;
	size_t want_len = strlen(want);

	if (!cbor_read_type_len(bytes, len, off, 3, &text_len))
		return 0;
	if (text_len != want_len || text_len > len - *off)
		return 0;
	if (memcmp(bytes + *off, want, want_len) != 0)
		return 0;
	*off += want_len;
	return 1;
}

static int validate_helloworld_app_output(const uint8_t *bytes, size_t len)
{
	static const uint8_t expected_stdout[] = "Hello, World!!\n";
	size_t off = 0;
	uint64_t map_len = 0;
	uint64_t value = 0;
	uint64_t text_len = 0;
	uint64_t stdout_len = 0;

	if (!cbor_read_type_len(bytes, len, &off, 5, &map_len) || map_len != 3)
		return 0;

	if (!cbor_read_text_key(bytes, len, &off, "status"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 3, &text_len) || text_len != 2 ||
	    text_len > len - off || memcmp(bytes + off, "ok", 2) != 0)
		return 0;
	off += text_len;

	if (!cbor_read_text_key(bytes, len, &off, "stdout"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 2, &stdout_len) ||
	    stdout_len != sizeof(expected_stdout) - 1 || stdout_len > len - off ||
	    memcmp(bytes + off, expected_stdout, sizeof(expected_stdout) - 1) != 0)
		return 0;
	off += stdout_len;

	if (!cbor_read_text_key(bytes, len, &off, "schema_version"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 0, &value) || value != 1)
		return 0;

	return off == len;
}

static int validate_helloworld_execute_response(const uint8_t *bytes, size_t len,
						const char *request_id)
{
	static const uint8_t expected_stdout[] = "Hello, World!!\n";
	size_t off = 0;
	uint64_t map_len = 0;
	uint64_t value = 0;
	uint64_t text_len = 0;
	uint64_t bytes_len = 0;

	if (!cbor_read_type_len(bytes, len, &off, 5, &map_len) || map_len != 6)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "schema_version"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 0, &value) || value != 1)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "request_id"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 3, &text_len) ||
	    text_len != strlen(request_id) || text_len > len - off ||
	    memcmp(bytes + off, request_id, text_len) != 0)
		return 0;
	off += text_len;
	if (!cbor_read_text_key(bytes, len, &off, "status"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 3, &text_len) || text_len != 2 ||
	    text_len > len - off || memcmp(bytes + off, "ok", 2) != 0)
		return 0;
	off += text_len;
	if (!cbor_read_text_key(bytes, len, &off, "exit_code"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 0, &value) || value != 0)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "stdout"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 2, &bytes_len) ||
	    bytes_len != sizeof(expected_stdout) - 1 || bytes_len > len - off ||
	    memcmp(bytes + off, expected_stdout, sizeof(expected_stdout) - 1) != 0)
		return 0;
	off += bytes_len;
	if (!cbor_read_text_key(bytes, len, &off, "app_output"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 2, &bytes_len) ||
	    bytes_len > len - off ||
	    !validate_helloworld_app_output(bytes + off, (size_t)bytes_len))
		return 0;
	off += bytes_len;
	return off == len;
}

static int validate_calcadd_app_output(const uint8_t *bytes, size_t len)
{
	size_t off = 0;
	uint64_t map_len = 0;
	uint64_t value = 0;
	uint64_t text_len = 0;
	uint64_t stdout_len = 0;

	if (!cbor_read_type_len(bytes, len, &off, 5, &map_len) || map_len != 4)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "schema_version"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 0, &value) || value != 1)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "status"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 3, &text_len) || text_len != 2 ||
	    text_len > len - off || memcmp(bytes + off, "ok", 2) != 0)
		return 0;
	off += text_len;
	if (!cbor_read_text_key(bytes, len, &off, "stdout"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 2, &stdout_len) ||
	    stdout_len != 3 || stdout_len > len - off ||
	    memcmp(bytes + off, "12\n", 3) != 0)
		return 0;
	off += stdout_len;
	if (!cbor_read_text_key(bytes, len, &off, "result"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 5, &map_len) || map_len != 1)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "sum"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 0, &value) || value != 12)
		return 0;
	return off == len;
}

static int validate_calcadd_execute_response(const uint8_t *bytes, size_t len,
					     const char *request_id)
{
	size_t off = 0;
	uint64_t map_len = 0;
	uint64_t value = 0;
	uint64_t text_len = 0;
	uint64_t bytes_len = 0;

	if (!cbor_read_type_len(bytes, len, &off, 5, &map_len) || map_len != 6)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "schema_version"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 0, &value) || value != 1)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "request_id"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 3, &text_len) ||
	    text_len != strlen(request_id) || text_len > len - off ||
	    memcmp(bytes + off, request_id, text_len) != 0)
		return 0;
	off += text_len;
	if (!cbor_read_text_key(bytes, len, &off, "status"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 3, &text_len) || text_len != 2 ||
	    text_len > len - off || memcmp(bytes + off, "ok", 2) != 0)
		return 0;
	off += text_len;
	if (!cbor_read_text_key(bytes, len, &off, "exit_code"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 0, &value) || value != 0)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "stdout"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 2, &bytes_len) ||
	    bytes_len != 3 || bytes_len > len - off ||
	    memcmp(bytes + off, "12\n", 3) != 0)
		return 0;
	off += bytes_len;
	if (!cbor_read_text_key(bytes, len, &off, "app_output"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 2, &bytes_len) ||
	    bytes_len > len - off ||
	    !validate_calcadd_app_output(bytes + off, (size_t)bytes_len))
		return 0;
	off += bytes_len;
	return off == len;
}

static int validate_negaposi_app_output(const uint8_t *bytes, size_t len)
{
	static const uint8_t expected_stdout[] =
		"Saving a Reversed Color Image\n";
	size_t off = 0;
	uint64_t map_len = 0;
	uint64_t value = 0;
	uint64_t text_len = 0;
	uint64_t bytes_len = 0;

	if (!cbor_read_type_len(bytes, len, &off, 5, &map_len) || map_len != 5)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "schema_version"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 0, &value) || value != 1)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "status"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 3, &text_len) || text_len != 2 ||
	    text_len > len - off || memcmp(bytes + off, "ok", 2) != 0)
		return 0;
	off += text_len;
	if (!cbor_read_text_key(bytes, len, &off, "files"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 5, &map_len) || map_len != 1)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "output"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 2, &bytes_len) ||
	    bytes_len > len - off ||
	    !looks_like_jpeg_bytes(bytes + off, (size_t)bytes_len))
		return 0;
	off += bytes_len;
	if (!cbor_read_text_key(bytes, len, &off, "metadata"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 5, &map_len) || map_len != 1)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "output_mime"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 3, &text_len) ||
	    text_len != strlen("image/jpeg") || text_len > len - off ||
	    memcmp(bytes + off, "image/jpeg", strlen("image/jpeg")) != 0)
		return 0;
	off += text_len;
	if (!cbor_read_text_key(bytes, len, &off, "stdout"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 2, &bytes_len) ||
	    bytes_len != sizeof(expected_stdout) - 1 || bytes_len > len - off ||
	    memcmp(bytes + off, expected_stdout, sizeof(expected_stdout) - 1) != 0)
		return 0;
	off += bytes_len;
	return off == len;
}

static int validate_negaposi_execute_response(const uint8_t *bytes, size_t len,
					      const char *request_id)
{
	static const uint8_t expected_stdout[] =
		"Saving a Reversed Color Image\n";
	size_t off = 0;
	uint64_t map_len = 0;
	uint64_t value = 0;
	uint64_t text_len = 0;
	uint64_t bytes_len = 0;

	if (!cbor_read_type_len(bytes, len, &off, 5, &map_len) || map_len != 6)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "schema_version"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 0, &value) || value != 1)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "request_id"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 3, &text_len) ||
	    text_len != strlen(request_id) || text_len > len - off ||
	    memcmp(bytes + off, request_id, text_len) != 0)
		return 0;
	off += text_len;
	if (!cbor_read_text_key(bytes, len, &off, "status"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 3, &text_len) || text_len != 2 ||
	    text_len > len - off || memcmp(bytes + off, "ok", 2) != 0)
		return 0;
	off += text_len;
	if (!cbor_read_text_key(bytes, len, &off, "exit_code"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 0, &value) || value != 0)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "stdout"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 2, &bytes_len) ||
	    bytes_len != sizeof(expected_stdout) - 1 || bytes_len > len - off ||
	    memcmp(bytes + off, expected_stdout, sizeof(expected_stdout) - 1) != 0)
		return 0;
	off += bytes_len;
	if (!cbor_read_text_key(bytes, len, &off, "app_output"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 2, &bytes_len) ||
	    bytes_len > len - off ||
	    !validate_negaposi_app_output(bytes + off, (size_t)bytes_len))
		return 0;
	off += bytes_len;
	return off == len;
}

static uint8_t *make_execute_envelope(const char *request_id,
				      const char *command,
				      const uint8_t *app_input,
				      size_t app_input_len,
				      const uint8_t *wasm,
				      size_t wasm_len,
				      size_t *out_len)
{
	size_t len = 1
		     + 1 + strlen("request_id") + cbor_len_size(strlen(request_id)) + strlen(request_id)
		     + 1 + strlen("command") + cbor_len_size(strlen(command)) + strlen(command)
		     + 1 + strlen("app_input_cbor") + cbor_len_size(app_input_len) + app_input_len
		     + 1 + strlen("request_timeout_ms") + 3
		     + 1 + strlen("wasm_bytes") + cbor_len_size(wasm_len) + wasm_len;
	uint8_t *buf = malloc(len);
	uint8_t *p = buf;

	if (!buf)
		err(1, "malloc execute envelope");
	*p++ = 0xa5;
	cbor_write_text(&p, "request_id");
	cbor_write_text(&p, request_id);
	cbor_write_text(&p, "command");
	cbor_write_text(&p, command);
	cbor_write_text(&p, "app_input_cbor");
	cbor_write_type_len(&p, 2, app_input_len);
	if (app_input_len) {
		memcpy(p, app_input, app_input_len);
		p += app_input_len;
	}
	cbor_write_text(&p, "request_timeout_ms");
	*p++ = 0x19;
	*p++ = 0x03;
	*p++ = 0xe8;
	cbor_write_text(&p, "wasm_bytes");
	cbor_write_type_len(&p, 2, wasm_len);
	if (wasm_len) {
		memcpy(p, wasm, wasm_len);
		p += wasm_len;
	}
	*out_len = (size_t)(p - buf);
	return buf;
}

static uint8_t *make_teep_resolve_envelope_for_command(
					   const char *command,
					   const uint8_t *app_input,
					   size_t app_input_len,
					   const uint8_t *teep_agent_wasm,
					   size_t teep_agent_wasm_len,
					   const uint8_t *catalog,
					   size_t catalog_len,
					   const uint8_t *app_wasm,
					   size_t app_wasm_len,
					   size_t *out_len)
{
	size_t len = 1
		     + 1 + strlen("request_id") + cbor_len_size(strlen("req-teep-resolve")) + strlen("req-teep-resolve")
		     + 1 + strlen("command") + cbor_len_size(strlen(command)) + strlen(command)
		     + 1 + strlen("app_input_cbor") + cbor_len_size(app_input_len) + app_input_len
		     + 1 + strlen("request_timeout_ms") + 3
		     + 1 + strlen("wasm_bytes") + cbor_len_size(teep_agent_wasm_len) + teep_agent_wasm_len
		     + 1 + strlen("catalog_cbor") + cbor_len_size(catalog_len) + catalog_len
		     + 1 + strlen("app_wasm_bytes") + cbor_len_size(app_wasm_len) + app_wasm_len;
	uint8_t *buf = malloc(len);
	uint8_t *p = buf;

	if (!buf)
		err(1, "malloc teep resolve envelope");
	*p++ = 0xa7;
	cbor_write_text(&p, "request_id");
	cbor_write_text(&p, "req-teep-resolve");
	cbor_write_text(&p, "command");
	cbor_write_text(&p, command);
	cbor_write_text(&p, "app_input_cbor");
	cbor_write_type_len(&p, 2, app_input_len);
	memcpy(p, app_input, app_input_len);
	p += app_input_len;
	cbor_write_text(&p, "request_timeout_ms");
	*p++ = 0x19;
	*p++ = 0x03;
	*p++ = 0xe8;
	cbor_write_text(&p, "wasm_bytes");
	cbor_write_type_len(&p, 2, teep_agent_wasm_len);
	memcpy(p, teep_agent_wasm, teep_agent_wasm_len);
	p += teep_agent_wasm_len;
	cbor_write_text(&p, "catalog_cbor");
	cbor_write_type_len(&p, 2, catalog_len);
	memcpy(p, catalog, catalog_len);
	p += catalog_len;
	cbor_write_text(&p, "app_wasm_bytes");
	cbor_write_type_len(&p, 2, app_wasm_len);
	memcpy(p, app_wasm, app_wasm_len);
	p += app_wasm_len;
	*out_len = (size_t)(p - buf);
	return buf;
}

static uint8_t *make_teep_resolve_envelope(const uint8_t *app_input,
					   size_t app_input_len,
					   const uint8_t *teep_agent_wasm,
					   size_t teep_agent_wasm_len,
					   const uint8_t *catalog,
					   size_t catalog_len,
					   const uint8_t *app_wasm,
					   size_t app_wasm_len,
					   size_t *out_len)
{
	return make_teep_resolve_envelope_for_command(
		"teep-agent-resolve", app_input, app_input_len,
		teep_agent_wasm, teep_agent_wasm_len, catalog, catalog_len,
		app_wasm, app_wasm_len, out_len);
}

static uint8_t *make_host_io_result_bytes_status(const char *io_id,
						 const char *kind,
						 const char *result_key,
						 const uint8_t *result,
						 size_t result_len,
						 uint8_t status,
						 const struct host_io_transcript *transcript,
						 size_t *out_len)
{
	size_t len = 1
		     + 1 + strlen("io_id") + cbor_len_size(strlen(io_id)) + strlen(io_id)
		     + 1 + strlen("kind") + cbor_len_size(strlen(kind)) + strlen(kind)
		     + 1 + strlen("status") + 1
		     + 1 + strlen(result_key) + cbor_len_size(result_len) + result_len
		     + 1 + strlen("sequence") + cbor_len_size(transcript ? transcript->sequence : 1)
		     + 1 + strlen("request_body_sha256") + cbor_len_size(32) + 32
		     + 1 + strlen("normalized_input_sha256") + cbor_len_size(32) + 32;
	uint8_t *buf = malloc(len);
	uint8_t *p = buf;
	uint64_t sequence = transcript ? transcript->sequence : 1;
	const uint8_t *request_body_sha256 = transcript ?
		transcript->request_body_sha256 : NULL;
	const uint8_t *normalized_input_sha256 = transcript ?
		transcript->normalized_input_sha256 : NULL;
	uint8_t zero_sha256[32] = { 0 };

	if (!request_body_sha256)
		request_body_sha256 = zero_sha256;
	if (!normalized_input_sha256)
		normalized_input_sha256 = zero_sha256;

	if (!buf)
		err(1, "malloc host io result");
	*p++ = 0xa7;
	cbor_write_text(&p, "io_id");
	cbor_write_text(&p, io_id);
	cbor_write_text(&p, "kind");
	cbor_write_text(&p, kind);
	cbor_write_text(&p, "status");
	*p++ = status;
	cbor_write_text(&p, result_key);
	cbor_write_type_len(&p, 2, result_len);
	if (result_len != 0)
		memcpy(p, result, result_len);
	p += result_len;
	cbor_write_text(&p, "sequence");
	cbor_write_type_len(&p, 0, sequence);
	cbor_write_text(&p, "request_body_sha256");
	cbor_write_type_len(&p, 2, 32);
	memcpy(p, request_body_sha256, 32);
	p += 32;
	cbor_write_text(&p, "normalized_input_sha256");
	cbor_write_type_len(&p, 2, 32);
	memcpy(p, normalized_input_sha256, 32);
	p += 32;
	*out_len = (size_t)(p - buf);
	return buf;
}

static uint8_t *make_host_io_result_bytes(const char *io_id, const char *kind,
					  const char *result_key,
					  const uint8_t *result,
					  size_t result_len,
					  size_t *out_len)
{
	return make_host_io_result_bytes_status(io_id, kind, result_key,
						result, result_len, 0, NULL,
						out_len);
}

static uint8_t *make_host_io_result(const char *io_id, const char *kind,
				    size_t *out_len)
{
	return make_host_io_result_bytes(io_id, kind, "response_body",
					 NULL, 0, out_len);
}

static uint8_t *make_host_io_result_for_transcript(
				    const char *io_id, const char *kind,
				    const struct host_io_transcript *transcript,
				    size_t *out_len)
{
	return make_host_io_result_bytes_status(io_id, kind, "response_body",
						NULL, 0, 0, transcript,
						out_len);
}

static uint8_t *make_host_io_result_bytes_for_transcript(
				    const char *io_id, const char *kind,
				    const char *result_key,
				    const uint8_t *result, size_t result_len,
				    const struct host_io_transcript *transcript,
				    size_t *out_len)
{
	return make_host_io_result_bytes_status(io_id, kind, result_key,
						result, result_len, 0,
						transcript, out_len);
}

static uint8_t *make_resume_envelope(const char *request_id,
				     const uint8_t *host_io_result,
				     size_t host_io_result_len,
				     size_t *out_len)
{
	size_t len = 1
		     + 1 + strlen("request_id") + cbor_len_size(strlen(request_id)) + strlen(request_id)
		     + 1 + strlen("host_io_result_cbor") + cbor_len_size(host_io_result_len) + host_io_result_len;
	uint8_t *buf = malloc(len);
	uint8_t *p = buf;

	if (!buf)
		err(1, "malloc resume envelope");
	*p++ = 0xa2;
	cbor_write_text(&p, "request_id");
	cbor_write_text(&p, request_id);
	cbor_write_text(&p, "host_io_result_cbor");
	cbor_write_type_len(&p, 2, host_io_result_len);
	memcpy(p, host_io_result, host_io_result_len);
	p += host_io_result_len;
	*out_len = (size_t)(p - buf);
	return buf;
}

static uint8_t *make_negaposi_input(const uint8_t *jpeg, size_t jpeg_len,
				    size_t *out_len)
{
	size_t len = 1
		     + 1 + strlen("files")
		     + 1
		     + 1 + strlen("input")
		     + cbor_len_size(jpeg_len) + jpeg_len;
	uint8_t *buf = malloc(len);
	uint8_t *p = buf;

	if (!buf)
		err(1, "malloc negaposi input");
	*p++ = 0xa1;
	cbor_write_text(&p, "files");
	*p++ = 0xa1;
	cbor_write_text(&p, "input");
	cbor_write_type_len(&p, 2, jpeg_len);
	memcpy(p, jpeg, jpeg_len);
	p += jpeg_len;
	*out_len = (size_t)(p - buf);
	return buf;
}

static uint8_t *make_teep_resolve_input_for_target(const char *target_command,
						   size_t *out_len)
{
	size_t len = 1
		     + 1 + strlen("schema_version") + 1
		     + 1 + strlen("command") + 1 + strlen("resolve_app")
		     + 1 + strlen("target_command") +
		       cbor_len_size(strlen(target_command)) +
		       strlen(target_command)
		     + 1 + strlen("resolver_mode") + 1 + strlen("mock")
		     + 1 + strlen("state_dir") + 1
		     + 1 + strlen("attestam_url") + 1;
	uint8_t *buf = malloc(len);
	uint8_t *p = buf;

	if (!buf)
		err(1, "malloc teep resolve input");
	*p++ = 0xa6;
	cbor_write_text(&p, "schema_version");
	*p++ = 0x01;
	cbor_write_text(&p, "command");
	cbor_write_text(&p, "resolve_app");
	cbor_write_text(&p, "target_command");
	cbor_write_text(&p, target_command);
	cbor_write_text(&p, "resolver_mode");
	cbor_write_text(&p, "mock");
	cbor_write_text(&p, "state_dir");
	cbor_write_text(&p, "");
	cbor_write_text(&p, "attestam_url");
	cbor_write_text(&p, "");
	*out_len = (size_t)(p - buf);
	return buf;
}

static uint8_t *make_teep_resolve_input(size_t *out_len)
{
	return make_teep_resolve_input_for_target("helloworld", out_len);
}

static uint8_t *make_teep_hostcall_probe_input(const char *command,
					       const char *attestam_url,
					       size_t *out_len)
{
	size_t map_len = attestam_url ? 3 : 2;
	size_t len = 1
		     + 1 + strlen("schema_version") + 1
		     + 1 + strlen("command") + cbor_len_size(strlen(command)) + strlen(command);
	uint8_t *buf = NULL;
	uint8_t *p = NULL;

	if (attestam_url)
		len += 1 + strlen("attestam_url") +
		       cbor_len_size(strlen(attestam_url)) + strlen(attestam_url);
	buf = malloc(len);
	if (!buf)
		err(1, "malloc teep hostcall probe input");
	p = buf;
	cbor_write_type_len(&p, 5, map_len);
	cbor_write_text(&p, "schema_version");
	*p++ = 0x01;
	cbor_write_text(&p, "command");
	cbor_write_text(&p, command);
	if (attestam_url) {
		cbor_write_text(&p, "attestam_url");
		cbor_write_text(&p, attestam_url);
	}
	*out_len = (size_t)(p - buf);
	return buf;
}

static int cbor_expect_text_value(const uint8_t *bytes, size_t len,
				  size_t *off, const char *want)
{
	uint64_t text_len = 0;
	size_t want_len = strlen(want);

	if (!cbor_read_type_len(bytes, len, off, 3, &text_len))
		return 0;
	if (text_len != want_len || text_len > len - *off)
		return 0;
	if (memcmp(bytes + *off, want, want_len) != 0)
		return 0;
	*off += want_len;
	return 1;
}

static int validate_teep_resolve_response(const uint8_t *bytes, size_t len)
{
	size_t off = 0;
	uint64_t map_len = 0;
	uint64_t app_map_len = 0;
	uint64_t value = 0;
	uint64_t bytes_len = 0;

	if (!cbor_read_type_len(bytes, len, &off, 5, &map_len) || map_len != 3)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "schema_version"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 0, &value) || value != 1)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "status") ||
	    !cbor_expect_text_value(bytes, len, &off, "ok"))
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "app"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 5, &app_map_len) ||
	    app_map_len != 6)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "command") ||
	    !cbor_expect_text_value(bytes, len, &off, "helloworld"))
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "component_id") ||
	    !cbor_expect_text_value(bytes, len, &off, "twep.example.helloworld"))
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "version") ||
	    !cbor_expect_text_value(bytes, len, &off, "0.1.0"))
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "abi") ||
	    !cbor_expect_text_value(bytes, len, &off, "twep-app-v1"))
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "wasm_file") ||
	    !cbor_expect_text_value(bytes, len, &off, "helloworld.wasm"))
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "sha256"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 2, &bytes_len) ||
	    bytes_len != 32 || bytes_len > len - off)
		return 0;
	off += bytes_len;
	return off == len;
}

static int validate_teep_resolve_error_response(const uint8_t *bytes,
						size_t len,
						const char *want_code,
						const char *want_message)
{
	size_t off = 0;
	uint64_t map_len = 0;
	uint64_t error_map_len = 0;
	uint64_t value = 0;

	if (!cbor_read_type_len(bytes, len, &off, 5, &map_len) || map_len != 3)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "schema_version"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 0, &value) || value != 1)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "status") ||
	    !cbor_expect_text_value(bytes, len, &off, "error"))
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "error"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 5, &error_map_len) ||
	    error_map_len != 2)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "code") ||
	    !cbor_expect_text_value(bytes, len, &off, want_code))
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "message") ||
	    !cbor_expect_text_value(bytes, len, &off, want_message))
		return 0;
	return off == len;
}

static int validate_teep_resolve_hash_mismatch_response(const uint8_t *bytes,
							size_t len)
{
	return validate_teep_resolve_error_response(
		bytes, len, "app.hash_mismatch", "app wasm hash mismatch");
}

static int validate_wrapped_teep_error_response(const uint8_t *bytes,
						size_t len,
						const char *want_code,
						const char *want_message)
{
	size_t off = 0;
	uint64_t map_len = 0;
	uint64_t error_map_len = 0;
	uint64_t details_map_len = 0;
	uint64_t value = 0;

	if (!cbor_read_type_len(bytes, len, &off, 5, &map_len) || map_len != 5)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "schema_version"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 0, &value) || value != 1)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "request_id") ||
	    !cbor_expect_text_value(bytes, len, &off, "req-teep-resolve"))
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "status") ||
	    !cbor_expect_text_value(bytes, len, &off, "error"))
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "exit_code"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 0, &value) || value != 1)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "error"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 5, &error_map_len) ||
	    error_map_len != 3)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "code") ||
	    !cbor_expect_text_value(bytes, len, &off, want_code))
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "message") ||
	    !cbor_expect_text_value(bytes, len, &off, want_message))
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "details"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 5, &details_map_len) ||
	    details_map_len != 3)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "source") ||
	    !cbor_expect_text_value(bytes, len, &off, "teep-agent"))
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "teep_code") ||
	    !cbor_expect_text_value(bytes, len, &off, want_code))
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "command") ||
	    !cbor_expect_text_value(bytes, len, &off,
				    "teep-agent-resolve-wrapped"))
		return 0;
	return off == len;
}

static int validate_app_runtime_error_response(const uint8_t *bytes,
					       size_t len,
					       const char *request_id,
					       const char *command,
					       const char *want_code,
					       const char *want_message,
					       const char *want_reason)
{
	size_t off = 0;
	uint64_t map_len = 0;
	uint64_t error_map_len = 0;
	uint64_t details_map_len = 0;
	uint64_t value = 0;

	if (!cbor_read_type_len(bytes, len, &off, 5, &map_len) ||
	    map_len != 5)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "schema_version"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 0, &value) || value != 1)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "request_id") ||
	    !cbor_expect_text_value(bytes, len, &off, request_id))
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "status") ||
	    !cbor_expect_text_value(bytes, len, &off, "error"))
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "exit_code"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 0, &value) || value != 1)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "error"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 5, &error_map_len) ||
	    error_map_len != 3)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "code") ||
	    !cbor_expect_text_value(bytes, len, &off, want_code))
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "message") ||
	    !cbor_expect_text_value(bytes, len, &off, want_message))
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "details"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 5, &details_map_len) ||
	    details_map_len != 3)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "source") ||
	    !cbor_expect_text_value(bytes, len, &off, "app-runtime"))
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "command") ||
	    !cbor_expect_text_value(bytes, len, &off, command))
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "reason") ||
	    !cbor_expect_text_value(bytes, len, &off, want_reason))
		return 0;
	return off == len;
}

static int validate_need_host_io_response(const uint8_t *bytes, size_t len,
					  const char *request_id,
					  const char *io_id,
					  const char *url,
					  struct host_io_transcript *transcript)
{
	size_t off = 0;
	uint64_t map_len = 0;
	uint64_t need_map_len = 0;
	uint64_t value = 0;
	uint64_t bytes_len = 0;
	int sequence_ok = 0;
	int request_body_sha_ok = 0;

	if (!cbor_read_type_len(bytes, len, &off, 5, &map_len) || map_len != 3)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "schema_version"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 0, &value) || value != 1)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "request_id") ||
	    !cbor_expect_text_value(bytes, len, &off, request_id))
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "need_host_io"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 5, &need_map_len) ||
	    need_map_len != 7)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "io_id") ||
	    !cbor_expect_text_value(bytes, len, &off, io_id))
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "kind") ||
	    !cbor_expect_text_value(bytes, len, &off, "http_post"))
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "url") ||
	    !cbor_expect_text_value(bytes, len, &off, url))
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "body"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 2, &bytes_len) ||
	    bytes_len > len - off)
		return 0;
	off += bytes_len;
	if (!cbor_read_text_key(bytes, len, &off, "sequence"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 0, &value) || value == 0)
		return 0;
	if (transcript)
		transcript->sequence = value;
	sequence_ok = 1;
	if (!cbor_read_text_key(bytes, len, &off, "request_body_sha256"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 2, &bytes_len) ||
	    bytes_len != 32 || bytes_len > len - off)
		return 0;
	if (transcript)
		memcpy(transcript->request_body_sha256, bytes + off, 32);
	off += bytes_len;
	request_body_sha_ok = 1;
	if (!cbor_read_text_key(bytes, len, &off, "normalized_input_sha256"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 2, &bytes_len) ||
	    bytes_len != 32 || bytes_len > len - off)
		return 0;
	if (transcript)
		memcpy(transcript->normalized_input_sha256, bytes + off, 32);
	off += bytes_len;
	return off == len && sequence_ok && request_body_sha_ok;
}

static int validate_need_evidence_response(const uint8_t *bytes, size_t len,
					   const char *request_id,
					   struct host_io_transcript *transcript)
{
	size_t off = 0;
	uint64_t map_len = 0;
	uint64_t need_map_len = 0;
	uint64_t value = 0;
	uint64_t bytes_len = 0;
	int sequence_ok = 0;
	int request_body_sha_ok = 0;

	if (!cbor_read_type_len(bytes, len, &off, 5, &map_len) || map_len != 3)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "schema_version"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 0, &value) || value != 1)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "request_id") ||
	    !cbor_expect_text_value(bytes, len, &off, request_id))
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "need_host_io"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 5, &need_map_len) ||
	    need_map_len != 7)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "io_id") ||
	    !cbor_expect_text_value(bytes, len, &off, "teep-evidence-1"))
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "kind") ||
	    !cbor_expect_text_value(bytes, len, &off, "create_evidence"))
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "challenge"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 2, &bytes_len) ||
	    bytes_len != 8 || bytes_len > len - off)
		return 0;
	off += bytes_len;
	if (!cbor_read_text_key(bytes, len, &off, "agent_public_key_cose"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 2, &bytes_len) ||
	    bytes_len != 7 || bytes_len > len - off)
		return 0;
	off += bytes_len;
	if (!cbor_read_text_key(bytes, len, &off, "sequence"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 0, &value) || value == 0)
		return 0;
	if (transcript)
		transcript->sequence = value;
	sequence_ok = 1;
	if (!cbor_read_text_key(bytes, len, &off, "request_body_sha256"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 2, &bytes_len) ||
	    bytes_len != 32 || bytes_len > len - off)
		return 0;
	if (transcript)
		memcpy(transcript->request_body_sha256, bytes + off, 32);
	off += bytes_len;
	request_body_sha_ok = 1;
	if (!cbor_read_text_key(bytes, len, &off, "normalized_input_sha256"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 2, &bytes_len) ||
	    bytes_len != 32 || bytes_len > len - off)
		return 0;
	if (transcript)
		memcpy(transcript->normalized_input_sha256, bytes + off, 32);
	off += bytes_len;
	return off == len && sequence_ok && request_body_sha_ok;
}

static int validate_resume_final_response(const uint8_t *bytes, size_t len,
					  const char *request_id)
{
	size_t off = 0;
	uint64_t map_len = 0;
	uint64_t value = 0;
	uint64_t bytes_len = 0;

	if (!cbor_read_type_len(bytes, len, &off, 5, &map_len) || map_len != 3)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "schema_version"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 0, &value) || value != 1)
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "request_id") ||
	    !cbor_expect_text_value(bytes, len, &off, request_id))
		return 0;
	if (!cbor_read_text_key(bytes, len, &off, "final_response_cbor"))
		return 0;
	if (!cbor_read_type_len(bytes, len, &off, 2, &bytes_len) ||
	    bytes_len == 0 || bytes_len > len - off)
		return 0;
	off += bytes_len;
	return off == len;
}

static void invoke_execute_helloworld(struct twep_ta_ctx *ctx,
				      const char *wasm_path)
{
	uint8_t *wasm = NULL;
	uint8_t *request = NULL;
	uint8_t response[4096];
	size_t wasm_len = 0;
	size_t request_len = 0;
	size_t response_len = 0;
	TEEC_Result res;
	uint32_t origin = 0;

	wasm = read_file(wasm_path, &wasm_len);
	request = make_execute_envelope("req-helloworld", "helloworld", NULL, 0,
					wasm, wasm_len, &request_len);
	res = invoke_production_raw(ctx, TA_TWEP_WR_CMD_EXECUTE, request,
				    request_len, response, sizeof(response),
				    &response_len, &origin);
	free(request);
	free(wasm);
	if (res != TEEC_SUCCESS)
		errx(1, "TA production execute helloworld failed with code 0x%x origin 0x%x",
		     res, origin);
	if (!validate_helloworld_execute_response(response, response_len,
						  "req-helloworld"))
		errx(1, "TA production execute helloworld returned unexpected response");
	puts("TA production execute helloworld ok");
}

static void invoke_execute_calcadd(struct twep_ta_ctx *ctx,
				   const char *wasm_path)
{
	uint8_t *wasm = NULL;
	uint8_t *request = NULL;
	uint8_t response[4096];
	size_t wasm_len = 0;
	size_t request_len = 0;
	size_t response_len = 0;
	TEEC_Result res;
	uint32_t origin = 0;

	wasm = read_file(wasm_path, &wasm_len);
	request = make_execute_envelope("req-calcadd", "calcadd",
					calcadd_3_4_5_input,
					sizeof(calcadd_3_4_5_input),
					wasm, wasm_len, &request_len);
	res = invoke_production_raw(ctx, TA_TWEP_WR_CMD_EXECUTE, request,
				    request_len, response, sizeof(response),
				    &response_len, &origin);
	free(request);
	free(wasm);
	if (res != TEEC_SUCCESS)
		errx(1, "TA production execute calcadd failed with code 0x%x origin 0x%x",
		     res, origin);
	if (!validate_calcadd_execute_response(response, response_len,
					       "req-calcadd")) {
		fprintf(stderr, "calcadd response hex: ");
		dump_hex(stderr, response, response_len);
		fputc('\n', stderr);
		errx(1, "TA production execute calcadd returned unexpected response");
	}
	puts("TA production execute calcadd ok");
}

static void invoke_execute_negaposi(struct twep_ta_ctx *ctx,
				    const char *wasm_path,
				    const char *jpeg_path)
{
	uint8_t *wasm = NULL;
	uint8_t *jpeg = NULL;
	uint8_t *app_input = NULL;
	uint8_t *request = NULL;
	uint8_t response[32768];
	size_t wasm_len = 0;
	size_t jpeg_len = 0;
	size_t app_input_len = 0;
	size_t request_len = 0;
	size_t response_len = 0;
	TEEC_Result res;
	uint32_t origin = 0;

	wasm = read_file(wasm_path, &wasm_len);
	jpeg = read_file(jpeg_path, &jpeg_len);
	if (!looks_like_jpeg_bytes(jpeg, jpeg_len))
		errx(1, "input fixture is not a JPEG: %s", jpeg_path);
	app_input = make_negaposi_input(jpeg, jpeg_len, &app_input_len);
	request = make_execute_envelope("req-negaposi", "negaposi",
					app_input, app_input_len,
					wasm, wasm_len, &request_len);
	res = invoke_production_raw(ctx, TA_TWEP_WR_CMD_EXECUTE, request,
				    request_len, response, sizeof(response),
				    &response_len, &origin);
	free(request);
	free(app_input);
	free(jpeg);
	free(wasm);
	if (res != TEEC_SUCCESS)
		errx(1, "TA production execute negaposi failed with code 0x%x origin 0x%x",
		     res, origin);
	if (!validate_negaposi_execute_response(response, response_len,
						"req-negaposi")) {
		fprintf(stderr, "negaposi response hex: ");
		dump_hex(stderr, response, response_len);
		fputc('\n', stderr);
		errx(1, "TA production execute negaposi returned unexpected response");
	}
	puts("TA production execute negaposi ok");
}

static void expect_execute_import_rejection(struct twep_ta_ctx *ctx,
					    const char *label,
					    const char *wasm_path)
{
	uint8_t *wasm = NULL;
	uint8_t *request = NULL;
	uint8_t response[4096];
	size_t wasm_len = 0;
	size_t request_len = 0;
	size_t response_len = 0;
	TEEC_Result res;
	uint32_t origin = 0;

	wasm = read_file(wasm_path, &wasm_len);
	request = make_execute_envelope("req-hostcall-reject", "helloworld",
					NULL, 0, wasm, wasm_len,
					&request_len);
	res = invoke_production_raw(ctx, TA_TWEP_WR_CMD_EXECUTE, request,
				    request_len, response, sizeof(response),
				    &response_len, &origin);
	free(request);
	free(wasm);
	if (res != TEEC_ERROR_BAD_FORMAT)
		errx(1, "TA production execute did not reject %s import: code 0x%x origin 0x%x",
		     label, res, origin);
	printf("TA production execute rejected %s import: code 0x%x origin 0x%x\n",
	       label, res, origin);
}

static void invoke_execute_hostcall_negative(struct twep_ta_ctx *ctx,
					     const char *env_wasm_path,
					     const char *teep_env_wasm_path)
{
	expect_execute_import_rejection(ctx, "env.*", env_wasm_path);
	expect_execute_import_rejection(ctx, "twep_teep_env.*",
					teep_env_wasm_path);
	puts("TrustZone TA execute general app hostcall rejection ok");
}

static void expect_execute_failure(struct twep_ta_ctx *ctx,
				   const char *wasm_path,
				   const char *label,
				   TEEC_Result expected)
{
	uint8_t *wasm = NULL;
	uint8_t *request = NULL;
	uint8_t response[4096];
	size_t wasm_len = 0;
	size_t request_len = 0;
	size_t response_len = 0;
	TEEC_Result res;
	uint32_t origin = 0;

	wasm = read_file(wasm_path, &wasm_len);
	request = make_execute_envelope("req-production-cleanup-negative",
					"helloworld", NULL, 0, wasm,
					wasm_len, &request_len);
	res = invoke_production_raw(ctx, TA_TWEP_WR_CMD_EXECUTE, request,
				    request_len, response, sizeof(response),
				    &response_len, &origin);
	free(request);
	free(wasm);
	if (res != expected)
		errx(1, "TA production execute did not reject %s with expected failure: want 0x%x got 0x%x origin 0x%x",
		     label, expected, res, origin);
	printf("TA production execute rejected %s: code 0x%x origin 0x%x\n",
	       label, res, origin);
}

static void expect_execute_output_limit_error(struct twep_ta_ctx *ctx,
					      const char *wasm_path)
{
	uint8_t *wasm = NULL;
	uint8_t *request = NULL;
	uint8_t response[4096];
	size_t wasm_len = 0;
	size_t request_len = 0;
	size_t response_len = 0;
	TEEC_Result res;
	uint32_t origin = 0;

	wasm = read_file(wasm_path, &wasm_len);
	request = make_execute_envelope("req-production-cleanup-negative",
					"helloworld", NULL, 0, wasm,
					wasm_len, &request_len);
	res = invoke_production_raw(ctx, TA_TWEP_WR_CMD_EXECUTE, request,
				    request_len, response, sizeof(response),
				    &response_len, &origin);
	free(request);
	free(wasm);
	if (res != TEEC_SUCCESS)
		errx(1, "TA production execute oversized app output returned code 0x%x origin 0x%x",
		     res, origin);
	if (!validate_app_runtime_error_response(
		    response, response_len, "req-production-cleanup-negative",
		    "helloworld", "app.resource_limit",
		    "resource limit exceeded", "max_output_bytes"))
		errx(1, "TA production execute returned unexpected oversized app output response");
	puts("TA production execute rejected oversized app output with structured app.resource_limit");
}

static void invoke_execute_cleanup_negative(struct twep_ta_ctx *ctx,
					    const char *helloworld_wasm_path,
					    const char *nonzero_wasm_path,
					    const char *trap_wasm_path,
					    const char *oversized_wasm_path)
{
	uint8_t *wasm = NULL;
	uint8_t *request = NULL;
	uint8_t short_response[64];
	size_t wasm_len = 0;
	size_t request_len = 0;
	size_t response_len = 0;
	TEEC_Result res;
	uint32_t origin = 0;

	wasm = read_file(helloworld_wasm_path, &wasm_len);
	request = make_execute_envelope("req-production-short-output",
					"helloworld", NULL, 0, wasm,
					wasm_len, &request_len);
	res = invoke_production_raw(ctx, TA_TWEP_WR_CMD_EXECUTE, request,
				    request_len, short_response,
				    sizeof(short_response), &response_len,
				    &origin);
	free(request);
	free(wasm);
	if (res != TEEC_ERROR_SHORT_BUFFER)
		errx(1, "TA production execute did not reject short output buffer: code 0x%x origin 0x%x",
		     res, origin);
	if (response_len <= sizeof(short_response))
		errx(1, "TA production execute did not report required output length");
	printf("TA production execute rejected short output buffer: code 0x%x origin 0x%x needed %zu\n",
	       res, origin, response_len);

	expect_execute_failure(ctx, nonzero_wasm_path, "nonzero app status",
			       TEEC_ERROR_GENERIC);
	expect_execute_output_limit_error(ctx, oversized_wasm_path);
	expect_execute_failure(ctx, trap_wasm_path, "trap app",
			       TEEC_ERROR_BAD_FORMAT);
	invoke_execute_helloworld(ctx, helloworld_wasm_path);
	puts("TA production execute cleanup after failures ok");
}

static void invoke_teep_agent_resolve(struct twep_ta_ctx *ctx,
				      const char *teep_agent_wasm_path,
				      const char *catalog_path,
				      const char *app_wasm_path)
{
	uint8_t *wasm = NULL;
	uint8_t *catalog = NULL;
	uint8_t *app_wasm = NULL;
	uint8_t *app_input = NULL;
	uint8_t *request = NULL;
	uint8_t response[4096];
	size_t wasm_len = 0;
	size_t catalog_len = 0;
	size_t app_wasm_len = 0;
	size_t app_input_len = 0;
	size_t request_len = 0;
	size_t response_len = 0;
	TEEC_Result res;
	uint32_t origin = 0;

	wasm = read_file(teep_agent_wasm_path, &wasm_len);
	catalog = read_file(catalog_path, &catalog_len);
	app_wasm = read_file(app_wasm_path, &app_wasm_len);
	app_input = make_teep_resolve_input(&app_input_len);
	request = make_teep_resolve_envelope(app_input, app_input_len,
					     wasm, wasm_len,
					     catalog, catalog_len,
					     app_wasm, app_wasm_len,
					     &request_len);
	res = invoke_production_raw(ctx, TA_TWEP_WR_CMD_EXECUTE, request,
				    request_len, response, sizeof(response),
				    &response_len, &origin);
	free(request);
	free(app_input);
	free(app_wasm);
	free(catalog);
	free(wasm);
	if (res != TEEC_SUCCESS)
		errx(1, "TA production teep-agent resolve failed with code 0x%x origin 0x%x",
		     res, origin);
	if (!validate_teep_resolve_response(response, response_len)) {
		fprintf(stderr, "teep-agent resolve response hex: ");
		dump_hex(stderr, response, response_len);
		fputc('\n', stderr);
		errx(1, "TA production teep-agent resolve returned unexpected response");
	}
	puts("TA production teep-agent resolve executed ok");
}

static void invoke_teep_agent_resolve_hash_negative(struct twep_ta_ctx *ctx,
						    const char *teep_agent_wasm_path,
						    const char *catalog_path,
						    const char *app_wasm_path)
{
	uint8_t *wasm = NULL;
	uint8_t *catalog = NULL;
	uint8_t *app_wasm = NULL;
	uint8_t *app_input = NULL;
	uint8_t *request = NULL;
	uint8_t response[4096];
	size_t wasm_len = 0;
	size_t catalog_len = 0;
	size_t app_wasm_len = 0;
	size_t app_input_len = 0;
	size_t request_len = 0;
	size_t response_len = 0;
	TEEC_Result res;
	uint32_t origin = 0;

	wasm = read_file(teep_agent_wasm_path, &wasm_len);
	catalog = read_file(catalog_path, &catalog_len);
	app_wasm = read_file(app_wasm_path, &app_wasm_len);
	if (app_wasm_len < 9)
		errx(1, "app wasm fixture too short for hash negative");
	app_wasm[app_wasm_len - 1] ^= 0x01;
	app_input = make_teep_resolve_input(&app_input_len);
	request = make_teep_resolve_envelope(app_input, app_input_len,
					     wasm, wasm_len,
					     catalog, catalog_len,
					     app_wasm, app_wasm_len,
					     &request_len);
	res = invoke_production_raw(ctx, TA_TWEP_WR_CMD_EXECUTE, request,
				    request_len, response, sizeof(response),
				    &response_len, &origin);
	free(request);
	free(app_input);
	free(app_wasm);
	free(catalog);
	free(wasm);
	if (res != TEEC_SUCCESS)
		errx(1, "TA production teep-agent hash negative failed with code 0x%x origin 0x%x",
		     res, origin);
	if (!validate_teep_resolve_hash_mismatch_response(response,
							  response_len)) {
		fprintf(stderr, "teep-agent hash negative response hex: ");
		dump_hex(stderr, response, response_len);
		fputc('\n', stderr);
		errx(1, "TA production teep-agent hash negative returned unexpected response");
	}
	puts("TA production teep-agent resolve rejected app.hash_mismatch ok");
}

static void expect_teep_agent_resolve_error(struct twep_ta_ctx *ctx,
					    const char *teep_agent_wasm_path,
					    const uint8_t *catalog,
					    size_t catalog_len,
					    const char *app_wasm_path,
					    const char *target_command,
					    const char *want_code,
					    const char *want_message,
					    const char *label)
{
	uint8_t *wasm = NULL;
	uint8_t *app_wasm = NULL;
	uint8_t *app_input = NULL;
	uint8_t *request = NULL;
	uint8_t response[4096];
	size_t wasm_len = 0;
	size_t app_wasm_len = 0;
	size_t app_input_len = 0;
	size_t request_len = 0;
	size_t response_len = 0;
	TEEC_Result res;
	uint32_t origin = 0;

	wasm = read_file(teep_agent_wasm_path, &wasm_len);
	app_wasm = read_file(app_wasm_path, &app_wasm_len);
	app_input = make_teep_resolve_input_for_target(target_command,
						       &app_input_len);
	request = make_teep_resolve_envelope(app_input, app_input_len,
					     wasm, wasm_len, catalog,
					     catalog_len, app_wasm,
					     app_wasm_len, &request_len);
	res = invoke_production_raw(ctx, TA_TWEP_WR_CMD_EXECUTE, request,
				    request_len, response, sizeof(response),
				    &response_len, &origin);
	free(request);
	free(app_input);
	free(app_wasm);
	free(wasm);
	if (res != TEEC_SUCCESS)
		errx(1, "TA production teep-agent %s failed with code 0x%x origin 0x%x",
		     label, res, origin);
	if (!validate_teep_resolve_error_response(response, response_len,
						  want_code, want_message)) {
		fprintf(stderr, "teep-agent %s response hex: ", label);
		dump_hex(stderr, response, response_len);
		fputc('\n', stderr);
		errx(1, "TA production teep-agent %s returned unexpected response",
		     label);
	}
	printf("TA production teep-agent resolve rejected %s ok\n", want_code);
}

static void invoke_teep_agent_resolve_catalog_negative(struct twep_ta_ctx *ctx,
						       const char *teep_agent_wasm_path,
						       const char *catalog_path,
						       const char *app_wasm_path)
{
	static const uint8_t invalid_catalog[] = { 0x80 };
	uint8_t *catalog = NULL;
	size_t catalog_len = 0;

	expect_teep_agent_resolve_error(ctx, teep_agent_wasm_path,
					invalid_catalog,
					sizeof(invalid_catalog),
					app_wasm_path, "helloworld",
					"catalog.invalid",
					"catalog entry is invalid",
					"catalog invalid negative");
	catalog = read_file(catalog_path, &catalog_len);
	expect_teep_agent_resolve_error(ctx, teep_agent_wasm_path,
					catalog, catalog_len, app_wasm_path,
					"missingapp", "catalog.not_found",
					"target command not found",
					"catalog not_found negative");
	free(catalog);
	puts("TA production teep-agent resolve catalog negatives ok");
}

static void expect_teep_agent_wrapped_error(struct twep_ta_ctx *ctx,
					    const char *teep_agent_wasm_path,
					    const uint8_t *catalog,
					    size_t catalog_len,
					    const uint8_t *app_wasm,
					    size_t app_wasm_len,
					    const char *target_command,
					    const char *want_code,
					    const char *want_message)
{
	uint8_t *wasm = NULL;
	uint8_t *app_input = NULL;
	uint8_t *request = NULL;
	struct trustzone_transport_response response = { };
	size_t wasm_len = 0;
	size_t app_input_len = 0;
	size_t request_len = 0;
	TEEC_Result res;
	uint32_t origin = 0;

	wasm = read_file(teep_agent_wasm_path, &wasm_len);
	app_input = make_teep_resolve_input_for_target(target_command,
						       &app_input_len);
	request = make_teep_resolve_envelope_for_command(
		"teep-agent-resolve-wrapped", app_input, app_input_len,
		wasm, wasm_len, catalog, catalog_len, app_wasm, app_wasm_len,
		&request_len);
	res = trustzone_transport_execute(ctx, request, request_len, &response,
					  &origin);
	free(request);
	free(app_input);
	free(wasm);
	if (res != TEEC_SUCCESS)
		errx(1, "TrustZone execute transport wrapped teep-agent error failed with code 0x%x origin 0x%x",
		     res, origin);
	if (!validate_wrapped_teep_error_response(response.ptr, response.len,
						  want_code, want_message)) {
		fprintf(stderr, "wrapped teep-agent error response hex: ");
		dump_hex(stderr, response.ptr, response.len);
		fputc('\n', stderr);
		trustzone_transport_response_free(&response);
		errx(1, "TA production wrapped teep-agent error returned unexpected response");
	}
	trustzone_transport_response_free(&response);
	printf("TA production teep-agent wrapped error mapped %s ok\n",
	       want_code);
	printf("TrustZone execute transport returned wrapped twep_wr_execute error %s ok\n",
	       want_code);
}

static void invoke_teep_agent_resolve_wrapped_error_negative(
						struct twep_ta_ctx *ctx,
						const char *teep_agent_wasm_path,
						const char *catalog_path,
						const char *app_wasm_path)
{
	static const uint8_t invalid_catalog[] = { 0x80 };
	uint8_t *catalog = NULL;
	uint8_t *app_wasm = NULL;
	uint8_t *bad_app_wasm = NULL;
	size_t catalog_len = 0;
	size_t app_wasm_len = 0;

	catalog = read_file(catalog_path, &catalog_len);
	app_wasm = read_file(app_wasm_path, &app_wasm_len);
	bad_app_wasm = read_file(app_wasm_path, &app_wasm_len);
	if (app_wasm_len < 9)
		errx(1, "app wasm fixture too short for wrapped hash negative");
	bad_app_wasm[app_wasm_len - 1] ^= 0x01;

	expect_teep_agent_wrapped_error(ctx, teep_agent_wasm_path,
					invalid_catalog,
					sizeof(invalid_catalog), app_wasm,
					app_wasm_len, "helloworld",
					"catalog.invalid",
					"catalog entry is invalid");
	expect_teep_agent_wrapped_error(ctx, teep_agent_wasm_path,
					catalog, catalog_len, app_wasm,
					app_wasm_len, "missingapp",
					"catalog.not_found",
					"target command not found");
	expect_teep_agent_wrapped_error(ctx, teep_agent_wasm_path,
					catalog, catalog_len, bad_app_wasm,
					app_wasm_len, "helloworld",
					"app.hash_mismatch",
					"app wasm hash mismatch");
	free(bad_app_wasm);
	free(app_wasm);
	free(catalog);
	puts("TA production teep-agent wrapped error mapping negatives ok");
}

static void invoke_execute_catalog_resource_negative(
					struct twep_ta_ctx *ctx,
					const char *teep_agent_wasm_path,
					const char *catalog_path,
					const char *app_wasm_path,
					const char *jpeg_path)
{
	uint8_t *wasm = NULL;
	uint8_t *catalog = NULL;
	uint8_t *patched_catalog = NULL;
	uint8_t *app_wasm = NULL;
	uint8_t *jpeg = NULL;
	uint8_t *app_input = NULL;
	uint8_t *request = NULL;
	uint8_t response[4096];
	size_t wasm_len = 0;
	size_t catalog_len = 0;
	size_t patched_catalog_len = 0;
	size_t app_wasm_len = 0;
	size_t jpeg_len = 0;
	size_t app_input_len = 0;
	size_t request_len = 0;
	size_t response_len = 0;
	TEEC_Result res;
	uint32_t origin = 0;

	wasm = read_file(teep_agent_wasm_path, &wasm_len);
	catalog = read_file(catalog_path, &catalog_len);
	patched_catalog = catalog_with_small_negaposi_output_limit(
		catalog, catalog_len, &patched_catalog_len);
	app_wasm = read_file(app_wasm_path, &app_wasm_len);
	jpeg = read_file(jpeg_path, &jpeg_len);
	if (!looks_like_jpeg_bytes(jpeg, jpeg_len))
		errx(1, "input fixture is not a JPEG: %s", jpeg_path);
	app_input = make_negaposi_input(jpeg, jpeg_len, &app_input_len);
	request = make_teep_resolve_envelope_for_command(
		"negaposi", app_input, app_input_len, wasm, wasm_len,
		patched_catalog, patched_catalog_len, app_wasm, app_wasm_len,
		&request_len);
	res = invoke_production_raw(ctx, TA_TWEP_WR_CMD_EXECUTE, request,
				    request_len, response, sizeof(response),
				    &response_len, &origin);
	free(request);
	free(app_input);
	free(jpeg);
	free(app_wasm);
	free(patched_catalog);
	free(catalog);
	free(wasm);
	if (res != TEEC_SUCCESS)
		errx(1, "TA production execute catalog resource negative failed with code 0x%x origin 0x%x",
		     res, origin);
	if (!validate_app_runtime_error_response(
		    response, response_len, "req-teep-resolve", "negaposi",
		    "app.resource_limit", "resource limit exceeded",
		    "max_output_bytes")) {
		fprintf(stderr, "catalog resource negative response hex: ");
		dump_hex(stderr, response, response_len);
		fputc('\n', stderr);
		errx(1, "TA production execute returned unexpected catalog resource response");
	}
	puts("TA production execute wrapped app.resource_limit ok");
	puts("TrustZone TA execute catalog resource limit negative ok");
}

static void invoke_host_io_resume(struct twep_ta_ctx *ctx)
{
	uint8_t *request = NULL;
	uint8_t *host_io_result = NULL;
	uint8_t *resume = NULL;
	uint8_t response[4096];
	size_t request_len = 0;
	size_t host_io_result_len = 0;
	size_t resume_len = 0;
	size_t response_len = 0;
	struct host_io_transcript transcript = { };
	TEEC_Result res;
	uint32_t origin = 0;

	request = make_execute_envelope("req-host-io", "teep-agent-host-io",
					NULL, 0, NULL, 0, &request_len);
	res = invoke_production_raw(ctx, TA_TWEP_WR_CMD_EXECUTE, request,
				    request_len, response, sizeof(response),
				    &response_len, &origin);
	free(request);
	if (res != TEEC_SUCCESS)
		errx(1, "TA production host io request failed with code 0x%x origin 0x%x",
		     res, origin);
	if (!validate_need_host_io_response(response, response_len,
					   "req-host-io", "io-1",
					   "https://ta.example.invalid/teep",
					   &transcript)) {
		fprintf(stderr, "host io need response hex: ");
		dump_hex(stderr, response, response_len);
		fputc('\n', stderr);
		errx(1, "TA production host io returned unexpected need_host_io response");
	}
	puts("TA production host io requested ok");

	host_io_result = make_host_io_result_for_transcript(
		"io-1", "http_post", &transcript, &host_io_result_len);
	resume = make_resume_envelope("req-host-io", host_io_result,
				      host_io_result_len, &resume_len);
	res = invoke_production_raw(ctx, TA_TWEP_WR_CMD_RESUME_HOST_IO,
				    resume, resume_len, response,
				    sizeof(response), &response_len, &origin);
	free(resume);
	free(host_io_result);
	if (res != TEEC_SUCCESS)
		errx(1, "TA production host io resume failed with code 0x%x origin 0x%x",
		     res, origin);
	if (!validate_resume_final_response(response, response_len,
					    "req-host-io")) {
		fprintf(stderr, "host io resume response hex: ");
		dump_hex(stderr, response, response_len);
		fputc('\n', stderr);
		errx(1, "TA production host io returned unexpected final response");
	}
	puts("TA production host io resumed ok");
}

static void expect_resume_failure(struct twep_ta_ctx *ctx,
				  const char *request_id,
				  const uint8_t *host_io_result,
				  size_t host_io_result_len,
				  const char *label)
{
	uint8_t *resume = NULL;
	uint8_t response[4096];
	size_t resume_len = 0;
	size_t response_len = 0;
	TEEC_Result res;
	uint32_t origin = 0;

	resume = make_resume_envelope(request_id, host_io_result,
				      host_io_result_len, &resume_len);
	res = invoke_production_raw(ctx, TA_TWEP_WR_CMD_RESUME_HOST_IO,
				    resume, resume_len, response,
				    sizeof(response), &response_len, &origin);
	free(resume);
	if (res != TEEC_ERROR_BAD_FORMAT)
		errx(1, "TA production host io did not reject %s: code 0x%x origin 0x%x",
		     label, res, origin);
	printf("TA production host io rejected %s: code 0x%x origin 0x%x\n",
	       label, res, origin);
}

static void seed_host_io_pending(struct twep_ta_ctx *ctx, const char *request_id,
				 struct host_io_transcript *transcript)
{
	uint8_t *request = NULL;
	uint8_t response[4096];
	size_t request_len = 0;
	size_t response_len = 0;
	TEEC_Result res;
	uint32_t origin = 0;

	request = make_execute_envelope(request_id, "teep-agent-host-io",
					NULL, 0, NULL, 0, &request_len);
	res = invoke_production_raw(ctx, TA_TWEP_WR_CMD_EXECUTE, request,
				    request_len, response, sizeof(response),
				    &response_len, &origin);
	free(request);
	if (res != TEEC_SUCCESS)
		errx(1, "TA production host io negative seed failed with code 0x%x origin 0x%x",
		     res, origin);
	if (!validate_need_host_io_response(response, response_len, request_id,
					   "io-1",
					   "https://ta.example.invalid/teep",
					   transcript))
		errx(1, "TA production host io negative seed returned unexpected need_host_io response");
}

static void drain_host_io_pending(struct twep_ta_ctx *ctx, const char *request_id,
				  const struct host_io_transcript *transcript)
{
	uint8_t *host_io_result = NULL;
	uint8_t *resume = NULL;
	uint8_t response[4096];
	size_t host_io_result_len = 0;
	size_t resume_len = 0;
	size_t response_len = 0;
	TEEC_Result res;
	uint32_t origin = 0;

	host_io_result = make_host_io_result_for_transcript(
		"io-1", "http_post", transcript, &host_io_result_len);
	resume = make_resume_envelope(request_id, host_io_result,
				      host_io_result_len, &resume_len);
	res = invoke_production_raw(ctx, TA_TWEP_WR_CMD_RESUME_HOST_IO,
				    resume, resume_len, response,
				    sizeof(response), &response_len, &origin);
	free(resume);
	free(host_io_result);
	if (res != TEEC_SUCCESS ||
	    !validate_resume_final_response(response, response_len, request_id))
		errx(1, "TA production host io negative drain failed with code 0x%x origin 0x%x",
		     res, origin);
}

static void verify_host_io_session_isolation(struct twep_ta_ctx *owner)
{
	struct twep_ta_ctx other;
	struct host_io_transcript transcript = { };
	uint8_t *host_io_result = NULL;
	size_t host_io_result_len = 0;

	seed_host_io_pending(owner, "req-session-owner", &transcript);
	host_io_result = make_host_io_result_for_transcript(
		"io-1", "http_post", &transcript, &host_io_result_len);
	open_ta(&other);
	expect_resume_failure(&other, "req-session-owner", host_io_result,
			      host_io_result_len, "cross-session resume");
	close_ta(&other);
	free(host_io_result);
	drain_host_io_pending(owner, "req-session-owner", &transcript);

	seed_host_io_pending(owner, "req-closed-session", &transcript);
	host_io_result = make_host_io_result_for_transcript(
		"io-1", "http_post", &transcript, &host_io_result_len);
	close_ta(owner);
	open_ta(owner);
	expect_resume_failure(owner, "req-closed-session", host_io_result,
			      host_io_result_len, "closed-session resume");
	free(host_io_result);
}

static void invoke_host_io_resume_negative(struct twep_ta_ctx *ctx)
{
	uint8_t *host_io_result = NULL;
	size_t host_io_result_len = 0;
	struct host_io_transcript transcript = { };
	struct host_io_transcript bad_transcript = { };

	host_io_result = make_host_io_result("io-1", "http_post",
					    &host_io_result_len);
	expect_resume_failure(ctx, "req-no-pending", host_io_result,
			      host_io_result_len, "missing pending request");
	free(host_io_result);

	seed_host_io_pending(ctx, "req-neg-request-id", &transcript);
	host_io_result = make_host_io_result_for_transcript(
		"io-1", "http_post", &transcript, &host_io_result_len);
	expect_resume_failure(ctx, "req-neg-request-id-other",
			      host_io_result, host_io_result_len,
			      "request_id mismatch");
	free(host_io_result);
	drain_host_io_pending(ctx, "req-neg-request-id", &transcript);

	seed_host_io_pending(ctx, "req-neg-io-id", &transcript);
	host_io_result = make_host_io_result_for_transcript(
		"wrong-io", "http_post", &transcript, &host_io_result_len);
	expect_resume_failure(ctx, "req-neg-io-id", host_io_result,
			      host_io_result_len, "io_id mismatch");
	free(host_io_result);
	drain_host_io_pending(ctx, "req-neg-io-id", &transcript);

	seed_host_io_pending(ctx, "req-neg-kind", &transcript);
	host_io_result = make_host_io_result_for_transcript(
		"io-1", "create_evidence", &transcript, &host_io_result_len);
	expect_resume_failure(ctx, "req-neg-kind", host_io_result,
			      host_io_result_len, "kind mismatch");
	free(host_io_result);
	drain_host_io_pending(ctx, "req-neg-kind", &transcript);

	seed_host_io_pending(ctx, "req-neg-status", &transcript);
	host_io_result = make_host_io_result_bytes_status("io-1", "http_post",
							 "response_body",
							 NULL, 0, 1,
							 &transcript,
							 &host_io_result_len);
	expect_resume_failure(ctx, "req-neg-status", host_io_result,
			      host_io_result_len, "nonzero status");
	free(host_io_result);
	drain_host_io_pending(ctx, "req-neg-status", &transcript);

	seed_host_io_pending(ctx, "req-neg-sequence", &transcript);
	bad_transcript = transcript;
	bad_transcript.sequence++;
	host_io_result = make_host_io_result_for_transcript(
		"io-1", "http_post", &bad_transcript, &host_io_result_len);
	expect_resume_failure(ctx, "req-neg-sequence", host_io_result,
			      host_io_result_len, "sequence mismatch");
	free(host_io_result);
	drain_host_io_pending(ctx, "req-neg-sequence", &transcript);

	seed_host_io_pending(ctx, "req-neg-body-digest", &transcript);
	bad_transcript = transcript;
	bad_transcript.request_body_sha256[0] ^= 0xff;
	host_io_result = make_host_io_result_for_transcript(
		"io-1", "http_post", &bad_transcript, &host_io_result_len);
	expect_resume_failure(ctx, "req-neg-body-digest", host_io_result,
			      host_io_result_len, "request body digest mismatch");
	free(host_io_result);
	drain_host_io_pending(ctx, "req-neg-body-digest", &transcript);

	seed_host_io_pending(ctx, "req-neg-input-digest", &transcript);
	bad_transcript = transcript;
	bad_transcript.normalized_input_sha256[0] ^= 0xff;
	host_io_result = make_host_io_result_for_transcript(
		"io-1", "http_post", &bad_transcript, &host_io_result_len);
	expect_resume_failure(ctx, "req-neg-input-digest", host_io_result,
			      host_io_result_len, "normalized input digest mismatch");
	free(host_io_result);
	drain_host_io_pending(ctx, "req-neg-input-digest", &transcript);

	verify_host_io_session_isolation(ctx);

	puts("TA production host io resume negatives ok");
}

static void invoke_teep_agent_hostcall_http(struct twep_ta_ctx *ctx)
{
	uint8_t *request = NULL;
	uint8_t *host_io_result = NULL;
	uint8_t *resume = NULL;
	uint8_t response[4096];
	size_t request_len = 0;
	size_t host_io_result_len = 0;
	size_t resume_len = 0;
	size_t response_len = 0;
	struct host_io_transcript transcript = { };
	TEEC_Result res;
	uint32_t origin = 0;

	request = make_execute_envelope("req-teep-http",
					"teep-agent-hostcall-http",
					NULL, 0, NULL, 0, &request_len);
	res = invoke_production_raw(ctx, TA_TWEP_WR_CMD_EXECUTE, request,
				    request_len, response, sizeof(response),
				    &response_len, &origin);
	free(request);
	if (res != TEEC_SUCCESS)
		errx(1, "TA production teep-agent http hostcall request failed with code 0x%x origin 0x%x",
		     res, origin);
	if (!validate_need_host_io_response(response, response_len,
					   "req-teep-http", "teep-http-1",
					   "https://ta.example.invalid/tam",
					   &transcript)) {
		fprintf(stderr, "teep-agent hostcall need response hex: ");
		dump_hex(stderr, response, response_len);
		fputc('\n', stderr);
		errx(1, "TA production teep-agent hostcall returned unexpected need_host_io response");
	}
	puts("TA production teep-agent http hostcall requested ok");

	host_io_result = make_host_io_result_for_transcript(
		"teep-http-1", "http_post", &transcript, &host_io_result_len);
	resume = make_resume_envelope("req-teep-http", host_io_result,
				      host_io_result_len, &resume_len);
	res = invoke_production_raw(ctx, TA_TWEP_WR_CMD_RESUME_HOST_IO,
				    resume, resume_len, response,
				    sizeof(response), &response_len, &origin);
	free(resume);
	free(host_io_result);
	if (res != TEEC_SUCCESS)
		errx(1, "TA production teep-agent http hostcall resume failed with code 0x%x origin 0x%x",
		     res, origin);
	if (!validate_resume_final_response(response, response_len,
					    "req-teep-http")) {
		fprintf(stderr, "teep-agent hostcall resume response hex: ");
		dump_hex(stderr, response, response_len);
		fputc('\n', stderr);
		errx(1, "TA production teep-agent hostcall returned unexpected final response");
	}
	puts("TA production teep-agent http hostcall resumed ok");
}

static void invoke_teep_agent_hostcall_evidence(struct twep_ta_ctx *ctx)
{
	static const uint8_t evidence[] = {
		0xa1, 0x68, 'e', 'v', 'i', 'd', 'e', 'n', 'c', 'e',
		0x44, 'd', 'e', 'v', '1',
	};
	uint8_t *request = NULL;
	uint8_t *host_io_result = NULL;
	uint8_t *resume = NULL;
	uint8_t response[4096];
	size_t request_len = 0;
	size_t host_io_result_len = 0;
	size_t resume_len = 0;
	size_t response_len = 0;
	struct host_io_transcript transcript = { };
	TEEC_Result res;
	uint32_t origin = 0;

	request = make_execute_envelope("req-teep-evidence",
					"teep-agent-hostcall-evidence",
					NULL, 0, NULL, 0, &request_len);
	res = invoke_production_raw(ctx, TA_TWEP_WR_CMD_EXECUTE, request,
				    request_len, response, sizeof(response),
				    &response_len, &origin);
	free(request);
	if (res != TEEC_SUCCESS)
		errx(1, "TA production teep-agent evidence hostcall request failed with code 0x%x origin 0x%x",
		     res, origin);
	if (!validate_need_evidence_response(response, response_len,
					    "req-teep-evidence", &transcript)) {
		fprintf(stderr, "teep-agent evidence need response hex: ");
		dump_hex(stderr, response, response_len);
		fputc('\n', stderr);
		errx(1, "TA production teep-agent evidence hostcall returned unexpected need_host_io response");
	}
	puts("TA production teep-agent evidence hostcall requested ok");

	host_io_result = make_host_io_result_bytes_for_transcript(
		"teep-evidence-1", "create_evidence", "evidence",
		evidence, sizeof(evidence), &transcript, &host_io_result_len);
	resume = make_resume_envelope("req-teep-evidence", host_io_result,
				      host_io_result_len, &resume_len);
	res = invoke_production_raw(ctx, TA_TWEP_WR_CMD_RESUME_HOST_IO,
				    resume, resume_len, response,
				    sizeof(response), &response_len, &origin);
	free(resume);
	free(host_io_result);
	if (res != TEEC_SUCCESS)
		errx(1, "TA production teep-agent evidence hostcall resume failed with code 0x%x origin 0x%x",
		     res, origin);
	if (!validate_resume_final_response(response, response_len,
					    "req-teep-evidence")) {
		fprintf(stderr, "teep-agent evidence resume response hex: ");
		dump_hex(stderr, response, response_len);
		fputc('\n', stderr);
		errx(1, "TA production teep-agent evidence hostcall returned unexpected final response");
	}
	puts("TA production teep-agent evidence hostcall resumed ok");
}

static TEEC_Result request_pending_http_transcript(
					struct twep_ta_ctx *ctx,
					const char *request_id,
					size_t request_body_len,
					uint8_t **host_io_result,
					size_t *host_io_result_len,
					uint32_t *origin)
{
	static const char command[] = "teep-agent-transcript-limit";
	static const char io_id[] = "teep-http-limit-1";
	static const char url[] =
		"https://ta.example.invalid/transcript-limit";
	struct host_io_transcript transcript = { };
	uint8_t *request_body = NULL;
	uint8_t *request = NULL;
	uint8_t *response = NULL;
	size_t request_len = 0;
	size_t response_len = 0;
	TEEC_Result res;

	*host_io_result = NULL;
	*host_io_result_len = 0;
	request_body = malloc(request_body_len ? request_body_len : 1);
	response = malloc(64 * 1024);
	if (!request_body || !response)
		errx(1, "out of memory building transcript resource-limit request");
	memset(request_body, 0xa5, request_body_len);
	request = make_execute_envelope(request_id, command,
				       request_body, request_body_len,
				       NULL, 0, &request_len);
	res = invoke_production_raw(ctx, TA_TWEP_WR_CMD_EXECUTE, request,
				    request_len, response, 64 * 1024,
				    &response_len, origin);
	free(request);
	free(request_body);
	if (res != TEEC_SUCCESS) {
		free(response);
		return res;
	}
	if (!validate_need_host_io_response(response, response_len,
					   request_id, io_id, url,
					   &transcript))
		errx(1, "TA transcript resource-limit request returned unexpected need_host_io response");
	*host_io_result = make_host_io_result_for_transcript(
		io_id, "http_post", &transcript, host_io_result_len);
	free(response);
	return TEEC_SUCCESS;
}

static TEEC_Result resume_pending_http_transcript(
					struct twep_ta_ctx *ctx,
					const char *request_id,
					const uint8_t *host_io_result,
					size_t host_io_result_len,
					size_t output_capacity,
					uint32_t *origin)
{
	uint8_t *resume = NULL;
	uint8_t *response = NULL;
	size_t resume_len = 0;
	size_t response_len = 0;
	TEEC_Result res;

	resume = make_resume_envelope(request_id, host_io_result,
				      host_io_result_len, &resume_len);
	response = malloc(output_capacity ? output_capacity : 1);
	if (!response)
		errx(1, "out of memory building transcript resource-limit resume");
	res = invoke_production_raw(ctx, TA_TWEP_WR_CMD_RESUME_HOST_IO,
				    resume, resume_len, response,
				    output_capacity, &response_len, origin);
	free(resume);
	if (res == TEEC_SUCCESS &&
	    !validate_resume_final_response(response, response_len, request_id))
		errx(1, "TA transcript resource-limit resume returned unexpected final response");
	free(response);
	return res;
}

static void invoke_teep_agent_transcript_limits(struct twep_ta_ctx *owner)
{
	struct twep_ta_ctx second;
	struct twep_ta_ctx third;
	uint8_t *owner_result = NULL;
	uint8_t *second_result = NULL;
	uint8_t *third_result = NULL;
	size_t owner_result_len = 0;
	size_t second_result_len = 0;
	size_t third_result_len = 0;
	TEEC_Result res;
	uint32_t origin = 0;

	res = request_pending_http_transcript(
		owner, "req-transcript-owner", 32768,
		&owner_result, &owner_result_len, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TA rejected the 32768-byte HTTP transcript boundary with code 0x%x origin 0x%x",
		     res, origin);
	open_ta(&second);
	res = request_pending_http_transcript(
		&second, "req-transcript-second", 32768,
		&second_result, &second_result_len, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TA rejected the 65536-byte aggregate HTTP transcript boundary with code 0x%x origin 0x%x",
		     res, origin);
	puts("TA D043 transcript 32768-byte and 65536-byte aggregate boundary accepted");

	open_ta(&third);
	res = request_pending_http_transcript(
		&third, "req-transcript-third-limit", 1,
		&third_result, &third_result_len, &origin);
	if (res != TEEC_ERROR_EXCESS_DATA)
		errx(1, "TA third pending HTTP transcript returned code 0x%x origin 0x%x",
		     res, origin);
	puts("TA D043 third pending HTTP transcript rejected with resource limit");

	invoke_teep_agent_hostcall_evidence(&third);
	puts("TA D043 create_evidence excluded from HTTP transcript quota");

	res = request_pending_http_transcript(
		owner, "req-transcript-owner-oversize", 32769,
		&third_result, &third_result_len, &origin);
	if (res != TEEC_ERROR_EXCESS_DATA)
		errx(1, "TA 32769-byte HTTP transcript replacement returned code 0x%x origin 0x%x",
		     res, origin);
	expect_resume_failure(owner, "req-transcript-owner", owner_result,
			      owner_result_len, "replaced transcript");
	free(owner_result);
	owner_result = NULL;
	puts("TA D043 32769-byte replacement rejected and old transcript invalidated");

	res = request_pending_http_transcript(
		&third, "req-transcript-third-short", 32768,
		&third_result, &third_result_len, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TA failed to seed terminal-failure transcript with code 0x%x origin 0x%x",
		     res, origin);
	res = resume_pending_http_transcript(
		&third, "req-transcript-third-short", third_result,
		third_result_len, 64, &origin);
	free(third_result);
	third_result = NULL;
	if (res != TEEC_ERROR_SHORT_BUFFER)
		errx(1, "TA accepted terminal short-buffer resume returned code 0x%x origin 0x%x",
		     res, origin);
	res = request_pending_http_transcript(
		owner, "req-transcript-owner-after-failure", 32768,
		&owner_result, &owner_result_len, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TA did not release terminal-failure transcript quota, code 0x%x origin 0x%x",
		     res, origin);
	puts("TA D043 accepted terminal failure released transcript quota");

	close_ta(&second);
	free(second_result);
	second_result = NULL;
	res = request_pending_http_transcript(
		&third, "req-transcript-third-after-close", 32768,
		&third_result, &third_result_len, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TA did not release closed-session transcript quota, code 0x%x origin 0x%x",
		     res, origin);
	puts("TA D043 session close released transcript quota");

	res = resume_pending_http_transcript(
		owner, "req-transcript-owner-after-failure", owner_result,
		owner_result_len, 4096, &origin);
	free(owner_result);
	owner_result = NULL;
	if (res != TEEC_SUCCESS)
		errx(1, "TA accepted transcript resume failed with code 0x%x origin 0x%x",
		     res, origin);
	open_ta(&second);
	res = request_pending_http_transcript(
		&second, "req-transcript-second-after-resume", 32768,
		&second_result, &second_result_len, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TA did not release accepted-resume transcript quota, code 0x%x origin 0x%x",
		     res, origin);
	puts("TA D043 accepted resume released transcript quota");

	free(second_result);
	free(third_result);
	close_ta(&second);
	close_ta(&third);
	puts("TA D043 transcript resource limits ok");
}

static void invoke_teep_agent_hostcall_http_wasm(struct twep_ta_ctx *ctx,
						 const char *teep_agent_path)
{
	uint8_t *teep_agent_wasm = NULL;
	uint8_t *app_input = NULL;
	uint8_t *request = NULL;
	uint8_t *host_io_result = NULL;
	uint8_t *resume = NULL;
	uint8_t response[4096];
	size_t teep_agent_wasm_len = 0;
	size_t app_input_len = 0;
	size_t request_len = 0;
	size_t host_io_result_len = 0;
	size_t resume_len = 0;
	size_t response_len = 0;
	struct host_io_transcript transcript = { };
	TEEC_Result res;
	uint32_t origin = 0;

	teep_agent_wasm = read_file(teep_agent_path, &teep_agent_wasm_len);
	app_input = make_teep_hostcall_probe_input("hostcall_http_probe",
						  "https://ta.example.invalid/tam",
						  &app_input_len);
	request = make_execute_envelope("req-teep-http-wasm",
					"teep-agent-resolve",
					app_input, app_input_len,
					teep_agent_wasm, teep_agent_wasm_len,
					&request_len);
	res = invoke_production_raw(ctx, TA_TWEP_WR_CMD_EXECUTE, request,
				    request_len, response, sizeof(response),
				    &response_len, &origin);
	free(request);
	free(app_input);
	free(teep_agent_wasm);
	if (res != TEEC_SUCCESS)
		errx(1, "TA production teep-agent wasm http hostcall request failed with code 0x%x origin 0x%x",
		     res, origin);
	if (!validate_need_host_io_response(response, response_len,
					   "req-teep-http-wasm",
					   "teep-http-1",
					   "https://ta.example.invalid/tam",
					   &transcript)) {
		fprintf(stderr, "teep-agent wasm http need response hex: ");
		dump_hex(stderr, response, response_len);
		fputc('\n', stderr);
		errx(1, "TA production teep-agent wasm http hostcall returned unexpected need_host_io response");
	}
	puts("TA production teep-agent wasm http hostcall requested ok");

	host_io_result = make_host_io_result_for_transcript(
		"teep-http-1", "http_post", &transcript, &host_io_result_len);
	resume = make_resume_envelope("req-teep-http-wasm", host_io_result,
				      host_io_result_len, &resume_len);
	res = invoke_production_raw(ctx, TA_TWEP_WR_CMD_RESUME_HOST_IO,
				    resume, resume_len, response,
				    sizeof(response), &response_len, &origin);
	free(resume);
	free(host_io_result);
	if (res != TEEC_SUCCESS)
		errx(1, "TA production teep-agent wasm http hostcall resume failed with code 0x%x origin 0x%x",
		     res, origin);
	if (!validate_resume_final_response(response, response_len,
					    "req-teep-http-wasm"))
		errx(1, "TA production teep-agent wasm http hostcall returned unexpected final response");
	puts("TA production teep-agent wasm http hostcall resumed ok");
}

struct acceptance_state_snapshot {
	uint8_t slot0[4096];
	uint8_t slot1[4096];
	uint8_t result[4096];
	size_t slot0_len;
	size_t slot1_len;
	size_t result_len;
};

static void capture_acceptance_state(struct twep_ta_ctx *ctx,
				     struct acceptance_state_snapshot *snapshot)
{
	memset(snapshot, 0, sizeof(*snapshot));
	secure_storage_get_optional(ctx, "teep-acceptance-state.0.cbor",
				    snapshot->slot0, sizeof(snapshot->slot0),
				    &snapshot->slot0_len);
	secure_storage_get_optional(ctx, "teep-acceptance-state.1.cbor",
				    snapshot->slot1, sizeof(snapshot->slot1),
				    &snapshot->slot1_len);
	secure_storage_get_optional(ctx, "verified-evidence-result.cbor",
				    snapshot->result, sizeof(snapshot->result),
				    &snapshot->result_len);
}

static void require_acceptance_state_unchanged(
				const struct acceptance_state_snapshot *before,
				const struct acceptance_state_snapshot *after,
				const char *label)
{
	if (before->slot0_len != after->slot0_len ||
	    before->slot1_len != after->slot1_len ||
	    before->result_len != after->result_len ||
	    memcmp(before->slot0, after->slot0, before->slot0_len) != 0 ||
	    memcmp(before->slot1, after->slot1, before->slot1_len) != 0 ||
	    memcmp(before->result, after->result, before->result_len) != 0)
		errx(1, "TA acceptance state changed after %s", label);
}

#ifdef TWEP_TA_D043_TEST_HOOKS
#define D043_CORRUPT_OBJECT ((TEEC_Result)0xF0100001)

static TEEC_Result d043_test_command(struct twep_ta_ctx *ctx, uint32_t op_code,
				     uint32_t selector, const void *data,
				     size_t data_len, uint32_t *value_a,
				     uint32_t *value_b)
{
	TEEC_Operation op;
	TEEC_Result res;
	uint32_t origin = 0;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_VALUE_INOUT, TEEC_NONE);
	op.params[0].value.a = op_code;
	op.params[0].value.b = selector;
	op.params[1].tmpref.buffer = (void *)data;
	op.params[1].tmpref.size = data_len;
	res = TEEC_InvokeCommand(&ctx->sess, TA_TWEP_WR_CMD_D043_TEST,
				 &op, &origin);
	if (res == TEEC_SUCCESS) {
		if (value_a)
			*value_a = op.params[2].value.a;
		if (value_b)
			*value_b = op.params[2].value.b;
	}
	return res;
}

static void d043_test_reset(struct twep_ta_ctx *ctx)
{
	TEEC_Result res = d043_test_command(
		ctx, TA_TWEP_WR_D043_TEST_RESET, 0, NULL, 0, NULL, NULL);

	if (res != TEEC_SUCCESS)
		errx(1, "TA D043 test reset failed with code 0x%x", res);
}

static void d043_test_arm_fault(struct twep_ta_ctx *ctx, uint32_t fault)
{
	TEEC_Result res = d043_test_command(
		ctx, TA_TWEP_WR_D043_TEST_ARM_FAULT, fault,
		NULL, 0, NULL, NULL);

	if (res != TEEC_SUCCESS)
		errx(1, "TA D043 test fault %u arm failed with code 0x%x",
		     fault, res);
}

static void d043_test_write_object(struct twep_ta_ctx *ctx, uint32_t object,
				   const void *data, size_t data_len)
{
	TEEC_Result res = d043_test_command(
		ctx, TA_TWEP_WR_D043_TEST_WRITE_OBJECT, object,
		data, data_len, NULL, NULL);

	if (res != TEEC_SUCCESS)
		errx(1, "TA D043 test object %u write failed with code 0x%x",
		     object, res);
}

static TEEC_Result d043_test_generation(struct twep_ta_ctx *ctx,
					uint64_t *generation)
{
	uint32_t lo = 0;
	uint32_t hi = 0;
	TEEC_Result res = d043_test_command(
		ctx, TA_TWEP_WR_D043_TEST_GET_GENERATION, 0,
		NULL, 0, &lo, &hi);

	if (res == TEEC_SUCCESS && generation)
		*generation = ((uint64_t)hi << 32) | lo;
	return res;
}

static void d043_require_generation(struct twep_ta_ctx *ctx,
				    uint64_t expected, const char *label)
{
	uint64_t generation = 0;
	TEEC_Result res = d043_test_generation(ctx, &generation);

	if (res != TEEC_SUCCESS || generation != expected)
		errx(1, "TA D043 %s generation mismatch: code 0x%x got %llu expected %llu",
		     label, res, (unsigned long long)generation,
		     (unsigned long long)expected);
}

static void d043_require_generation_error(struct twep_ta_ctx *ctx,
					  TEEC_Result expected,
					  const char *label)
{
	TEEC_Result res = d043_test_generation(ctx, NULL);

	if (res != expected)
		errx(1, "TA D043 %s returned code 0x%x expected 0x%x",
		     label, res, expected);
}

static void d043_require_pending_clear(struct twep_ta_ctx *ctx)
{
	uint32_t count = 0;
	uint32_t bytes = 0;
	TEEC_Operation op;
	TEEC_Result res;
	uint32_t origin = 0;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_VALUE_INOUT, TEEC_NONE);
	op.params[0].value.a = TA_TWEP_WR_D043_TEST_GET_PENDING_STATE;
	res = TEEC_InvokeCommand(&ctx->sess, TA_TWEP_WR_CMD_D043_TEST,
				 &op, &origin);
	count = op.params[2].value.a;
	bytes = op.params[2].value.b;
	if (res != TEEC_SUCCESS || op.params[0].value.b != 0 || count != 0 ||
	    bytes != 0)
		errx(1, "TA D043 pending state leaked: code 0x%x flags %u count %u bytes %u",
		     res, op.params[0].value.b, count, bytes);
}

static TEEC_Result d047_test_operation(struct twep_ta_ctx *ctx,
				       uint32_t operation, uint32_t sequence,
				       uint64_t expected_generation,
				       const void *catalog, size_t catalog_len,
				       uint64_t *new_generation)
{
	TEEC_Operation op;
	TEEC_Result res;
	uint32_t origin = 0;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_VALUE_INOUT, TEEC_NONE);
	op.params[0].value.a = operation;
	op.params[0].value.b = sequence;
	op.params[1].tmpref.buffer = (void *)catalog;
	op.params[1].tmpref.size = catalog_len;
	op.params[2].value.a = (uint32_t)expected_generation;
	op.params[2].value.b = (uint32_t)(expected_generation >> 32);
	res = TEEC_InvokeCommand(&ctx->sess, TA_TWEP_WR_CMD_D043_TEST,
				 &op, &origin);
	if (res == TEEC_SUCCESS && new_generation)
		*new_generation = ((uint64_t)op.params[2].value.b << 32) |
			op.params[2].value.a;
	return res;
}

static void d047_require_active(struct twep_ta_ctx *ctx, const void *catalog,
				       size_t catalog_len, const char *label)
{
	TEEC_Result res = d047_test_operation(
		ctx, TA_TWEP_WR_D043_TEST_CATALOG_EXPECT_ACTIVE, 0, 0,
		catalog, catalog_len, NULL);

	if (res != TEEC_SUCCESS)
		errx(1, "TA D047 %s active Catalog mismatch: code 0x%x",
		     label, res);
}

static void invoke_d047_catalog_transactions(struct twep_ta_ctx *ctx)
{
	static const uint8_t catalog1[] = { 0xa1, 0x61, 'v', 0x01 };
	static const uint8_t catalog2[] = { 0xa1, 0x61, 'v', 0x02 };
	static const uint8_t catalog3[] = { 0xa1, 0x61, 'v', 0x03 };
	uint64_t generation = 0;
	TEEC_Result res;

	d043_test_reset(ctx);
	res = d047_test_operation(ctx, TA_TWEP_WR_D043_TEST_CATALOG_COMMIT,
				  1, 0, catalog1, sizeof(catalog1), &generation);
	if (res != TEEC_SUCCESS || generation != 1)
		errx(1, "TA D047 initial Catalog commit failed: code 0x%x generation %llu",
		     res, (unsigned long long)generation);
	d047_require_active(ctx, catalog1, sizeof(catalog1), "initial commit");
	close_ta(ctx);
	open_ta(ctx);
	d047_require_active(ctx, catalog1, sizeof(catalog1), "restart readback");
	puts("TA D047 Catalog initial commit and restart readback ok");

	res = d047_test_operation(ctx, TA_TWEP_WR_D043_TEST_CATALOG_COMMIT,
				  2, 1, catalog2, sizeof(catalog2), &generation);
	if (res != TEEC_SUCCESS || generation != 2)
		errx(1, "TA D047 Catalog update failed: code 0x%x generation %llu",
		     res, (unsigned long long)generation);
	d047_require_active(ctx, catalog2, sizeof(catalog2), "update");
	puts("TA D047 Catalog inactive-slot update and readback ok");
	res = d047_test_operation(ctx, TA_TWEP_WR_D043_TEST_CATALOG_COMMIT,
				  2, 2, catalog3, sizeof(catalog3), NULL);
	if (res == TEEC_SUCCESS)
		errx(1, "TA D047 equal-sequence Catalog unexpectedly staged");
	d043_require_generation(ctx, 2, "D047 equal-sequence rejection");
	d047_require_active(ctx, catalog2, sizeof(catalog2),
			    "equal-sequence rejection preservation");
	close_ta(ctx);
	open_ta(ctx);
	d047_require_active(ctx, catalog2, sizeof(catalog2),
			    "equal-sequence restart preservation");
	puts("TA D047 equal-sequence rejection preserved prior Catalog ok");
	res = d047_test_operation(ctx, TA_TWEP_WR_D043_TEST_CATALOG_COMMIT,
				  3, 2, catalog2, sizeof(catalog2), NULL);
	if (res == TEEC_SUCCESS)
		errx(1, "TA D047 replayed Catalog transcript unexpectedly committed");
	d043_require_generation(ctx, 2, "D047 replay rejection");
	d047_require_active(ctx, catalog2, sizeof(catalog2),
			    "replay rejection preservation");
	puts("TA D047 replay rejection preserved prior Catalog ok");

	{
		static const struct {
			uint32_t fault;
			const char *label;
		} faults[] = {
			{ TA_TWEP_WR_D047_FAULT_CATALOG_SLOT_CREATE,
			  "Catalog slot-create" },
			{ TA_TWEP_WR_D047_FAULT_CATALOG_SLOT_WRITE,
			  "Catalog slot-write" },
			{ TA_TWEP_WR_D047_FAULT_CATALOG_SLOT_AFTER_CLOSE,
			  "Catalog slot-after-close" },
			{ TA_TWEP_WR_D047_FAULT_CATALOG_SLOT_REOPEN,
			  "Catalog slot-reopen" },
			{ TA_TWEP_WR_D047_FAULT_CATALOG_SLOT_READBACK,
			  "Catalog slot-readback" },
		};
		size_t i;

		for (i = 0; i < sizeof(faults) / sizeof(faults[0]); i++) {
			d043_test_arm_fault(ctx, faults[i].fault);
			res = d047_test_operation(
				ctx, TA_TWEP_WR_D043_TEST_CATALOG_COMMIT,
				3, 2, catalog3, sizeof(catalog3), NULL);
			if (res == TEEC_SUCCESS)
				errx(1, "TA D047 %s fault unexpectedly committed",
				     faults[i].label);
			d043_require_generation(ctx, 2, faults[i].label);
			d047_require_active(ctx, catalog2, sizeof(catalog2),
					    faults[i].label);
			close_ta(ctx);
			open_ta(ctx);
			d047_require_active(ctx, catalog2, sizeof(catalog2),
					    faults[i].label);
			printf("TA D047 %s fault preserved prior Catalog ok\n",
			       faults[i].label);
		}
	}
	puts("TA D047 Catalog staging fault matrix preserved prior Catalog ok");

	d043_test_arm_fault(ctx, TA_TWEP_WR_D043_FAULT_SLOT_WRITE);
	res = d047_test_operation(ctx, TA_TWEP_WR_D043_TEST_CATALOG_COMMIT,
				  3, 2, catalog3, sizeof(catalog3), NULL);
	if (res == TEEC_SUCCESS)
		errx(1, "TA D047 D043 publication fault unexpectedly committed");
	d043_require_generation(ctx, 2, "D047 D043 publication fault");
	d047_require_active(ctx, catalog2, sizeof(catalog2),
			    "D043 publication fault preservation");
	close_ta(ctx);
	open_ta(ctx);
	d047_require_active(ctx, catalog2, sizeof(catalog2),
			    "D043 publication fault restart preservation");
	puts("TA D047 D043 publication fault preserved prior Catalog ok");

	res = d047_test_operation(ctx, TA_TWEP_WR_D043_TEST_NONCATALOG_COMMIT,
				  1, 2, NULL, 0, &generation);
	if (res != TEEC_SUCCESS || generation != 3)
		errx(1, "TA D047 non-Catalog acceptance failed: code 0x%x generation %llu",
		     res, (unsigned long long)generation);
	d047_require_active(ctx, catalog2, sizeof(catalog2),
			    "later non-Catalog acceptance");
	puts("TA D047 later non-Catalog acceptance preserved Catalog visibility ok");
	d043_test_reset(ctx);
}

static void invoke_d047_catalog_live_readback(struct twep_ta_ctx *ctx)
{
	TEEC_Result res = d047_test_operation(
		ctx, TA_TWEP_WR_D043_TEST_CATALOG_EXPECT_PRESENT, 0, 0,
		NULL, 0, NULL);

	if (res != TEEC_SUCCESS)
		errx(1, "TA D047 live Catalog restart readback failed: code 0x%x",
		     res);
	puts("component-kind=twep-catalog-v1");
	puts("component-name=default");
	puts("TA D047 live Catalog restart readback ok");
}

static size_t d043_make_slot(uint8_t *out, uint64_t schema_version,
			     uint64_t generation, uint8_t digest_byte,
			     size_t component_count, size_t long_id_len)
{
	uint8_t *p = out;
	size_t i;

	cbor_write_type_len(&p, 5, 4);
	cbor_write_text(&p, "generation");
	cbor_write_type_len(&p, 0, generation);
	cbor_write_text(&p, "schema_version");
	cbor_write_type_len(&p, 0, schema_version);
	cbor_write_text(&p, "component_sequences");
	cbor_write_type_len(&p, 5, component_count);
	for (i = 0; i < component_count; i++) {
		size_t id_len = long_id_len ? long_id_len : 1;
		size_t j;

		cbor_write_type_len(&p, 2, id_len);
		for (j = 0; j < id_len; j++)
			*p++ = long_id_len ? (uint8_t)(j + 1) : (uint8_t)i;
		cbor_write_type_len(&p, 0, i + 1);
	}
	cbor_write_text(&p, "last_consumed_query_response_sha256");
	cbor_write_type_len(&p, 2, 32);
	memset(p, digest_byte, 32);
	p += 32;
	return (size_t)(p - out);
}

static size_t d043_make_legacy(uint8_t *out, size_t component_count)
{
	uint8_t *p = out;
	size_t i;

	cbor_write_type_len(&p, 5, component_count);
	for (i = 0; i < component_count; i++) {
		cbor_write_type_len(&p, 2, 1);
		*p++ = (uint8_t)i;
		cbor_write_type_len(&p, 0, i + 1);
	}
	return (size_t)(p - out);
}

static size_t d043_make_noncanonical_slot(uint8_t *out)
{
	uint8_t *p = out;

	cbor_write_type_len(&p, 5, 4);
	cbor_write_text(&p, "generation");
	*p++ = 0x18;
	*p++ = 0x01;
	cbor_write_text(&p, "schema_version");
	cbor_write_type_len(&p, 0, 1);
	cbor_write_text(&p, "component_sequences");
	cbor_write_type_len(&p, 5, 0);
	cbor_write_text(&p, "last_consumed_query_response_sha256");
	cbor_write_type_len(&p, 2, 32);
	memset(p, 0x55, 32);
	p += 32;
	return (size_t)(p - out);
}

static size_t d043_make_duplicate_component_slot(uint8_t *out)
{
	uint8_t *p = out;

	cbor_write_type_len(&p, 5, 4);
	cbor_write_text(&p, "generation");
	cbor_write_type_len(&p, 0, 1);
	cbor_write_text(&p, "schema_version");
	cbor_write_type_len(&p, 0, 1);
	cbor_write_text(&p, "component_sequences");
	cbor_write_type_len(&p, 5, 2);
	cbor_write_type_len(&p, 2, 1);
	*p++ = 0x01;
	cbor_write_type_len(&p, 0, 1);
	cbor_write_type_len(&p, 2, 1);
	*p++ = 0x01;
	cbor_write_type_len(&p, 0, 2);
	cbor_write_text(&p, "last_consumed_query_response_sha256");
	cbor_write_type_len(&p, 2, 32);
	memset(p, 0x66, 32);
	p += 32;
	return (size_t)(p - out);
}
#endif

static void invoke_teep_agent_acceptance_probe_once(
						struct twep_ta_ctx *ctx,
						const char *teep_agent_path,
						const char *probe_command,
						const char *request_id,
						uint64_t expected_generation,
						bool test_transcript_mismatch)
{
	uint8_t *teep_agent_wasm = NULL;
	uint8_t *app_input = NULL;
	uint8_t *request = NULL;
	uint8_t *host_io_result = NULL;
	uint8_t *resume = NULL;
	uint8_t response[4096];
	size_t teep_agent_wasm_len = 0;
	size_t app_input_len = 0;
	size_t request_len = 0;
	size_t host_io_result_len = 0;
	size_t resume_len = 0;
	size_t response_len = 0;
	struct host_io_transcript transcript = { };
	struct host_io_transcript bad_transcript = { };
	struct acceptance_state_snapshot before = { };
	struct acceptance_state_snapshot after = { };
	TEEC_Result res;
	uint32_t origin = 0;

	teep_agent_wasm = read_file(teep_agent_path, &teep_agent_wasm_len);
	app_input = make_teep_hostcall_probe_input(
		probe_command, "https://ta.example.invalid/tam", &app_input_len);
	request = make_execute_envelope(request_id, "teep-agent-resolve",
					app_input, app_input_len,
					teep_agent_wasm, teep_agent_wasm_len,
					&request_len);
	res = invoke_production_raw(ctx, TA_TWEP_WR_CMD_EXECUTE, request,
				    request_len, response, sizeof(response),
				    &response_len, &origin);
	free(request);
	free(app_input);
	free(teep_agent_wasm);
	if (res != TEEC_SUCCESS)
		errx(1, "TA acceptance probe request failed with code 0x%x origin 0x%x",
		     res, origin);
	if (!validate_need_host_io_response(
		    response, response_len, request_id, "teep-http-1",
		    "https://ta.example.invalid/tam", &transcript))
		errx(1, "TA acceptance probe returned unexpected need_host_io response");

	if (test_transcript_mismatch) {
		capture_acceptance_state(ctx, &before);
		bad_transcript = transcript;
		bad_transcript.request_body_sha256[0] ^= 0xff;
		host_io_result = make_host_io_result_for_transcript(
			"teep-http-1", "http_post", &bad_transcript,
			&host_io_result_len);
		expect_resume_failure(ctx, request_id, host_io_result,
				      host_io_result_len,
				      "acceptance transcript mismatch");
		free(host_io_result);
		host_io_result = NULL;
		capture_acceptance_state(ctx, &after);
		require_acceptance_state_unchanged(
			&before, &after, "acceptance transcript mismatch");
		puts("TA acceptance transcript mismatch rejected with state unchanged");
	}

	host_io_result = make_host_io_result_for_transcript(
		"teep-http-1", "http_post", &transcript, &host_io_result_len);
	resume = make_resume_envelope(request_id, host_io_result,
				      host_io_result_len, &resume_len);
	res = invoke_production_raw(ctx, TA_TWEP_WR_CMD_RESUME_HOST_IO,
				    resume, resume_len, response,
				    sizeof(response), &response_len, &origin);
	free(resume);
	free(host_io_result);
	if (res != TEEC_SUCCESS ||
	    !validate_resume_final_response(response, response_len, request_id))
		errx(1, "TA acceptance probe resume failed at generation %llu with code 0x%x origin 0x%x",
		     (unsigned long long)expected_generation, res, origin);
	printf("TA production acceptance generation %llu committed ok\n",
	       (unsigned long long)expected_generation);
}

static void invoke_teep_agent_acceptance_probe(struct twep_ta_ctx *ctx,
					       const char *teep_agent_path)
{
	invoke_teep_agent_acceptance_probe_once(
		ctx, teep_agent_path, "hostcall_acceptance_probe_1",
		"req-teep-acceptance-1", 1, true);
	invoke_teep_agent_acceptance_probe_once(
		ctx, teep_agent_path, "hostcall_acceptance_probe_2",
		"req-teep-acceptance-2", 2, false);
	puts("TA production acceptance state two-slot persistence ok");
}

static uint8_t *seed_teep_agent_acceptance_pending(
					struct twep_ta_ctx *ctx,
					const char *teep_agent_path,
					const char *probe_command,
					const char *request_id,
					size_t *host_io_result_len)
{
	uint8_t *teep_agent_wasm = NULL;
	uint8_t *app_input = NULL;
	uint8_t *request = NULL;
	uint8_t *host_io_result = NULL;
	uint8_t response[4096];
	size_t teep_agent_wasm_len = 0;
	size_t app_input_len = 0;
	size_t request_len = 0;
	size_t response_len = 0;
	struct host_io_transcript transcript = { };
	TEEC_Result res;
	uint32_t origin = 0;

	teep_agent_wasm = read_file(teep_agent_path, &teep_agent_wasm_len);
	app_input = make_teep_hostcall_probe_input(
		probe_command, "https://ta.example.invalid/tam", &app_input_len);
	request = make_execute_envelope(request_id, "teep-agent-resolve",
				       app_input, app_input_len,
				       teep_agent_wasm, teep_agent_wasm_len,
				       &request_len);
	res = invoke_production_raw(ctx, TA_TWEP_WR_CMD_EXECUTE, request,
				    request_len, response, sizeof(response),
				    &response_len, &origin);
	free(request);
	free(app_input);
	free(teep_agent_wasm);
	if (res != TEEC_SUCCESS)
		errx(1, "TA acceptance negative seed failed with code 0x%x origin 0x%x",
		     res, origin);
	if (!validate_need_host_io_response(
		    response, response_len, request_id, "teep-http-1",
		    "https://ta.example.invalid/tam", &transcript))
		errx(1, "TA acceptance negative seed returned unexpected need_host_io response");

	host_io_result = make_host_io_result_for_transcript(
		"teep-http-1", "http_post", &transcript, host_io_result_len);
	return host_io_result;
}

static void invoke_teep_agent_acceptance_commit_negative(
					struct twep_ta_ctx *ctx,
					const char *teep_agent_path,
					const char *probe_command,
					const char *request_id,
					const char *label,
					bool test_session_lifetime)
{
	uint8_t *host_io_result = NULL;
	uint8_t *resume = NULL;
	uint8_t response[4096];
	size_t host_io_result_len = 0;
	size_t resume_len = 0;
	size_t response_len = 0;
	struct acceptance_state_snapshot before = { };
	struct acceptance_state_snapshot after = { };
	struct twep_ta_ctx other;
	TEEC_Result res;
	uint32_t origin = 0;

	capture_acceptance_state(ctx, &before);
	host_io_result = seed_teep_agent_acceptance_pending(
		ctx, teep_agent_path, probe_command, request_id,
		&host_io_result_len);
	capture_acceptance_state(ctx, &after);
	require_acceptance_state_unchanged(&before, &after,
					   "acceptance pending seed");

	if (test_session_lifetime) {
		open_ta(&other);
		expect_resume_failure(&other, request_id, host_io_result,
				      host_io_result_len,
				      "acceptance cross-session resume");
		close_ta(&other);
		capture_acceptance_state(ctx, &after);
		require_acceptance_state_unchanged(
			&before, &after, "acceptance cross-session resume");
		puts("TA acceptance cross-session resume rejected with state unchanged");
	}

	resume = make_resume_envelope(request_id, host_io_result,
				      host_io_result_len, &resume_len);
	res = invoke_production_raw(ctx, TA_TWEP_WR_CMD_RESUME_HOST_IO,
				    resume, resume_len, response,
				    sizeof(response), &response_len, &origin);
	free(resume);
	if (res != TEEC_ERROR_GENERIC)
		errx(1, "TA acceptance %s returned code 0x%x origin 0x%x",
		     label, res, origin);
	capture_acceptance_state(ctx, &after);
	require_acceptance_state_unchanged(&before, &after, label);
	printf("TA acceptance %s rejected with state unchanged\n", label);

	if (test_session_lifetime) {
		close_ta(ctx);
		open_ta(ctx);
		expect_resume_failure(ctx, request_id, host_io_result,
				      host_io_result_len,
				      "acceptance restart without pending");
		capture_acceptance_state(ctx, &after);
		require_acceptance_state_unchanged(
			&before, &after, "acceptance restart without pending");
		puts("TA acceptance restart without pending rejected with state unchanged");
	}
	free(host_io_result);
}

static void invoke_teep_agent_acceptance_negatives(
					struct twep_ta_ctx *ctx,
					const char *teep_agent_path)
{
	invoke_teep_agent_acceptance_commit_negative(
		ctx, teep_agent_path, "hostcall_acceptance_probe_2",
		"req-teep-acceptance-replay", "replay", true);
	invoke_teep_agent_acceptance_commit_negative(
		ctx, teep_agent_path, "hostcall_acceptance_probe_stale",
		"req-teep-acceptance-stale", "stale generation", false);
}

static void verify_teep_agent_acceptance_result_mirror(
						struct twep_ta_ctx *ctx)
{
	static const uint8_t expected[] = {
		0xa5, 0x6e, 's', 'c', 'h', 'e', 'm', 'a', '_', 'v', 'e', 'r',
		's', 'i', 'o', 'n', 0x02, 0x6f, 'd', 'e', 'c', 'i', 's', 'i',
		'o', 'n', '_', 's', 'o', 'u', 'r', 'c', 'e', 0x76, 'a', 't',
		't', 'e', 's', 't', 'a', 'm', '-', 's', 'i', 'g', 'n', 'e',
		'd', '-', 'u', 'p', 'd', 'a', 't', 'e', 0x75, 't', 'a', 'm',
		'_', 'r', 'e', 's', 'p', 'o', 'n', 's', 'e', '_', 'v', 'e',
		'r', 'i', 'f', 'i', 'e', 'd', 0xf5, 0x78, 0x18, 'c', 'h',
		'a', 'l', 'l', 'e', 'n', 'g', 'e', '_', 'r', 'e', 's', 'p',
		'o', 'n', 's', 'e', '_', 'b', 'o', 'u', 'n', 'd', 0xf5, 0x75,
		'a', 'c', 'c', 'e', 'p', 't', 'a', 'n', 'c', 'e', '_', 'g',
		'e', 'n', 'e', 'r', 'a', 't', 'i', 'o', 'n', 0x02,
	};
	uint8_t read_back[4096];
	size_t read_len = 0;

	secure_storage_get(ctx, "verified-evidence-result.cbor", read_back,
			   sizeof(read_back), &read_len);
	if (read_len != sizeof(expected) ||
	    memcmp(read_back, expected, sizeof(expected)) != 0) {
		fprintf(stderr, "TA verified result mirror hex: ");
		dump_hex(stderr, read_back, read_len);
		fputc('\n', stderr);
		errx(1, "TA production teep-agent verified result mirror mismatch");
	}
	puts("TA production teep-agent verified result secure storage mirror ok");
}

#ifdef TWEP_TA_D043_TEST_HOOKS
static TEEC_Result d043_resume_acceptance(struct twep_ta_ctx *ctx,
					  const char *request_id,
					  const uint8_t *host_io_result,
					  size_t host_io_result_len)
{
	uint8_t *resume;
	uint8_t response[4096];
	size_t resume_len = 0;
	size_t response_len = 0;
	uint32_t origin = 0;
	TEEC_Result res;

	resume = make_resume_envelope(request_id, host_io_result,
				      host_io_result_len, &resume_len);
	res = invoke_production_raw(ctx, TA_TWEP_WR_CMD_RESUME_HOST_IO,
				    resume, resume_len, response,
				    sizeof(response), &response_len, &origin);
	free(resume);
	return res;
}

static void d043_seed_generation_one(struct twep_ta_ctx *ctx,
				     const char *teep_agent_path)
{
	d043_test_reset(ctx);
	invoke_teep_agent_acceptance_probe_once(
		ctx, teep_agent_path, "hostcall_acceptance_probe_1",
		"req-d043-seed-1", 1, false);
	d043_require_generation(ctx, 1, "seed");
}

static void d043_require_result_unchanged(
				const struct acceptance_state_snapshot *before,
				const struct acceptance_state_snapshot *after,
				const char *label)
{
	if (before->result_len != after->result_len ||
	    memcmp(before->result, after->result, before->result_len) != 0)
		errx(1, "TA D043 result changed after %s", label);
}

static void d043_require_stale_result_rejected(struct twep_ta_ctx *ctx,
						const char *teep_agent_path,
						const char *label)
{
	uint8_t *teep_agent_wasm = NULL;
	uint8_t *app_input = NULL;
	uint8_t *request = NULL;
	uint8_t response[4096];
	size_t teep_agent_wasm_len = 0;
	size_t app_input_len = 0;
	size_t request_len = 0;
	size_t response_len = 0;
	TEEC_Result res;
	uint32_t origin = 0;

	teep_agent_wasm = read_file(teep_agent_path, &teep_agent_wasm_len);
	app_input = make_teep_hostcall_probe_input(
		"hostcall_acceptance_result_stale_probe", NULL,
		&app_input_len);
	request = make_execute_envelope("req-d043-stale-result-gate",
					"teep-agent-resolve", app_input,
					app_input_len, teep_agent_wasm,
					teep_agent_wasm_len, &request_len);
	res = invoke_production_raw(ctx, TA_TWEP_WR_CMD_EXECUTE, request,
				    request_len, response, sizeof(response),
				    &response_len, &origin);
	free(request);
	free(app_input);
	free(teep_agent_wasm);
	if (res != TEEC_SUCCESS || !validate_teep_resolve_error_response(
			response, response_len,
			"hostcall.acceptance_result_stale",
			"stale acceptance result rejected"))
		errx(1, "TA D043 %s stale-result read gate failed with code 0x%x origin 0x%x",
		     label, res, origin);
}

static void d043_run_precommit_fault(struct twep_ta_ctx *ctx,
				     const char *teep_agent_path,
				     uint32_t fault, const char *label)
{
	struct acceptance_state_snapshot before = { };
	struct acceptance_state_snapshot after = { };
	uint8_t *host_io_result;
	size_t host_io_result_len = 0;
	TEEC_Result res;
	char request_id[80];

	d043_seed_generation_one(ctx, teep_agent_path);
	capture_acceptance_state(ctx, &before);
	snprintf(request_id, sizeof(request_id), "req-d043-%s", label);
	host_io_result = seed_teep_agent_acceptance_pending(
		ctx, teep_agent_path, "hostcall_acceptance_probe_2",
		request_id, &host_io_result_len);
	d043_test_arm_fault(ctx, fault);
	res = d043_resume_acceptance(ctx, request_id, host_io_result,
				     host_io_result_len);
	if (res != TEEC_ERROR_GENERIC)
		errx(1, "TA D043 %s fault returned code 0x%x", label, res);
	capture_acceptance_state(ctx, &after);
	require_acceptance_state_unchanged(&before, &after, label);
	d043_require_generation(ctx, 1, label);
	res = d043_resume_acceptance(ctx, request_id, host_io_result,
				     host_io_result_len);
	if (res == TEEC_SUCCESS)
		errx(1, "TA D043 %s fault left transcript retryable", label);
	free(host_io_result);
}

static void d043_run_postcommit_fault(struct twep_ta_ctx *ctx,
				      const char *teep_agent_path,
				      uint32_t fault, const char *label)
{
	struct acceptance_state_snapshot before = { };
	struct acceptance_state_snapshot after = { };
	struct acceptance_state_snapshot retried = { };
	uint8_t *host_io_result;
	size_t host_io_result_len = 0;
	TEEC_Result res;
	char request_id[80];

	d043_seed_generation_one(ctx, teep_agent_path);
	capture_acceptance_state(ctx, &before);
	snprintf(request_id, sizeof(request_id), "req-d043-%s", label);
	host_io_result = seed_teep_agent_acceptance_pending(
		ctx, teep_agent_path, "hostcall_acceptance_probe_2",
		request_id, &host_io_result_len);
	d043_test_arm_fault(ctx, fault);
	res = d043_resume_acceptance(ctx, request_id, host_io_result,
				     host_io_result_len);
	if (res != TEEC_ERROR_GENERIC)
		errx(1, "TA D043 %s fault returned code 0x%x", label, res);
	d043_require_generation(ctx, 2, label);
	capture_acceptance_state(ctx, &after);
	d043_require_result_unchanged(&before, &after, label);
	d043_require_stale_result_rejected(ctx, teep_agent_path, label);
	res = d043_resume_acceptance(ctx, request_id, host_io_result,
				     host_io_result_len);
	if (res == TEEC_SUCCESS)
		errx(1, "TA D043 %s fault left transcript retryable", label);
	capture_acceptance_state(ctx, &retried);
	require_acceptance_state_unchanged(&after, &retried, "fault retry");
	free(host_io_result);
	invoke_teep_agent_acceptance_probe_once(
		ctx, teep_agent_path, "hostcall_acceptance_probe_3",
		"req-d043-fresh-3", 3, false);
	d043_require_generation(ctx, 3, "fresh post-fault commit");
}

static void d043_run_continuation_alloc_fault(struct twep_ta_ctx *ctx,
					      const char *teep_agent_path)
{
	uint8_t *teep_agent_wasm;
	uint8_t *app_input;
	uint8_t *request;
	uint8_t *host_io_result = NULL;
	uint8_t response[4096];
	size_t teep_agent_wasm_len = 0;
	size_t app_input_len = 0;
	size_t request_len = 0;
	size_t response_len = 0;
	size_t host_io_result_len = 0;
	uint32_t origin = 0;
	TEEC_Result res;

	d043_test_reset(ctx);
	teep_agent_wasm = read_file(teep_agent_path, &teep_agent_wasm_len);
	app_input = make_teep_hostcall_probe_input(
		"hostcall_acceptance_probe_1",
		"https://ta.example.invalid/tam", &app_input_len);
	request = make_execute_envelope(
		"req-d043-continuation-fault", "teep-agent-resolve",
		app_input, app_input_len, teep_agent_wasm, teep_agent_wasm_len,
		&request_len);
	d043_test_arm_fault(ctx, TA_TWEP_WR_D043_FAULT_CONTINUATION_ALLOC);
	res = invoke_production_raw(ctx, TA_TWEP_WR_CMD_EXECUTE, request,
				    request_len, response, sizeof(response),
				    &response_len, &origin);
	free(request);
	free(app_input);
	free(teep_agent_wasm);
	if (res != TEEC_ERROR_OUT_OF_MEMORY)
		errx(1, "TA D043 continuation allocation fault returned code 0x%x origin 0x%x",
		     res, origin);
	d043_require_pending_clear(ctx);
	res = request_pending_http_transcript(
		ctx, "req-d043-quota-reuse", 32768,
		&host_io_result, &host_io_result_len, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TA D043 continuation fault did not release quota: code 0x%x",
		     res);
	res = resume_pending_http_transcript(
		ctx, "req-d043-quota-reuse", host_io_result,
		host_io_result_len, 4096, &origin);
	free(host_io_result);
	if (res != TEEC_SUCCESS)
		errx(1, "TA D043 quota reuse cleanup failed with code 0x%x", res);
}

static void d043_run_state_fixture_matrix(struct twep_ta_ctx *ctx,
					  const char *teep_agent_path)
{
	uint8_t slot0[4096];
	uint8_t slot1[4097];
	uint8_t legacy[256];
	uint8_t malformed_slot[] = { 0xa0 };
	uint8_t malformed_legacy[] = { 0xff };
	uint8_t noncanonical_legacy[] = { 0xa1, 0x41, 0x00, 0x18, 0x01 };
	size_t slot0_len;
	size_t slot1_len;
	size_t legacy_len;
	struct acceptance_state_snapshot before = { };
	struct acceptance_state_snapshot after = { };
	uint8_t *host_io_result;
	size_t host_io_result_len = 0;
	TEEC_Result res;

	d043_test_reset(ctx);
	slot0_len = d043_make_slot(slot0, 1, 1, 0x11, 0, 0);
	d043_test_write_object(ctx, TA_TWEP_WR_D043_OBJECT_SLOT0,
			       slot0, slot0_len);
	d043_test_write_object(ctx, TA_TWEP_WR_D043_OBJECT_SLOT1,
			       malformed_slot, sizeof(malformed_slot));
	d043_require_generation(ctx, 1, "valid plus malformed peer");

	d043_test_reset(ctx);
	d043_test_write_object(ctx, TA_TWEP_WR_D043_OBJECT_SLOT0,
			       slot0, slot0_len);
	slot1_len = d043_make_slot(slot1, 2, 2, 0x22, 0, 0);
	d043_test_write_object(ctx, TA_TWEP_WR_D043_OBJECT_SLOT1,
			       slot1, slot1_len);
	d043_require_generation_error(ctx, TEEC_ERROR_NOT_SUPPORTED,
				      "unsupported newer peer");

	d043_test_reset(ctx);
	d043_test_write_object(ctx, TA_TWEP_WR_D043_OBJECT_SLOT0,
			       slot0, slot0_len);
	slot1_len = d043_make_slot(slot1, 1, 1, 0x22, 0, 0);
	d043_test_write_object(ctx, TA_TWEP_WR_D043_OBJECT_SLOT1,
			       slot1, slot1_len);
	d043_require_generation_error(ctx, TEEC_ERROR_SECURITY,
				      "equal-generation divergence");

	d043_test_reset(ctx);
	d043_test_write_object(ctx, TA_TWEP_WR_D043_OBJECT_SLOT0,
			       malformed_slot, sizeof(malformed_slot));
	d043_test_write_object(ctx, TA_TWEP_WR_D043_OBJECT_SLOT1,
			       malformed_slot, sizeof(malformed_slot));
	d043_require_generation_error(ctx, D043_CORRUPT_OBJECT,
				      "both slots invalid");

	d043_test_reset(ctx);
	slot0_len = d043_make_noncanonical_slot(slot0);
	d043_test_write_object(ctx, TA_TWEP_WR_D043_OBJECT_SLOT0,
			       slot0, slot0_len);
	d043_require_generation_error(ctx, D043_CORRUPT_OBJECT,
				      "non-canonical slot");

	d043_test_reset(ctx);
	slot0_len = d043_make_duplicate_component_slot(slot0);
	d043_test_write_object(ctx, TA_TWEP_WR_D043_OBJECT_SLOT0,
			       slot0, slot0_len);
	d043_require_generation_error(ctx, D043_CORRUPT_OBJECT,
				      "duplicate component key");

	d043_test_reset(ctx);
	legacy_len = d043_make_legacy(legacy, 32);
	d043_test_write_object(ctx, TA_TWEP_WR_D043_OBJECT_LEGACY,
			       legacy, legacy_len);
	d043_require_generation(ctx, 0, "32-component legacy migration");

	d043_test_reset(ctx);
	legacy_len = d043_make_legacy(legacy, 33);
	d043_test_write_object(ctx, TA_TWEP_WR_D043_OBJECT_LEGACY,
			       legacy, legacy_len);
	d043_require_generation_error(ctx, D043_CORRUPT_OBJECT,
				      "33-component legacy migration");

	d043_test_reset(ctx);
	d043_test_write_object(ctx, TA_TWEP_WR_D043_OBJECT_LEGACY,
			       malformed_legacy, sizeof(malformed_legacy));
	d043_require_generation_error(ctx, D043_CORRUPT_OBJECT,
				      "malformed legacy migration");

	d043_test_reset(ctx);
	d043_test_write_object(ctx, TA_TWEP_WR_D043_OBJECT_LEGACY,
			       noncanonical_legacy,
			       sizeof(noncanonical_legacy));
	d043_require_generation_error(ctx, D043_CORRUPT_OBJECT,
				      "non-canonical legacy migration");

	d043_test_reset(ctx);
	slot0_len = d043_make_slot(slot0, 1, 1, 0x11, 0, 0);
	d043_test_write_object(ctx, TA_TWEP_WR_D043_OBJECT_SLOT0,
			       slot0, slot0_len);
	legacy_len = d043_make_legacy(legacy, 1);
	d043_test_write_object(ctx, TA_TWEP_WR_D043_OBJECT_LEGACY,
			       legacy, legacy_len);
	d043_require_generation(ctx, 1, "valid slot ignores legacy");

	d043_test_reset(ctx);
	slot0_len = d043_make_slot(slot0, 1, 1, 0x33, 1, 3971);
	if (slot0_len != sizeof(slot0))
		errx(1, "TA D043 4096-byte fixture encoded to %zu bytes", slot0_len);
	d043_test_write_object(ctx, TA_TWEP_WR_D043_OBJECT_SLOT0,
			       slot0, slot0_len);
	d043_require_generation(ctx, 1, "4096-byte state boundary");

	d043_test_reset(ctx);
	memset(slot1, 0, sizeof(slot1));
	d043_test_write_object(ctx, TA_TWEP_WR_D043_OBJECT_SLOT0,
			       slot1, sizeof(slot1));
	d043_require_generation_error(ctx, D043_CORRUPT_OBJECT,
				      "4097-byte state boundary");

	d043_test_reset(ctx);
	slot0_len = d043_make_slot(slot0, 1, UINT64_MAX, 0x44, 0, 0);
	d043_test_write_object(ctx, TA_TWEP_WR_D043_OBJECT_SLOT0,
			       slot0, slot0_len);
	capture_acceptance_state(ctx, &before);
	host_io_result = seed_teep_agent_acceptance_pending(
		ctx, teep_agent_path, "hostcall_acceptance_probe_3",
		"req-d043-overflow", &host_io_result_len);
	res = d043_resume_acceptance(ctx, "req-d043-overflow",
				     host_io_result, host_io_result_len);
	free(host_io_result);
	if (res != TEEC_ERROR_GENERIC)
		errx(1, "TA D043 generation overflow returned code 0x%x", res);
	capture_acceptance_state(ctx, &after);
	require_acceptance_state_unchanged(&before, &after,
					   "generation overflow");
}

static void invoke_teep_agent_acceptance_faults(struct twep_ta_ctx *ctx,
						 const char *teep_agent_path)
{
	d043_run_precommit_fault(ctx, teep_agent_path,
		TA_TWEP_WR_D043_FAULT_SLOT_CREATE, "slot-create");
	d043_run_precommit_fault(ctx, teep_agent_path,
		TA_TWEP_WR_D043_FAULT_SLOT_WRITE, "slot-write");
	d043_run_postcommit_fault(ctx, teep_agent_path,
		TA_TWEP_WR_D043_FAULT_SLOT_AFTER_CLOSE, "slot-after-close");
	d043_run_postcommit_fault(ctx, teep_agent_path,
		TA_TWEP_WR_D043_FAULT_SLOT_REOPEN, "slot-reopen");
	d043_run_postcommit_fault(ctx, teep_agent_path,
		TA_TWEP_WR_D043_FAULT_RESULT_WRITE, "result-write");
	d043_run_continuation_alloc_fault(ctx, teep_agent_path);
	d043_run_state_fixture_matrix(ctx, teep_agent_path);
	puts("TA D043 protected-storage fault matrix ok");
}

static void invoke_teep_agent_two_session_generation(
					struct twep_ta_ctx *ctx,
					const char *teep_agent_path)
{
	struct twep_ta_ctx second;
	struct acceptance_state_snapshot after_a = { };
	struct acceptance_state_snapshot after_b = { };
	uint8_t *a_result;
	uint8_t *b_result;
	size_t a_result_len = 0;
	size_t b_result_len = 0;
	TEEC_Result res;

	d043_test_reset(ctx);
	open_ta(&second);
	a_result = seed_teep_agent_acceptance_pending(
		ctx, teep_agent_path, "hostcall_acceptance_probe_1",
		"req-d043-session-a", &a_result_len);
	b_result = seed_teep_agent_acceptance_pending(
		&second, teep_agent_path, "hostcall_acceptance_probe_stale",
		"req-d043-session-b", &b_result_len);
	res = d043_resume_acceptance(ctx, "req-d043-session-a",
				     a_result, a_result_len);
	if (res != TEEC_SUCCESS)
		errx(1, "TA D043 session A commit failed with code 0x%x", res);
	d043_require_generation(ctx, 1, "session A commit");
	capture_acceptance_state(ctx, &after_a);
	res = d043_resume_acceptance(&second, "req-d043-session-b",
				     b_result, b_result_len);
	if (res != TEEC_ERROR_GENERIC)
		errx(1, "TA D043 stale session B returned code 0x%x", res);
	capture_acceptance_state(ctx, &after_b);
	require_acceptance_state_unchanged(&after_a, &after_b,
					   "stale session B");
	res = d043_resume_acceptance(&second, "req-d043-session-b",
				     b_result, b_result_len);
	if (res == TEEC_SUCCESS)
		errx(1, "TA D043 stale session B transcript was retryable");
	free(a_result);
	free(b_result);
	invoke_teep_agent_acceptance_probe_once(
		&second, teep_agent_path, "hostcall_acceptance_probe_2",
		"req-d043-session-fresh", 2, false);
	d043_require_generation(ctx, 2, "fresh two-session commit");
	close_ta(&second);
	puts("TA D043 synchronized two-session generation ok");
}
#endif

static void invoke_teep_agent_hostcall_evidence_wasm(struct twep_ta_ctx *ctx,
						     const char *teep_agent_path)
{
	static const uint8_t evidence[] = {
		0xa1, 0x68, 'e', 'v', 'i', 'd', 'e', 'n', 'c', 'e',
		0x44, 'd', 'e', 'v', '1',
	};
	uint8_t *teep_agent_wasm = NULL;
	uint8_t *app_input = NULL;
	uint8_t *request = NULL;
	uint8_t *host_io_result = NULL;
	uint8_t *resume = NULL;
	uint8_t response[4096];
	size_t teep_agent_wasm_len = 0;
	size_t app_input_len = 0;
	size_t request_len = 0;
	size_t host_io_result_len = 0;
	size_t resume_len = 0;
	size_t response_len = 0;
	struct host_io_transcript transcript = { };
	TEEC_Result res;
	uint32_t origin = 0;

	teep_agent_wasm = read_file(teep_agent_path, &teep_agent_wasm_len);
	app_input = make_teep_hostcall_probe_input("hostcall_evidence_probe",
						  NULL, &app_input_len);
	request = make_execute_envelope("req-teep-evidence-wasm",
					"teep-agent-resolve",
					app_input, app_input_len,
					teep_agent_wasm, teep_agent_wasm_len,
					&request_len);
	res = invoke_production_raw(ctx, TA_TWEP_WR_CMD_EXECUTE, request,
				    request_len, response, sizeof(response),
				    &response_len, &origin);
	free(request);
	free(app_input);
	free(teep_agent_wasm);
	if (res != TEEC_SUCCESS)
		errx(1, "TA production teep-agent wasm evidence hostcall request failed with code 0x%x origin 0x%x",
		     res, origin);
	if (!validate_need_evidence_response(response, response_len,
					    "req-teep-evidence-wasm",
					    &transcript)) {
		fprintf(stderr, "teep-agent wasm evidence need response hex: ");
		dump_hex(stderr, response, response_len);
		fputc('\n', stderr);
		errx(1, "TA production teep-agent wasm evidence hostcall returned unexpected need_host_io response");
	}
	puts("TA production teep-agent wasm evidence hostcall requested ok");

	host_io_result = make_host_io_result_bytes_for_transcript(
		"teep-evidence-1", "create_evidence", "evidence",
		evidence, sizeof(evidence), &transcript, &host_io_result_len);
	resume = make_resume_envelope("req-teep-evidence-wasm",
				      host_io_result, host_io_result_len,
				      &resume_len);
	res = invoke_production_raw(ctx, TA_TWEP_WR_CMD_RESUME_HOST_IO,
				    resume, resume_len, response,
				    sizeof(response), &response_len, &origin);
	free(resume);
	free(host_io_result);
	if (res != TEEC_SUCCESS)
		errx(1, "TA production teep-agent wasm evidence hostcall resume failed with code 0x%x origin 0x%x",
		     res, origin);
	if (!validate_resume_final_response(response, response_len,
					    "req-teep-evidence-wasm"))
		errx(1, "TA production teep-agent wasm evidence hostcall returned unexpected final response");
	puts("TA production teep-agent wasm evidence hostcall resumed ok");
}

static void expect_teep_agent_bad_object_probe(struct twep_ta_ctx *ctx,
					       const char *teep_agent_path,
					       const char *probe_command,
					       const char *want_message,
					       const char *label)
{
	uint8_t *teep_agent_wasm = NULL;
	uint8_t *app_input = NULL;
	uint8_t *request = NULL;
	uint8_t response[4096];
	size_t teep_agent_wasm_len = 0;
	size_t app_input_len = 0;
	size_t request_len = 0;
	size_t response_len = 0;
	TEEC_Result res;
	uint32_t origin = 0;

	teep_agent_wasm = read_file(teep_agent_path, &teep_agent_wasm_len);
	app_input = make_teep_hostcall_probe_input(probe_command, NULL,
						  &app_input_len);
	request = make_execute_envelope("req-teep-bad-object",
					"teep-agent-resolve",
					app_input, app_input_len,
					teep_agent_wasm, teep_agent_wasm_len,
					&request_len);
	res = invoke_production_raw(ctx, TA_TWEP_WR_CMD_EXECUTE, request,
				    request_len, response, sizeof(response),
				    &response_len, &origin);
	free(request);
	free(app_input);
	free(teep_agent_wasm);
	if (res != TEEC_SUCCESS)
		errx(1, "TA production teep-agent bad object %s probe failed with code 0x%x origin 0x%x",
		     label, res, origin);
	if (!validate_teep_resolve_error_response(
		    response, response_len, "hostcall.bad_object_blocked",
		    want_message)) {
		fprintf(stderr, "teep-agent bad object %s response hex: ",
			label);
		dump_hex(stderr, response, response_len);
		fputc('\n', stderr);
		errx(1, "TA production teep-agent bad object %s probe returned unexpected response",
		     label);
	}
	printf("TA production teep-agent rejected bad %s object id ok\n",
	       label);
}

static void expect_d043_test_probe_rejected(struct twep_ta_ctx *ctx,
					    const char *teep_agent_path)
{
	uint8_t *teep_agent_wasm = NULL;
	uint8_t *app_input = NULL;
	uint8_t *request = NULL;
	uint8_t response[4096];
	size_t teep_agent_wasm_len = 0;
	size_t app_input_len = 0;
	size_t request_len = 0;
	size_t response_len = 0;
	TEEC_Result res;
	uint32_t origin = 0;

	teep_agent_wasm = read_file(teep_agent_path, &teep_agent_wasm_len);
	app_input = make_teep_hostcall_probe_input(
		"hostcall_acceptance_result_stale_probe", NULL,
		&app_input_len);
	request = make_execute_envelope("req-teep-d043-test-probe",
					"teep-agent-resolve",
					app_input, app_input_len,
					teep_agent_wasm, teep_agent_wasm_len,
					&request_len);
	res = invoke_production_raw(ctx, TA_TWEP_WR_CMD_EXECUTE, request,
				    request_len, response, sizeof(response),
				    &response_len, &origin);
	free(request);
	free(app_input);
	free(teep_agent_wasm);
	if (res != TEEC_ERROR_NOT_SUPPORTED)
		errx(1, "ordinary TA accepted D043 test probe with code 0x%x origin 0x%x",
		     res, origin);
	puts("TA ordinary build rejected D043 test probe ok");
}

static void invoke_teep_agent_hostcall_object_negative(
							struct twep_ta_ctx *ctx,
							const char *teep_agent_path)
{
	expect_d043_test_probe_rejected(ctx, teep_agent_path);
	expect_teep_agent_bad_object_probe(ctx, teep_agent_path,
					   "hostcall_bad_read_probe",
					   "bad read object blocked", "read");
	expect_teep_agent_bad_object_probe(ctx, teep_agent_path,
					   "hostcall_bad_write_probe",
					   "bad write object blocked", "write");
	expect_teep_agent_bad_object_probe(
		ctx, teep_agent_path, "hostcall_verified_result_write_probe",
		"generic acceptance result write blocked", "protected-result write");
	expect_secure_storage_put_rejected(ctx,
					   "verified-evidence-result.cbor");
	expect_secure_storage_put_rejected(ctx,
					   "teep-acceptance-state.cbor");
	expect_secure_storage_put_rejected(ctx,
					   "teep-acceptance-state.0.cbor");
	expect_secure_storage_put_rejected(ctx,
					   "teep-acceptance-state.1.cbor");
	puts("TA REE generic acceptance-state writes rejected ok");
	expect_secure_storage_put_rejected(ctx, "twep-catalog-state.cbor");
	expect_secure_storage_put_rejected(ctx, "twep-catalog-state.0.cbor");
	expect_secure_storage_put_rejected(ctx, "twep-catalog-state.1.cbor");
	expect_secure_storage_get_rejected(ctx, "twep-catalog-state.cbor", 64);
	expect_secure_storage_get_rejected(ctx, "twep-catalog-state.0.cbor", 64);
	expect_secure_storage_get_rejected(ctx, "twep-catalog-state.1.cbor", 64);
	expect_secure_storage_get_rejected(ctx, "twep-catalog-state.cbor", 1);
	expect_secure_storage_get_rejected(ctx, "twep-catalog-state.0.cbor", 1);
	expect_secure_storage_get_rejected(ctx, "twep-catalog-state.1.cbor", 1);
	puts("TA REE generic catalog-state reads and writes rejected ok");
	puts("TA production teep-agent hostcall object negative ok");
}

static uint8_t *read_file(const char *path, size_t *out_len)
{
	FILE *fp;
	long len;
	uint8_t *buf;

	fp = fopen(path, "rb");
	if (!fp)
		err(1, "open %s", path);
	if (fseek(fp, 0, SEEK_END) != 0)
		err(1, "seek %s", path);
	len = ftell(fp);
	if (len < 0)
		err(1, "tell %s", path);
	if (fseek(fp, 0, SEEK_SET) != 0)
		err(1, "rewind %s", path);

	buf = malloc(len == 0 ? 1 : (size_t)len);
	if (!buf)
		err(1, "allocate %s", path);
	if (len != 0 && fread(buf, 1, (size_t)len, fp) != (size_t)len)
		err(1, "read %s", path);
	if (fclose(fp) != 0)
		err(1, "close %s", path);
	*out_len = (size_t)len;
	return buf;
}

static uint8_t hex_nibble(uint8_t ch, const char *name)
{
	if (ch >= '0' && ch <= '9')
		return ch - '0';
	if (ch >= 'a' && ch <= 'f')
		return (uint8_t)(ch - 'a' + 10);
	errx(1, "ABI vector %s contains non-lowercase-hex byte 0x%02x",
	     name, ch);
}

static uint8_t *read_named_abi_vector(const uint8_t *file, size_t file_len,
				      const char *name, size_t *out_len)
{
	size_t name_len = strlen(name);
	size_t line = 0;

	while (line < file_len) {
		size_t end = line;
		size_t hex_start;
		size_t hex_len;
		uint8_t *bytes;
		size_t i;

		while (end < file_len && file[end] != '\n')
			end++;
		if (end > line && file[end - 1] == '\r')
			end--;
		if (end > line && file[line] != '#' &&
		    end - line > name_len && file[line + name_len] == '|' &&
		    memcmp(file + line, name, name_len) == 0) {
			hex_start = line + name_len + 1;
			hex_len = end - hex_start;
			if (hex_len == 0 || (hex_len & 1) != 0)
				errx(1, "ABI vector %s has invalid hex length", name);
			bytes = malloc(hex_len / 2);
			if (!bytes)
				err(1, "allocate ABI vector %s", name);
			for (i = 0; i < hex_len; i += 2) {
				bytes[i / 2] =
					(uint8_t)(hex_nibble(file[hex_start + i], name) << 4) |
					hex_nibble(file[hex_start + i + 1], name);
			}
			*out_len = hex_len / 2;
			return bytes;
		}
		line = end < file_len ? end + 1 : file_len;
	}
	errx(1, "ABI vector %s not found", name);
}

static void invoke_abi_vectors(struct twep_ta_ctx *ctx, const char *path)
{
	static const char *const names[] = {
		"public-request",
		"public-response",
		"agent-resolve-request",
		"agent-resolve-response",
		"trustzone-execute-envelope",
		"trustzone-resume-envelope",
	};
	uint8_t *file;
	uint8_t *execute = NULL;
	uint8_t *resume = NULL;
	uint8_t response[128];
	size_t file_len = 0;
	size_t execute_len = 0;
	size_t resume_len = 0;
	size_t response_len = 0;
	uint32_t origin = 0;
	TEEC_Result res;
	size_t i;

	file = read_file(path, &file_len);
	for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
		uint8_t *vector;
		size_t vector_len = 0;

		vector = read_named_abi_vector(file, file_len, names[i],
					       &vector_len);
		if (vector_len == 0)
			errx(1, "ABI vector %s is empty", names[i]);
		free(vector);
	}
	execute = read_named_abi_vector(file, file_len,
					"trustzone-execute-envelope",
					&execute_len);
	resume = read_named_abi_vector(file, file_len,
				       "trustzone-resume-envelope", &resume_len);

	expect_production_success(ctx, TA_TWEP_WR_CMD_EXECUTE,
				  "canonical vector execute", execute,
				  execute_len);
	res = invoke_production_raw(ctx, TA_TWEP_WR_CMD_RESUME_HOST_IO,
				    resume, resume_len, response,
				    sizeof(response), &response_len, &origin);
	if (res != TEEC_ERROR_BAD_FORMAT)
		errx(1, "canonical resume vector without pending request returned code 0x%x origin 0x%x",
		     res, origin);

	free(resume);
	free(execute);
	free(file);
	puts("TA canonical ABI vectors parsed from shared bytes ok");
}

static void invoke_provision(struct twep_ta_ctx *ctx, const char *name,
			     const char *path)
{
	uint8_t *bytes;
	size_t bytes_len;

	bytes = read_file(path, &bytes_len);
	if (bytes_len == 0)
		errx(1, "refusing to provision empty object %s", name);
	secure_storage_put(ctx, name, bytes, bytes_len);
	free(bytes);
	printf("provisioned %s from %s\n", name, path);
}

static void invoke_read_object(struct twep_ta_ctx *ctx, const char *name)
{
	uint8_t buf[65536];
	size_t read_len = 0;

	memset(buf, 0, sizeof(buf));
	secure_storage_get(ctx, name, buf, sizeof(buf), &read_len);
	if (read_len != 0 && fwrite(buf, 1, read_len, stdout) != read_len)
		err(1, "write stdout");
}

static void invoke_read_object_small(struct twep_ta_ctx *ctx, const char *name)
{
	uint8_t buf[8];
	size_t read_len = 0;

	memset(buf, 0, sizeof(buf));
	secure_storage_get(ctx, name, buf, sizeof(buf), &read_len);
	if (read_len != 0 && fwrite(buf, 1, read_len, stdout) != read_len)
		err(1, "write stdout");
}

static void usage(const char *argv0)
{
	fprintf(stderr,
		"usage: %s [smoke|status|random-time|cbor-dry-run|abi-vectors <vectors.hex>|execute-abi-negative|execute-helloworld <helloworld.wasm>|execute-calcadd <calcadd.wasm>|execute-negaposi <negaposi.wasm> <input.jpg>|execute-hostcall-negative <env-import.wasm> <teep-env-import.wasm>|execute-cleanup-negative <helloworld.wasm> <nonzero-status.wasm> <trap.wasm> <oversized-output.wasm>|execute-catalog-resource-negative <teep-agent.wasm> <catalog.cbor> <negaposi.wasm> <input.jpg>|teep-agent-resolve <teep-agent.wasm> <catalog.cbor> <helloworld.wasm>|teep-agent-resolve-hash-negative <teep-agent.wasm> <catalog.cbor> <helloworld.wasm>|teep-agent-resolve-catalog-negative <teep-agent.wasm> <catalog.cbor> <helloworld.wasm>|teep-agent-resolve-wrapped-error-negative <teep-agent.wasm> <catalog.cbor> <helloworld.wasm>|host-io-resume|host-io-resume-negative|teep-agent-hostcall-http|teep-agent-hostcall-evidence|teep-agent-transcript-limits|teep-agent-hostcall-http-wasm <teep-agent.wasm>|teep-agent-hostcall-evidence-wasm <teep-agent.wasm>|teep-agent-acceptance-probe <teep-agent.wasm>|teep-agent-hostcall-object-negative <teep-agent.wasm>|wamr-spike <helloworld.wasm>|wamr-spike-expect-reject <unsupported.wasm>|wamr-spike-input-negative <helloworld.wasm>|wamr-spike-output-negative <helloworld.wasm> <oversized-output.wasm>|wamr-spike-cleanup-negative <helloworld.wasm> <nonzero-status.wasm> <trap.wasm>|provision <object> <file>|read <object>|read-small <object>]\n",
		argv0);
#ifdef TWEP_TA_D043_TEST_HOOKS
	fprintf(stderr,
		"test-only: %s [teep-agent-acceptance-faults <teep-agent.wasm>|teep-agent-two-session-generation <teep-agent.wasm>|d047-catalog-transactions|d047-catalog-live-readback]\n",
		argv0);
#endif
}

int main(int argc, char *argv[])
{
	struct twep_ta_ctx ctx;

	open_ta(&ctx);

	if (argc == 1 || strcmp(argv[1], "smoke") == 0) {
		invoke_ping(&ctx);
		invoke_platform_status(&ctx);
		invoke_secure_storage_smoke(&ctx);
		invoke_random_smoke(&ctx);
		invoke_time_smoke(&ctx);
		invoke_cbor_dry_run_smoke(&ctx);
		puts("twep-wr-ta smoke ok");
	} else if (argc == 2 && strcmp(argv[1], "status") == 0) {
		invoke_platform_status(&ctx);
	} else if (argc == 2 && strcmp(argv[1], "random-time") == 0) {
		invoke_random_smoke(&ctx);
		invoke_time_smoke(&ctx);
	} else if (argc == 2 && strcmp(argv[1], "cbor-dry-run") == 0) {
		invoke_cbor_dry_run_smoke(&ctx);
	} else if (argc == 3 && strcmp(argv[1], "abi-vectors") == 0) {
		invoke_abi_vectors(&ctx, argv[2]);
	} else if (argc == 2 && strcmp(argv[1], "execute-abi-negative") == 0) {
		invoke_execute_abi_negative(&ctx);
	} else if (argc == 3 && strcmp(argv[1], "execute-helloworld") == 0) {
		invoke_execute_helloworld(&ctx, argv[2]);
	} else if (argc == 3 && strcmp(argv[1], "execute-calcadd") == 0) {
		invoke_execute_calcadd(&ctx, argv[2]);
	} else if (argc == 4 && strcmp(argv[1], "execute-negaposi") == 0) {
		invoke_execute_negaposi(&ctx, argv[2], argv[3]);
	} else if (argc == 4 &&
		   strcmp(argv[1], "execute-hostcall-negative") == 0) {
		invoke_execute_hostcall_negative(&ctx, argv[2], argv[3]);
	} else if (argc == 6 &&
		   strcmp(argv[1], "execute-cleanup-negative") == 0) {
		invoke_execute_cleanup_negative(&ctx, argv[2], argv[3],
						argv[4], argv[5]);
	} else if (argc == 6 &&
		   strcmp(argv[1], "execute-catalog-resource-negative") == 0) {
		invoke_execute_catalog_resource_negative(&ctx, argv[2],
							 argv[3], argv[4],
							 argv[5]);
	} else if (argc == 5 && strcmp(argv[1], "teep-agent-resolve") == 0) {
		invoke_teep_agent_resolve(&ctx, argv[2], argv[3], argv[4]);
	} else if (argc == 5 &&
		   strcmp(argv[1], "teep-agent-resolve-hash-negative") == 0) {
		invoke_teep_agent_resolve_hash_negative(&ctx, argv[2], argv[3],
							argv[4]);
	} else if (argc == 5 &&
		   strcmp(argv[1], "teep-agent-resolve-catalog-negative") == 0) {
		invoke_teep_agent_resolve_catalog_negative(&ctx, argv[2],
							   argv[3],
							   argv[4]);
	} else if (argc == 5 &&
		   strcmp(argv[1],
			  "teep-agent-resolve-wrapped-error-negative") == 0) {
		invoke_teep_agent_resolve_wrapped_error_negative(
			&ctx, argv[2], argv[3], argv[4]);
	} else if (argc == 2 && strcmp(argv[1], "host-io-resume") == 0) {
		invoke_host_io_resume(&ctx);
	} else if (argc == 2 && strcmp(argv[1], "host-io-resume-negative") == 0) {
		invoke_host_io_resume_negative(&ctx);
	} else if (argc == 2 && strcmp(argv[1], "teep-agent-hostcall-http") == 0) {
		invoke_teep_agent_hostcall_http(&ctx);
	} else if (argc == 2 &&
		   strcmp(argv[1], "teep-agent-hostcall-evidence") == 0) {
		invoke_teep_agent_hostcall_evidence(&ctx);
	} else if (argc == 2 &&
		   strcmp(argv[1], "teep-agent-transcript-limits") == 0) {
		invoke_teep_agent_transcript_limits(&ctx);
	} else if (argc == 3 &&
		   strcmp(argv[1], "teep-agent-hostcall-http-wasm") == 0) {
		invoke_teep_agent_hostcall_http_wasm(&ctx, argv[2]);
	} else if (argc == 3 &&
		   strcmp(argv[1], "teep-agent-hostcall-evidence-wasm") == 0) {
		invoke_teep_agent_hostcall_evidence_wasm(&ctx, argv[2]);
	} else if (argc == 3 &&
		   strcmp(argv[1], "teep-agent-acceptance-probe") == 0) {
		invoke_teep_agent_acceptance_probe(&ctx, argv[2]);
		invoke_teep_agent_acceptance_negatives(&ctx, argv[2]);
		verify_teep_agent_acceptance_result_mirror(&ctx);
#ifdef TWEP_TA_D043_TEST_HOOKS
	} else if (argc == 3 &&
		   strcmp(argv[1], "teep-agent-acceptance-faults") == 0) {
		invoke_teep_agent_acceptance_faults(&ctx, argv[2]);
	} else if (argc == 3 &&
		   strcmp(argv[1], "teep-agent-two-session-generation") == 0) {
		invoke_teep_agent_two_session_generation(&ctx, argv[2]);
	} else if (argc == 2 &&
		   strcmp(argv[1], "d047-catalog-transactions") == 0) {
		invoke_d047_catalog_transactions(&ctx);
	} else if (argc == 2 &&
		   strcmp(argv[1], "d047-catalog-live-readback") == 0) {
		invoke_d047_catalog_live_readback(&ctx);
#endif
	} else if (argc == 3 &&
		   strcmp(argv[1], "teep-agent-hostcall-object-negative") == 0) {
		invoke_teep_agent_hostcall_object_negative(&ctx, argv[2]);
	} else if (argc == 3 && strcmp(argv[1], "wamr-spike") == 0) {
		invoke_wamr_spike(&ctx, argv[2]);
	} else if (argc == 3 && strcmp(argv[1], "wamr-spike-expect-reject") == 0) {
		invoke_wamr_spike_expect_reject(&ctx, argv[2]);
	} else if (argc == 3 && strcmp(argv[1], "wamr-spike-input-negative") == 0) {
		invoke_wamr_spike_input_negative(&ctx, argv[2]);
	} else if (argc == 4 && strcmp(argv[1], "wamr-spike-output-negative") == 0) {
		invoke_wamr_spike_output_negative(&ctx, argv[2], argv[3]);
	} else if (argc == 5 && strcmp(argv[1], "wamr-spike-cleanup-negative") == 0) {
		invoke_wamr_spike_cleanup_negative(&ctx, argv[2], argv[3], argv[4]);
	} else if (argc == 4 && strcmp(argv[1], "provision") == 0) {
		invoke_provision(&ctx, argv[2], argv[3]);
	} else if (argc == 3 && strcmp(argv[1], "read") == 0) {
		invoke_read_object(&ctx, argv[2]);
	} else if (argc == 3 && strcmp(argv[1], "read-small") == 0) {
		invoke_read_object_small(&ctx, argv[2]);
	} else {
		usage(argv[0]);
		close_ta(&ctx);
		return 2;
	}

	close_ta(&ctx);

	return 0;
}
