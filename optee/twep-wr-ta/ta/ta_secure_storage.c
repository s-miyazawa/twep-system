/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
// SPDX-License-Identifier: BSD-2-Clause

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <tee_internal_api.h>

#include "ta_internal.h"

static bool object_name_eq(const char *ptr, uint32_t len, const char *want)
{
	size_t want_len = strlen(want);

	return ptr && len == want_len &&
	       TEE_MemCompare(ptr, want, want_len) == 0;
}

bool twep_ta_d047_object_name_reserved(const char *name, uint32_t name_len)
{
	static const char *const reserved[] = {
		"twep-catalog-state.cbor",
		"twep-catalog-state.0.cbor",
		"twep-catalog-state.1.cbor",
		"teep-agent/twep-catalog-state.cbor",
		"teep-agent/twep-catalog-state.0.cbor",
		"teep-agent/twep-catalog-state.1.cbor",
	};
	size_t i = 0;

	if (!name)
		return false;
	for (i = 0; i < sizeof(reserved) / sizeof(reserved[0]); i++) {
		size_t len = strlen(reserved[i]);

		if (name_len == len &&
		    TEE_MemCompare(name, reserved[i], len) == 0)
			return true;
	}
	return false;
}

TEE_Result twep_ta_cmd_measure_wasm(uint32_t param_types,
				   TEE_Param params[4])
{
	const uint32_t expected = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						 TEE_PARAM_TYPE_MEMREF_OUTPUT,
						 TEE_PARAM_TYPE_NONE,
						 TEE_PARAM_TYPE_NONE);
	uint8_t digest[32] = { 0 };
	TEE_Result res = TEE_SUCCESS;

	if (param_types != expected)
		return TEE_ERROR_BAD_PARAMETERS;
	if (params[0].memref.size == 0)
		return TEE_ERROR_BAD_PARAMETERS;
	if (params[1].memref.size < sizeof(digest)) {
		params[1].memref.size = sizeof(digest);
		return TEE_ERROR_SHORT_BUFFER;
	}

	res = twep_ta_sha256_bytes(params[0].memref.buffer, params[0].memref.size,
			   digest);
	if (res != TEE_SUCCESS)
		return res;
	TEE_MemMove(params[1].memref.buffer, digest, sizeof(digest));
	params[1].memref.size = sizeof(digest);
	IMSG("twep-wr-ta measure wasm");
	return TEE_SUCCESS;
}

TEE_Result twep_ta_cmd_secure_storage_put(uint32_t param_types,
					 TEE_Param params[4])
{
	const uint32_t expected = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						 TEE_PARAM_TYPE_MEMREF_INPUT,
						 TEE_PARAM_TYPE_NONE,
						 TEE_PARAM_TYPE_NONE);
	TEE_ObjectHandle object = TEE_HANDLE_NULL;
	void *object_id = NULL;
	void *data = NULL;
	uint32_t flags = TEE_DATA_FLAG_ACCESS_READ |
			 TEE_DATA_FLAG_ACCESS_WRITE |
			 TEE_DATA_FLAG_ACCESS_WRITE_META |
			 TEE_DATA_FLAG_OVERWRITE;
	TEE_Result res;

	if (param_types != expected)
		return TEE_ERROR_BAD_PARAMETERS;
	if (params[0].memref.size == 0 || params[1].memref.size == 0)
		return TEE_ERROR_BAD_PARAMETERS;
	if (object_name_eq(params[0].memref.buffer, params[0].memref.size,
			   "verified-evidence-result.cbor") ||
	    object_name_eq(params[0].memref.buffer, params[0].memref.size,
			   "teep-acceptance-state.cbor") ||
	    object_name_eq(params[0].memref.buffer, params[0].memref.size,
			   "teep-acceptance-state.0.cbor") ||
	    object_name_eq(params[0].memref.buffer, params[0].memref.size,
			   "teep-acceptance-state.1.cbor") ||
	    twep_ta_d047_object_name_reserved(params[0].memref.buffer,
				       params[0].memref.size)) {
		IMSG("twep-wr-ta generic secure storage acceptance-state write rejected");
		return TEE_ERROR_ACCESS_DENIED;
	}

	object_id = TEE_Malloc(params[0].memref.size, 0);
	if (!object_id)
		return TEE_ERROR_OUT_OF_MEMORY;
	TEE_MemMove(object_id, params[0].memref.buffer, params[0].memref.size);

	data = TEE_Malloc(params[1].memref.size, 0);
	if (!data) {
		TEE_Free(object_id);
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	TEE_MemMove(data, params[1].memref.buffer, params[1].memref.size);

	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
					 object_id,
					 params[0].memref.size,
					 flags, TEE_HANDLE_NULL, NULL, 0,
					 &object);
	if (res != TEE_SUCCESS) {
		EMSG("twep-wr-ta secure storage create failed 0x%08x", res);
		TEE_Free(object_id);
		TEE_Free(data);
		return res;
	}

	res = TEE_WriteObjectData(object, data, params[1].memref.size);
	if (res != TEE_SUCCESS) {
		EMSG("twep-wr-ta secure storage write failed 0x%08x", res);
		TEE_CloseAndDeletePersistentObject1(object);
		TEE_Free(object_id);
		TEE_Free(data);
		return res;
	}

	TEE_CloseObject(object);
	TEE_Free(object_id);
	TEE_Free(data);
	IMSG("twep-wr-ta secure storage put");
	return TEE_SUCCESS;
}

TEE_Result twep_ta_cmd_secure_storage_get(uint32_t param_types,
					 TEE_Param params[4])
{
	const uint32_t expected = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						 TEE_PARAM_TYPE_MEMREF_OUTPUT,
						 TEE_PARAM_TYPE_NONE,
						 TEE_PARAM_TYPE_NONE);
	TEE_ObjectHandle object = TEE_HANDLE_NULL;
	TEE_ObjectInfo object_info = { };
	void *object_id = NULL;
	void *data = NULL;
	uint32_t read_bytes = 0;
	TEE_Result res;

	if (param_types != expected)
		return TEE_ERROR_BAD_PARAMETERS;
	if (params[0].memref.size == 0)
		return TEE_ERROR_BAD_PARAMETERS;
	if (twep_ta_d047_object_name_reserved(params[0].memref.buffer,
				       params[0].memref.size)) {
		IMSG("twep-wr-ta generic secure storage catalog-state read rejected");
		return TEE_ERROR_ACCESS_DENIED;
	}

	object_id = TEE_Malloc(params[0].memref.size, 0);
	if (!object_id)
		return TEE_ERROR_OUT_OF_MEMORY;
	TEE_MemMove(object_id, params[0].memref.buffer, params[0].memref.size);

	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
				       object_id,
				       params[0].memref.size,
				       TEE_DATA_FLAG_ACCESS_READ |
				       TEE_DATA_FLAG_SHARE_READ,
				       &object);
	if (res != TEE_SUCCESS) {
		EMSG("twep-wr-ta secure storage open failed 0x%08x", res);
		TEE_Free(object_id);
		return res;
	}

	res = TEE_GetObjectInfo1(object, &object_info);
	if (res != TEE_SUCCESS)
		goto out;

	if (params[1].memref.size < object_info.dataSize) {
		params[1].memref.size = object_info.dataSize;
		res = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}

	data = TEE_Malloc(object_info.dataSize, 0);
	if (!data) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	res = TEE_ReadObjectData(object, data, object_info.dataSize,
				 &read_bytes);
	if (res != TEE_SUCCESS)
		goto out;
	if (read_bytes != object_info.dataSize) {
		res = TEE_ERROR_CORRUPT_OBJECT;
		goto out;
	}

	TEE_MemMove(params[1].memref.buffer, data, read_bytes);
	params[1].memref.size = read_bytes;
	IMSG("twep-wr-ta secure storage get");

out:
	TEE_CloseObject(object);
	TEE_Free(object_id);
	if (data)
		TEE_Free(data);
	return res;
}
