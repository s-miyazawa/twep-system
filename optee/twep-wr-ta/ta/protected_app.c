/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */

#include <limits.h>
#include <stdbool.h>
#include <string.h>

#include <tee_internal_api.h>

#include "acceptance_state.h"
#include "protected_app.h"

#define APP_RECORD_HEADER_SIZE 68
#define APP_RECORD_MAX_SIZE (TWEP_PROTECTED_APP_MAX_SIZE + 512)

static const uint8_t app_record_magic[8] = { 'T', 'W', 'E', 'P', 'A', 'P', 'P', 1 };
static const char app_slot0_id[] = "twep-app-state.0.bin";
static const char app_slot1_id[] = "twep-app-state.1.bin";
static const uint8_t app_component_tag[] = "twep-app-v1";

struct app_state {
	uint8_t *raw;
	size_t raw_len;
	uint64_t acceptance_generation;
	uint64_t sequence;
	const uint8_t *component_id;
	size_t component_id_len;
	const uint8_t *digest;
	const uint8_t *wasm;
	size_t wasm_len;
	int slot;
};

static uint32_t read_be32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | p[3];
}

static uint64_t read_be64(const uint8_t *p)
{
	uint64_t value = 0;
	int i;

	for (i = 0; i < 8; i++)
		value = (value << 8) | p[i];
	return value;
}

static void write_be32(uint8_t *p, uint32_t value)
{
	p[0] = (uint8_t)(value >> 24);
	p[1] = (uint8_t)(value >> 16);
	p[2] = (uint8_t)(value >> 8);
	p[3] = (uint8_t)value;
}

static void write_be64(uint8_t *p, uint64_t value)
{
	int i;

	for (i = 7; i >= 0; i--) {
		p[i] = (uint8_t)value;
		value >>= 8;
	}
}

static TEE_Result app_sha256(const uint8_t *bytes, size_t len, uint8_t out[32])
{
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	uint32_t out_len = 32;
	TEE_Result res;

	if (!bytes || !len || len > UINT32_MAX)
		return TEE_ERROR_BAD_PARAMETERS;
	res = TEE_AllocateOperation(&op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
	if (res == TEE_SUCCESS)
		res = TEE_DigestDoFinal(op, bytes, (uint32_t)len, out, &out_len);
	if (op != TEE_HANDLE_NULL)
		TEE_FreeOperation(op);
	if (res == TEE_SUCCESS && out_len != 32)
		return TEE_ERROR_GENERIC;
	return res;
}

bool twep_app_component_id_is_valid(const uint8_t *id, size_t len)
{
	size_t tag_len = sizeof(app_component_tag) - 1;
	size_t command_len;
	size_t off;

	/* Canonical CBOR: [h'twep-app-v1', h'<non-empty command>']. */
	if (!id || len < 2 + tag_len + 2 || id[0] != 0x82 ||
	    id[1] != (uint8_t)(0x40 + tag_len) ||
	    TEE_MemCompare(id + 2, app_component_tag, tag_len) != 0)
		return false;
	off = 2 + tag_len;
	if (id[off] >= 0x41 && id[off] <= 0x57) {
		command_len = id[off] - 0x40;
		off++;
	} else if (id[off] == 0x58 && off + 1 < len && id[off + 1] >= 24) {
		command_len = id[off + 1];
		off += 2;
	} else {
		return false;
	}
	if (!command_len || off + command_len != len)
		return false;
	for (; off < len; off++) {
		if (id[off] == 0)
			return false;
	}
	return true;
}

static void app_state_release(struct app_state *state)
{
	if (state->raw)
		TEE_Free(state->raw);
	TEE_MemFill(state, 0, sizeof(*state));
}

static TEE_Result parse_app_record(struct app_state *state)
{
	uint32_t component_len;
	uint32_t wasm_len;
	uint8_t computed[32];

	if (!state->raw || state->raw_len < APP_RECORD_HEADER_SIZE ||
	    TEE_MemCompare(state->raw, app_record_magic,
			   sizeof(app_record_magic)) != 0)
		return TEE_ERROR_BAD_FORMAT;
	state->acceptance_generation = read_be64(state->raw + 8);
	state->sequence = read_be64(state->raw + 16);
	component_len = read_be32(state->raw + 24);
	wasm_len = read_be32(state->raw + 28);
	if (!state->acceptance_generation || !state->sequence || !component_len ||
	    !wasm_len || wasm_len > TWEP_PROTECTED_APP_MAX_SIZE ||
	    APP_RECORD_HEADER_SIZE + (size_t)component_len + wasm_len !=
		    state->raw_len)
		return TEE_ERROR_BAD_FORMAT;
	state->digest = state->raw + 32;
	state->component_id = state->raw + APP_RECORD_HEADER_SIZE;
	state->component_id_len = component_len;
	state->wasm = state->component_id + component_len;
	state->wasm_len = wasm_len;
	if (!twep_app_component_id_is_valid(state->component_id,
					    state->component_id_len) ||
	    app_sha256(state->wasm, state->wasm_len, computed) != TEE_SUCCESS ||
	    TEE_MemCompare(computed, state->digest, 32) != 0)
		return TEE_ERROR_SECURITY;
	return TEE_SUCCESS;
}

static TEE_Result read_app_slot(int slot, struct app_state *state)
{
	const char *id = slot ? app_slot1_id : app_slot0_id;
	TEE_ObjectHandle object = TEE_HANDLE_NULL;
	TEE_ObjectInfo info = { };
	uint32_t read_len = 0;
	TEE_Result res;

	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, id, strlen(id),
				       TEE_DATA_FLAG_ACCESS_READ |
				       TEE_DATA_FLAG_SHARE_READ, &object);
	if (res != TEE_SUCCESS)
		return res;
	res = TEE_GetObjectInfo1(object, &info);
	if (res != TEE_SUCCESS)
		goto out;
	if (!info.dataSize || info.dataSize > APP_RECORD_MAX_SIZE) {
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}
	state->raw = TEE_Malloc(info.dataSize, 0);
	if (!state->raw) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	res = TEE_ReadObjectData(object, state->raw, info.dataSize, &read_len);
	if (res == TEE_SUCCESS && read_len != info.dataSize)
		res = TEE_ERROR_CORRUPT_OBJECT;
	if (res == TEE_SUCCESS) {
		state->raw_len = read_len;
		state->slot = slot;
		res = parse_app_record(state);
	}
out:
	TEE_CloseObject(object);
	return res;
}

static bool app_records_agree(const struct app_state *a,
			      const struct app_state *b)
{
	return a->raw_len == b->raw_len &&
	       TEE_MemCompare(a->raw, b->raw, a->raw_len) == 0;
}

static TEE_Result load_active_app(struct app_state *active)
{
	struct app_state slots[2] = { };
	bool present = false;
	int selected = -1;
	int i;
	TEE_Result res = TEE_ERROR_ITEM_NOT_FOUND;

	for (i = 0; i < 2; i++) {
		uint64_t generation = 0;
		uint64_t sequence = 0;

		res = read_app_slot(i, &slots[i]);
		if (res == TEE_ERROR_ITEM_NOT_FOUND)
			continue;
		present = true;
		if (res == TEE_ERROR_BAD_FORMAT || res == TEE_ERROR_CORRUPT_OBJECT ||
		    res == TEE_ERROR_SECURITY)
			continue;
		if (res != TEE_SUCCESS)
			goto out;
		res = twep_acceptance_component_sequence(
			slots[i].component_id, slots[i].component_id_len,
			&generation, &sequence);
		if (res == TEE_SUCCESS && sequence == slots[i].sequence &&
		    generation >= slots[i].acceptance_generation &&
		    (selected < 0 || slots[i].acceptance_generation >
				     slots[selected].acceptance_generation))
			selected = i;
		else if (res != TEE_SUCCESS && res != TEE_ERROR_ITEM_NOT_FOUND)
			goto out;
	}
	if (selected < 0) {
		res = present ? TEE_ERROR_CORRUPT_OBJECT : TEE_ERROR_ITEM_NOT_FOUND;
		goto out;
	}
	if (slots[1 - selected].raw &&
	    slots[1 - selected].acceptance_generation ==
		    slots[selected].acceptance_generation &&
	    !app_records_agree(&slots[0], &slots[1])) {
		res = TEE_ERROR_SECURITY;
		goto out;
	}
	*active = slots[selected];
	TEE_MemFill(&slots[selected], 0, sizeof(slots[selected]));
	res = TEE_SUCCESS;
out:
	for (i = 0; i < 2; i++)
		app_state_release(&slots[i]);
	return res;
}

static TEE_Result write_app_slot(int slot, const uint8_t *record,
				 size_t record_len)
{
	const char *id = slot ? app_slot1_id : app_slot0_id;
	TEE_ObjectHandle object = TEE_HANDLE_NULL;
	uint32_t flags = TEE_DATA_FLAG_ACCESS_READ |
		TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_ACCESS_WRITE_META |
		TEE_DATA_FLAG_OVERWRITE;
	TEE_Result res;

	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, id, strlen(id),
					 flags, TEE_HANDLE_NULL, NULL, 0, &object);
	if (res == TEE_SUCCESS)
		res = TEE_WriteObjectData(object, record, record_len);
	if (res != TEE_SUCCESS && object != TEE_HANDLE_NULL)
		TEE_CloseAndDeletePersistentObject1(object);
	else if (object != TEE_HANDLE_NULL)
		TEE_CloseObject(object);
	return res;
}

TEE_Result twep_app_commit(const uint8_t query_response_sha256[32],
			   const uint8_t *component_id,
			   size_t component_id_len, uint64_t sequence,
			   uint64_t expected_generation, const uint8_t *wasm,
			   size_t wasm_len, const uint8_t wasm_sha256[32],
			   uint64_t *new_generation)
{
	struct app_state active = { };
	struct app_state verify = { };
	uint8_t computed[32];
	uint8_t *record = NULL;
	size_t record_len;
	uint64_t current_generation = 0;
	uint64_t prior_sequence = 0;
	int target_slot = 0;
	TEE_Result res;

	if (!query_response_sha256 ||
	    !twep_app_component_id_is_valid(component_id, component_id_len) ||
	    !sequence || !wasm || !wasm_len ||
	    wasm_len > TWEP_PROTECTED_APP_MAX_SIZE || !wasm_sha256 ||
	    !new_generation || expected_generation == UINT64_MAX ||
	    component_id_len > UINT32_MAX || wasm_len > UINT32_MAX)
		return TEE_ERROR_BAD_PARAMETERS;
	res = app_sha256(wasm, wasm_len, computed);
	if (res != TEE_SUCCESS)
		return res;
	if (TEE_MemCompare(computed, wasm_sha256, 32) != 0)
		return TEE_ERROR_SECURITY;
	res = twep_acceptance_generation(&current_generation);
	if (res != TEE_SUCCESS)
		return res;
	if (current_generation != expected_generation)
		return TEE_ERROR_ACCESS_CONFLICT;
	res = twep_acceptance_component_sequence(component_id, component_id_len,
					 &current_generation, &prior_sequence);
	if (res == TEE_SUCCESS && sequence <= prior_sequence)
		return TEE_ERROR_ACCESS_CONFLICT;
	if (res != TEE_SUCCESS && res != TEE_ERROR_ITEM_NOT_FOUND)
		return res;
	res = load_active_app(&active);
	if (res == TEE_SUCCESS)
		target_slot = active.slot == 0 ? 1 : 0;
	else if (res != TEE_ERROR_ITEM_NOT_FOUND &&
		 res != TEE_ERROR_CORRUPT_OBJECT)
		goto out;
	record_len = APP_RECORD_HEADER_SIZE + component_id_len + wasm_len;
	record = TEE_Malloc(record_len, 0);
	if (!record) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	TEE_MemMove(record, app_record_magic, sizeof(app_record_magic));
	write_be64(record + 8, expected_generation + 1);
	write_be64(record + 16, sequence);
	write_be32(record + 24, (uint32_t)component_id_len);
	write_be32(record + 28, (uint32_t)wasm_len);
	TEE_MemMove(record + 32, computed, 32);
	TEE_MemMove(record + APP_RECORD_HEADER_SIZE, component_id,
		    component_id_len);
	TEE_MemMove(record + APP_RECORD_HEADER_SIZE + component_id_len, wasm,
		    wasm_len);
	res = write_app_slot(target_slot, record, record_len);
	if (res != TEE_SUCCESS)
		goto out;
	res = read_app_slot(target_slot, &verify);
	if (res != TEE_SUCCESS || verify.raw_len != record_len ||
	    TEE_MemCompare(verify.raw, record, record_len) != 0) {
		res = TEE_ERROR_CORRUPT_OBJECT;
		goto out;
	}
	res = twep_acceptance_commit(query_response_sha256, component_id,
				     component_id_len, sequence,
				     expected_generation, new_generation);
out:
	if (record)
		TEE_Free(record);
	app_state_release(&active);
	app_state_release(&verify);
	return res;
}

TEE_Result twep_app_read_active(uint8_t *wasm, size_t wasm_cap,
				size_t *wasm_len, uint8_t wasm_sha256[32])
{
	struct app_state active = { };
	TEE_Result res;

	if (!wasm_len)
		return TEE_ERROR_BAD_PARAMETERS;
	res = load_active_app(&active);
	if (res != TEE_SUCCESS)
		return res;
	*wasm_len = active.wasm_len;
	if (active.wasm_len > wasm_cap) {
		res = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}
	if (!wasm) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}
	TEE_MemMove(wasm, active.wasm, active.wasm_len);
	if (wasm_sha256)
		TEE_MemMove(wasm_sha256, active.digest, 32);
out:
	app_state_release(&active);
	return res;
}
