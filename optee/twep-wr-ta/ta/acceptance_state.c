/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */
#include <limits.h>
#include <stdbool.h>
#include <string.h>

#include <tee_internal_api.h>

#include "acceptance_state.h"
#include "twep_wr_ta.h"

#define ACCEPTANCE_STATE_MAX_SIZE 4096
#define ACCEPTANCE_STATE_MAX_COMPONENTS 32
#define CATALOG_STATE_MAX_PAYLOAD 65536
#define CATALOG_STATE_MAX_RECORD (CATALOG_STATE_MAX_PAYLOAD + 512)

static const char slot0_id[] = "teep-acceptance-state.0.cbor";
static const char slot1_id[] = "teep-acceptance-state.1.cbor";
static const char legacy_id[] = "protected-sequence-freshness.cbor";
static const char catalog_slot0_id[] = "twep-catalog-state.0.cbor";
static const char catalog_slot1_id[] = "twep-catalog-state.1.cbor";
static const uint8_t default_catalog_component_id[] = {
	0x82, 0x4f, 't', 'w', 'e', 'p', '-', 'c', 'a', 't', 'a', 'l', 'o', 'g',
	'-', 'v', '1', 0x47, 'd', 'e', 'f', 'a', 'u', 'l', 't'
};

#ifdef TWEP_TA_D043_TEST_HOOKS
static uint32_t test_fault;

static bool take_test_fault(uint32_t fault)
{
	if (test_fault != fault)
		return false;
	test_fault = TA_TWEP_WR_D043_FAULT_NONE;
	return true;
}
#endif

struct cursor {
	const uint8_t *buf;
	size_t len;
	size_t off;
};

struct component_sequence {
	const uint8_t *id;
	size_t id_len;
	uint64_t sequence;
};

struct acceptance_state {
	uint8_t raw[ACCEPTANCE_STATE_MAX_SIZE];
	size_t raw_len;
	uint64_t generation;
	uint8_t digest[32];
	bool have_digest;
	struct component_sequence components[ACCEPTANCE_STATE_MAX_COMPONENTS];
	size_t component_count;
	int active_slot;
};

struct catalog_state {
	uint8_t *raw;
	size_t raw_len;
	uint64_t acceptance_generation;
	uint64_t sequence;
	const uint8_t *component_id;
	size_t component_id_len;
	const uint8_t *digest;
	const uint8_t *catalog;
	size_t catalog_len;
	int slot;
};

enum parse_status {
	PARSE_VALID,
	PARSE_MALFORMED,
	PARSE_UNSUPPORTED,
};

static bool read_uint(struct cursor *cur, uint8_t major, uint64_t *value)
{
	uint8_t initial;
	uint8_t ai;
	uint64_t out = 0;
	size_t bytes = 0;
	size_t i;

	if (cur->off >= cur->len)
		return false;
	initial = cur->buf[cur->off++];
	if ((initial >> 5) != major)
		return false;
	ai = initial & 0x1f;
	if (ai < 24) {
		*value = ai;
		return true;
	}
	if (ai == 24)
		bytes = 1;
	else if (ai == 25)
		bytes = 2;
	else if (ai == 26)
		bytes = 4;
	else if (ai == 27)
		bytes = 8;
	else
		return false;
	if (bytes > cur->len - cur->off)
		return false;
	for (i = 0; i < bytes; i++)
		out = (out << 8) | cur->buf[cur->off++];
	if ((bytes == 1 && out < 24) ||
	    (bytes == 2 && out <= UINT8_MAX) ||
	    (bytes == 4 && out <= UINT16_MAX) ||
	    (bytes == 8 && out <= UINT32_MAX))
		return false;
	*value = out;
	return true;
}

static bool read_bytes(struct cursor *cur, uint8_t major,
		       const uint8_t **bytes, size_t *len)
{
	uint64_t n;

	if (!read_uint(cur, major, &n) || n > SIZE_MAX ||
	    (size_t)n > cur->len - cur->off)
		return false;
	*bytes = cur->buf + cur->off;
	*len = (size_t)n;
	cur->off += *len;
	return true;
}

static bool read_expected_text(struct cursor *cur, const char *expected)
{
	const uint8_t *value;
	size_t value_len;
	size_t expected_len = strlen(expected);

	return read_bytes(cur, 3, &value, &value_len) &&
	       value_len == expected_len &&
	       TEE_MemCompare(value, expected, expected_len) == 0;
}

static int canonical_bstr_compare(const uint8_t *a, size_t a_len,
				  const uint8_t *b, size_t b_len)
{
	if (a_len < b_len)
		return -1;
	if (a_len > b_len)
		return 1;
	return TEE_MemCompare(a, b, a_len);
}

static bool parse_components(struct cursor *cur, struct acceptance_state *state)
{
	uint64_t count;
	size_t i;

	if (!read_uint(cur, 5, &count) || count > ACCEPTANCE_STATE_MAX_COMPONENTS)
		return false;
	for (i = 0; i < (size_t)count; i++) {
		const uint8_t *id;
		size_t id_len;
		uint64_t sequence;

		if (!read_bytes(cur, 2, &id, &id_len) || !id_len ||
		    !read_uint(cur, 0, &sequence))
			return false;
		if (i && canonical_bstr_compare(
				 state->components[i - 1].id,
				 state->components[i - 1].id_len,
				 id, id_len) >= 0)
			return false;
		state->components[i].id = id;
		state->components[i].id_len = id_len;
		state->components[i].sequence = sequence;
	}
	state->component_count = (size_t)count;
	return true;
}

static enum parse_status parse_slot(struct acceptance_state *state)
{
	struct cursor cur = {
		.buf = state->raw,
		.len = state->raw_len,
	};
	const uint8_t *digest;
	size_t digest_len;
	uint64_t map_len;
	uint64_t schema_version;

	if (!read_uint(&cur, 5, &map_len) || map_len != 4 ||
	    !read_expected_text(&cur, "generation") ||
	    !read_uint(&cur, 0, &state->generation) || !state->generation ||
	    !read_expected_text(&cur, "schema_version") ||
	    !read_uint(&cur, 0, &schema_version) ||
	    !read_expected_text(&cur, "component_sequences") ||
	    !parse_components(&cur, state) ||
	    !read_expected_text(&cur,
				"last_consumed_query_response_sha256") ||
	    !read_bytes(&cur, 2, &digest, &digest_len) || digest_len != 32 ||
	    cur.off != cur.len)
		return PARSE_MALFORMED;
	TEE_MemMove(state->digest, digest, sizeof(state->digest));
	state->have_digest = true;
	return schema_version == 1 ? PARSE_VALID : PARSE_UNSUPPORTED;
}

static enum parse_status parse_legacy(struct acceptance_state *state)
{
	struct cursor cur = {
		.buf = state->raw,
		.len = state->raw_len,
	};

	state->generation = 0;
	state->have_digest = false;
	if (!parse_components(&cur, state) || cur.off != cur.len)
		return PARSE_MALFORMED;
	return PARSE_VALID;
}

static TEE_Result read_object(const char *id, struct acceptance_state *state)
{
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
	if (!info.dataSize || info.dataSize > sizeof(state->raw)) {
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}
	res = TEE_ReadObjectData(object, state->raw, info.dataSize, &read_len);
	if (res == TEE_SUCCESS && read_len != info.dataSize)
		res = TEE_ERROR_CORRUPT_OBJECT;
	if (res == TEE_SUCCESS)
		state->raw_len = read_len;
out:
	TEE_CloseObject(object);
	return res;
}

static bool states_equal(const struct acceptance_state *a,
			 const struct acceptance_state *b)
{
	return a->raw_len == b->raw_len &&
	       TEE_MemCompare(a->raw, b->raw, a->raw_len) == 0;
}

static TEE_Result load_current(struct acceptance_state *current)
{
	struct acceptance_state slots[2] = { };
	const char *ids[2] = { slot0_id, slot1_id };
	bool present[2] = { false, false };
	enum parse_status status[2] = { PARSE_MALFORMED, PARSE_MALFORMED };
	size_t valid_count = 0;
	int selected = -1;
	int i;
	TEE_Result res;

	for (i = 0; i < 2; i++) {
		res = read_object(ids[i], &slots[i]);
		if (res == TEE_ERROR_ITEM_NOT_FOUND)
			continue;
		present[i] = true;
		if (res != TEE_SUCCESS)
			continue;
		status[i] = parse_slot(&slots[i]);
		if (status[i] == PARSE_UNSUPPORTED)
			return TEE_ERROR_NOT_SUPPORTED;
		if (status[i] == PARSE_VALID) {
			valid_count++;
			if (selected < 0 || slots[i].generation >
					  slots[selected].generation)
				selected = i;
		}
	}
	if (valid_count) {
		if (status[0] == PARSE_VALID && status[1] == PARSE_VALID &&
		    slots[0].generation == slots[1].generation &&
		    !states_equal(&slots[0], &slots[1]))
			return TEE_ERROR_SECURITY;
		*current = slots[selected];
		current->active_slot = selected;
		if (parse_slot(current) != PARSE_VALID)
			return TEE_ERROR_CORRUPT_OBJECT;
		return TEE_SUCCESS;
	}
	if (present[0] || present[1])
		return TEE_ERROR_CORRUPT_OBJECT;

	TEE_MemFill(current, 0, sizeof(*current));
	current->active_slot = -1;
	res = read_object(legacy_id, current);
	if (res == TEE_ERROR_ITEM_NOT_FOUND)
		return TEE_SUCCESS;
	if (res != TEE_SUCCESS || parse_legacy(current) != PARSE_VALID)
		return TEE_ERROR_CORRUPT_OBJECT;
	return TEE_SUCCESS;
}

static TEE_Result digest_sha256(const uint8_t *bytes, size_t len,
				uint8_t digest[32])
{
	TEE_OperationHandle operation = TEE_HANDLE_NULL;
	uint32_t digest_len = 32;
	TEE_Result res;

	res = TEE_AllocateOperation(&operation, TEE_ALG_SHA256,
				    TEE_MODE_DIGEST, 0);
	if (res != TEE_SUCCESS)
		return res;
	res = TEE_DigestDoFinal(operation, (void *)bytes, len, digest,
				&digest_len);
	TEE_FreeOperation(operation);
	if (res != TEE_SUCCESS || digest_len != 32)
		return TEE_ERROR_GENERIC;
	return TEE_SUCCESS;
}

static size_t type_len_size(uint64_t value)
{
	if (value < 24)
		return 1;
	if (value <= UINT8_MAX)
		return 2;
	if (value <= UINT16_MAX)
		return 3;
	if (value <= UINT32_MAX)
		return 5;
	return 9;
}

static size_t text_size(const char *text)
{
	size_t len = strlen(text);

	return type_len_size(len) + len;
}

static size_t bstr_size(size_t len)
{
	return type_len_size(len) + len;
}

static void write_type_len(uint8_t **out, uint8_t major, uint64_t value)
{
	size_t bytes = type_len_size(value) - 1;
	size_t i;

	if (!bytes) {
		*(*out)++ = (uint8_t)((major << 5) | value);
		return;
	}
	*(*out)++ = (uint8_t)((major << 5) |
			      (bytes == 1 ? 24 : bytes == 2 ? 25 :
			       bytes == 4 ? 26 : 27));
	for (i = bytes; i > 0; i--)
		*(*out)++ = (uint8_t)(value >> ((i - 1) * 8));
}

static void write_text(uint8_t **out, const char *text)
{
	size_t len = strlen(text);

	write_type_len(out, 3, len);
	TEE_MemMove(*out, text, len);
	*out += len;
}

static void write_bstr(uint8_t **out, const uint8_t *bytes, size_t len)
{
	write_type_len(out, 2, len);
	TEE_MemMove(*out, bytes, len);
	*out += len;
}

static TEE_Result encode_updated(const struct acceptance_state *current,
				 const uint8_t digest[32],
				 const uint8_t *component_id,
				 size_t component_id_len,
				 uint64_t sequence,
				 uint8_t out[ACCEPTANCE_STATE_MAX_SIZE],
				 size_t *out_len)
{
	uint8_t *p = out;
	size_t i;
	size_t insert_at = current->component_count;
	bool replacing = false;
	size_t count = current->component_count;
	size_t encoded_size;

	if (component_id_len > ACCEPTANCE_STATE_MAX_SIZE)
		return TEE_ERROR_EXCESS_DATA;

	for (i = 0; i < current->component_count; i++) {
		int cmp = canonical_bstr_compare(
			current->components[i].id, current->components[i].id_len,
			component_id, component_id_len);

		if (!cmp) {
			if (sequence <= current->components[i].sequence)
				return TEE_ERROR_ACCESS_CONFLICT;
			insert_at = i;
			replacing = true;
			break;
		}
		if (cmp > 0) {
			insert_at = i;
			break;
		}
	}
	if (!replacing) {
		if (count == ACCEPTANCE_STATE_MAX_COMPONENTS)
			return TEE_ERROR_EXCESS_DATA;
		count++;
	}

	encoded_size = type_len_size(4) +
		text_size("generation") + type_len_size(current->generation + 1) +
		text_size("schema_version") + type_len_size(1) +
		text_size("component_sequences") + type_len_size(count) +
		text_size("last_consumed_query_response_sha256") + bstr_size(32);
	for (i = 0; i < current->component_count; i++) {
		if (replacing && i == insert_at)
			continue;
		encoded_size += bstr_size(current->components[i].id_len) +
			type_len_size(current->components[i].sequence);
	}
	encoded_size += bstr_size(component_id_len) + type_len_size(sequence);
	if (encoded_size > ACCEPTANCE_STATE_MAX_SIZE)
		return TEE_ERROR_EXCESS_DATA;

	write_type_len(&p, 5, 4);
	write_text(&p, "generation");
	write_type_len(&p, 0, current->generation + 1);
	write_text(&p, "schema_version");
	write_type_len(&p, 0, 1);
	write_text(&p, "component_sequences");
	write_type_len(&p, 5, count);
	for (i = 0; i < count; i++) {
		if (i == insert_at) {
			write_bstr(&p, component_id, component_id_len);
			write_type_len(&p, 0, sequence);
			if (!replacing)
				continue;
		}
		if (replacing && i == insert_at)
			continue;
		{
			size_t old_i = i - (!replacing && i > insert_at ? 1 : 0);

			write_bstr(&p, current->components[old_i].id,
				   current->components[old_i].id_len);
			write_type_len(&p, 0,
				       current->components[old_i].sequence);
		}
	}
	write_text(&p, "last_consumed_query_response_sha256");
	write_bstr(&p, digest, 32);
	*out_len = (size_t)(p - out);
	return *out_len == encoded_size ? TEE_SUCCESS : TEE_ERROR_BAD_STATE;
}

static TEE_Result write_slot(int slot, const uint8_t *bytes, size_t len)
{
	const char *id = slot ? slot1_id : slot0_id;
	TEE_ObjectHandle object = TEE_HANDLE_NULL;
	uint32_t flags = TEE_DATA_FLAG_ACCESS_READ |
			 TEE_DATA_FLAG_ACCESS_WRITE |
			 TEE_DATA_FLAG_ACCESS_WRITE_META |
			 TEE_DATA_FLAG_OVERWRITE;
	TEE_Result res;

#ifdef TWEP_TA_D043_TEST_HOOKS
	if (take_test_fault(TA_TWEP_WR_D043_FAULT_SLOT_CREATE))
		return TEE_ERROR_STORAGE_NOT_AVAILABLE;
#endif
	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, id, strlen(id),
					 flags, TEE_HANDLE_NULL, NULL, 0,
					 &object);
	if (res != TEE_SUCCESS)
		return res;
#ifdef TWEP_TA_D043_TEST_HOOKS
	if (take_test_fault(TA_TWEP_WR_D043_FAULT_SLOT_WRITE))
		res = TEE_ERROR_STORAGE_NOT_AVAILABLE;
	else
#endif
		res = TEE_WriteObjectData(object, bytes, len);
	if (res != TEE_SUCCESS) {
		TEE_CloseAndDeletePersistentObject1(object);
		return res;
	}
	TEE_CloseObject(object);
#ifdef TWEP_TA_D043_TEST_HOOKS
	if (take_test_fault(TA_TWEP_WR_D043_FAULT_SLOT_AFTER_CLOSE))
		return TEE_ERROR_STORAGE_NOT_AVAILABLE;
#endif
	return TEE_SUCCESS;
}

TEE_Result twep_acceptance_generation(uint64_t *generation)
{
	struct acceptance_state current = { };
	TEE_Result res;

	if (!generation)
		return TEE_ERROR_BAD_PARAMETERS;
	res = load_current(&current);
	if (res == TEE_SUCCESS)
		*generation = current.generation;
	return res;
}

TEE_Result twep_acceptance_component_sequence(const uint8_t *component_id,
					       size_t component_id_len,
					       uint64_t *generation,
					       uint64_t *sequence)
{
	struct acceptance_state current = { };
	TEE_Result res;
	size_t i;

	if (!component_id || !component_id_len || !generation || !sequence)
		return TEE_ERROR_BAD_PARAMETERS;
	res = load_current(&current);
	if (res != TEE_SUCCESS)
		return res;
	*generation = current.generation;
	for (i = 0; i < current.component_count; i++) {
		if (current.components[i].id_len == component_id_len &&
		    TEE_MemCompare(current.components[i].id, component_id,
				   component_id_len) == 0) {
			*sequence = current.components[i].sequence;
			return TEE_SUCCESS;
		}
	}
	return TEE_ERROR_ITEM_NOT_FOUND;
}

TEE_Result twep_acceptance_commit(const uint8_t query_response_sha256[32],
				  const uint8_t *component_id,
				  size_t component_id_len,
				  uint64_t sequence,
				  uint64_t expected_generation,
				  uint64_t *new_generation)
{
	struct acceptance_state current = { };
	struct acceptance_state verify = { };
	uint8_t encoded[ACCEPTANCE_STATE_MAX_SIZE];
	size_t encoded_len = 0;
	int target_slot;
	TEE_Result res;

	if (!query_response_sha256 || !component_id || !component_id_len ||
	    !sequence || !new_generation)
		return TEE_ERROR_BAD_PARAMETERS;
	res = load_current(&current);
	if (res != TEE_SUCCESS)
		return res;
	if (current.generation != expected_generation)
		return TEE_ERROR_ACCESS_CONFLICT;
	if (current.generation == UINT64_MAX)
		return TEE_ERROR_OVERFLOW;
	if (current.have_digest &&
	    TEE_MemCompare(current.digest, query_response_sha256, 32) == 0)
		return TEE_ERROR_ACCESS_CONFLICT;
	res = encode_updated(&current, query_response_sha256, component_id,
			     component_id_len, sequence, encoded, &encoded_len);
	if (res != TEE_SUCCESS)
		return res;
	target_slot = current.active_slot == 0 ? 1 : 0;
	res = write_slot(target_slot, encoded, encoded_len);
	if (res != TEE_SUCCESS)
		return res;
#ifdef TWEP_TA_D043_TEST_HOOKS
	if (take_test_fault(TA_TWEP_WR_D043_FAULT_SLOT_REOPEN))
		return TEE_ERROR_CORRUPT_OBJECT;
#endif
	res = read_object(target_slot ? slot1_id : slot0_id, &verify);
	if (res != TEE_SUCCESS || parse_slot(&verify) != PARSE_VALID ||
	    verify.raw_len != encoded_len ||
	    TEE_MemCompare(verify.raw, encoded, encoded_len) != 0)
		return TEE_ERROR_CORRUPT_OBJECT;
	*new_generation = current.generation + 1;
	return TEE_SUCCESS;
}

bool twep_catalog_component_id_is_default(const uint8_t *component_id,
					   size_t component_id_len)
{
	return component_id &&
	       component_id_len == sizeof(default_catalog_component_id) &&
	       TEE_MemCompare(component_id, default_catalog_component_id,
			      sizeof(default_catalog_component_id)) == 0;
}

static void catalog_state_release(struct catalog_state *state)
{
	if (state && state->raw)
		TEE_Free(state->raw);
	if (state)
		TEE_MemFill(state, 0, sizeof(*state));
}

static enum parse_status parse_catalog_record(struct catalog_state *state)
{
	struct cursor cur = {
		.buf = state->raw,
		.len = state->raw_len,
	};
	const uint8_t *component_id;
	const uint8_t *digest;
	const uint8_t *catalog;
	size_t component_id_len;
	size_t digest_len;
	size_t catalog_len;
	uint64_t map_len;
	uint64_t schema_version;
	uint8_t computed_digest[32];

	/* Exact key order also enforces canonical encoding and no duplicates. */
	if (!read_uint(&cur, 5, &map_len) || map_len != 6 ||
	    !read_expected_text(&cur, "catalog_cbor") ||
	    !read_bytes(&cur, 2, &catalog, &catalog_len) ||
	    !catalog_len || catalog_len > CATALOG_STATE_MAX_PAYLOAD ||
	    !read_expected_text(&cur, "catalog_sha256") ||
	    !read_bytes(&cur, 2, &digest, &digest_len) || digest_len != 32 ||
	    !read_expected_text(&cur, "schema_version") ||
	    !read_uint(&cur, 0, &schema_version) ||
	    !read_expected_text(&cur, "sequence_number") ||
	    !read_uint(&cur, 0, &state->sequence) || !state->sequence ||
	    !read_expected_text(&cur, "component_id_cbor") ||
	    !read_bytes(&cur, 2, &component_id, &component_id_len) ||
	    !read_expected_text(&cur, "acceptance_generation") ||
	    !read_uint(&cur, 0, &state->acceptance_generation) ||
	    !state->acceptance_generation || cur.off != cur.len)
		return PARSE_MALFORMED;
	if (schema_version != 1)
		return PARSE_UNSUPPORTED;
	if (!twep_catalog_component_id_is_default(component_id,
						 component_id_len) ||
	    digest_sha256(catalog, catalog_len, computed_digest) != TEE_SUCCESS ||
	    TEE_MemCompare(digest, computed_digest, sizeof(computed_digest)) != 0)
		return PARSE_MALFORMED;
	state->component_id = component_id;
	state->component_id_len = component_id_len;
	state->digest = digest;
	state->catalog = catalog;
	state->catalog_len = catalog_len;
	return PARSE_VALID;
}

static TEE_Result read_catalog_slot(int slot, struct catalog_state *state,
				    enum parse_status *status)
{
	const char *id = slot ? catalog_slot1_id : catalog_slot0_id;
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
	if (!info.dataSize || info.dataSize > CATALOG_STATE_MAX_RECORD) {
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}
	state->raw = TEE_Malloc(info.dataSize, 0);
	if (!state->raw) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	res = TEE_ReadObjectData(object, state->raw, info.dataSize, &read_len);
	if (res != TEE_SUCCESS || read_len != info.dataSize) {
		if (res == TEE_SUCCESS)
			res = TEE_ERROR_CORRUPT_OBJECT;
		goto out;
	}
	state->raw_len = read_len;
	state->slot = slot;
	*status = parse_catalog_record(state);
out:
	TEE_CloseObject(object);
	return res;
}

static bool catalog_records_agree(const struct catalog_state *a,
				  const struct catalog_state *b)
{
	return a->sequence == b->sequence &&
	       a->component_id_len == b->component_id_len &&
	       TEE_MemCompare(a->component_id, b->component_id,
			      a->component_id_len) == 0 &&
	       TEE_MemCompare(a->digest, b->digest, 32) == 0 &&
	       a->catalog_len == b->catalog_len &&
	       TEE_MemCompare(a->catalog, b->catalog, a->catalog_len) == 0;
}

static TEE_Result load_active_catalog(struct catalog_state *active)
{
	struct catalog_state slots[2] = { };
	enum parse_status status[2] = { PARSE_MALFORMED, PARSE_MALFORMED };
	bool present[2] = { false, false };
	uint64_t generation = 0;
	uint64_t accepted_sequence = 0;
	int selected = -1;
	int matching = 0;
	int i;
	TEE_Result res;

	res = twep_acceptance_component_sequence(default_catalog_component_id,
						 sizeof(default_catalog_component_id),
						 &generation, &accepted_sequence);
	if (res != TEE_SUCCESS)
		return res;
	(void)generation;
	for (i = 0; i < 2; i++) {
		res = read_catalog_slot(i, &slots[i], &status[i]);
		if (res == TEE_ERROR_ITEM_NOT_FOUND)
			continue;
		present[i] = true;
		if (res == TEE_ERROR_BAD_FORMAT ||
		    res == TEE_ERROR_CORRUPT_OBJECT)
			continue;
		if (res != TEE_SUCCESS)
			goto out;
		if (status[i] == PARSE_UNSUPPORTED) {
			res = TEE_ERROR_NOT_SUPPORTED;
			goto out;
		}
		if (status[i] == PARSE_VALID &&
		    slots[i].sequence == accepted_sequence) {
			matching++;
			if (selected < 0 || slots[i].acceptance_generation >
					  slots[selected].acceptance_generation)
				selected = i;
		}
	}
	if (!matching) {
		res = (present[0] || present[1]) ? TEE_ERROR_CORRUPT_OBJECT :
			TEE_ERROR_ITEM_NOT_FOUND;
		goto out;
	}
	if (matching == 2 && !catalog_records_agree(&slots[0], &slots[1])) {
		res = TEE_ERROR_SECURITY;
		goto out;
	}
	*active = slots[selected];
	TEE_MemFill(&slots[selected], 0, sizeof(slots[selected]));
	res = TEE_SUCCESS;
out:
	for (i = 0; i < 2; i++)
		catalog_state_release(&slots[i]);
	return res;
}

static TEE_Result encode_catalog_record(uint64_t acceptance_generation,
					uint64_t sequence,
					const uint8_t *catalog,
					size_t catalog_len,
					const uint8_t digest[32],
					uint8_t *out, size_t out_cap,
					size_t *out_len)
{
	uint8_t *p = out;
	size_t needed = type_len_size(6) +
		text_size("catalog_cbor") + bstr_size(catalog_len) +
		text_size("catalog_sha256") + bstr_size(32) +
		text_size("schema_version") + type_len_size(1) +
		text_size("sequence_number") + type_len_size(sequence) +
		text_size("component_id_cbor") +
		bstr_size(sizeof(default_catalog_component_id)) +
		text_size("acceptance_generation") +
		type_len_size(acceptance_generation);

	if (needed > out_cap)
		return TEE_ERROR_SHORT_BUFFER;
	write_type_len(&p, 5, 6);
	write_text(&p, "catalog_cbor");
	write_bstr(&p, catalog, catalog_len);
	write_text(&p, "catalog_sha256");
	write_bstr(&p, digest, 32);
	write_text(&p, "schema_version");
	write_type_len(&p, 0, 1);
	write_text(&p, "sequence_number");
	write_type_len(&p, 0, sequence);
	write_text(&p, "component_id_cbor");
	write_bstr(&p, default_catalog_component_id,
		   sizeof(default_catalog_component_id));
	write_text(&p, "acceptance_generation");
	write_type_len(&p, 0, acceptance_generation);
	*out_len = (size_t)(p - out);
	return *out_len == needed ? TEE_SUCCESS : TEE_ERROR_BAD_STATE;
}

static TEE_Result write_catalog_slot(int slot, const uint8_t *record,
				     size_t record_len)
{
	const char *id = slot ? catalog_slot1_id : catalog_slot0_id;
	TEE_ObjectHandle object = TEE_HANDLE_NULL;
	uint32_t flags = TEE_DATA_FLAG_ACCESS_READ |
		TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_ACCESS_WRITE_META |
		TEE_DATA_FLAG_OVERWRITE;
	TEE_Result res;

#ifdef TWEP_TA_D043_TEST_HOOKS
	if (take_test_fault(TA_TWEP_WR_D047_FAULT_CATALOG_SLOT_CREATE))
		return TEE_ERROR_STORAGE_NOT_AVAILABLE;
#endif
	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, id, strlen(id),
					 flags, TEE_HANDLE_NULL, NULL, 0, &object);
	if (res != TEE_SUCCESS)
		return res;
#ifdef TWEP_TA_D043_TEST_HOOKS
	if (take_test_fault(TA_TWEP_WR_D047_FAULT_CATALOG_SLOT_WRITE))
		res = TEE_ERROR_STORAGE_NOT_AVAILABLE;
	else
#endif
	res = TEE_WriteObjectData(object, record, record_len);
	if (res != TEE_SUCCESS) {
		TEE_CloseAndDeletePersistentObject1(object);
		return res;
	}
	TEE_CloseObject(object);
#ifdef TWEP_TA_D043_TEST_HOOKS
	if (take_test_fault(TA_TWEP_WR_D047_FAULT_CATALOG_SLOT_AFTER_CLOSE))
		return TEE_ERROR_STORAGE_NOT_AVAILABLE;
#endif
	return TEE_SUCCESS;
}

TEE_Result twep_catalog_commit(const uint8_t query_response_sha256[32],
			       const uint8_t *component_id,
			       size_t component_id_len,
			       uint64_t sequence,
			       uint64_t expected_generation,
			       const uint8_t *catalog,
			       size_t catalog_len,
			       const uint8_t catalog_sha256[32],
			       uint64_t *new_generation)
{
	struct catalog_state active = { };
	struct catalog_state verify = { };
	uint8_t computed_digest[32];
	uint8_t *record = NULL;
	size_t record_len = 0;
	uint64_t current_generation = 0;
	uint64_t current_sequence = 0;
	enum parse_status verify_status = PARSE_MALFORMED;
	int target_slot = 0;
	TEE_Result res;

	if (!query_response_sha256 ||
	    !twep_catalog_component_id_is_default(component_id,
						 component_id_len) ||
	    !sequence || !catalog || !catalog_len ||
	    catalog_len > CATALOG_STATE_MAX_PAYLOAD || !catalog_sha256 ||
	    !new_generation || expected_generation == UINT64_MAX)
		return TEE_ERROR_BAD_PARAMETERS;
	res = digest_sha256(catalog, catalog_len, computed_digest);
	if (res != TEE_SUCCESS)
		return res;
	if (TEE_MemCompare(computed_digest, catalog_sha256, 32) != 0)
		return TEE_ERROR_SECURITY;
	res = twep_acceptance_generation(&current_generation);
	if (res != TEE_SUCCESS)
		return res;
	if (current_generation != expected_generation)
		return TEE_ERROR_ACCESS_CONFLICT;
	res = twep_acceptance_component_sequence(default_catalog_component_id,
						 sizeof(default_catalog_component_id),
						 &current_generation,
						 &current_sequence);
	if (res == TEE_SUCCESS) {
		if (sequence <= current_sequence) {
			res = TEE_ERROR_ACCESS_CONFLICT;
			goto out;
		}
		res = load_active_catalog(&active);
		if (res != TEE_SUCCESS)
			goto out;
		target_slot = active.slot == 0 ? 1 : 0;
	} else if (res != TEE_ERROR_ITEM_NOT_FOUND) {
		goto out;
	}
	record = TEE_Malloc(CATALOG_STATE_MAX_RECORD, 0);
	if (!record) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	res = encode_catalog_record(expected_generation + 1, sequence, catalog,
				    catalog_len, computed_digest, record,
				    CATALOG_STATE_MAX_RECORD, &record_len);
	if (res != TEE_SUCCESS)
		goto out;
	res = write_catalog_slot(target_slot, record, record_len);
	if (res != TEE_SUCCESS)
		goto out;
#ifdef TWEP_TA_D043_TEST_HOOKS
	if (take_test_fault(TA_TWEP_WR_D047_FAULT_CATALOG_SLOT_REOPEN)) {
		res = TEE_ERROR_CORRUPT_OBJECT;
		goto out;
	}
#endif
	res = read_catalog_slot(target_slot, &verify, &verify_status);
#ifdef TWEP_TA_D043_TEST_HOOKS
	if (res == TEE_SUCCESS &&
	    take_test_fault(TA_TWEP_WR_D047_FAULT_CATALOG_SLOT_READBACK)) {
		res = TEE_ERROR_CORRUPT_OBJECT;
		goto out;
	}
#endif
	if (res != TEE_SUCCESS || verify_status != PARSE_VALID ||
	    verify.raw_len != record_len ||
	    TEE_MemCompare(verify.raw, record, record_len) != 0) {
		res = TEE_ERROR_CORRUPT_OBJECT;
		goto out;
	}
	catalog_state_release(&verify);
	res = twep_acceptance_commit(query_response_sha256, component_id,
				     component_id_len, sequence,
				     expected_generation, new_generation);
out:
	if (record)
		TEE_Free(record);
	catalog_state_release(&active);
	catalog_state_release(&verify);
	return res;
}

TEE_Result twep_catalog_read_active(uint8_t *catalog, size_t catalog_cap,
				    size_t *catalog_len)
{
	struct catalog_state active = { };
	TEE_Result res;

	if (!catalog_len)
		return TEE_ERROR_BAD_PARAMETERS;
	res = load_active_catalog(&active);
	if (res != TEE_SUCCESS)
		return res;
	*catalog_len = active.catalog_len;
	if (active.catalog_len > catalog_cap) {
		res = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}
	if (active.catalog_len && !catalog) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}
	TEE_MemMove(catalog, active.catalog, active.catalog_len);
out:
	catalog_state_release(&active);
	return res;
}

#ifdef TWEP_TA_D043_TEST_HOOKS
static const char *test_object_id(uint32_t target)
{
	switch (target) {
	case TA_TWEP_WR_D043_OBJECT_SLOT0:
		return slot0_id;
	case TA_TWEP_WR_D043_OBJECT_SLOT1:
		return slot1_id;
	case TA_TWEP_WR_D043_OBJECT_LEGACY:
		return legacy_id;
	case TA_TWEP_WR_D043_OBJECT_CATALOG_SLOT0:
		return catalog_slot0_id;
	case TA_TWEP_WR_D043_OBJECT_CATALOG_SLOT1:
		return catalog_slot1_id;
	default:
		return NULL;
	}
}

void twep_acceptance_test_reset_fault(void)
{
	test_fault = TA_TWEP_WR_D043_FAULT_NONE;
}

TEE_Result twep_acceptance_test_arm_fault(uint32_t fault)
{
	if (fault < TA_TWEP_WR_D043_FAULT_SLOT_CREATE ||
	    fault > TA_TWEP_WR_D047_FAULT_CATALOG_SLOT_READBACK)
		return TEE_ERROR_BAD_PARAMETERS;
	test_fault = fault;
	return TEE_SUCCESS;
}

TEE_Result twep_acceptance_test_write_object(uint32_t target,
					     const uint8_t *data,
					     size_t data_len)
{
	const char *id = test_object_id(target);
	TEE_ObjectHandle object = TEE_HANDLE_NULL;
	uint32_t flags = TEE_DATA_FLAG_ACCESS_READ |
			 TEE_DATA_FLAG_ACCESS_WRITE |
			 TEE_DATA_FLAG_ACCESS_WRITE_META |
			 TEE_DATA_FLAG_OVERWRITE;
	TEE_Result res;

	if (!id || (!data && data_len))
		return TEE_ERROR_BAD_PARAMETERS;
	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, id, strlen(id),
					 flags, TEE_HANDLE_NULL, NULL, 0,
					 &object);
	if (res != TEE_SUCCESS)
		return res;
	if (data_len)
		res = TEE_WriteObjectData(object, data, data_len);
	if (res != TEE_SUCCESS)
		TEE_CloseAndDeletePersistentObject1(object);
	else
		TEE_CloseObject(object);
	return res;
}

TEE_Result twep_acceptance_test_delete_object(uint32_t target)
{
	const char *id = test_object_id(target);
	TEE_ObjectHandle object = TEE_HANDLE_NULL;
	TEE_Result res;

	if (!id)
		return TEE_ERROR_BAD_PARAMETERS;
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, id, strlen(id),
				       TEE_DATA_FLAG_ACCESS_WRITE_META, &object);
	if (res == TEE_ERROR_ITEM_NOT_FOUND)
		return TEE_SUCCESS;
	if (res != TEE_SUCCESS)
		return res;
	TEE_CloseAndDeletePersistentObject1(object);
	return TEE_SUCCESS;
}

TEE_Result twep_catalog_test_commit(const uint8_t *catalog, size_t catalog_len,
				    uint64_t sequence,
				    uint64_t expected_generation,
				    uint64_t *new_generation)
{
	uint8_t digest[32];
	TEE_Result res;

	res = digest_sha256(catalog, catalog_len, digest);
	if (res != TEE_SUCCESS)
		return res;
	return twep_catalog_commit(digest, default_catalog_component_id,
				   sizeof(default_catalog_component_id), sequence,
				   expected_generation, catalog, catalog_len,
				   digest, new_generation);
}

TEE_Result twep_catalog_test_expect_active(const uint8_t *catalog,
					   size_t catalog_len)
{
	struct catalog_state active = { };
	TEE_Result res;

	res = load_active_catalog(&active);
	if (res != TEE_SUCCESS)
		return res;
	if (active.catalog_len != catalog_len ||
	    TEE_MemCompare(active.catalog, catalog, catalog_len) != 0)
		res = TEE_ERROR_CORRUPT_OBJECT;
	catalog_state_release(&active);
	return res;
}

TEE_Result twep_catalog_test_expect_active_present(void)
{
	size_t catalog_len = 0;
	TEE_Result res = twep_catalog_read_active(NULL, 0, &catalog_len);

	return res == TEE_ERROR_SHORT_BUFFER && catalog_len ? TEE_SUCCESS :
		TEE_ERROR_CORRUPT_OBJECT;
}

TEE_Result twep_catalog_test_commit_non_catalog(uint64_t sequence,
						uint64_t expected_generation,
						uint64_t *new_generation)
{
	static const uint8_t component_id[] = {
		0x82, 0x45, 'o', 't', 'h', 'e', 'r',
		0x47, 'd', 'e', 'f', 'a', 'u', 'l', 't'
	};
	uint8_t digest[32];

	TEE_MemFill(digest, (uint8_t)sequence, sizeof(digest));
	return twep_acceptance_commit(digest, component_id, sizeof(component_id),
				      sequence, expected_generation,
				      new_generation);
}
#endif
