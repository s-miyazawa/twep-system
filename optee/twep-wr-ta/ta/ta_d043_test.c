/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
// SPDX-License-Identifier: BSD-2-Clause

#include <stdint.h>

#include <twep_wr_ta.h>
#include <tee_internal_api.h>

#include "acceptance_state.h"
#include "ta_internal.h"

static uint32_t g_d043_runtime_test_fault;

bool twep_ta_take_d043_runtime_test_fault(uint32_t fault)
{
	if (g_d043_runtime_test_fault != fault)
		return false;
	g_d043_runtime_test_fault = TA_TWEP_WR_D043_FAULT_NONE;
	return true;
}

void twep_ta_d043_runtime_test_reset(void)
{
	g_d043_runtime_test_fault = TA_TWEP_WR_D043_FAULT_NONE;
}

#ifdef TWEP_TA_D043_TEST_HOOKS
static TEE_Result d043_test_delete_result(void)
{
	static const char id[] = "verified-evidence-result.cbor";
	TEE_ObjectHandle object = TEE_HANDLE_NULL;
	TEE_Result res;

	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, id, sizeof(id) - 1,
				       TEE_DATA_FLAG_ACCESS_WRITE_META, &object);
	if (res == TEE_ERROR_ITEM_NOT_FOUND)
		return TEE_SUCCESS;
	if (res != TEE_SUCCESS)
		return res;
	TEE_CloseAndDeletePersistentObject1(object);
	return TEE_SUCCESS;
}

TEE_Result twep_ta_cmd_d043_test(uint32_t param_types, TEE_Param params[4])
{
	const uint32_t expected = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_VALUE_INOUT, TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_VALUE_INOUT, TEE_PARAM_TYPE_NONE);
	uint32_t op;
	uint32_t selector;
	uint64_t generation = 0;
	TEE_Result res = TEE_SUCCESS;

	if (param_types != expected)
		return TEE_ERROR_BAD_PARAMETERS;
	op = params[0].value.a;
	selector = params[0].value.b;
	switch (op) {
	case TA_TWEP_WR_D043_TEST_RESET:
		g_d043_runtime_test_fault = TA_TWEP_WR_D043_FAULT_NONE;
		twep_acceptance_test_reset_fault();
		res = twep_acceptance_test_delete_object(
			TA_TWEP_WR_D043_OBJECT_SLOT0);
		if (res == TEE_SUCCESS)
			res = twep_acceptance_test_delete_object(
				TA_TWEP_WR_D043_OBJECT_SLOT1);
		if (res == TEE_SUCCESS)
			res = twep_acceptance_test_delete_object(
				TA_TWEP_WR_D043_OBJECT_LEGACY);
		if (res == TEE_SUCCESS)
			res = twep_acceptance_test_delete_object(
				TA_TWEP_WR_D043_OBJECT_CATALOG_SLOT0);
		if (res == TEE_SUCCESS)
			res = twep_acceptance_test_delete_object(
				TA_TWEP_WR_D043_OBJECT_CATALOG_SLOT1);
		if (res == TEE_SUCCESS)
			res = d043_test_delete_result();
		return res;
	case TA_TWEP_WR_D043_TEST_ARM_FAULT:
		g_d043_runtime_test_fault = TA_TWEP_WR_D043_FAULT_NONE;
		twep_acceptance_test_reset_fault();
		if (selector == TA_TWEP_WR_D043_FAULT_CONTINUATION_ALLOC ||
		    selector == TA_TWEP_WR_D043_FAULT_RESULT_WRITE) {
			g_d043_runtime_test_fault = selector;
			return TEE_SUCCESS;
		}
		return twep_acceptance_test_arm_fault(selector);
	case TA_TWEP_WR_D043_TEST_WRITE_OBJECT:
		if (selector == TA_TWEP_WR_D043_OBJECT_RESULT)
			return twep_ta_write_persistent_object(
				"verified-evidence-result.cbor",
				sizeof("verified-evidence-result.cbor") - 1,
				params[1].memref.buffer,
				params[1].memref.size);
		return twep_acceptance_test_write_object(
			selector, params[1].memref.buffer,
			params[1].memref.size);
	case TA_TWEP_WR_D043_TEST_DELETE_OBJECT:
		if (selector == TA_TWEP_WR_D043_OBJECT_RESULT)
			return d043_test_delete_result();
		return twep_acceptance_test_delete_object(selector);
	case TA_TWEP_WR_D043_TEST_GET_GENERATION:
		res = twep_acceptance_generation(&generation);
		if (res == TEE_SUCCESS) {
			params[2].value.a = (uint32_t)generation;
			params[2].value.b = (uint32_t)(generation >> 32);
		}
		return res;
	case TA_TWEP_WR_D043_TEST_GET_PENDING_STATE:
		twep_ta_pending_diagnostics(&params[0].value.b,
					    &params[2].value.a,
					    &params[2].value.b);
		return TEE_SUCCESS;
	case TA_TWEP_WR_D043_TEST_CATALOG_COMMIT:
		generation = ((uint64_t)params[2].value.b << 32) |
			params[2].value.a;
		res = twep_catalog_test_commit(params[1].memref.buffer,
					       params[1].memref.size, selector,
					       generation, &generation);
		if (res == TEE_SUCCESS) {
			params[2].value.a = (uint32_t)generation;
			params[2].value.b = (uint32_t)(generation >> 32);
		}
		return res;
	case TA_TWEP_WR_D043_TEST_CATALOG_EXPECT_ACTIVE:
		return twep_catalog_test_expect_active(params[1].memref.buffer,
						       params[1].memref.size);
	case TA_TWEP_WR_D043_TEST_NONCATALOG_COMMIT:
		generation = ((uint64_t)params[2].value.b << 32) |
			params[2].value.a;
		res = twep_catalog_test_commit_non_catalog(selector, generation,
							    &generation);
		if (res == TEE_SUCCESS) {
			params[2].value.a = (uint32_t)generation;
			params[2].value.b = (uint32_t)(generation >> 32);
		}
		return res;
	case TA_TWEP_WR_D043_TEST_CATALOG_EXPECT_PRESENT:
		return twep_catalog_test_expect_active_present();
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
#endif
