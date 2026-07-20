/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef ACCEPTANCE_STATE_H
#define ACCEPTANCE_STATE_H

#include <stddef.h>
#include <stdint.h>
#include <tee_internal_api.h>

TEE_Result twep_acceptance_generation(uint64_t *generation);

TEE_Result twep_acceptance_component_sequence(const uint8_t *component_id,
					       size_t component_id_len,
					       uint64_t *generation,
					       uint64_t *sequence);

TEE_Result twep_acceptance_commit(const uint8_t query_response_sha256[32],
				  const uint8_t *component_id,
				  size_t component_id_len,
				  uint64_t sequence,
				  uint64_t expected_generation,
				  uint64_t *new_generation);

bool twep_catalog_component_id_is_default(const uint8_t *component_id,
					   size_t component_id_len);

TEE_Result twep_catalog_commit(const uint8_t query_response_sha256[32],
			       const uint8_t *component_id,
			       size_t component_id_len,
			       uint64_t sequence,
			       uint64_t expected_generation,
			       const uint8_t *catalog,
			       size_t catalog_len,
			       const uint8_t catalog_sha256[32],
			       uint64_t *new_generation);

TEE_Result twep_catalog_read_active(uint8_t *catalog, size_t catalog_cap,
				    size_t *catalog_len);

#ifdef TWEP_TA_D043_TEST_HOOKS
void twep_acceptance_test_reset_fault(void);
TEE_Result twep_acceptance_test_arm_fault(uint32_t fault);
TEE_Result twep_acceptance_test_write_object(uint32_t target,
					     const uint8_t *data,
					     size_t data_len);
TEE_Result twep_acceptance_test_delete_object(uint32_t target);
TEE_Result twep_catalog_test_commit(const uint8_t *catalog, size_t catalog_len,
				    uint64_t sequence,
				    uint64_t expected_generation,
				    uint64_t *new_generation);
TEE_Result twep_catalog_test_expect_active(const uint8_t *catalog,
					   size_t catalog_len);
TEE_Result twep_catalog_test_expect_active_present(void);
TEE_Result twep_catalog_test_commit_non_catalog(uint64_t sequence,
						uint64_t expected_generation,
						uint64_t *new_generation);
#endif

#endif /* ACCEPTANCE_STATE_H */
