/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef PROTECTED_APP_H
#define PROTECTED_APP_H

#include <stddef.h>
#include <stdint.h>
#include <tee_internal_api.h>

#define TWEP_PROTECTED_APP_MAX_SIZE (128 * 1024)

bool twep_app_component_id_is_valid(const uint8_t *component_id,
				    size_t component_id_len);

TEE_Result twep_app_commit(const uint8_t query_response_sha256[32],
			   const uint8_t *component_id,
			   size_t component_id_len, uint64_t sequence,
			   uint64_t expected_generation, const uint8_t *wasm,
			   size_t wasm_len, const uint8_t wasm_sha256[32],
			   uint64_t *new_generation);

TEE_Result twep_app_read_active(uint8_t *wasm, size_t wasm_cap,
				size_t *wasm_len, uint8_t wasm_sha256[32]);

#endif /* PROTECTED_APP_H */
