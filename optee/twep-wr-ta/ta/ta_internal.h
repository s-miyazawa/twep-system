/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef TWEP_WR_TA_INTERNAL_H
#define TWEP_WR_TA_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <tee_internal_api.h>

#if defined(__GNUC__)
#define TWEP_TA_HIDDEN __attribute__((visibility("hidden")))
#else
#define TWEP_TA_HIDDEN
#endif

enum twep_ta_production_envelope_kind {
	TWEP_TA_ENVELOPE_INIT,
	TWEP_TA_ENVELOPE_EXECUTE,
	TWEP_TA_ENVELOPE_RESUME_HOST_IO,
};

TWEP_TA_HIDDEN TEE_Result twep_ta_dispatch_command(uint32_t command,
						    uint32_t param_types,
						    TEE_Param params[4]);
TWEP_TA_HIDDEN TEE_Result twep_ta_cmd_ping(uint32_t, TEE_Param[4]);
TWEP_TA_HIDDEN TEE_Result twep_ta_cmd_get_platform_status(uint32_t,
							   TEE_Param[4]);
TWEP_TA_HIDDEN TEE_Result twep_ta_cmd_measure_wasm(uint32_t, TEE_Param[4]);
TWEP_TA_HIDDEN TEE_Result twep_ta_cmd_secure_storage_put(uint32_t,
							  TEE_Param[4]);
TWEP_TA_HIDDEN TEE_Result twep_ta_cmd_secure_storage_get(uint32_t,
							  TEE_Param[4]);
TWEP_TA_HIDDEN TEE_Result twep_ta_cmd_get_random(uint32_t, TEE_Param[4]);
TWEP_TA_HIDDEN TEE_Result twep_ta_cmd_get_time(uint32_t, TEE_Param[4]);
TWEP_TA_HIDDEN TEE_Result twep_ta_cmd_cbor_dry_run(uint32_t, TEE_Param[4]);
TWEP_TA_HIDDEN bool twep_ta_d047_object_name_reserved(const char *, uint32_t);
TWEP_TA_HIDDEN TEE_Result twep_ta_sha256_bytes(const uint8_t *, size_t,
						uint8_t[32]);
TWEP_TA_HIDDEN TEE_Result twep_ta_cmd_wamr_spike_exec(uint32_t,
							   TEE_Param[4]);
TWEP_TA_HIDDEN TEE_Result twep_ta_cmd_production_envelope(
	uint32_t, TEE_Param[4], enum twep_ta_production_envelope_kind,
	const char *);
#ifdef TWEP_TA_D043_TEST_HOOKS
TWEP_TA_HIDDEN TEE_Result twep_ta_cmd_d043_test(uint32_t, TEE_Param[4]);
TWEP_TA_HIDDEN bool twep_ta_take_d043_runtime_test_fault(uint32_t);
TWEP_TA_HIDDEN void twep_ta_d043_runtime_test_reset(void);
TWEP_TA_HIDDEN void twep_ta_pending_diagnostics(uint32_t *, uint32_t *,
						uint32_t *);
TWEP_TA_HIDDEN TEE_Result twep_ta_write_persistent_object(
	const char *, uint32_t, const uint8_t *, uint32_t);
#endif
#ifdef TWEP_TA_WAMR_LINK
TWEP_TA_HIDDEN bool twep_ta_ensure_wamr_runtime(void);
TWEP_TA_HIDDEN void twep_ta_wamr_cleanup_if_idle(void);
TWEP_TA_HIDDEN bool twep_ta_wasm_has_import_section(const void *, size_t);
#endif

#endif /* TWEP_WR_TA_INTERNAL_H */
