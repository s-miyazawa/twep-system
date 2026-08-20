# Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
global-incdirs-y += include
srcs-y += twep_wr_ta.c
srcs-y += ta_production_runtime.c
srcs-y += ta_runtime_cbor.c
srcs-y += ta_host_io_continuation.c
srcs-y += ta_app_runtime.c
srcs-y += ta_teep_hostcalls.c
srcs-y += ta_teep_runtime.c
srcs-y += ta_wasm_signature.c
srcs-y += ta_command_router.c
srcs-y += ta_basic_commands.c
srcs-y += ta_secure_storage.c
srcs-y += ta_wamr_spike.c
srcs-y += acceptance_state.c
srcs-y += protected_app.c

ifeq ($(TWEP_TA_D043_TEST_HOOKS),1)
srcs-y += ta_d043_test.c
global-cppflags-y += -DTWEP_TA_D043_TEST_HOOKS=1
endif

ifeq ($(TWEP_TA_WAMR_LINK),1)
global-cppflags-y += -I$(WAMR_ROOT_DIR)/core/iwasm/include
global-cppflags-y += -DTWEP_TA_WAMR_LINK=1
libdirs += $(WAMR_SPIKE_IWASM_LIB_DIR)
libnames += iwasm
libdeps += $(WAMR_SPIKE_IWASM_LIB_DIR)/libiwasm.a
endif
