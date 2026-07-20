# Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
global-incdirs-y += include
srcs-y += twep_wr_ta.c
srcs-y += acceptance_state.c

ifeq ($(TWEP_TA_D043_TEST_HOOKS),1)
global-cppflags-y += -DTWEP_TA_D043_TEST_HOOKS=1
endif

ifeq ($(TWEP_TA_WAMR_SPIKE_LINK),1)
global-cppflags-y += -I$(WAMR_ROOT_DIR)/core/iwasm/include
global-cppflags-y += -DTWEP_TA_WAMR_SPIKE_LINK=1
libdirs += $(WAMR_SPIKE_IWASM_LIB_DIR)
libnames += iwasm
libdeps += $(WAMR_SPIKE_IWASM_LIB_DIR)/libiwasm.a
endif
