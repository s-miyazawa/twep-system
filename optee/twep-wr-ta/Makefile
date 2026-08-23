# Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
export V ?= 0

OPTEE_ROOT ?= $(HOME)/opt/optee
OPTEE_CLIENT_EXPORT ?= $(OPTEE_ROOT)/out-br/host/aarch64-buildroot-linux-gnu/sysroot/usr
TA_DEV_KIT_DIR ?= $(OPTEE_ROOT)/optee_os/out/arm/export-ta_arm64
HOST_CROSS_COMPILE ?= $(OPTEE_ROOT)/out-br/host/bin/aarch64-buildroot-linux-gnu-
TA_CROSS_COMPILE ?= $(OPTEE_ROOT)/toolchains/aarch64/bin/aarch64-none-linux-gnu-
WAMR_ROOT_DIR ?= $(HOME)/opt/wasm-micro-runtime
WAMR_TA_BUILD_DIR ?= $(CURDIR)/build/wamr-ta
WAMR_SPIKE_IWASM_LIB_DIR ?= $(WAMR_TA_BUILD_DIR)
TA_OUT_DIR ?=
TWEP_TA_WAMR_TARGET ?= AARCH64

# TWEP_TA_WAMR_SPIKE_LINK is the deprecated input name.  Preserve it as an
# exact alias, but fail when callers provide conflicting values.
ifneq ($(origin TWEP_TA_WAMR_SPIKE_LINK),undefined)
ifneq ($(origin TWEP_TA_WAMR_LINK),undefined)
ifneq ($(TWEP_TA_WAMR_LINK),$(TWEP_TA_WAMR_SPIKE_LINK))
$(error TWEP_TA_WAMR_LINK and deprecated TWEP_TA_WAMR_SPIKE_LINK conflict)
endif
endif
TWEP_TA_WAMR_LINK := $(TWEP_TA_WAMR_SPIKE_LINK)
endif
TWEP_TA_WAMR_LINK ?= 0
TWEP_TA_D043_TEST_HOOKS ?= 0
CMAKE ?= cmake

.PHONY: all
all:
	$(MAKE) -C host CROSS_COMPILE="$(HOST_CROSS_COMPILE)" TEEC_EXPORT="$(OPTEE_CLIENT_EXPORT)" \
		TWEP_TA_D043_TEST_HOOKS="$(TWEP_TA_D043_TEST_HOOKS)" --no-builtin-variables
ifeq ($(TWEP_TA_WAMR_LINK),1)
	$(CMAKE) -S wamr-ta -B "$(WAMR_TA_BUILD_DIR)" \
		-DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY \
		-DCMAKE_C_COMPILER="$(TA_CROSS_COMPILE)gcc" \
		-DCMAKE_AR="$(TA_CROSS_COMPILE)ar" \
		-DCMAKE_RANLIB="$(TA_CROSS_COMPILE)ranlib" \
		-DTA_DEV_KIT_DIR="$(TA_DEV_KIT_DIR)" \
		-DWAMR_ROOT_DIR="$(WAMR_ROOT_DIR)" \
		-DWAMR_BUILD_TARGET="$(TWEP_TA_WAMR_TARGET)"
	$(CMAKE) --build "$(WAMR_TA_BUILD_DIR)" --target iwasm
endif
	$(MAKE) -C ta $(if $(TA_OUT_DIR),O="$(TA_OUT_DIR)") \
		CROSS_COMPILE="$(TA_CROSS_COMPILE)" TA_DEV_KIT_DIR="$(TA_DEV_KIT_DIR)" \
		WAMR_ROOT_DIR="$(WAMR_ROOT_DIR)" \
		WAMR_SPIKE_IWASM_LIB_DIR="$(WAMR_SPIKE_IWASM_LIB_DIR)" \
		TWEP_TA_WAMR_LINK="$(TWEP_TA_WAMR_LINK)" \
		TWEP_TA_D043_TEST_HOOKS="$(TWEP_TA_D043_TEST_HOOKS)" LDFLAGS=""

.PHONY: clean
clean:
	$(MAKE) -C host clean
	$(MAKE) -C ta clean $(if $(TA_OUT_DIR),O="$(TA_OUT_DIR)") \
		TA_DEV_KIT_DIR="$(TA_DEV_KIT_DIR)"
