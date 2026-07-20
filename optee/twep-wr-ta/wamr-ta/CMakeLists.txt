# Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
cmake_minimum_required(VERSION 3.16)
project(twep_wamr_ta C ASM)

if(NOT DEFINED WAMR_ROOT_DIR)
  set(WAMR_ROOT_DIR "$ENV{HOME}/opt/wasm-micro-runtime")
endif()

if(NOT DEFINED TA_DEV_KIT_DIR)
  message(FATAL_ERROR "TA_DEV_KIT_DIR is required")
endif()

set(WAMR_BUILD_PLATFORM "twep-ta")
set(WAMR_BUILD_TARGET "AARCH64")
set(WAMR_BUILD_INTERP 1)
set(WAMR_BUILD_AOT 0)
set(WAMR_BUILD_JIT 0)
set(WAMR_BUILD_FAST_JIT 0)
set(WAMR_BUILD_FAST_INTERP 0)
set(WAMR_BUILD_LIBC_BUILTIN 0)
set(WAMR_BUILD_LIBC_WASI 0)
set(WAMR_BUILD_MULTI_MODULE 1)
set(WAMR_BUILD_SHARED_MEMORY 0)
set(WAMR_BUILD_THREAD_MGR 0)
set(WAMR_BUILD_REF_TYPES 1)
set(WAMR_BUILD_BULK_MEMORY 1)
set(WAMR_BUILD_BULK_MEMORY_OPT 0)
set(WAMR_BUILD_CALL_INDIRECT_OVERLONG 1)
set(WAMR_BUILD_INSTRUCTION_METERING 0)
set(WAMR_BUILD_SHRUNK_MEMORY 1)
set(WAMR_DISABLE_HW_BOUND_CHECK 1)
set(WAMR_DISABLE_STACK_HW_BOUND_CHECK 1)
set(WAMR_DISABLE_WAKEUP_BLOCKING_OP 1)
set(SHARED_PLATFORM_CONFIG ${CMAKE_CURRENT_LIST_DIR}/platform/shared_platform.cmake)

include(${WAMR_ROOT_DIR}/build-scripts/runtime_lib.cmake)

add_library(iwasm STATIC ${WAMR_RUNTIME_LIB_SOURCE})
set_property(
  SOURCE ${WAMR_ROOT_DIR}/core/shared/platform/common/math/math.c
  APPEND PROPERTY COMPILE_OPTIONS
  -Wno-double-promotion
  -Wno-sign-compare
)
target_include_directories(iwasm PRIVATE
  ${WAMR_ROOT_DIR}/core/iwasm/include
  ${TA_DEV_KIT_DIR}/include
)
target_compile_options(iwasm PRIVATE
  -ffreestanding
  -fno-stack-protector
  -Wno-unused-parameter
  -Wno-unused-function
)
