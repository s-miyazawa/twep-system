# Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
cmake_minimum_required(VERSION 3.14)
project(twep_wr C)

if(NOT DEFINED WAMR_ROOT_DIR)
  set(WAMR_ROOT_DIR "$ENV{HOME}/opt/wasm-micro-runtime")
endif()

string(TOLOWER ${CMAKE_HOST_SYSTEM_NAME} WAMR_BUILD_PLATFORM)
if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(arm64|aarch64)")
  set(WAMR_BUILD_TARGET "AARCH64")
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "riscv64")
  set(WAMR_BUILD_TARGET "RISCV64")
elseif(CMAKE_SIZEOF_VOID_P EQUAL 8)
  set(WAMR_BUILD_TARGET "X86_64")
else()
  set(WAMR_BUILD_TARGET "X86_32")
endif()

set(WAMR_BUILD_INTERP 1)
set(WAMR_BUILD_AOT 0)
set(WAMR_BUILD_JIT 0)
set(WAMR_BUILD_LIBC_BUILTIN 1)
set(WAMR_BUILD_LIBC_WASI 0)
set(WAMR_BUILD_FAST_INTERP 0)
set(WAMR_BUILD_MULTI_MODULE 0)
set(WAMR_BUILD_SHARED_MEMORY 0)
set(WAMR_BUILD_THREAD_MGR 0)
set(WAMR_BUILD_REF_TYPES 1)
set(WAMR_BUILD_INSTRUCTION_METERING 1)

include(${WAMR_ROOT_DIR}/build-scripts/runtime_lib.cmake)

set(TWEP_WR_PLATFORM_BACKEND "linux" CACHE STRING "twep-wr platform backend")
set_property(CACHE TWEP_WR_PLATFORM_BACKEND PROPERTY STRINGS linux arm-optee riscv-optee sgx keystone)
set(TWEP_WR_PLATFORM_SOURCE "")
if(TWEP_WR_PLATFORM_BACKEND STREQUAL "linux")
  set(TWEP_WR_PLATFORM_SOURCE src/platform/linux/platform_linux.c)
elseif(TWEP_WR_PLATFORM_BACKEND STREQUAL "arm-optee" OR
       TWEP_WR_PLATFORM_BACKEND STREQUAL "riscv-optee")
  if(TWEP_WR_PLATFORM_BACKEND STREQUAL "arm-optee")
    if(NOT CMAKE_SYSTEM_PROCESSOR MATCHES "^(arm|arm64|aarch64)")
      message(FATAL_ERROR "TWEP_WR_PLATFORM_BACKEND=arm-optee requires an arm or aarch64 target, got ${CMAKE_SYSTEM_PROCESSOR}")
    endif()
    set(TWEP_WR_OPTEE_PROFILE_SOURCE src/platform/arm-optee/platform_arm_optee.c)
  else()
    if(NOT CMAKE_SYSTEM_PROCESSOR STREQUAL "riscv64")
      message(FATAL_ERROR "TWEP_WR_PLATFORM_BACKEND=riscv-optee requires a riscv64 target, got ${CMAKE_SYSTEM_PROCESSOR}")
    endif()
    set(TWEP_WR_OPTEE_PROFILE_SOURCE src/platform/riscv-optee/platform_riscv_optee.c)
  endif()
  set(TWEP_WR_PLATFORM_SOURCE
        src/platform/optee-common/optee_execute.c
        src/platform/optee-common/optee_artifacts.c
        src/platform/optee-common/optee_candidate.c
        src/platform/optee-common/optee_diagnostics.c
        src/platform/optee-common/optee_envelope.c
        src/platform/optee-common/optee_host_io.c
        src/platform/optee-common/optee_session_storage.c
        src/platform/optee-common/optee_storage.c
        src/platform/optee-common/optee_transport.c
        ${TWEP_WR_OPTEE_PROFILE_SOURCE}
  )
elseif(TWEP_WR_PLATFORM_BACKEND STREQUAL "sgx")
  set(TWEP_WR_PLATFORM_SOURCE src/platform/sgx/platform_sgx.c)
elseif(TWEP_WR_PLATFORM_BACKEND STREQUAL "keystone")
  set(TWEP_WR_PLATFORM_SOURCE src/platform/keystone/platform_keystone.c)
else()
  message(FATAL_ERROR "unsupported TWEP_WR_PLATFORM_BACKEND=${TWEP_WR_PLATFORM_BACKEND}")
endif()

add_library(twep_wr SHARED
  src/app_runtime.c
  src/catalog_resolver.c
  src/response_cbor.c
  src/runtime.c
  src/teep_agent_runtime.c
  src/wasm_signature.c
  ${TWEP_WR_PLATFORM_SOURCE}
  ${WAMR_RUNTIME_LIB_SOURCE}
)

# Keep -Werror on TWEP sources while allowing the pinned upstream WAMR 2.4.5
# sources to build with newer cross compilers (notably GCC 14).
set_source_files_properties(${WAMR_RUNTIME_LIB_SOURCE}
  PROPERTIES COMPILE_OPTIONS "-Wno-error"
)

target_include_directories(twep_wr PRIVATE
  include
  src
  ${WAMR_ROOT_DIR}/core/iwasm/include
)

if(TWEP_WR_PLATFORM_BACKEND STREQUAL "arm-optee" OR
   TWEP_WR_PLATFORM_BACKEND STREQUAL "riscv-optee")
  target_compile_definitions(twep_wr PRIVATE TWEP_WR_PLATFORM_BACKEND_OPTEE=1)
  set(TWEP_WR_TEEC_EXPORT "$ENV{HOME}/opt/optee/out-br/host/aarch64-buildroot-linux-gnu/sysroot/usr" CACHE PATH "OP-TEE client export prefix")
  set(TWEP_WR_TEEC_LIB_DIR "${TWEP_WR_TEEC_EXPORT}/lib" CACHE PATH "OP-TEE libteec directory")
  if(NOT EXISTS "${TWEP_WR_TEEC_EXPORT}/include/tee_client_api.h")
    message(FATAL_ERROR "tee_client_api.h not found below TWEP_WR_TEEC_EXPORT=${TWEP_WR_TEEC_EXPORT}")
  endif()
  target_include_directories(twep_wr PRIVATE
    ${TWEP_WR_TEEC_EXPORT}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../optee/twep-wr-ta/ta/include
  )
  target_link_directories(twep_wr PRIVATE ${TWEP_WR_TEEC_LIB_DIR})
  target_link_options(twep_wr PRIVATE "LINKER:--allow-shlib-undefined")
  target_link_libraries(twep_wr PRIVATE teec)
endif()

target_compile_features(twep_wr PRIVATE c_std_11)
target_compile_options(twep_wr PRIVATE -Wall -Wextra -Werror -fPIC)
target_link_libraries(twep_wr PRIVATE m dl pthread rt crypto)
