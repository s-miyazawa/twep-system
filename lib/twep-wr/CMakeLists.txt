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
set(TWEP_WR_PLATFORM_SOURCE "")
if(TWEP_WR_PLATFORM_BACKEND STREQUAL "linux")
  set(TWEP_WR_PLATFORM_SOURCE src/platform/linux/platform_linux.c)
elseif(TWEP_WR_PLATFORM_BACKEND STREQUAL "trustzone")
  set(TWEP_WR_PLATFORM_SOURCE
        src/platform/trustzone/platform_trustzone.c
        src/platform/trustzone/trustzone_artifacts.c
        src/platform/trustzone/trustzone_candidate.c
        src/platform/trustzone/trustzone_diagnostics.c
        src/platform/trustzone/trustzone_envelope.c
        src/platform/trustzone/trustzone_host_io.c
        src/platform/trustzone/trustzone_session_storage.c
        src/platform/trustzone/trustzone_storage.c
        src/platform/trustzone/trustzone_transport.c
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

target_include_directories(twep_wr PRIVATE
  include
  src
  ${WAMR_ROOT_DIR}/core/iwasm/include
)

if(TWEP_WR_PLATFORM_BACKEND STREQUAL "trustzone")
  target_compile_definitions(twep_wr PRIVATE TWEP_WR_PLATFORM_BACKEND_TRUSTZONE=1)
  set(TWEP_WR_TEEC_EXPORT "$ENV{HOME}/opt/optee/out-br/host/aarch64-buildroot-linux-gnu/sysroot/usr" CACHE PATH "OP-TEE client export prefix for TrustZone backend")
  set(TWEP_WR_TEEC_LIB_DIR "${TWEP_WR_TEEC_EXPORT}/lib" CACHE PATH "OP-TEE libteec directory for TrustZone backend")
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
