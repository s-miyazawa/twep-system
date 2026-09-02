# Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause

# CMake requires enable_testing() in directory scope so that ctest can find the
# top-level CTestTestfile.cmake; add_test() remains inside the configuration
# function with the rest of the SGX backend-test definition.
if(TWEP_WR_SGX_BACKEND_TESTS)
  enable_testing()
endif()

function(twep_wr_configure_sgx_backend target source_root binary_root)
  if(NOT TARGET "${target}")
    message(FATAL_ERROR "SGX backend target does not exist: ${target}")
  endif()
  if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "SGX currently requires x86_64")
  endif()

  set(SGX_EDGER8R "${TWEP_WR_SGX_SDK}/bin/x64/sgx_edger8r")
  set(SGX_SIGN "${TWEP_WR_SGX_SDK}/bin/x64/sgx_sign")
  set(SGX_LIB_DIR "${TWEP_WR_SGX_SDK}/lib64")
  set(SGX_GENERATED_DIR "${binary_root}/sgx-generated")
  set(SGX_ENCLAVE_DIR "${source_root}/src/platform/sgx/enclave")
  set(SGX_EDL_DIR "${binary_root}/sgx-edl")
  file(MAKE_DIRECTORY "${SGX_EDL_DIR}")
  if(TWEP_WR_SGX_TEST_HOOKS)
    configure_file("${SGX_ENCLAVE_DIR}/twep_wr_sgx_test.edl"
                   "${SGX_EDL_DIR}/twep_wr_sgx.edl" COPYONLY)
  else()
    file(READ "${SGX_ENCLAVE_DIR}/twep_wr_sgx.edl" SGX_PRODUCTION_EDL)
    if(SGX_PRODUCTION_EDL MATCHES "ecall_test_")
      message(FATAL_ERROR
        "production SGX EDL must not expose private test ECALLs")
    endif()
    configure_file("${SGX_ENCLAVE_DIR}/twep_wr_sgx.edl"
                   "${SGX_EDL_DIR}/twep_wr_sgx.edl" COPYONLY)
  endif()
  set(SGX_EDL "${SGX_EDL_DIR}/twep_wr_sgx.edl")

  set(SGX_WAMR_REQUIRED_PATHS
      "product-mini/platforms/linux-sgx/CMakeLists.txt"
      "core/iwasm/include/wasm_export.h"
      "core/shared/utils/bh_platform.h"
      "core/shared/platform/linux-sgx/platform_internal.h")
  foreach(required_path IN LISTS SGX_WAMR_REQUIRED_PATHS)
    if(NOT EXISTS "${WAMR_ROOT_DIR}/${required_path}")
      message(FATAL_ERROR
        "SGX Enclave build requires a WAMR source tree with the linux-sgx "
        "layout; missing '${required_path}' below WAMR_ROOT_DIR="
        "'${WAMR_ROOT_DIR}'")
    endif()
  endforeach()
  set(SGX_WAMR_COPY_DIR "${binary_root}/sgx-wamr-source")
  set(SGX_WAMR_SOURCE_DIR
      "${SGX_WAMR_COPY_DIR}/product-mini/platforms/linux-sgx")
  set(SGX_WAMR_BUILD_DIR "${binary_root}/sgx-wamr")
  set(SGX_WAMR_TRUSTED_LIB "${SGX_WAMR_BUILD_DIR}/libvmlib.a")
  set(SGX_WAMR_UNTRUSTED_LIB "${SGX_WAMR_BUILD_DIR}/libvmlib_untrusted.a")

  if(NOT TWEP_WR_SGX_BACKEND_TESTS)
    find_library(SGX_URTS_LIB NAMES sgx_urts
      PATHS "/usr/lib/${CMAKE_LIBRARY_ARCHITECTURE}"
            "/lib/${CMAKE_LIBRARY_ARCHITECTURE}"
      NO_DEFAULT_PATH)
    if(NOT SGX_URTS_LIB)
      message(FATAL_ERROR "SGX requires the system PSW libsgx_urts")
    endif()
    set(SGX_TRTS_LIB sgx_trts)
    set(SGX_TSERVICE_LIB sgx_tservice)
  else()
    set(SGX_URTS_LIB "${SGX_LIB_DIR}/libsgx_urts_sim.so")
    set(SGX_TRTS_LIB sgx_trts_sim)
    set(SGX_TSERVICE_LIB sgx_tservice_sim)
  endif()
  foreach(required ${SGX_EDGER8R} ${SGX_SIGN} "${SGX_URTS_LIB}")
    if(NOT EXISTS "${required}")
      message(FATAL_ERROR "SGX dependency not found: ${required}")
    endif()
  endforeach()

  file(MAKE_DIRECTORY "${SGX_GENERATED_DIR}")
  execute_process(
    COMMAND "${SGX_EDGER8R}" --untrusted "${SGX_EDL}"
            --search-path "${SGX_ENCLAVE_DIR}"
            --search-path "${TWEP_WR_SGX_SDK}/include"
            --search-path "${WAMR_ROOT_DIR}/core/shared/platform/linux-sgx"
            --untrusted-dir "${SGX_GENERATED_DIR}"
    RESULT_VARIABLE SGX_EDGER8R_UNTRUSTED_RESULT)
  if(NOT SGX_EDGER8R_UNTRUSTED_RESULT EQUAL 0)
    message(FATAL_ERROR "SGX edger8r untrusted bridge generation failed")
  endif()
  execute_process(
    COMMAND "${SGX_EDGER8R}" --trusted "${SGX_EDL}"
            --search-path "${SGX_ENCLAVE_DIR}"
            --search-path "${TWEP_WR_SGX_SDK}/include"
            --search-path "${WAMR_ROOT_DIR}/core/shared/platform/linux-sgx"
            --trusted-dir "${SGX_GENERATED_DIR}"
    RESULT_VARIABLE SGX_EDGER8R_TRUSTED_RESULT)
  if(NOT SGX_EDGER8R_TRUSTED_RESULT EQUAL 0)
    message(FATAL_ERROR "SGX edger8r trusted bridge generation failed")
  endif()

  add_custom_command(
    OUTPUT "${SGX_WAMR_TRUSTED_LIB}" "${SGX_WAMR_UNTRUSTED_LIB}"
    COMMAND "${CMAKE_COMMAND}" -E rm -rf "${SGX_WAMR_COPY_DIR}"
    COMMAND "${CMAKE_COMMAND}" -E copy_directory
            "${WAMR_ROOT_DIR}" "${SGX_WAMR_COPY_DIR}"
    COMMAND "${CMAKE_COMMAND}" -S "${SGX_WAMR_SOURCE_DIR}"
            -B "${SGX_WAMR_BUILD_DIR}"
            -DWAMR_BUILD_INTERP=1 -DWAMR_BUILD_AOT=0 -DWAMR_BUILD_JIT=0
            -DWAMR_BUILD_LIBC_BUILTIN=1 -DWAMR_BUILD_LIBC_WASI=0
            -DWAMR_BUILD_FAST_INTERP=0 -DWAMR_BUILD_MULTI_MODULE=0
            -DWAMR_BUILD_SHARED_MEMORY=0 -DWAMR_BUILD_THREAD_MGR=0
            -DWAMR_BUILD_LIB_PTHREAD=0
            -DWAMR_BUILD_INSTRUCTION_METERING=1
    COMMAND "${CMAKE_COMMAND}" --build "${SGX_WAMR_BUILD_DIR}"
    COMMENT "Building SGX trusted WAMR for linux-sgx")
  add_custom_target(twep_wr_sgx_wamr
    DEPENDS "${SGX_WAMR_TRUSTED_LIB}" "${SGX_WAMR_UNTRUSTED_LIB}")

  set(SGX_TRUSTED_SOURCES
      twep_wr_sgx_enclave.c
      sgx_sealed_store.c
      sgx_protected_state_common.c
      sgx_acceptance_state.c
      sgx_protected_catalog.c
      sgx_protected_app.c
      sgx_dcap_evidence.c
      sgx_catalog.c
      sgx_wasm_signature.c
      sgx_teep_runtime.c
      sgx_app_runtime.c)
  set(SGX_TRUSTED_OBJECTS "")
  foreach(SGX_TRUSTED_SOURCE IN LISTS SGX_TRUSTED_SOURCES)
    string(REGEX REPLACE "\\.c$" ".o" SGX_TRUSTED_OBJECT_NAME
           "${SGX_TRUSTED_SOURCE}")
    list(APPEND SGX_TRUSTED_OBJECTS
         "${SGX_GENERATED_DIR}/${SGX_TRUSTED_OBJECT_NAME}")
    add_custom_command(
      OUTPUT "${SGX_GENERATED_DIR}/${SGX_TRUSTED_OBJECT_NAME}"
      COMMAND "${CMAKE_C_COMPILER}" -c
              "${SGX_ENCLAVE_DIR}/${SGX_TRUSTED_SOURCE}"
              -o "${SGX_GENERATED_DIR}/${SGX_TRUSTED_OBJECT_NAME}"
              -nostdinc -fvisibility=hidden -fpie -fstack-protector-strong
              -ffunction-sections -fdata-sections
              -I"${SGX_ENCLAVE_DIR}"
              -I"${SGX_GENERATED_DIR}" -I"${TWEP_WR_SGX_SDK}/include"
              -I"${TWEP_WR_SGX_SDK}/include/tlibc"
              -I"${WAMR_ROOT_DIR}/core/iwasm/include"
              -I"${WAMR_ROOT_DIR}/core/shared/utils"
              -I"${WAMR_ROOT_DIR}/core/shared/platform/linux-sgx"
              -DWASM_ENABLE_LIBC_WASI=0
              $<$<NOT:$<BOOL:${TWEP_WR_SGX_BACKEND_TESTS}>>:-DTWEP_WR_SGX_HW=1>
              $<$<BOOL:${TWEP_WR_SGX_TEST_HOOKS}>:-DTWEP_WR_SGX_TEST_HOOKS=1>
      DEPENDS "${SGX_ENCLAVE_DIR}/${SGX_TRUSTED_SOURCE}"
              "${SGX_ENCLAVE_DIR}/sgx_runtime_internal.h"
              "${SGX_ENCLAVE_DIR}/sgx_protected_state_internal.h"
              "${SGX_GENERATED_DIR}/twep_wr_sgx_t.h")
  endforeach()

  set(SGX_BRIDGE_OBJECT "${SGX_GENERATED_DIR}/twep_wr_sgx_t.o")
  set(SGX_UNSIGNED_ENCLAVE "${binary_root}/twep_wr_sgx.so")
  set(SGX_SIGNING_KEY "${binary_root}/twep_wr_sgx_dev_signing_key.pem")
  set(SGX_SIGNED_ENCLAVE "${binary_root}/twep_wr_sgx.signed.so")
  add_custom_command(
    OUTPUT "${SGX_BRIDGE_OBJECT}"
    COMMAND "${CMAKE_C_COMPILER}" -c
            "${SGX_GENERATED_DIR}/twep_wr_sgx_t.c"
            -o "${SGX_BRIDGE_OBJECT}"
            -nostdinc -fvisibility=hidden -fpie -fstack-protector-strong
            -ffunction-sections -fdata-sections
            -I"${SGX_GENERATED_DIR}" -I"${TWEP_WR_SGX_SDK}/include"
            -I"${TWEP_WR_SGX_SDK}/include/tlibc"
    DEPENDS "${SGX_GENERATED_DIR}/twep_wr_sgx_t.c")
  add_custom_command(
    OUTPUT "${SGX_UNSIGNED_ENCLAVE}"
    COMMAND "${CMAKE_C_COMPILER}" ${SGX_TRUSTED_OBJECTS} "${SGX_BRIDGE_OBJECT}"
            "${SGX_WAMR_TRUSTED_LIB}"
            -o "${SGX_UNSIGNED_ENCLAVE}"
            -Wl,-z,relro,-z,now,-z,noexecstack -Wl,--no-undefined
            -nostdlib -nodefaultlibs -nostartfiles -L"${SGX_LIB_DIR}"
            -Wl,--whole-archive -l${SGX_TRTS_LIB} -Wl,--no-whole-archive
            -Wl,--start-group -lsgx_tstdc -lsgx_tcrypto
            -l${SGX_TSERVICE_LIB} -Wl,--end-group
            -Wl,-Bstatic -Wl,-Bsymbolic -Wl,-pie,-eenclave_entry
            -Wl,--export-dynamic -Wl,--defsym,__ImageBase=0
            -Wl,--gc-sections
            -Wl,--version-script=${SGX_ENCLAVE_DIR}/twep_wr_sgx.lds
    DEPENDS ${SGX_TRUSTED_OBJECTS} "${SGX_BRIDGE_OBJECT}"
            "${SGX_WAMR_TRUSTED_LIB}"
            "${SGX_ENCLAVE_DIR}/twep_wr_sgx.lds")

  if(NOT TWEP_WR_SGX_BACKEND_TESTS AND NOT TWEP_WR_SGX_HW_DEBUG)
    if(NOT TWEP_WR_SGX_SIGNED_ENCLAVE)
      message(FATAL_ERROR "HW release build requires TWEP_WR_SGX_SIGNED_ENCLAVE")
    endif()
    set(SGX_SIGNED_ENCLAVE "${TWEP_WR_SGX_SIGNED_ENCLAVE}")
  else()
    add_custom_command(
      OUTPUT "${SGX_SIGNING_KEY}"
      COMMAND openssl genrsa -3 -out "${SGX_SIGNING_KEY}" 3072
      COMMENT "Generating disposable SGX debug enclave signing key")
    add_custom_command(
      OUTPUT "${SGX_SIGNED_ENCLAVE}"
      COMMAND "${SGX_SIGN}" sign -key "${SGX_SIGNING_KEY}"
              -enclave "${SGX_UNSIGNED_ENCLAVE}"
              -out "${SGX_SIGNED_ENCLAVE}"
              -config "${SGX_ENCLAVE_DIR}/twep_wr_sgx.config.xml"
      DEPENDS "${SGX_UNSIGNED_ENCLAVE}" "${SGX_SIGNING_KEY}"
              "${SGX_ENCLAVE_DIR}/twep_wr_sgx.config.xml")
  endif()
  add_custom_target(twep_wr_sgx_enclave ALL DEPENDS "${SGX_SIGNED_ENCLAVE}")
  add_dependencies(twep_wr_sgx_enclave twep_wr_sgx_wamr)

  target_sources("${target}" PRIVATE
    "${source_root}/src/platform/sgx/platform_sgx.c"
    "${source_root}/src/platform/sgx/sgx_platform_compat.c"
    "${SGX_GENERATED_DIR}/twep_wr_sgx_u.c")
  add_dependencies("${target}" twep_wr_sgx_enclave)
  target_include_directories("${target}" PRIVATE
    "${SGX_GENERATED_DIR}"
    "${TWEP_WR_SGX_SDK}/include")
  target_compile_definitions("${target}" PRIVATE
    TWEP_WR_PLATFORM_BACKEND_SGX=1
    TWEP_WR_SGX_ENCLAVE_PATH="${SGX_SIGNED_ENCLAVE}"
    TWEP_WR_NO_REE_WAMR=1)
  if(NOT TWEP_WR_SGX_BACKEND_TESTS)
    target_compile_definitions("${target}" PRIVATE
      TWEP_WR_SGX_HW=1
      TWEP_WR_SGX_DEBUG=$<BOOL:${TWEP_WR_SGX_HW_DEBUG}>)
  else()
    target_compile_definitions("${target}" PRIVATE TWEP_WR_SGX_DEBUG=1)
  endif()
  if(TWEP_WR_SGX_TEST_HOOKS)
    target_compile_definitions("${target}" PRIVATE TWEP_WR_SGX_TEST_HOOKS=1)
  endif()
  target_link_libraries("${target}" PUBLIC
    "${SGX_WAMR_UNTRUSTED_LIB}"
    "${SGX_URTS_LIB}")
  if(TWEP_WR_SGX_BACKEND_TESTS)
    target_link_libraries("${target}" PUBLIC
      "${SGX_LIB_DIR}/libsgx_uae_service_sim.so")
    set_target_properties("${target}" PROPERTIES BUILD_RPATH "${SGX_LIB_DIR}")
  else()
    target_include_directories("${target}" PRIVATE /usr/include)
    target_link_libraries("${target}" PUBLIC sgx_dcap_ql)
  endif()

  if(TWEP_WR_SGX_BACKEND_TESTS)
    add_executable(sgx_backend_test "${source_root}/tests/sgx_backend_test.c")
    target_include_directories(sgx_backend_test PRIVATE
      "${source_root}/include" "${source_root}/src"
      "${WAMR_ROOT_DIR}/core/iwasm/include")
    target_compile_features(sgx_backend_test PRIVATE c_std_11)
    target_compile_options(sgx_backend_test PRIVATE -Wall -Wextra -Werror)
    target_compile_definitions(sgx_backend_test PRIVATE
      TWEP_WR_PLATFORM_BACKEND_SGX=1
      TWEP_WR_SGX_ENCLAVE_PATH="${SGX_SIGNED_ENCLAVE}"
      TWEP_WR_TEST_ARTIFACT_DIR="${TWEP_WR_TEST_ARTIFACT_DIR}"
      TWEP_WR_TESTDATA_DIR="${source_root}/../../testdata")
    if(TWEP_WR_SGX_TEST_HOOKS)
      target_compile_definitions(sgx_backend_test PRIVATE TWEP_WR_SGX_TEST_HOOKS=1)
    endif()
    target_link_libraries(sgx_backend_test PRIVATE "${target}" crypto)
    set_target_properties(sgx_backend_test PROPERTIES BUILD_RPATH "${SGX_LIB_DIR}")
    add_test(NAME sgx_backend_lifecycle COMMAND sgx_backend_test all)
    set_tests_properties(sgx_backend_lifecycle PROPERTIES
      ENVIRONMENT "LD_LIBRARY_PATH=${SGX_LIB_DIR}:$ENV{LD_LIBRARY_PATH}")
    foreach(SGX_SCENARIO
        execute-helloworld execute-calcadd execute-negaposi teep-agent-resolve
        hostcall-negative resource-limit-negative output-limit-negative
        cleanup-negative wasm-signature-negative app-hash-negative)
      string(REPLACE "-" "_" SGX_TEST_SUFFIX "${SGX_SCENARIO}")
      add_test(NAME "sgx_backend_${SGX_TEST_SUFFIX}"
        COMMAND sgx_backend_test "${SGX_SCENARIO}")
      set_tests_properties("sgx_backend_${SGX_TEST_SUFFIX}" PROPERTIES
        ENVIRONMENT "LD_LIBRARY_PATH=${SGX_LIB_DIR}:$ENV{LD_LIBRARY_PATH}")
    endforeach()
    if(TWEP_WR_SGX_TEST_HOOKS)
      add_test(NAME sgx_backend_protected_offline
        COMMAND sgx_backend_test protected-offline)
      set_tests_properties(sgx_backend_protected_offline PROPERTIES
        ENVIRONMENT "LD_LIBRARY_PATH=${SGX_LIB_DIR}:$ENV{LD_LIBRARY_PATH}")
      add_test(NAME sgx_backend_dcap_evidence
        COMMAND sgx_backend_test dcap-evidence)
      set_tests_properties(sgx_backend_dcap_evidence PROPERTIES
        ENVIRONMENT "LD_LIBRARY_PATH=${SGX_LIB_DIR}:$ENV{LD_LIBRARY_PATH}")
      add_test(NAME sgx_backend_transcript_commit
        COMMAND sgx_backend_test transcript-commit)
      set_tests_properties(sgx_backend_transcript_commit PROPERTIES
        ENVIRONMENT "LD_LIBRARY_PATH=${SGX_LIB_DIR}:$ENV{LD_LIBRARY_PATH}")
      add_test(NAME sgx_backend_agent_measurement
        COMMAND sgx_backend_test agent-measurement)
      set_tests_properties(sgx_backend_agent_measurement PROPERTIES
        ENVIRONMENT "LD_LIBRARY_PATH=${SGX_LIB_DIR}:$ENV{LD_LIBRARY_PATH}")
    endif()
  else()
    find_package(CURL REQUIRED)
    add_executable(sgx_hw_runner "${source_root}/tests/sgx_hw_runner.c")
    target_include_directories(sgx_hw_runner PRIVATE "${source_root}/include")
    target_compile_features(sgx_hw_runner PRIVATE c_std_11)
    target_compile_options(sgx_hw_runner PRIVATE -Wall -Wextra -Werror)
    target_link_libraries(sgx_hw_runner PRIVATE "${target}" CURL::libcurl)
  endif()
endfunction()
