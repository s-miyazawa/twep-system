# Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause

set(PLATFORM_SHARED_DIR ${CMAKE_CURRENT_LIST_DIR})

add_definitions(-DBH_PLATFORM_TWEP_TA)

include_directories(${PLATFORM_SHARED_DIR})
include_directories(${WAMR_ROOT_DIR}/core/shared/platform/include)

set(PLATFORM_SHARED_SOURCE
  ${PLATFORM_SHARED_DIR}/twep_ta_platform.c
  ${WAMR_ROOT_DIR}/core/shared/platform/common/math/math.c
)
