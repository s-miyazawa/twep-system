/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <twep_wr_ta.h>

#define TA_UUID TA_TWEP_WR_UUID

/*
 * D043 compare-and-commit is a read-modify-write transaction over shared
 * protected state.  One multi-session TA instance, without
 * TA_FLAG_CONCURRENT, makes OP-TEE serialize command entry while retaining
 * session-owned pending transcripts.
 */
#define TA_FLAGS (TA_FLAG_SINGLE_INSTANCE | TA_FLAG_MULTI_SESSION)
#ifdef TWEP_TA_WAMR_SPIKE_LINK
#define TA_STACK_SIZE (128 * 1024)
#define TA_DATA_SIZE (8 * 1024 * 1024)
#else
#define TA_STACK_SIZE (2 * 1024)
#define TA_DATA_SIZE (32 * 1024)
#endif

#define TA_VERSION "0.1"
#define TA_DESCRIPTION "twep-wr TrustZone scaffold TA"

#endif /* USER_TA_HEADER_DEFINES_H */
