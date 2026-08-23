/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef TWEP_WAMR_TA_PLATFORM_INTERNAL_H
#define TWEP_WAMR_TA_PLATFORM_INTERNAL_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <tee_internal_api.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef BH_PLATFORM_TWEP_TA
#define BH_PLATFORM_TWEP_TA
#endif
#define BH_APPLET_PRESERVED_STACK_SIZE (32 * 1024)
#define BH_THREAD_DEFAULT_PRIORITY 0
#define os_thread_local_attribute __thread
#define os_getpagesize() 4096
#define os_alloca __builtin_alloca

typedef uintptr_t korp_tid;
typedef struct {
	int locked;
} korp_mutex;
typedef struct {
	int signaled;
} korp_cond;
typedef struct {
	int locked;
} korp_rwlock;
typedef struct {
	int value;
} korp_sem;

#define OS_THREAD_MUTEX_INITIALIZER { 0 }

typedef int os_file_handle;
typedef int os_raw_file_handle;
typedef int os_dir_stream;
typedef int os_poll_file_handle;
typedef unsigned long os_nfds_t;

typedef struct {
	int tv_sec;
	long tv_nsec;
} os_timespec;

static inline long twep_ta_labs(long value)
{
	return value < 0 ? -value : value;
}

#define labs twep_ta_labs

static inline os_file_handle
os_get_invalid_handle(void)
{
	return -1;
}

static inline os_raw_file_handle
os_invalid_raw_handle(void)
{
	return -1;
}

double sqrt(double x);
float sqrtf(float x);
double fabs(double x);
float fabsf(float x);
double ceil(double x);
float ceilf(float x);
double floor(double x);
float floorf(float x);
double trunc(double x);
float truncf(float x);
double rint(double x);
float rintf(float x);
int snprintf(char *str, size_t size, const char *format, ...);
int vsnprintf(char *str, size_t size, const char *format, va_list ap);
void *bsearch(const void *key, const void *base, size_t nmemb, size_t size,
	      int (*compar)(const void *, const void *));
unsigned long long strtoull(const char *nptr, char **endptr, int base);
int strncasecmp(const char *s1, const char *s2, size_t n);
float strtof(const char *nptr, char **endptr);
double strtod(const char *nptr, char **endptr);
int isnan(double value);
int signbit(double value);

#ifdef __cplusplus
}
#endif

#endif
