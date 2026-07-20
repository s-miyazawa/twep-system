/* Copyright (c) 2026 SECOM CO., LTD. All rights reserved. */
/* SPDX-License-Identifier: BSD-2-Clause */

#include "platform_api_extension.h"
#include "platform_api_vmcore.h"

int bh_platform_init(void)
{
	return 0;
}

void bh_platform_destroy(void)
{
}

void *os_malloc(unsigned size)
{
	return TEE_Malloc(size, 0);
}

void *os_realloc(void *ptr, unsigned size)
{
	return TEE_Realloc(ptr, size);
}

void os_free(void *ptr)
{
	TEE_Free(ptr);
}

int os_printf(const char *format, ...)
{
	(void)format;
	return 0;
}

int os_vprintf(const char *format, va_list ap)
{
	(void)format;
	(void)ap;
	return 0;
}

int snprintf(char *str, size_t size, const char *format, ...)
{
	(void)format;
	if (size > 0)
		str[0] = '\0';
	return 0;
}

int vsnprintf(char *str, size_t size, const char *format, va_list ap)
{
	(void)format;
	(void)ap;
	if (size > 0)
		str[0] = '\0';
	return 0;
}

void *bsearch(const void *key, const void *base, size_t nmemb, size_t size,
	      int (*compar)(const void *, const void *))
{
	const uint8_t *items = base;
	size_t low = 0;
	size_t high = nmemb;

	while (low < high) {
		size_t mid = low + ((high - low) / 2);
		const void *candidate = items + (mid * size);
		int cmp = compar(key, candidate);

		if (cmp == 0)
			return (void *)candidate;
		if (cmp < 0)
			high = mid;
		else
			low = mid + 1;
	}
	return NULL;
}

unsigned long long strtoull(const char *nptr, char **endptr, int base)
{
	unsigned long long value = 0;
	const char *p = nptr;

	(void)base;
	while (*p >= '0' && *p <= '9') {
		value = (value * 10) + (unsigned long long)(*p - '0');
		p++;
	}
	if (endptr)
		*endptr = (char *)p;
	return value;
}

int strncasecmp(const char *s1, const char *s2, size_t n)
{
	size_t i = 0;

	for (i = 0; i < n; i++) {
		unsigned char c1 = (unsigned char)s1[i];
		unsigned char c2 = (unsigned char)s2[i];

		if (c1 >= 'A' && c1 <= 'Z')
			c1 = (unsigned char)(c1 - 'A' + 'a');
		if (c2 >= 'A' && c2 <= 'Z')
			c2 = (unsigned char)(c2 - 'A' + 'a');
		if (c1 != c2)
			return (int)c1 - (int)c2;
		if (c1 == '\0')
			return 0;
	}
	return 0;
}

float strtof(const char *nptr, char **endptr)
{
	if (endptr)
		*endptr = (char *)nptr;
	return 0;
}

double strtod(const char *nptr, char **endptr)
{
	if (endptr)
		*endptr = (char *)nptr;
	return 0;
}

int twep_ta_isnan(double value)
{
	return value != value;
}

uint64 os_time_get_boot_us(void)
{
	TEE_Time time = { };

	TEE_GetSystemTime(&time);
	return ((uint64)time.seconds * 1000000) + ((uint64)time.millis * 1000);
}

uint64 os_time_thread_cputime_us(void)
{
	return os_time_get_boot_us();
}

korp_tid os_self_thread(void)
{
	return 1;
}

uint8 *os_thread_get_stack_boundary(void)
{
	return NULL;
}

void os_thread_jit_write_protect_np(bool enabled)
{
	(void)enabled;
}

int os_mutex_init(korp_mutex *mutex)
{
	mutex->locked = 0;
	return 0;
}

int os_recursive_mutex_init(korp_mutex *mutex)
{
	return os_mutex_init(mutex);
}

int os_mutex_destroy(korp_mutex *mutex)
{
	(void)mutex;
	return 0;
}

int os_mutex_lock(korp_mutex *mutex)
{
	mutex->locked = 1;
	return 0;
}

int os_mutex_unlock(korp_mutex *mutex)
{
	mutex->locked = 0;
	return 0;
}

void *os_mmap(void *hint, size_t size, int prot, int flags, os_file_handle file)
{
	void *addr;

	(void)hint;
	(void)prot;
	(void)flags;
	(void)file;
	addr = TEE_Malloc(size, 0);
	if (addr)
		TEE_MemFill(addr, 0, size);
	return addr;
}

void os_munmap(void *addr, size_t size)
{
	(void)size;
	TEE_Free(addr);
}

int os_mprotect(void *addr, size_t size, int prot)
{
	(void)addr;
	(void)size;
	(void)prot;
	return 0;
}

void *os_mremap(void *old_addr, size_t old_size, size_t new_size)
{
	void *new_addr = TEE_Malloc(new_size, 0);

	if (!new_addr)
		return NULL;
	TEE_MemMove(new_addr, old_addr, old_size < new_size ? old_size : new_size);
	TEE_Free(old_addr);
	return new_addr;
}

void os_dcache_flush(void)
{
}

void os_icache_flush(void *start, size_t len)
{
	(void)start;
	(void)len;
}

int os_thread_create(korp_tid *p_tid, thread_start_routine_t start, void *arg,
		     unsigned int stack_size)
{
	(void)p_tid;
	(void)start;
	(void)arg;
	(void)stack_size;
	return -1;
}

int os_thread_create_with_prio(korp_tid *p_tid, thread_start_routine_t start,
			       void *arg, unsigned int stack_size, int prio)
{
	(void)prio;
	return os_thread_create(p_tid, start, arg, stack_size);
}

int os_thread_join(korp_tid thread, void **retval)
{
	(void)thread;
	(void)retval;
	return -1;
}

int os_thread_detach(korp_tid thread)
{
	(void)thread;
	return -1;
}

void os_thread_exit(void *retval)
{
	(void)retval;
}

int os_thread_env_init(void)
{
	return 0;
}

void os_thread_env_destroy(void)
{
}

bool os_thread_env_inited(void)
{
	return true;
}

int os_usleep(uint32 usec)
{
	(void)usec;
	return 0;
}

int os_cond_init(korp_cond *cond)
{
	cond->signaled = 0;
	return 0;
}

int os_cond_destroy(korp_cond *cond)
{
	(void)cond;
	return 0;
}

int os_cond_wait(korp_cond *cond, korp_mutex *mutex)
{
	(void)cond;
	(void)mutex;
	return 0;
}

int os_cond_reltimedwait(korp_cond *cond, korp_mutex *mutex, uint64 useconds)
{
	(void)useconds;
	return os_cond_wait(cond, mutex);
}

int os_cond_signal(korp_cond *cond)
{
	cond->signaled = 1;
	return 0;
}

int os_cond_broadcast(korp_cond *cond)
{
	return os_cond_signal(cond);
}

int os_rwlock_init(korp_rwlock *lock)
{
	lock->locked = 0;
	return 0;
}

int os_rwlock_rdlock(korp_rwlock *lock)
{
	lock->locked = 1;
	return 0;
}

int os_rwlock_wrlock(korp_rwlock *lock)
{
	return os_rwlock_rdlock(lock);
}

int os_rwlock_unlock(korp_rwlock *lock)
{
	lock->locked = 0;
	return 0;
}

int os_rwlock_destroy(korp_rwlock *lock)
{
	(void)lock;
	return 0;
}

korp_sem *os_sem_open(const char *name, int oflags, int mode, int val)
{
	korp_sem *sem;

	(void)name;
	(void)oflags;
	(void)mode;
	sem = TEE_Malloc(sizeof(*sem), 0);
	if (!sem)
		return NULL;
	sem->value = val;
	return sem;
}

int os_sem_close(korp_sem *sem)
{
	TEE_Free(sem);
	return 0;
}

int os_sem_wait(korp_sem *sem)
{
	if (sem->value > 0)
		sem->value--;
	return 0;
}

int os_sem_trywait(korp_sem *sem)
{
	return os_sem_wait(sem);
}

int os_sem_post(korp_sem *sem)
{
	sem->value++;
	return 0;
}

int os_sem_getvalue(korp_sem *sem, int *sval)
{
	*sval = sem->value;
	return 0;
}

int os_sem_unlink(const char *name)
{
	(void)name;
	return 0;
}

int os_blocking_op_init(void)
{
	return 0;
}

void os_begin_blocking_op(void)
{
}

void os_end_blocking_op(void)
{
}

int os_wakeup_blocking_op(korp_tid tid)
{
	(void)tid;
	return -1;
}

int os_dumps_proc_mem_info(char *out, unsigned int size)
{
	(void)out;
	(void)size;
	return -1;
}
