#pragma once

#include <pthread.h>

char* csnet_trim(char* name);
void csnet_oom(unsigned int size);
int csnet_online_cpus(void);
int csnet_bind_to_cpu(pthread_t tid, int cpuid);
int csnet_bound_cpuid(pthread_t tid);
int csnet_md5sum(const char* path, unsigned char* buff);
unsigned long csnet_gettime(void);
void csnet_coredump_init(void);
int csnet_openfiles_init(int max);
void csnet_signals_init(void);

