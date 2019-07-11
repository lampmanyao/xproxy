#pragma once

#include <pthread.h>

/*
 * See GCC-5.2 manual
 * 6.57 Other Built-in Functions Provided by GCC
 *  long __builtin_expect (long exp, long c)
 * for more details.
 */

#if defined __GUN__
# define fast(x) __builtin_expect(!!(x), 1)
# define slow(x) __builtin_expect(!!(x), 0)
#else
# define fast(x) (x)
# define slow(x) (x)
#endif

int set_nonblocking(int sfd);
int listen_and_bind(const char * address, int port);
int connect_without_timeout(const char *host, int port);
int connect_with_timeout(const char *host, int port, int milliseconds);
void wait_milliseconds(int milliseconds);

void oom(unsigned int size);
int online_cpus(void);
int bind_to_cpu(pthread_t tid, int cpuid);
int bound_cpuid(pthread_t tid);
long gettime(void);
void coredump_init(void);
int openfiles_init(long);
void signals_init(void);

