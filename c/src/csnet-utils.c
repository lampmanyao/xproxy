#include "csnet-utils.h"
#include "csnet-log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <openssl/md5.h>

#if defined(__APPLE__)
#include <sys/types.h>
#include <sys/sysctl.h>
#include <mach/thread_act.h>
#endif

int
csnet_file_md5(const char* path, unsigned char* buff) {
	FILE* file = fopen(path, "rb");
	if (!file) {
		return -1;
	}

	MD5_CTX md5_ctx;
	int bytes;
	unsigned char data[1024];

	MD5_Init(&md5_ctx);
	while ((bytes = fread(data, 1, 1024, file)) != 0) {
		MD5_Update(&md5_ctx, data, bytes);
	}
	MD5_Final(buff, &md5_ctx);
	fclose(file);
	return 0;
}

int
csnet_md5(const char* str, unsigned char* buff) {
	MD5_CTX md5_ctx;
	MD5_Init(&md5_ctx);
	MD5_Update(&md5_ctx, str, strlen(str));
	MD5_Final(buff, &md5_ctx);
	return 0;
}

char*
csnet_trim(char* name) {
	char* start_pos = name;
	while ((*start_pos == ' ') || (*start_pos == '\t')) {
		start_pos++;
	}
	if (strlen(start_pos) == 0) {
		return NULL;
	}
	char* end_pos = name + strlen(name) - 1;
	while ((*end_pos == ' ') || (*end_pos == '\t')) {
		*end_pos = 0;
		end_pos--;
	}
	int len = (int)(end_pos - start_pos) + 1;
	if (len <= 0) {
		return NULL;
	}
	return start_pos;
}

void
csnet_oom(unsigned int size) {
	fprintf(stderr, "out of memory trying to allocate %u bytes\n", size);
	fflush(stderr);
	abort();
}

inline int
csnet_online_cpus(void) {
#if defined(__APPLE__)
	int name[2];
	size_t len = 4;
	int32_t count;
	name[0] = CTL_HW;
	name[1] = HW_AVAILCPU;
	sysctl(name, 2, &count, &len, NULL, 0);
	if (count < 1) {
		name[1] = HW_NCPU;
		sysctl(name, 2, &count, &len, NULL, 0);
		if (count < 1) {
			count = 1;
		}
	}
	return count;
#else
	int cores = sysconf(_SC_NPROCESSORS_ONLN);
	return cores > 0 ? cores : 1;
#endif
}

inline int
csnet_bind_to_cpu(pthread_t tid, int cpuid) {
#if defined(__APPLE__)
	mach_port_t mach_tid = pthread_mach_thread_np(tid);
	thread_affinity_policy_data_t policy = { cpuid };
	thread_policy_set(mach_tid, THREAD_AFFINITY_POLICY, (thread_policy_t)&policy, 1);
	return 0;
#else
	cpu_set_t mask;
	CPU_ZERO(&mask);
	CPU_SET(cpuid, &mask);
	return pthread_setaffinity_np(tid, sizeof(mask), &mask);
#endif
}

inline int
csnet_bound_cpuid(pthread_t tid) {
#if defined(__APPLE__)
	mach_port_t mach_tid = pthread_mach_thread_np(tid);
	thread_affinity_policy_data_t policy;
	mach_msg_type_number_t count;
	unsigned int get_default = 0;
	thread_policy_get(mach_tid, THREAD_AFFINITY_POLICY, (thread_policy_t)&policy,
	                  &count, &get_default);
	return policy.affinity_tag;
#else
	cpu_set_t mask;
	CPU_ZERO(&mask);
	pthread_getaffinity_np(tid, sizeof(mask), &mask);
	int online_cpus = csnet_online_cpus();
	for (int i = 0; i < online_cpus; i++) {
		if (CPU_ISSET(i, &mask)) {
			return i;
		}
	}
	return -1;
#endif
}

inline unsigned long
csnet_gettime(void) {
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_sec * 1000000 + tv.tv_usec;
}

void
csnet_coredump_init(void) {
	struct rlimit rlimit;
	rlimit.rlim_cur = RLIM_INFINITY;
	rlimit.rlim_max = RLIM_INFINITY;
	setrlimit(RLIMIT_CORE, &rlimit);
}

int
csnet_openfiles_init(int max) {
	struct rlimit rlimit;
	rlimit.rlim_cur = max;
	rlimit.rlim_max = max;
	return setrlimit(RLIMIT_NOFILE, &rlimit);
}

volatile int running = 1;

static void
ctrlc_handle(int num) {
	if (num == 2) {
		debug("catch SIGINI");
		running = 0;
	}
}

void
csnet_signals_init(void) {
	signal(SIGHUP, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);  /* avoid send() crashes */
	signal(SIGTTOU, SIG_IGN);
	signal(SIGTTIN, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);
	signal(SIGTERM, SIG_IGN);
	//signal(SIGINT,  SIG_IGN);
	signal(SIGINT,  ctrlc_handle);
}

