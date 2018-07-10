#pragma once

#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/syscall.h>

#define LL_ERROR   0
#define LL_WARNING 1
#define LL_INFO    2
#define LL_DEBUG   3

#define LOGGER_DEFAULT_FILE_SIZE 5 /* MB */
#define LOGGER_DEFAULT_LEVEL     3

#if defined(__APPLE__)
#  define csnet_threadid() pthread_mach_thread_np(pthread_self())
#elif defined(__linux__)
#  define csnet_threadid() syscall(__NR_gettid)
#else
#  error "Unknown OS. Only support linux or macos!"
#endif

#define debug(fmt, args ...) do { \
	char time_buff[32]; \
	struct timeval tv; \
	struct tm tm; \
	gettimeofday(&tv, NULL); \
	localtime_r(&tv.tv_sec, &tm); \
	snprintf(time_buff, 32, "%04d-%02d-%02d %02d:%02d:%02d.%06d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, (int)tv.tv_usec); \
	fprintf(stderr, "%s %s:%u %5ld debug " fmt "\n", time_buff, __FILE__, __LINE__, (long)csnet_threadid(), ##args); \
	fflush(stderr); \
} while (0)

#define fatal(fmt, args ...) do { \
	char time_buff[32]; \
	struct timeval tv; \
	struct tm tm; \
	gettimeofday(&tv, NULL); \
	localtime_r(&tv.tv_sec, &tm); \
	snprintf(time_buff, 32, "%04d-%02d-%02d %02d:%02d:%02d.%06d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, (int)tv.tv_usec); \
	fprintf(stderr, "%s %s:%u %5ld fatal " fmt "\n", time_buff, __FILE__, __LINE__, (long)csnet_threadid(), ##args); \
	fflush(stderr); \
	exit(-1); \
} while (0)

#define log_d(log, fmt, args ...) do { \
	char time_buff[32]; \
	_format_time(log, time_buff); \
        csnet_log_log(log, LL_DEBUG, "%s %5ld debug %s:%d " fmt "\n", time_buff, (long)csnet_threadid(), __FILE__, __LINE__, ##args); \
} while (0)

#define log_i(log, fmt, args ...) do { \
	char time_buff[32]; \
	_format_time(log, time_buff); \
        csnet_log_log(log, LL_INFO, "%s %5ld  info %s:%d " fmt "\n", time_buff, (long)csnet_threadid(), __FILE__, __LINE__, ##args); \
} while (0)

#define log_w(log, fmt, args ...) do { \
	char time_buff[32]; \
	_format_time(log, time_buff); \
        csnet_log_log(log, LL_WARNING, "%s %5ld  warn %s:%d " fmt "\n", time_buff, (long)csnet_threadid(), __FILE__, __LINE__, ##args); \
} while (0)

#define log_e(log, fmt, args ...) do { \
	char time_buff[32]; \
	_format_time(log, time_buff); \
        csnet_log_log(log, LL_ERROR, "%s %5ld error %s:%d " fmt "\n", time_buff, (long)csnet_threadid(), __FILE__, __LINE__, ##args); \
} while (0)

#define log_f(log, fmt, args ...) do { \
	char time_buff[32]; \
	_format_time(log, time_buff); \
	csnet_log_fatal(log, "%s %5ld fatal %s:%d " fmt "\n", time_buff, (long)csnet_threadid(), __FILE__, __LINE__, ##args); \
} while (0)

struct csnet_log;

void _format_time(struct csnet_log*, char* time_buff);

struct csnet_log* csnet_log_new(const char* logname, int level, long rotate_size);
void csnet_log_log(struct csnet_log*, int level, const char* fmt, ...);
void csnet_log_fatal(struct csnet_log*, const char* fmt, ...);
void csnet_log_free(struct csnet_log*);

