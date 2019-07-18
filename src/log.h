#pragma once

#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/syscall.h>

#if defined(__APPLE__)
#  define threadid() pthread_mach_thread_np(pthread_self())
#elif defined(__linux__)
#  define threadid() syscall(__NR_gettid)
#else
#  error "Unknown OS. Only support linux or macos!"
#endif

#define COLOR_RESET "\e[0m"
#define RED_BEGIN  "\e[0;31m"
#define GREEN_BEGIN "\e[0;32m"
#define YELLO_BEGIN "\e[0;33m"

#define DEBUG(fmt, args ...) do { \
	char time_buff[32]; \
	struct timeval tv; \
	struct tm tm; \
	gettimeofday(&tv, NULL); \
	localtime_r(&tv.tv_sec, &tm); \
	snprintf(time_buff, 32, "%04d-%02d-%02d %02d:%02d:%02d.%06d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, (int)tv.tv_usec); \
	fprintf(stdout, "%s %s:%u %ld " GREEN_BEGIN "DEBUG " COLOR_RESET fmt "\n", time_buff, __FILE__, __LINE__, (long)threadid(), ##args); \
	fflush(stdout); \
} while (0)

#define INFO(fmt, args ...) do { \
	char time_buff[32]; \
	struct timeval tv; \
	struct tm tm; \
	gettimeofday(&tv, NULL); \
	localtime_r(&tv.tv_sec, &tm); \
	snprintf(time_buff, 32, "%04d-%02d-%02d %02d:%02d:%02d.%06d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, (int)tv.tv_usec); \
	fprintf(stdout, "%s %s:%u %ld " YELLO_BEGIN "INFO " COLOR_RESET fmt "\n", time_buff, __FILE__, __LINE__, (long)threadid(), ##args); \
	fflush(stdout); \
} while (0)



#define ERROR(fmt, args ...) do { \
	char time_buff[32]; \
	struct timeval tv; \
	struct tm tm; \
	gettimeofday(&tv, NULL); \
	localtime_r(&tv.tv_sec, &tm); \
	snprintf(time_buff, 32, "%04d-%02d-%02d %02d:%02d:%02d.%06d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, (int)tv.tv_usec); \
	fprintf(stderr, "%s %s:%u %ld " RED_BEGIN "ERROR " COLOR_RESET fmt "\n", time_buff, __FILE__, __LINE__, (long)threadid(), ##args); \
	fflush(stderr); \
} while (0)

#define FATAL(fmt, args ...) do { \
	char time_buff[32]; \
	struct timeval tv; \
	struct tm tm; \
	gettimeofday(&tv, NULL); \
	localtime_r(&tv.tv_sec, &tm); \
	snprintf(time_buff, 32, "%04d-%02d-%02d %02d:%02d:%02d.%06d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, (int)tv.tv_usec); \
	fprintf(stderr, "%s %s:%u %ld " RED_BEGIN "FATAL " COLOR_RESET fmt "\n", time_buff, __FILE__, __LINE__, (long)threadid(), ##args); \
	fflush(stderr); \
	exit(-1); \
} while (0)

