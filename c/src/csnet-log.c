#include "csnet-log.h"
#include "csnet-cond.h"
#include "csnet-fast.h"
#include "csnet-utils.h"
#include "csnet-spinlock.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <time.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <stdarg.h>
#include <pthread.h>

#define BUFFER_SIZE  (1024 * 1024)  /* 1M easy for rotate */
#define BUFFER_LEN   4096
#define LOG_NAME_LEN 1024
#define N_ELEMENTS   100

typedef struct log_buffer {
	int seek;
	int remain;
	char data[BUFFER_SIZE];
	struct log_buffer* next;
} log_buffer_t;

struct csnet_log {
	pthread_t tid;
	int level;
	csnet_spinlock_t lock;
	int rotate_size;
	int fseek;
	int fd;
	time_t last_sec;
	char last_timestamp[20];
	char logname[LOG_NAME_LEN];
	struct csnet_cond cond;
	log_buffer_t* head;
	log_buffer_t* tail;
	log_buffer_t** buffers;
};

static inline log_buffer_t*
_malloc_log_buffer(void) {
	log_buffer_t* b = NULL;
	b = calloc(1, sizeof(log_buffer_t));

	if (!b) {
		csnet_oom(sizeof(log_buffer_t));
	}

	b->seek = 0;
	b->remain = BUFFER_SIZE;
	b->next = NULL;
	return b;
}

static inline void
_append(log_buffer_t* log_buffer, const char* msg, int _len) {
	if (csnet_slow(!log_buffer)) {
		return;
	}
	memcpy(log_buffer->data + log_buffer->seek, msg, _len);
	log_buffer->seek += _len;
	log_buffer->remain -= _len;
}

static inline log_buffer_t**
_create_log_buffers(void) {
	log_buffer_t** arr = calloc(N_ELEMENTS, sizeof(log_buffer_t*));
	if (!arr) {
		csnet_oom(N_ELEMENTS * sizeof(log_buffer_t*));
	}

	for (int i = 0; i < N_ELEMENTS; i++) {
		log_buffer_t* b = _malloc_log_buffer();
		arr[i] = b;
	}

	arr[N_ELEMENTS - 1]->next = arr[0];
	for (int i = 0; i < N_ELEMENTS - 1; i++) {
		arr[i]->next = arr[i + 1];
	}

	return arr;
}

static inline void
_free_log_buffers(log_buffer_t** arr) {
	assert(arr);
	for (int i = 0; i < N_ELEMENTS; i++) {
		free(arr[i]);
	}
	free(arr);
}

static inline int
_create_new_file(struct csnet_log* log) {
	assert(log);
	close(log->fd);
	char path[2048];
	struct timeval tv;
	struct tm tm;

	gettimeofday(&tv, NULL);
	localtime_r(&tv.tv_sec, &tm);
	snprintf(path, 2048, "%s-%04d%02d%02d-%02d-%02d-%02d-%06d.log",
		log->logname,
		tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour,
		tm.tm_min, tm.tm_sec, (int)tv.tv_usec);
	log->fd = open(path, O_RDWR | O_CREAT | O_APPEND, 0644);

	if (log->fd == -1) {
		debug("open");
		return -1;
	}

	log->fseek = 0;

	return 0;
}

inline void
_format_time(struct csnet_log* log, char* time_buff) {
	assert(log);
	struct timeval tv;
	gettimeofday(&tv, NULL);

	if (tv.tv_sec != log->last_sec) {
		struct tm tm;
		localtime_r(&tv.tv_sec, &tm);
		snprintf(log->last_timestamp, 20, "%04d-%02d-%02d %02d:%02d:%02d",
			tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
			tm.tm_hour, tm.tm_min, tm.tm_sec);
		log->last_sec = tv.tv_sec;
	}

	sprintf(time_buff, "%s.%06d", log->last_timestamp, (int)tv.tv_usec);
}

static void*
csnet_log_flush_to_disk_thread(void* arg) {
	struct csnet_log* log = (struct csnet_log*)arg;
	while (1) {
		if (log->head == log->tail) {
			csnet_cond_nonblocking_wait(&log->cond, 1, 0);
		}

		csnet_spinlock_lock(&log->lock);
		log->fseek += write(log->fd, log->head->data, log->head->seek);
		if (log->fseek >= log->rotate_size) {
			_create_new_file(log);
		}

		log->head->seek = 0;
		log->head->remain = BUFFER_SIZE;
		log->head = log->head->next;
		csnet_spinlock_unlock(&log->lock);
	}
	debug("csnet_log_flush_to_disk_thread exit");
	return NULL;
}

struct csnet_log*
csnet_log_new(const char* logname, int level, long rotate_size) {
	struct csnet_log* log = calloc(1, sizeof(struct csnet_log));
	csnet_spinlock_init(&log->lock);
	log->level = level;
	log->rotate_size = rotate_size;
	log->fseek = 0;

	strncpy(log->logname, logname, LOG_NAME_LEN);

	char path[2048] = {0};
	struct timeval tv;
	struct tm tm;

	gettimeofday(&tv, NULL);
	localtime_r(&tv.tv_sec, &tm);

	snprintf(path, 2048, "%s-%04d%02d%02d-%02d-%02d-%02d-%06d.log",
		log->logname,
		tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
		tm.tm_hour, tm.tm_min, tm.tm_sec, (int)tv.tv_usec);

	log->fd = open(path, O_RDWR | O_CREAT | O_APPEND, 0644);

	if (log->fd == -1) {
		fprintf(stderr, "can not open %s\n", path);
		fflush(stderr);
		free(log);
		return NULL;
	}

	log->last_sec = tv.tv_sec;
	snprintf(log->last_timestamp, 20, "%04d-%02d-%02d %02d:%02d:%02d",
		tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
		tm.tm_hour, tm.tm_min, tm.tm_sec);

	csnet_cond_init(&log->cond);

	log->buffers = _create_log_buffers();
	log->head = log->buffers[0];
	log->tail = log->buffers[0];

	if (pthread_create(&log->tid, NULL, csnet_log_flush_to_disk_thread, log) < 0) {
		debug("ERROR: can not create csnet_log_flush_to_disk_thread(): pthread_create(): %s", strerror(errno));
		close(log->fd);
		_free_log_buffers(log->buffers);
		free(log);
		return NULL;
	}

	csnet_bind_to_cpu(log->tid, csnet_online_cpus() - 3);

	return log;
}

void
csnet_log_log(struct csnet_log* log, int level, const char* fmt, ...) {
	if (level > log->level) {
		return;
	}

	char buf[BUFFER_LEN] = {0};
	int len = 0;
	va_list ap;
	va_start(ap, fmt);
	len = vsnprintf(buf, BUFFER_LEN, fmt, ap);
	va_end(ap);

	csnet_spinlock_lock(&log->lock);
	if (log->tail->remain > len) {
		_append(log->tail, buf, len);
	} else {
		log->tail = log->tail->next;
		log->tail->seek = 0;
		log->tail->remain = BUFFER_LEN;
		csnet_cond_signal_one(&log->cond);
		_append(log->tail, buf, len);
	}

	csnet_spinlock_unlock(&log->lock);
}

void
csnet_log_fatal(struct csnet_log* log, const char* fmt, ...) {
	char buf[BUFFER_LEN] = {0};
	va_list ap;
	va_start(ap, fmt);
	int len = vsnprintf(buf, BUFFER_LEN, fmt, ap);
	va_end(ap);

	csnet_spinlock_lock(&log->lock);
	write(log->fd, log->head->data, log->head->seek);
	write(log->fd, buf, len);
	csnet_spinlock_unlock(&log->lock);
	exit(-1);
}

void
csnet_log_free(struct csnet_log* log) {
	pthread_join(log->tid, NULL);
	close(log->fd);
	csnet_cond_destroy(&log->cond);
	_free_log_buffers(log->buffers);
	free(log);
}

