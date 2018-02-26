#include "csnet-cond.h"

#include <sys/time.h>

int
csnet_cond_init(struct csnet_cond* cond) {
	if (pthread_mutex_init(&cond->mutex, NULL) < 0) {
		return -1;
	}

	if (pthread_cond_init(&cond->cond, NULL) < 0) {
		pthread_mutex_destroy(&cond->mutex);
		return -1;
	}

	return 0;
}

void
csnet_cond_destroy(struct csnet_cond* cond) {
	pthread_mutex_destroy(&cond->mutex);
	pthread_cond_destroy(&cond->cond);
}

void
csnet_cond_blocking_wait(struct csnet_cond* cond) {
	pthread_mutex_lock(&cond->mutex);
	pthread_cond_wait(&cond->cond, &cond->mutex);
	pthread_mutex_unlock(&cond->mutex);
}

void
csnet_cond_nonblocking_wait(struct csnet_cond* cond, int seconds, int microseconds) {
#if defined(__APPLE__)
	struct timespec timeout = {seconds, microseconds * 1000};
	pthread_mutex_lock(&cond->mutex);
	pthread_cond_timedwait_relative_np(&cond->cond, &cond->mutex, &timeout);
	pthread_mutex_unlock(&cond->mutex);
#else
	struct timeval now;
	struct timespec timeout;
	gettimeofday(&now, NULL);
	timeout.tv_sec = now.tv_sec + seconds;
	timeout.tv_nsec = now.tv_usec + microseconds * 1000;
	pthread_mutex_lock(&cond->mutex);
	pthread_cond_timedwait(&cond->cond, &cond->mutex, &timeout);
	pthread_mutex_unlock(&cond->mutex);
#endif
}

void
csnet_cond_signal_one(struct csnet_cond* cond) {
	pthread_cond_signal(&cond->cond);
}

void
csnet_cond_signal_all(struct csnet_cond* cond) {
	pthread_cond_broadcast(&cond->cond);
}

