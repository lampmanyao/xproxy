#pragma once

#include <pthread.h>

#define CSNET_COND_INITILIAZER              \
{                                           \
	.mutex = PTHREAD_MUTEX_INITIALIZER, \
	.cond = PTHREAD_COND_INITIALIZER    \
}

struct csnet_cond {
	pthread_mutex_t mutex;
	pthread_cond_t cond;
};

int csnet_cond_init(struct csnet_cond*);
void csnet_cond_destroy(struct csnet_cond*);
void csnet_cond_blocking_wait(struct csnet_cond*);
void csnet_cond_nonblocking_wait(struct csnet_cond*, int seconds, int microseconds);
void csnet_cond_signal_one(struct csnet_cond*);
void csnet_cond_signal_all(struct csnet_cond*);

