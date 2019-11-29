#pragma once

#include <pthread.h>

#include "el.h"

struct btgfw;

typedef void (*accept_callback) (struct btgfw *btgfw, int lfd);

struct btgfw {
	int poller;
	int sfd;
	int nthread;
	pthread_t tid;
	accept_callback accept_cb;
	struct el *els[0];
};

const char *btgfw_version(void);
struct btgfw *btgfw_new(int sfd, int nthread, accept_callback accept_cb);
void btgfw_free(struct btgfw *);
void btgfw_loop(struct btgfw *, int timeout);

