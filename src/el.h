#pragma once

#include "rbtree.h"
#include <pthread.h>

struct tcp_connection;

struct el {
	int poller;
	pthread_t tid;
	struct rbtree *tree;
};

struct el *el_new();
void el_free(struct el *);
void el_watch(struct el *, struct tcp_connection*);
void el_stop_watch(struct el *, struct tcp_connection*);
void el_run(struct el *);

