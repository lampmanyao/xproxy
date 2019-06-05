#pragma once

#include <pthread.h>

/*
 * Forward declarations
 */
struct csnet_log;
struct csnet_el;
struct csnet_msg;
struct csnet_module;

struct csnet {
	int ep;
	int listenfd;
	int nthread;
	int max_conn;
	pthread_t tid;
	struct csnet_log* log;
	struct csnet_el* els[0];
};

struct csnet* csnet_new(int port, int nthread, int max_conn,
                        struct csnet_log* log, struct csnet_module* module);

void csnet_free(struct csnet*);
void csnet_reset_module(struct csnet*, struct csnet_module* module);
void csnet_loop(struct csnet*, int timeout);

