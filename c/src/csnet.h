#pragma once

#include <pthread.h>

/*
 * Forward declarations
 */
struct csnet_epoller;
struct csnet_log;
struct cs_lfqueue;
struct csnet_el;
struct csnet_msg;
struct csnet_module;

struct csnet {
	pthread_t tid;
	int listenfd;
	int thread_count;
	int max_conn;
	struct csnet_epoller* epoller;
	struct cs_lfqueue* q;
	struct csnet_log* log;
	struct csnet_el* el_list[0];
};

struct csnet* csnet_new(int port, int thread_count, int max_conn,
                        struct csnet_log* log, struct csnet_module* module,
                        struct cs_lfqueue* q);

void csnet_free(struct csnet*);
void csnet_reset_module(struct csnet*, struct csnet_module* module);
void csnet_loop(struct csnet*, int timeout);
int csnet_sendto(struct cs_lfqueue* q, struct csnet_msg* msg);

