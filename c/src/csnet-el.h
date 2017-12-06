#pragma once

#include <openssl/ssl.h>
#include <pthread.h>

/*
 * Forward declarations
 */
struct csnet_epoller;
struct cs_lfqueue;
struct csnet_module;
struct csnet_log;
struct csnet_sockset;

struct csnet_el {
	pthread_t tid;
	int max_conn;
	int cur_conn;
	struct csnet_epoller* epoller;
	struct csnet_sockset* sockset;
	struct csnet_log* log;
	struct csnet_module* module;
	struct cs_lfqueue* q;
};

struct csnet_el* csnet_el_new(int max_conn, struct csnet_log* log, struct csnet_module* module, struct cs_lfqueue* q);
void csnet_el_free(struct csnet_el*);
int csnet_el_add_connection(struct csnet_el*, int fd);
void csnet_el_run_io_thread(struct csnet_el*);

