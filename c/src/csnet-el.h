#pragma once

#include <openssl/ssl.h>
#include <pthread.h>

/*
 * Forward declarations
 */
struct csnet_module;
struct csnet_log;
struct csnet_sockset;

struct csnet_el {
	int ep;
	int max_conn;
	int cur_conn;
	pthread_t tid;
	struct csnet_sockset* sockset;
	struct csnet_log* log;
	struct csnet_module* module;
};

struct csnet_el* csnet_el_new(int max_conn, struct csnet_log* log,
			      struct csnet_module* module);
void csnet_el_free(struct csnet_el*);
int csnet_el_watch(struct csnet_el*, int fd);
void csnet_el_run(struct csnet_el*);

