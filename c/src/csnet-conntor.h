#pragma once

#include <pthread.h>

/*
 * Forward declarations
 */
struct csnet_log;
struct csnet_config;
struct csnet_sockset;
struct csnet_socket;
struct csnet_module;

struct csnet_conntor {
	int ep;
	pthread_t tid;
	struct csnet_sockset* sockset;
	struct csnet_log* log;
	struct csnet_module* module;
	struct csnet_config* config;
};

struct csnet_conntor* csnet_conntor_new(struct csnet_config*,
                                        struct csnet_log*,
                                        struct csnet_module*);
void csnet_conntor_free(struct csnet_conntor*);
void csnet_conntor_loop(struct csnet_conntor*);
void csnet_conntor_reset_module(struct csnet_conntor*, struct csnet_module*);
struct csnet_socket* csnet_conntor_connectto(struct csnet_conntor*, char*, int);

