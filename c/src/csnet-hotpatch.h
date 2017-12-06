#pragma once

#include <pthread.h>

/*
 * Forward declarations
 */
struct csnet_module;
struct cs_lfqueue;
struct csnet;
struct csnet_conntor;
struct csnet_log;
struct csnet_config;

struct csnet_hotpatch {
	pthread_t tid;
	struct csnet_module* module;
	struct cs_lfqueue* q;
	struct csnet* csnet;
	struct csnet_conntor* conntor;
	struct csnet_log* log;
	struct csnet_config* config;
};

struct csnet_hotpatch* csnet_hotpatch_new(struct csnet_module* module,
                                         struct cs_lfqueue* q,
                                         struct csnet* csnet,
                                         struct csnet_conntor* conntor,
                                         struct csnet_log* log,
                                         struct csnet_config* config);

void csnet_hotpatch_free(struct csnet_hotpatch*);
int csnet_hotpatch_do_patching(struct csnet_hotpatch*);

