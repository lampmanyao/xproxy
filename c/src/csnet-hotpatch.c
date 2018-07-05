#include "csnet-hotpatch.h"
#include "csnet-utils.h"
#include "csnet-log.h"
#include "csnet-config.h"
#include "csnet.h"
#include "csnet-log.h"
#include "csnet-module.h"
#include "csnet-conntor.h"
#include "csnet-socket-api.h"

#include "cs-lfqueue.h"
#include "cs-priority-queue.h"

#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

static int hotpatching(void* target, void* replacement);

static void*
csnet_hotpatch_thread(void* arg) {
	struct csnet_hotpatch* hp = arg;
	while (1) {
		csnet_hotpatch_do_patching(hp);
		sleep(10);
	}

	debug("csnet_hotpatch_thread exit");
	return NULL;
}

struct csnet_hotpatch*
csnet_hotpatch_new(struct csnet_module* module,
		   struct cs_lfqueue* q,
                   struct csnet* csnet,
                   struct csnet_conntor* conntor,
                   struct csnet_log* log,
                   struct csnet_config* config) {
	struct csnet_hotpatch* hp = calloc(1, sizeof(*hp));
	hp->module = module;
	hp->q = q;
	hp->csnet = csnet;
	hp->conntor = conntor;
	hp->log = log;
	hp->config = config;
	if (pthread_create(&hp->tid, NULL, csnet_hotpatch_thread, hp) < 0) {
		fatal("fatal: can not create hotpatch_thread(): %s", strerror(errno));
	}
	csnet_bind_to_cpu(hp->tid, csnet_online_cpus() - 2);
	return hp;
}

void
csnet_hotpatch_free(struct csnet_hotpatch* hp) {
	pthread_join(hp->tid, NULL);
	free(hp);
}

int csnet_hotpatch_do_patching(struct csnet_hotpatch* hp) {
	int ret = -1;
	int len = strlen("business-module.so");
	struct cs_pqueue* pq = cs_pqueue_new(CS_PQ_HIGHEST_PRIORITY);
	DIR* d;
	struct dirent* dir;
	d = opendir(".");

	if (d) {
		while ((dir = readdir(d)) != NULL) {
			if (strncmp(dir->d_name, "business-module.so", len) == 0) {
				struct stat stat_buff;
				stat(dir->d_name, &stat_buff);
				char buff[32] = {0};
				strcat(buff, "./");
				strcat(buff, dir->d_name);
				char* value = strdup(buff);
				cs_pqueue_push(pq, stat_buff.st_mtime, value);
			}
		}
		closedir(d);
	}

	struct cs_pqnode* highest = cs_pqueue_pop(pq);
	if (highest) {
		unsigned char new_md5[17];
		csnet_file_md5(highest->value, new_md5);
		new_md5[16] = '\0';

		if (strcmp((char*)new_md5, (char*)hp->module->md5) == 0) {
			ret = -1;
			goto out;
		}

		struct csnet_module* old_module = hp->module;
		hp->module = csnet_module_new();
		csnet_module_init(hp->module, hp->conntor, hp->q, hp->log, hp->config);
		csnet_module_load(hp->module, highest->value);

		if (hotpatching(old_module->business_entry, hp->module->business_entry) == 0) {
			csnet_reset_module(hp->csnet, hp->module);
			if (hp->conntor) {
				csnet_conntor_reset_module(hp->conntor, hp->module);
			}
			while (hp->conntor && old_module->ref_count != 0) {
				csnet_wait_milliseconds(10);
			}
			csnet_module_term(old_module);
			csnet_module_free(old_module);
			log_i(hp->log, "hotpatch done");
			ret = 0;
			goto out;
		}

		log_e(hp->log, "hotpatch failed");
		ret = -1;
	}

out:
	if (highest) {
		free(highest->value);
		cs_pqueue_delete(pq, highest);
	}
	cs_pqueue_free(pq);
	return ret;
}

/*
 * This function was obtained from http://nullprogram.com/blog/2016/03/31/.
 * Copyright (c) 2016 wellons <wellons@nullprogram.com>
 */

static int
hotpatching(void* target, void* replacement) {
	int ret;
	int pgsize;
	assert(((uintptr_t)target & 0x07) == 0);
	pgsize = getpagesize();
	void* page = (void *)((uintptr_t)target & ~(pgsize - 1));
	ret = mprotect(page, pgsize, PROT_WRITE | PROT_EXEC);

	if (ret == -1) {
		return -1;
	}

	uint32_t rel = (char *)replacement - (char *)target - 5;
	union {
		uint8_t bytes[8];
		uint64_t value;
	} instruction = {{0xe9, rel >> 0, rel >> 8, rel >> 16, rel >> 24}};

	*(uint64_t *)target = instruction.value;
	mprotect(page, pgsize, PROT_EXEC);

	return 0;
}

