#include "btgfw.h"
#include "utils.h"
#include "tcp-connection.h"
#include "poller.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <strings.h>

#ifdef JEMALLOC
#include <jemalloc/jemalloc.h>
#endif

#define CPUID_MASK 127

const char *
btgfw_version(void)
{
	return BTGFW_MAJOR "." BTGFW_MINOR "." BTGFW_REVISION;
}

struct btgfw *
btgfw_new(int sfd, int nthread, accept_callback accept_cb)
{
	struct btgfw *btgfw;
	btgfw = calloc(1, sizeof(*btgfw) + (size_t)nthread * sizeof(struct el *));
	if (!btgfw) {
		oom(sizeof(*btgfw));
	}

	btgfw->poller = poller_open();
	if (btgfw->poller < 0) {
		FATAL("cannot open poller: %s", strerror(errno));
	}

	btgfw->sfd = sfd;

	poller_add(btgfw->poller, btgfw->sfd, NULL);

	for (int i = 0; i < nthread; i++) {
		btgfw->els[i] = el_new();
	}

	btgfw->nthread = nthread;
	btgfw->accept_cb = accept_cb;

	return btgfw;
}

void
btgfw_loop(struct btgfw *btgfw, int timeout)
{
	int cpus = online_cpus();

	for (int i = 0; i < btgfw->nthread; i++) {
		el_run(btgfw->els[i]);
		bind_to_cpu(btgfw->els[i]->tid, i % cpus);
	}

	while (1) {
		struct poller_event ev[1024];
		int n = poller_wait(btgfw->poller, ev, 1024, timeout);
		for (int i = 0; i < n; ++i) {
			if (ev[i].read) {
				btgfw->accept_cb(btgfw, btgfw->sfd);
			}
		}

		if (n == -1) {
			if (errno == EINTR) {
				continue;
			}

			ERROR("poller_wait(): %s", strerror(errno));
			return;
		}
	}
}

void
btgfw_free(struct btgfw *btgfw)
{
	pthread_join(btgfw->tid, NULL);
	poller_close(btgfw->poller);
	for (int i = 0; i < btgfw->nthread; i++) {
		el_free(btgfw->els[i]);
	}
	free(btgfw);
}

