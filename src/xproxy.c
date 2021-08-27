#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <strings.h>

#include "xproxy.h"
#include "utils.h"
#include "tcp-connection.h"
#include "poller.h"
#include "log.h"
#include "config.h"

#define CPUID_MASK 127

struct xproxy *xproxy_new(int sfd, int nthread, accept_callback accept_cb)
{
	struct xproxy *xproxy = NULL;
	size_t size = sizeof(*xproxy) + (size_t)nthread * sizeof(struct el *);

	xproxy = calloc(1, size);
	if (!xproxy)
		oom(size);

	xproxy->poller = poller_open();

	if (xproxy->poller < 0)
		FATAL("cannot open poller: %s", strerror(errno));

	xproxy->sfd = sfd;

	poller_add(xproxy->poller, xproxy->sfd, NULL);

	for (int i = 0; i < nthread; i++)
		xproxy->els[i] = el_new();

	xproxy->nthread = nthread;
	xproxy->accept_cb = accept_cb;

	return xproxy;
}

void xproxy_loop(struct xproxy *xproxy, int timeout)
{
	int cpus = online_cpus();

	for (int i = 0; i < xproxy->nthread; i++) {
		el_run(xproxy->els[i]);
		bind_to_cpu(xproxy->els[i]->tid, i % cpus);
	}

	while (1) {
		struct poller_event ev[1024];
		int n = poller_wait(xproxy->poller, ev, 1024, timeout);
		for (int i = 0; i < n; ++i) {
			if (ev[i].read) {
				xproxy->accept_cb(xproxy, xproxy->sfd);
			}
		}

		if (n == -1) {
			if (errno == EINTR)
				continue;

			return;
		}
	}
}

void xproxy_free(struct xproxy *xproxy)
{
	pthread_join(xproxy->tid, NULL);
	poller_close(xproxy->poller);
	for (int i = 0; i < xproxy->nthread; i++)
		el_free(xproxy->els[i]);
	free(xproxy);
}

const char *xproxy_version(void)
{
	return VERSION;
}

