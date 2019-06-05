#include "csnet.h"
#include "csnet-cond.h"
#include "csnet-fast.h"
#include "csnet-utils.h"
#include "csnet-socket.h"
#include "csnet-socket-api.h"
#include "csnet-el.h"
#include "csnet-msg.h"
#include "csnet-module.h"
#include "csnet-btgfw.h"

#if defined(__APPLE__)
#include "csnet-kqueue.h"
#else
#include "csnet-epoll.h"
#endif


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef JEMALLOC
#include <jemalloc/jemalloc.h>
#endif

#define MAGIC_NUMBER 1024
#define CPUID_MASK 127

static inline void
_do_accept(struct csnet* csnet, int* listenfd) {
	while (1) {
		int fd;
		struct sockaddr_in sin;
		socklen_t len = sizeof(struct sockaddr_in);
		bzero(&sin, len);
		fd = accept(*listenfd, (struct sockaddr*)&sin, &len);

		if (fd > 0) {
			log_i(csnet->log, "accept incoming [%s:%d] with socket %d.",
				inet_ntoa(sin.sin_addr), ntohs(sin.sin_port), fd);
			int bufsize = 1024 * 1024;
			setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (char*)&bufsize, sizeof(bufsize));
			setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char*)&bufsize, sizeof(bufsize));
			csnet_set_nonblocking(fd);
			if (csnet_el_watch(csnet->els[fd % csnet->nthread], fd) == -1) {
				close(fd);
				return;
			}
		} else {
			if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
				/* We have processed all incoming connections. */
				return;
			} else {
				log_e(csnet->log, "accept(): %s", strerror(errno));
				return;
			}
		}
	}
}


struct csnet*
csnet_new(int port, int nthread, int max_conn,
          struct csnet_log* log, struct csnet_module* module) {
	struct csnet* csnet;
	csnet = calloc(1, sizeof(*csnet) + nthread * sizeof(struct csnet_el*));
	if (!csnet) {
		csnet_oom(sizeof(*csnet));
	}

	csnet->ep = csnet_ep_open();
	if (csnet->ep < 0) {
		log_f(log, "cannot open ep: %s", strerror(errno));
	}

	csnet->listenfd = csnet_listen_port(port);
	if (csnet->listenfd == -1) {
		log_f(log, "epoll_create(): %s", strerror(errno));
	}

	if (csnet_set_nonblocking(csnet->listenfd) == -1) {
		log_f(log, "cannot set socket: %d to nonblock", csnet->listenfd);
	}

	if (csnet_ep_add(csnet->ep, csnet->listenfd, NULL) == -1) {
		log_f(log, "epoll_ctl(): %s", strerror(errno));
	}

	for (int i = 0; i < nthread; i++) {
		int count = max_conn / nthread + 1;
		csnet->els[i] = csnet_el_new(count, log, module);
	}


	csnet->nthread = nthread;
	csnet->max_conn = max_conn;
	csnet->log = log;

	log_i(csnet->log, "Listening on port: %d", port);

	return csnet;
}

void
csnet_reset_module(struct csnet* csnet, struct csnet_module* module) {
	for (int i = 0; i < csnet->nthread; i++) {
		csnet->els[i]->module = module;
	}
}

void
csnet_loop(struct csnet* csnet, int timeout) {
	int online_cpus = csnet_online_cpus();

	for (int i = 0; i < csnet->nthread; i++) {
		csnet_el_run(csnet->els[i]);
		int cpuid = ((i % (online_cpus - 2)) + 2) & CPUID_MASK;
		csnet_bind_to_cpu(csnet->els[i]->tid, cpuid);
	}

	while (1) {
		struct csnet_event ev[1024];
		int n = csnet_ep_wait(csnet->ep, ev, 1024, timeout);
		for (int i = 0; i < n; ++i) {
			if (ev[i].read) {
				_do_accept(csnet, &csnet->listenfd);
			}

			if (ev[i].eof) {
				log_w(csnet->log, "eof");
			}

			if (ev[i].error) {
				log_w(csnet->log, "error");
			}
		}

		if (n == -1) {
			if (errno == EINTR) {
				continue;
			}
			log_e(csnet->log, "ep wait error: %s", strerror(errno));
			return;
		}
	}
}

void
csnet_free(struct csnet* csnet) {
	pthread_join(csnet->tid, NULL);
	close(csnet->listenfd);
	csnet_ep_close(csnet->ep);
	for (int i = 0; i < csnet->nthread; i++) {
		csnet_el_free(csnet->els[i]);
	}
	free(csnet);
}

