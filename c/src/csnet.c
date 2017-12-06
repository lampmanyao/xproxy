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

#include "cs-lfqueue.h"

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

static struct csnet_cond cond = CSNET_COND_INITILIAZER;

static void _do_accept(struct csnet* csnet, int* listenfd);

struct csnet*
csnet_new(int port,
          int thread_count,
          int max_conn,
          struct csnet_log* log,
          struct csnet_module* module,
          struct cs_lfqueue* q) {
	struct csnet* csnet;
	csnet = calloc(1, sizeof(*csnet) + thread_count * sizeof(struct csnet_el*));
	if (!csnet) {
		csnet_oom(sizeof(*csnet));
	}

	csnet->listenfd = csnet_listen_port(port);
	if (csnet->listenfd == -1) {
		log_fatal(log, "epoll_create(): %s", strerror(errno));
	}

	if (csnet_set_nonblocking(csnet->listenfd) == -1) {
		log_fatal(log, "cannot set socket: %d to nonblock", csnet->listenfd);
	}

	csnet->thread_count = thread_count;
	csnet->max_conn = max_conn;
	csnet->epoller = csnet_epoller_new(MAGIC_NUMBER);

	if (!csnet->epoller) {
		log_fatal(log, "epoll_create(): %s", strerror(errno));
	}

	if (csnet_epoller_add(csnet->epoller, csnet->listenfd, 0) == -1) {
		log_fatal(log, "epoll_ctl(): %s", strerror(errno));
	}

	for (int i = 0; i < thread_count; i++) {
		int count = max_conn / thread_count + 1;
		csnet->el_list[i] = csnet_el_new(count, log, module, q);
	}

	csnet->log = log;
	csnet->q = q;
	return csnet;
}

void
csnet_reset_module(struct csnet* csnet, struct csnet_module* module) {
	for (int i = 0; i < csnet->thread_count; i++) {
		csnet->el_list[i]->module = module;
	}
}

void*
csnet_dispatch_thread(void* arg) {
	struct csnet* csnet = (struct csnet*)arg;
	struct cs_lfqueue* q = csnet->q;
	cs_lfqueue_register_thread(q);

	while (1) {
		struct csnet_msg* msg = NULL;
		int ret = cs_lfqueue_deq(q, (void*)&msg);
		if (csnet_fast(ret == 0)) {
			csnet_socket_send(msg->socket, msg->data, msg->size);
			csnet_msg_free(msg);
		} else {
			csnet_cond_nonblocking_wait(&cond, 1, 0);
		}
	}

	debug("csnet_dispatch_thread exit");
	return NULL;
}

void
csnet_loop(struct csnet* csnet, int timeout) {
	int online_cpus = csnet_online_cpus();

	for (int i = 0; i < csnet->thread_count; i++) {
		csnet_el_run_io_thread(csnet->el_list[i]);
		/* Skip CPU0 and CPU1
		   FIXME: Only work when online_cpus <= CPUID_MASK + 1. */
		int cpuid = ((i % (online_cpus - 2)) + 2) & CPUID_MASK;
		csnet_bind_to_cpu(csnet->el_list[i]->tid, cpuid);
	}

	if (pthread_create(&csnet->tid, NULL, csnet_dispatch_thread, csnet) < 0) {
		log_fatal(csnet->log, "pthread_create(): %s", strerror(errno));
	}

	csnet_bind_to_cpu(csnet->tid, online_cpus - 1);

	while (1) {
		int ready = csnet_epoller_wait(csnet->epoller, timeout);
		for (int i = 0; i < ready; ++i) {
			csnet_epoller_event_t* ee = csnet_epoller_get_event(csnet->epoller, i);
			int fd = csnet_epoller_event_fd(ee);

			if (csnet_epoller_event_is_readable(ee)) {
				if (fd == csnet->listenfd) {
					/* Have a notification on the listening socket,
					   which means one or more new incoming connecttions */
					_do_accept(csnet, &csnet->listenfd);
				}
			}

			if (csnet_epoller_event_is_error(ee)) {
				log_error(csnet->log, "epoll event error");
				close(fd);
				continue;
			}
		}

		if (ready == -1) {
			if (errno == EINTR) {
				/* Stopped by a signal */
				continue;
			} else {
				log_error(csnet->log, "epoll_wait(): %s", strerror(errno));
				return;
			}
		}
	}
	debug("csnet_loop exit");
}

void
csnet_free(struct csnet* csnet) {
	pthread_join(csnet->tid, NULL);
	close(csnet->listenfd);
	csnet_epoller_free(csnet->epoller);
	for (int i = 0; i < csnet->thread_count; i++) {
		csnet_el_free(csnet->el_list[i]);
	}
	free(csnet);
}

int
csnet_sendto(struct cs_lfqueue* q, struct csnet_msg* msg) {
	cs_lfqueue_enq(q, msg);
	csnet_cond_signal_one(&cond);
	return 0;
}

static inline void
_do_accept(struct csnet* csnet, int* listenfd) {
	while (1) {
		int fd;
		struct sockaddr_in sin;
		socklen_t len = sizeof(struct sockaddr_in);
		bzero(&sin, len);
		fd = accept(*listenfd, (struct sockaddr*)&sin, &len);

		if (fd > 0) {
			log_info(csnet->log, "accept incoming [%s:%d] with socket: %d.",
				inet_ntoa(sin.sin_addr), ntohs(sin.sin_port), fd);

			if (csnet_set_nonblocking(fd) == -1) {
				log_error(csnet->log, "can not set socket: %d to nonblock", fd);
				close(fd);
				continue;
			}

			if (csnet_el_add_connection(csnet->el_list[fd % csnet->thread_count], fd) == -1) {
				close(fd);
				return;
			}
		} else {
			if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
				/* We have processed all incoming connections. */
				return;
			} else {
				log_error(csnet->log, "accept(): %s", strerror(errno));
				return;
			}
		}
	}
}

