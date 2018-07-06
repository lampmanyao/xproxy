#include "csnet-conntor.h"
#include "csnet-atomic.h"
#include "csnet.h"
#include "csnet-rb.h"
#include "csnet-socket-api.h"
#include "csnet-utils.h"
#include "csnet-log.h"
#include "csnet-msg.h"
#include "csnet-fast.h"
#include "csnet-spinlock.h"
#include "csnet-config.h"
#include "csnet-module.h"
#include "csnet-sockset.h"
#include "csnet-socket.h"
#include "csnet-msg.h"
#include "cs-lfqueue.h"
#include "csnet-btgfw.h"

#if defined(__APPLE__)
#include "csnet-kqueue.h"
#else
#include "csnet-epoll.h"
#endif

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <strings.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define MAGIC_NUMBER 1024
#define SLOT_SIZE 32

static void readable_event(struct csnet_conntor* conntor, struct csnet_socket* socket);

static void*
csnet_conntor_io_thread(void* arg) {
	struct csnet_conntor* conntor = (struct csnet_conntor *)arg;
	struct cs_lfqueue* q = conntor->q;
	cs_lfqueue_register_thread(q);

	while (1) {
		int ready = csnet_epoller_wait(conntor->epoller, 1000);
		for (int i = 0; i < ready; ++i) {
			csnet_epoller_event_t* ee;
			struct csnet_socket* socket;
			unsigned int sid;

			ee = csnet_epoller_get_event(conntor->epoller, i);
			sid = csnet_epoller_event_sid(ee);
			socket = csnet_sockset_get_socket(conntor->sockset, sid);

			if (csnet_fast(csnet_epoller_event_is_r(ee))) {
				readable_event(conntor, socket);
			} else if (csnet_epoller_event_is_e(ee)) {
				/* EPOLLERR and EPOLLHUP events can occur if the remote peer
				 * was colsed or a terminal hangup occured. We do nothing
				 * here but LOGGING. */
				log_w(conntor->log, "EPOLLERR on socket: %d", socket->fd);
			}
		}

		if (ready == -1) {
			if (errno == EINTR) {
				/* Stopped by a signal */
				continue;
			} else {
				log_e(conntor->log, "epoll_wait(): %s", strerror(errno));
				return NULL;
			}
		}
	}

	debug("csnet_conntor_io_thread exit");

	return NULL;
}

struct csnet_conntor*
csnet_conntor_new(struct csnet_config* config,
                  struct csnet_log* log,
                  struct csnet_module* module,
                  struct cs_lfqueue* q) {
	struct csnet_conntor* conntor = calloc(1, sizeof(struct csnet_conntor));
	if (!conntor) {
		csnet_oom(sizeof(struct csnet_conntor));
	}

	conntor->epoller = csnet_epoller_new(MAGIC_NUMBER);
	if (!conntor->epoller) {
		log_f(log, "epoll_create(): %s", strerror(errno));
	}

	conntor->log = log;
	conntor->sockset = csnet_sockset_new(1024, BTGFW_REMOTE);
	conntor->module = module;
	conntor->config = config;
	conntor->q = q;

	return conntor;
}

void
csnet_conntor_free(struct csnet_conntor* conntor) {
	pthread_join(conntor->tid, NULL);
	csnet_epoller_free(conntor->epoller);
	csnet_sockset_free(conntor->sockset);
	free(conntor);
}

void
csnet_conntor_reset_module(struct csnet_conntor* conntor, struct csnet_module* module) {
	conntor->module = module;
}

struct csnet_socket*
csnet_conntor_connectto(struct csnet_conntor* conntor, char* host, int port) {
	int fd = csnet_connect_with_timeout(host, port, 1000);
	if (fd > 0) {
		log_i(conntor->log, "connected to %s:%d. socket %d", host, port, fd);

		unsigned int sid;
		struct csnet_socket* socket;

		csnet_set_nonblocking(fd);
		sid = csnet_sockset_put(conntor->sockset, fd);
		csnet_epoller_add(conntor->epoller, fd, sid);
		socket = csnet_sockset_get_socket(conntor->sockset, sid);
		return socket;
	} else {
		log_w(conntor->log, "failed or timeout connect to %s:%d", host, port);
		return NULL;
	}
}

void
csnet_conntor_loop(struct csnet_conntor* conntor) {
	if (pthread_create(&conntor->tid, NULL, csnet_conntor_io_thread, conntor) < 0) {
		log_f(conntor->log, "pthread_create() failed: %s", strerror(errno));
	}
	csnet_bind_to_cpu(conntor->tid, csnet_online_cpus() - 4);
}

static void
readable_event(struct csnet_conntor* conntor, struct csnet_socket* socket) {
	int r = csnet_socket_recv(socket);
	if (csnet_fast(r > 0)) {
		char* data = csnet_rb_data(socket->rb);
		unsigned int len = socket->rb->len;
		int state = socket->state;
		int rt = csnet_module_entry(conntor->module, socket, state, data, len);

		if (rt != -1) {
			csnet_rb_seek(socket->rb, rt);
		} else {
			log_e(conntor->log, "module return error, closing socket %d (%s)",
				  socket->fd, socket->host);
			csnet_epoller_del(conntor->epoller, socket->fd, socket->sid);
			csnet_sockset_reset_socket(conntor->sockset, socket->sid);
		}
	} else if (r == 0) {
		log_i(conntor->log, "remote socket %d receive buffer is full, wait for next time", socket->fd);
		csnet_epoller_r(conntor->epoller, socket->fd, socket->sid);
	} else {
		log_w(conntor->log, "remote peer close, closing socket %d (%s)",
			 socket->fd, socket->host);
		csnet_epoller_del(conntor->epoller, socket->fd, socket->sid);
		csnet_sockset_reset_socket(conntor->sockset, socket->sid);
	}
}

