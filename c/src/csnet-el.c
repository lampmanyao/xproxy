#include "csnet.h"
#include "csnet-rb.h"
#include "csnet-el.h"
#include "csnet-msg.h"
#include "csnet-log.h"
#include "csnet-fast.h"
#include "csnet-utils.h"
#include "csnet-module.h"
#include "csnet-socket.h"
#include "csnet-sockset.h"
#include "csnet-socket-api.h"
#if defined(__APPLE__)
#include "csnet-kqueue.h"
#else
#include "csnet-epoll.h"
#endif
#include "csnet-btgfw.h"

#include "cs-lfqueue.h"

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <strings.h>
#include <signal.h>
#include <netinet/in.h>

#ifdef JEMALLOC
#include <jemalloc/jemalloc.h>
#endif

static void readable_event(struct csnet_el* el, struct csnet_socket* socket);

struct csnet_el*
csnet_el_new(int max_conn, struct csnet_log* log,
             struct csnet_module* module, cs_lfqueue_t* q) {
	struct csnet_el* el = calloc(1, sizeof(*el));
	if (!el) {
		csnet_oom(sizeof(*el));
	}

	el->max_conn = max_conn;
	el->cur_conn = 0;
	el->epoller = csnet_epoller_new(max_conn);
	el->sockset = csnet_sockset_new(max_conn, BTGFW_CLIENT);
	el->log = log;
	el->module = module;
	el->q = q;

	return el;
}

int
csnet_el_watch(struct csnet_el* el, int fd) {
	unsigned int sid;
	if (csnet_slow(el->cur_conn++ > el->max_conn)) {
		log_w(el->log, "Too much connections, closing socket %d", fd);
		return -1;
	}

	sid = csnet_sockset_put(el->sockset, fd);
	csnet_epoller_add(el->epoller, fd, sid);
	return 0;
}

static void*
csnet_el_io_thread(void* arg) {
	struct csnet_el* el = (struct csnet_el*)arg;
	cs_lfqueue_register_thread(el->q);

	while (1) {
		int ready = csnet_epoller_wait(el->epoller, 1000);
		for (int i = 0; i < ready; ++i) {
			csnet_epoller_event_t* ee;
			struct csnet_socket* socket;
			unsigned int sid;

			ee = csnet_epoller_get_event(el->epoller, i);
			sid = csnet_epoller_event_sid(ee);
			socket = csnet_sockset_get_socket(el->sockset, sid);

			if (csnet_fast(csnet_epoller_event_is_r(ee))) {
				readable_event(el, socket);
			} else if (csnet_epoller_event_is_e(ee)) {
				/*
				 * EPOLLERR and EPOLLHUP events can occur if the remote peer
				 * was colsed or a terminal hangup occured. We do nothing
				 * here but LOGGING.
				 */
				log_w(el->log, "EPOLLERR on socket: %d", socket->fd);
			}
		}

		if (ready == -1) {
			if (errno == EINTR) {
				/* Stopped by a signal */
				continue;
			} else {
				log_e(el->log, "epoll_wait(): %s", strerror(errno));
				return NULL;
			}
		}
	}

	debug("csnet_el_io_thread exit");

	return NULL;
}

void
csnet_el_run(struct csnet_el* el) {
	if (pthread_create(&el->tid, NULL, csnet_el_io_thread, el) < 0) {
		log_f(el->log, "pthread_create(): %s", strerror(errno));
	}
}

void
csnet_el_free(struct csnet_el* el) {
	pthread_kill(el->tid, SIGTERM);
	csnet_epoller_free(el->epoller);
	csnet_sockset_free(el->sockset);
}

static void
readable_event(struct csnet_el* el, struct csnet_socket* socket) {
	int r = csnet_socket_recv(socket);
	if (csnet_fast(r > 0)) {
		char* data = csnet_rb_data(socket->rb);
		unsigned int len = csnet_rb_len(socket->rb);
		int state = socket->state;
		int rt = csnet_module_entry(el->module, socket, state, data, len);

		if (rt != -1) {
			csnet_rb_seek(socket->rb, rt);
		} else {
			log_e(el->log, "module return error, closing socket %d (%s)",
				  socket->fd, socket->host);
			csnet_epoller_del(el->epoller, socket->fd, socket->sid);
			csnet_sockset_reset_socket(el->sockset, socket->sid);
			el->cur_conn--;
		}
	} else if (r == 0) {
		log_i(el->log, "client socket %d receive buffer is full, wait for next time", socket->fd);
		csnet_epoller_r(el->epoller, socket->fd, socket->sid);
	} else {
		log_w(el->log, "client peer close, closing socket %d (%s)",
			 socket->fd, socket->host);
		csnet_epoller_del(el->epoller, socket->fd, socket->sid);
		csnet_sockset_reset_socket(el->sockset, socket->sid);
		el->cur_conn--;
	}
}

