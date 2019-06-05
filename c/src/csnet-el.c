#include "csnet.h"
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


struct csnet_el*
csnet_el_new(int max_conn, struct csnet_log* log, struct csnet_module* module) {
	struct csnet_el* el = calloc(1, sizeof(*el));
	if (!el) {
		csnet_oom(sizeof(*el));
	}
	el->ep = csnet_ep_open();
	el->max_conn = max_conn;
	el->cur_conn = 0;
	el->sockset = csnet_sockset_new(max_conn, BTGFW_CLIENT);
	el->log = log;
	el->module = module;

	return el;
}

void
csnet_el_free(struct csnet_el* el) {
	pthread_kill(el->tid, SIGTERM);
	csnet_ep_close(el->ep);
	csnet_sockset_free(el->sockset);
}

int
csnet_el_watch(struct csnet_el* el, int fd) {
	struct csnet_socket* sock;
	unsigned int sid;

	if (csnet_slow(el->cur_conn++ > el->max_conn)) {
		log_w(el->log, "Too much connections, closing socket %d", fd);
		return -1;
	}

	sock = csnet_sockset_put(el->sockset, fd);
	sid = sock->sid;
	csnet_ep_add(el->ep, fd, sock);

	return 0;
}

static void
_do_read(struct csnet_el* el, struct csnet_socket* socket, uint32_t sid, int fd) {
	int r = csnet_socket_recv(socket);
	if (csnet_fast(r > 0)) {
		char* data = csnet_rb_data(&socket->rb);
		size_t len = csnet_rb_len(&socket->rb);
		int stage = socket->stage;
		int rt = csnet_module_entry(el->module, socket, stage, data, len);
		if (rt != -1) {
			csnet_rb_seek(&socket->rb, rt);
		} else {
			log_e(el->log, "module return error, closing socket %d (%s)",
			      socket->fd, socket->host);
			struct csnet_socket* remote_sock = socket->sock;
			if (remote_sock) {
				log_i(el->log, "closing remote socket %d", remote_sock->fd);
				csnet_socket_reset(remote_sock);
			}
			csnet_ep_del(el->ep, fd, socket);
			csnet_sockset_reset_socket(el->sockset, socket->sid);
			el->cur_conn--;
		}
	} else if (r == 0) {
		log_i(el->log, "client socket %d receive buffer is full, wait for next time", fd);
		csnet_ep_r(el->ep, fd, socket);
	} else {
		log_w(el->log, "client peer close, closing socket %d (%s)", fd, socket->host);
		struct csnet_socket* remote_sock = socket->sock;
		if (remote_sock) {
			log_i(el->log, "closing remote socket %d", remote_sock->fd);
			csnet_socket_reset(remote_sock);
		}
		csnet_ep_del(el->ep, fd, socket);
		csnet_sockset_reset_socket(el->sockset, socket->sid);
		el->cur_conn--;
	}
}

static void*
csnet_el_io_thread(void* arg) {
	struct csnet_el* el = (struct csnet_el*)arg;

	while (1) {
		struct csnet_event ev[1024];
		int n = csnet_ep_wait(el->ep, ev, 1024, 1000);
		for (int i = 0; i < n; ++i) {
			struct csnet_socket* socket;
			uint32_t sid;
			int fd;

			socket = ev[i].ptr;
			sid = socket->sid;
			fd = socket->fd;

			if (ev[i].read) {
				_do_read(el, socket, sid, fd);
			}

			if (ev[i].write) {
				log_i(el->log, "client socket %d writable", fd);
				/* _do_write(el, socket, sid, fd); */
			}

			if (ev[i].eof || ev[i].error) {
				log_e(el->log, "socket %d EOF/Error: %s", fd);
				struct csnet_socket* remote_sock = socket->sock;
				if (remote_sock) {
					log_i(el->log, "closing remote socket %d", remote_sock->fd);
					csnet_socket_reset(remote_sock);
				}
				csnet_ep_del(el->ep, fd, socket);
				csnet_sockset_reset_socket(el->sockset, socket->sid);
				el->cur_conn--;
			}
		}

		if (n == -1) {
			if (errno == EINTR) {
				continue;
			} else {
				return NULL;
			}
		}
	}

	return NULL;
}

void
csnet_el_run(struct csnet_el* el) {
	if (pthread_create(&el->tid, NULL, csnet_el_io_thread, el) < 0) {
		log_f(el->log, "pthread_create(): %s", strerror(errno));
	}
}

