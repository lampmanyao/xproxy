#include "csnet-conntor.h"
#include "csnet-atomic.h"
#include "csnet.h"
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


static void
_do_read(struct csnet_conntor* conntor, struct csnet_socket* socket, unsigned int sid, int fd) {
	int r = csnet_socket_recv(socket);
	if (csnet_fast(r > 0)) {
		char* data = csnet_rb_data(&socket->rb);
		unsigned int len = csnet_rb_len(&socket->rb);
		int stage = socket->stage;
		int rt = csnet_module_entry(conntor->module, socket, stage, data, len);
		if (rt != -1) {
			csnet_rb_seek(&socket->rb, rt);
		} else {
			log_e(conntor->log, "module return error, closing socket %d (%s)",
				  socket->fd, socket->host);
			struct csnet_socket* client_sock = socket->sock;
			if (client_sock) {
				log_w(conntor->log, "close client socket %d", client_sock->fd);
				csnet_socket_reset(client_sock);
			}
			csnet_ep_del(conntor->ep, socket->fd, socket);
			csnet_sockset_reset_socket(conntor->sockset, socket->sid);
		}
	} else if (r == 0) {
		log_i(conntor->log, "remote socket %d receive buffer is full, wait for next time", socket->fd);
		csnet_ep_r(conntor->ep, socket->fd, socket);
	} else {
		log_e(conntor->log, "remote peer close, close socket %d (%s)", socket->fd, socket->host);
		struct csnet_socket* client_sock = socket->sock;
		if (client_sock) {
			log_w(conntor->log, "close client socket %d", client_sock->fd);
			csnet_socket_reset(client_sock);
		}
		csnet_ep_del(conntor->ep, socket->fd, socket);
		csnet_sockset_reset_socket(conntor->sockset, socket->sid);
	}
}


static void*
csnet_conntor_io_thread(void* arg) {
	struct csnet_conntor* conntor = (struct csnet_conntor *)arg;

	while (1) {
		struct csnet_event ev[1024];
		int ready = csnet_ep_wait(conntor->ep, ev, 1024, 1000);
		for (int i = 0; i < ready; ++i) {
			struct csnet_socket* socket;
			uint32_t sid;
			int fd;

			socket = ev[i].ptr;
			sid = socket->sid;
			fd = socket->fd;

			if (csnet_fast(ev[i].read)) {
				 _do_read(conntor, socket, sid, fd);
			}

			if (ev[i].write) {
				log_i(conntor->log, "socket %d writable", fd);
				/* _do_write(conntor, socket, sid, fd); */
			}

			if (ev[i].eof || ev[i].error) {
				log_w(conntor->log, "socket %d EOF/Error", fd);
				struct csnet_socket* client_sock = socket->sock;
				if (client_sock) {
					log_w(conntor->log, "close client socket %d", client_sock->fd);
					csnet_socket_reset(client_sock);
				}
				csnet_ep_del(conntor->ep, socket->fd, socket);
				csnet_sockset_reset_socket(conntor->sockset, socket->sid);
			}
		}

		if (ready == -1) {
			if (errno == EINTR) {
				continue;
			} else {
				log_e(conntor->log, "ep_wait(): %s", strerror(errno));
				return NULL;
			}
		}
	}

	return NULL;
}

struct csnet_conntor*
csnet_conntor_new(struct csnet_config* config,
                  struct csnet_log* log,
                  struct csnet_module* module) {
	struct csnet_conntor* conntor = calloc(1, sizeof(struct csnet_conntor));
	if (!conntor) {
		csnet_oom(sizeof(struct csnet_conntor));
	}

	conntor->ep = csnet_ep_open();
	if (conntor->ep < 0) {
		log_f(log, "ep_open(): %s", strerror(errno));
	}

	conntor->log = log;
	conntor->sockset = csnet_sockset_new(1024, BTGFW_REMOTE);
	conntor->module = module;
	conntor->config = config;

	return conntor;
}

void
csnet_conntor_free(struct csnet_conntor* conntor) {
	pthread_join(conntor->tid, NULL);
	csnet_ep_close(conntor->ep);
	csnet_sockset_free(conntor->sockset);
	free(conntor);
}

void
csnet_conntor_reset_module(struct csnet_conntor* conntor, struct csnet_module* module) {
	conntor->module = module;
}

struct csnet_socket*
csnet_conntor_connectto(struct csnet_conntor* conntor, char* host, int port) {
	struct csnet_socket* socket;
	int fd;

	fd = csnet_connect_with_timeout(host, port, 1000);
	if (fd > 0) {
		log_i(conntor->log, "connected to %s:%d. socket %d", host, port, fd);

		int bufsize = 1024 * 1024;
		setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (char*)&bufsize, sizeof(bufsize));
		setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char*)&bufsize, sizeof(bufsize));

		csnet_set_nonblocking(fd);
		socket = csnet_sockset_put(conntor->sockset, fd);
		csnet_ep_add(conntor->ep, fd, socket);
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

