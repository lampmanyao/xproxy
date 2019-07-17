#include "el.h"
#include "log.h"
#include "utils.h"
#include "tcp-connection.h"
#include "btgfw.h"
#include "poller.h"

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <strings.h>
#include <signal.h>
#include <netinet/in.h>

struct el *
el_new()
{
	struct el *el = calloc(1, sizeof(*el));
	if (!el) {
		oom(sizeof(*el));
	}
	el->poller = poller_open();
	el->tree = rbtree_new();
	return el;
}

void
el_free(struct el *el)
{
	poller_close(el->poller);
	rbtree_free(el->tree);
	free(el);
}

void
el_watch(struct el *el, struct tcp_connection *tcp_conn)
{
	poller_add(el->poller, tcp_conn->fd, tcp_conn);
	struct rbnode *node = rbnode_new(tcp_conn->fd, tcp_conn);
	rbtree_insert(el->tree, node);
}

void
el_stop_watch(struct el *el, struct tcp_connection *tcp_conn)
{
	struct rbnode *node = rbtree_search(el->tree, tcp_conn->fd);
	if (node) {
		rbtree_delete(el->tree, node);
	}
	poller_del(el->poller, tcp_conn->fd, tcp_conn);
}

static void *
el_io_thread(void *arg)
{
	struct el *el = (struct el *)arg;

	while (1) {
		struct poller_event ev[1024];
		int n = poller_wait(el->poller, ev, 1024, 1000);
		for (int i = 0; i < n; ++i) {
			struct tcp_connection *tcp_conn;
			tcp_conn = ev[i].ptr;
			struct rbnode *node = rbtree_search(el->tree, tcp_conn->fd);

			if (!node || (node->value != tcp_conn)) {
				continue;
			}

			if (ev[i].read) {
				tcp_conn->recv_cb(el, tcp_conn);
			}

			if (ev[i].write) {
				tcp_conn->send_cb(el, tcp_conn);
			}

			if (ev[i].error) {
				poller_del(el->poller, tcp_conn->fd, tcp_conn);
				free_tcp_connection(tcp_conn);
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
el_run(struct el *el)
{
	if (pthread_create(&el->tid, NULL, el_io_thread, el) < 0) {
		FATAL("pthread_create(): %s", strerror(errno));
	}
}

