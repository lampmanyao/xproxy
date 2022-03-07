#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <strings.h>
#include <signal.h>
#include <netinet/in.h>

#include "el.h"
#include "log.h"
#include "utils.h"
#include "tcp-connection.h"
#include "xproxy.h"
#include "poller.h"

struct el *el_new()
{
	struct el *el = calloc(1, sizeof(*el));
	if (!el)
		oom(sizeof(*el));

	el->poller = poller_open();
	return el;
}

void el_free(struct el *el)
{
	poller_close(el->poller);
	free(el);
}

void el_watch(struct el *el, struct tcp_connection *tcp_conn)
{
	poller_add(el->poller, tcp_conn->fd, tcp_conn);
}

void el_unwatch(struct el *el, struct tcp_connection *tcp_conn)
{
	poller_del(el->poller, tcp_conn->fd, tcp_conn);
}

static void remove_tcp_connection(struct poller_event *ev, int n, struct tcp_connection *tcp_conn)
{
	for (int i = 0; i < n; i++) {
		if (ev[i].ptr == tcp_conn) {
			ev[i].ptr = NULL;
			break;
		}
	}
}

static void handle_error(struct el *el, struct poller_event *ev, int n, struct tcp_connection *tcp_conn)
{
	if (tcp_conn->peer_tcp_conn) {
		remove_tcp_connection(ev, n, tcp_conn->peer_tcp_conn);
		el_unwatch(el, tcp_conn->peer_tcp_conn);
		free_tcp_connection(tcp_conn->peer_tcp_conn);
	}

	remove_tcp_connection(ev, n, tcp_conn);
	el_unwatch(el, tcp_conn);
	free_tcp_connection(tcp_conn);
}

static void *el_io_thread(void *arg)
{
	struct el *el = (struct el *)arg;

	while (1) {
		struct poller_event ev[1024];
		int n = poller_wait(el->poller, ev, 1024, 1000);
		for (int i = 0; i < n; ++i) {
			struct tcp_connection *tcp_conn;
			tcp_conn = ev[i].ptr;

			if (!tcp_conn)
				continue;

			if (ev[i].read) {
				if (tcp_conn->recv_cb(el, tcp_conn) == -1) {
					handle_error(el, ev, n, tcp_conn);
					continue;
				}
			}

			if (ev[i].write) {
				if (tcp_conn->send_cb(el, tcp_conn) == -1) {
					handle_error(el, ev, n, tcp_conn);
					continue;
				}
			}

			if (ev[i].eof || ev[i].error) {
				handle_error(el, ev, n, tcp_conn);
			}
		}

		if (n == -1) {
			if (errno == EINTR)
				continue;
			return NULL;
		}
	}

	return NULL;
}

void el_run(struct el *el)
{
	if (pthread_create(&el->tid, NULL, el_io_thread, el) < 0)
		FATAL("pthread_create(): %s", strerror(errno));
}

