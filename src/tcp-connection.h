#pragma once

#include <stddef.h>

struct el;
struct tcp_connection;

typedef int (*recv_callback) (struct el*, struct tcp_connection*);
typedef int (*send_callback) (struct el*, struct tcp_connection*);

struct tcp_connection {
	int fd;
	int stage;
	int closed;
	char host[256];

	/* read buffer */
	char *rbuf;
	size_t rbuf_size;
	size_t rbuf_seek;
	size_t rbuf_len;

	/* send buffer */
	char *sbuf;
	size_t sbuf_size;
	size_t sbuf_len;

	recv_callback recv_cb;
	send_callback send_cb;

	struct tcp_connection *peer_tcp_conn;
};

struct tcp_connection *new_tcp_connection(int, size_t size, recv_callback recv_cb, send_callback send_cb);
void free_tcp_connection(struct tcp_connection *);
void tcp_connection_rbuf_seek(struct tcp_connection *, size_t len);
void tcp_connection_sbuf_seek(struct tcp_connection *, size_t len);
void tcp_connection_sbuf_append(struct tcp_connection *, char *data, size_t len);

