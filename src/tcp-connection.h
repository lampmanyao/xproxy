#pragma once

#include <stddef.h>

struct el;
struct tcp_connection;

typedef int (*recv_callback) (struct el*, struct tcp_connection*);
typedef int (*send_callback) (struct el*, struct tcp_connection*);

struct tcp_connection {
	int fd;
	int stage;

	char *rxbuf;
	size_t rxbuf_capacity;
	size_t rxbuf_length;

	char *txbuf;
	size_t txbuf_capacity;
	size_t txbuf_length;

	recv_callback recv_cb;
	send_callback send_cb;

	struct tcp_connection *peer_tcp_conn;

	char host[256];
};

struct tcp_connection *new_tcp_connection(int, size_t, recv_callback, send_callback);
void free_tcp_connection(struct tcp_connection *);

void tcp_connection_append_rxbuf(struct tcp_connection *, char *, size_t);
void tcp_connection_reset_rxbuf(struct tcp_connection *);

void tcp_connection_append_txbuf(struct tcp_connection *, char *, size_t);
void tcp_connection_reset_txbuf(struct tcp_connection *);

void tcp_connection_move_txbuf(struct tcp_connection *, size_t);
void tcp_connection_move_rxbuf(struct tcp_connection *, size_t);

