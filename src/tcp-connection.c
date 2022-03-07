#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/tcp.h>

#include "tcp-connection.h"
#include "log.h"
#include "utils.h"
#include "socks5.h"

struct tcp_connection* new_tcp_connection(int fd, size_t bufsize, recv_callback recv_cb, send_callback send_cb)
{
	struct tcp_connection *tcp_conn = calloc(1, sizeof(*tcp_conn));
	if (slow(!tcp_conn))
		oom(sizeof(*tcp_conn));

#if 0
	int opt = 1;
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
#endif

	tcp_conn->fd = fd;
	tcp_conn->stage = SOCKS5_STAGE_EXCHG_METHOD;
	memset(tcp_conn->host, 0, 256);

	tcp_conn->rxbuf = malloc(bufsize);
	memset(tcp_conn->rxbuf, 0, bufsize);
	tcp_conn->rxbuf_capacity = bufsize;
	tcp_conn->rxbuf_length = 0;

	tcp_conn->txbuf = malloc(bufsize);
	memset(tcp_conn->txbuf, 0, bufsize);
	tcp_conn->txbuf_capacity = bufsize;
	tcp_conn->txbuf_length = 0;

	tcp_conn->recv_cb = recv_cb;
	tcp_conn->send_cb = send_cb;

	tcp_conn->peer_tcp_conn = NULL;

	return tcp_conn;
}

void free_tcp_connection(struct tcp_connection *tcp_conn)
{
	close(tcp_conn->fd);
	free(tcp_conn->rxbuf);
	free(tcp_conn->txbuf);
	free(tcp_conn);
}


void tcp_connection_append_rxbuf(struct tcp_connection *tcp_conn, char *data, size_t len)
{
	size_t available = tcp_conn->rxbuf_capacity - tcp_conn->rxbuf_length;
	if (available >= len) {
		memcpy(tcp_conn->rxbuf + tcp_conn->rxbuf_length, data, len);
		tcp_conn->rxbuf_length += len;
	} else {
		if (tcp_conn->rxbuf_length > 0) {
			char *new_buf = calloc(1, tcp_conn->rxbuf_length + len);
			memcpy(new_buf, tcp_conn->rxbuf, tcp_conn->rxbuf_length);
			memcpy(new_buf + tcp_conn->rxbuf_length, data, len);
			free(tcp_conn->rxbuf);
			tcp_conn->rxbuf = new_buf;
			tcp_conn->rxbuf_capacity = tcp_conn->rxbuf_length + len;
			tcp_conn->rxbuf_length += len;
		} else {
			char *new_buf = calloc(1, len);
			memcpy(new_buf, data, len);
			free(tcp_conn->rxbuf);
			tcp_conn->rxbuf = new_buf;
			tcp_conn->rxbuf_capacity = len;
			tcp_conn->rxbuf_length = len;
		}
	}
}

void tcp_connection_append_txbuf(struct tcp_connection *tcp_conn, char *data, size_t len)
{
	size_t available = tcp_conn->txbuf_capacity - tcp_conn->txbuf_length;
	if (available >= len) {
		memcpy(tcp_conn->txbuf + tcp_conn->txbuf_length, data, len);
		tcp_conn->txbuf_length += len;
	} else {
		if (tcp_conn->txbuf_length > 0) {
			char *new_buf = calloc(1, tcp_conn->txbuf_length + len);
			memcpy(new_buf, tcp_conn->txbuf, tcp_conn->txbuf_length);
			memcpy(new_buf + tcp_conn->txbuf_length, data, len);
			free(tcp_conn->txbuf);
			tcp_conn->txbuf = new_buf;
			tcp_conn->txbuf_capacity = tcp_conn->txbuf_length + len;
			tcp_conn->txbuf_length += len;
		} else {
			char *new_buf = calloc(1, len);
			memcpy(new_buf, data, len);
			free(tcp_conn->txbuf);
			tcp_conn->txbuf = new_buf;
			tcp_conn->txbuf_capacity = len;
			tcp_conn->txbuf_length = len;
		}
	}
}

void tcp_connection_reset_txbuf(struct tcp_connection *tcp_conn)
{
	tcp_conn->txbuf_length = 0;
}

void tcp_connection_reset_rxbuf(struct tcp_connection *tcp_conn)
{
	tcp_conn->rxbuf_length = 0;
}

void tcp_connection_move_txbuf(struct tcp_connection *tcp_conn, size_t len)
{
	tcp_conn->txbuf_length -= len;
	memmove(tcp_conn->txbuf, tcp_conn->txbuf + len, tcp_conn->txbuf_length);
}

void tcp_connection_move_rxbuf(struct tcp_connection *tcp_conn, size_t len)
{
	tcp_conn->rxbuf_length -= len;
	memmove(tcp_conn->rxbuf, tcp_conn->rxbuf + len, tcp_conn->rxbuf_length);
}

