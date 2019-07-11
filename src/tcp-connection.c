#include "tcp-connection.h"
#include "log.h"
#include "utils.h"
#include "socks5.h"

#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/tcp.h>

struct tcp_connection*
new_tcp_connection(int fd, size_t bufsize, recv_callback recv_cb, send_callback send_cb)
{
	struct tcp_connection *tcp_conn = calloc(1, sizeof(*tcp_conn));
	if (slow(!tcp_conn)) {
		oom(sizeof(*tcp_conn));
	}

//	int opt = 1;
//	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

	tcp_conn->fd = fd;
	tcp_conn->stage = SOCKS5_STAGE_EXCHG_METHOD;
	tcp_conn->closed = 0;
	memset(tcp_conn->host, 0, 256);

	tcp_conn->rbuf_size = bufsize;
	tcp_conn->rbuf_len = 0;
	tcp_conn->rbuf = malloc(bufsize);
	memset(tcp_conn->rbuf, 0, bufsize);

	tcp_conn->sbuf_size = bufsize;
	tcp_conn->sbuf_len = 0;
	tcp_conn->sbuf = malloc(bufsize);
	memset(tcp_conn->sbuf, 0, bufsize);

	tcp_conn->recv_cb = recv_cb;
	tcp_conn->send_cb = send_cb;
	tcp_conn->peer_tcp_conn = NULL;

	return tcp_conn;
}

void
free_tcp_connection(struct tcp_connection *tcp_conn)
{
	close(tcp_conn->fd);
	free(tcp_conn->rbuf);
	free(tcp_conn->sbuf);
	free(tcp_conn);
}

void
tcp_connection_sbuf_append(struct tcp_connection *tcp_conn, char *data, size_t len)
{
	assert(tcp_conn != NULL);

	if (fast(tcp_conn->sbuf_size - tcp_conn->sbuf_len >= len)) {
		memcpy(tcp_conn->sbuf + tcp_conn->sbuf_len, data, len);
		tcp_conn->sbuf_len += len;
	} else {
		char *newbuff = malloc(tcp_conn->sbuf_size + len);
		assert(newbuff != NULL);
		tcp_conn->sbuf_size += len;
		memcpy(newbuff, tcp_conn->sbuf, tcp_conn->sbuf_len);
		memcpy(newbuff + tcp_conn->sbuf_len, data, len);
		free(tcp_conn->sbuf);
		tcp_conn->sbuf = newbuff;
		tcp_conn->sbuf_len += len;
	}
}

void
tcp_connection_sbuf_seek(struct tcp_connection *tcp_conn, size_t len)
{
	assert(tcp_conn != NULL);
	assert(tcp_conn->sbuf_len >= len);

	size_t move_len = tcp_conn->sbuf_len - len;
	tcp_conn->sbuf_len = move_len;
	if (move_len > 0) {
		memmove(tcp_conn->sbuf, tcp_conn->sbuf + len, move_len);
	}
}

void
tcp_connection_rbuf_seek(struct tcp_connection *tcp_conn, size_t len)
{
	assert(tcp_conn != NULL);
	assert(tcp_conn->rbuf_len <= len);

	size_t move_len = tcp_conn->rbuf_len - len;
	tcp_conn->rbuf_len = move_len;
	if (move_len > 0) {
		memmove(tcp_conn->rbuf, tcp_conn->rbuf + len, move_len);
	}
}

