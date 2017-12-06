#include "csnet-socket.h"
#include "csnet-log.h"
#include "csnet-fast.h"
#include "csnet-utils.h"
#include "csnet-rb.h"
#include "csnet-socks5.h"

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#ifdef JEMALLOC
#include <jemalloc/jemalloc.h>
#endif

#define READ_BUFFER_SIZE  (16 * 1024)

struct csnet_socket*
csnet_socket_new(int rsize, int type) {
	struct csnet_socket* socket = calloc(1, sizeof(*socket));
	if (csnet_slow(!socket)) {
		csnet_oom(sizeof(*socket));
	}
	socket->fd = 0;
	socket->sid = 0;
	socket->state = SOCKS5_ST_START;
	socket->type = type;
	socket->rb = csnet_rb_new(rsize);
	socket->sock = NULL;
	return socket;
}

void
csnet_socket_free(struct csnet_socket* socket) {
	csnet_rb_free(socket->rb);
	free(socket);
}

int
csnet_socket_recv(struct csnet_socket* socket) {
	char recvbuf[READ_BUFFER_SIZE] = {0};
	int nrecv;

tryagain:
	nrecv = recv(socket->fd, recvbuf, READ_BUFFER_SIZE, 0);
	if (csnet_fast(nrecv > 0)) {
		csnet_rb_append(socket->rb, recvbuf, nrecv);
		return nrecv;
	}

	if (nrecv < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
			goto tryagain;
		}
		debug("recv() error from socket[%d]: %s", socket->fd, strerror(errno));
		return -1; /* error */
	}

	return -1; /* peer closed */
}

int
csnet_socket_send(struct csnet_socket* socket, char* buff, int len) {
	int nsend = 0;
	int remain = len;
	while (remain > 0) {
		nsend = send(socket->fd, buff + len - remain, remain, 0);
		if (csnet_slow(nsend < 0)) {
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
				continue;
			}
			debug("send() error to socket[%d]: %s", socket->fd, strerror(errno));
			return -1;
		}
		remain -= nsend;
	}
	return len;
}

void
csnet_socket_reset(struct csnet_socket* socket) {
	close(socket->fd);
	socket->sid = 0;
	socket->state = SOCKS5_ST_START;
	csnet_rb_reset(socket->rb);
}

