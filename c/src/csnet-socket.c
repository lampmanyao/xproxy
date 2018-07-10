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
	socket->stage = SOCKS5_STAGE_EXMETHOD;
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
	int r = recv(socket->fd, recvbuf, READ_BUFFER_SIZE, 0);
	if (csnet_fast(r > 0)) {
		csnet_rb_append(socket->rb, recvbuf, r);
		return r;
	}

	if (r < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return 0;
		}
		return -1; /* error */
	}

	return -1; /* peer closed */
}

int
csnet_socket_send(struct csnet_socket* socket, char* buff, int len) {
	int s = 0;
	int remain = len;
	while (remain > 0) {
		s = send(socket->fd, buff + len - remain, remain, 0);
		if (csnet_slow(s < 0)) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				continue;
			}
			return -1;
		}
		remain -= s;
	}
	return len;
}

void
csnet_socket_reset(struct csnet_socket* socket) {
	close(socket->fd);
	socket->sid = 0;
	socket->stage = SOCKS5_STAGE_EXMETHOD;
	csnet_rb_reset(socket->rb);
}

