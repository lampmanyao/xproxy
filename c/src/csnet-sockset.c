#include "csnet-sockset.h"
#include "csnet-socket.h"
#include "csnet-rb.h"
#include "csnet-utils.h"
#include "csnet-atomic.h"
#include "csnet-socks5.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef JEMALLOC
#include <jemalloc/jemalloc.h>
#endif

static unsigned int CURRSID  = 0xab;

static inline unsigned int
SOCKID(void) {
	unsigned int sid;
	unsigned int tmp;

again:
	sid = INC_ONE_ATOMIC(&CURRSID);
	if (sid >= 0xbabeface) {
		tmp = ACCESS_ONCE(CURRSID);
		if (tmp >= 0xbabeface) {
			CURRSID = 0xab;
		}
		goto again;
	}
	return sid;
}

struct csnet_sockset*
csnet_sockset_new(int max_conn, int type) {
	struct csnet_sockset* set = calloc(1, sizeof(*set) + max_conn * sizeof(struct csnet_socket*));
	if (!set) {
		csnet_oom(sizeof(*set));
	}

	set->max_conn = max_conn;
	for (int i = 0; i < max_conn; i++) {
		struct csnet_socket* socket = csnet_socket_new(1024, type);
		set->set[i] = socket;
	}

	return set;
}

void
csnet_sockset_free(struct csnet_sockset* set) {
	for (int i = 0; i < set->max_conn; i++) {
		csnet_socket_free(set->set[i]);
	}
	free(set);
}

unsigned int
csnet_sockset_put(struct csnet_sockset* set, int fd) {
	int count = set->max_conn;
	unsigned int sid = SOCKID();
	struct csnet_socket* socket = set->set[sid % set->max_conn];
	while (socket->sid != 0 && --count > 0) {
		sid = SOCKID();
		socket = set->set[sid % set->max_conn];
	}
	socket->sid = sid;
	socket->fd = fd;
	socket->state = SOCKS5_ST_EXMETHOD;
	return sid;
}

struct csnet_socket*
csnet_sockset_get_socket(struct csnet_sockset* set, unsigned int sid) {
	return set->set[sid % set->max_conn];
}

void
csnet_sockset_reset_socket(struct csnet_sockset* set, unsigned int sid) {
	struct csnet_socket* socket = set->set[sid % set->max_conn];
	if (socket->sid == sid) {
		csnet_socket_reset(socket);
		socket->sock = NULL;
	}
}

