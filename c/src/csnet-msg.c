#include "csnet-msg.h"
#include "csnet-socket.h"

#include <stdlib.h>
#include <string.h>

struct csnet_msg*
csnet_msg_new(int size, struct csnet_socket* socket) {
	struct csnet_msg* m = calloc(1, sizeof(*m) + size);
	m->socket = socket;
	m->size = size;
	m->offset = 0;
	return m;
}

void
csnet_msg_free(struct csnet_msg* m) {
	free(m);
}

void
csnet_msg_append(struct csnet_msg* m, char* data, int len) {
	memcpy(m->data + m->offset, data, len);
	m->offset += len;
}

