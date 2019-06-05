#pragma once

#include "csnet-rb.h"
#include "csnet-sb.h"

struct csnet_socket {
	int fd;
	unsigned int sid;
	int stage;
	int type;
	struct csnet_rb rb;
	struct csnet_sb sb;
	struct csnet_socket* sock;
	char host[128];
};

struct csnet_socket* csnet_socket_new(int rb_size, int type);
void csnet_socket_free(struct csnet_socket*);
int csnet_socket_recv(struct csnet_socket*);
int csnet_socket_send_buff(struct csnet_socket*, char* buff, int len);
int csnet_socket_send(struct csnet_socket*);
void csnet_socket_reset(struct csnet_socket*);

