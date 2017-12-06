#pragma once

/*
 * Forward declarations
 */
struct csnet_rb;

struct csnet_socket {
	int fd;
	unsigned int sid;
	int state;
	int type;
	struct csnet_rb* rb;
	struct csnet_socket* sock;
	char host[128];
};

struct csnet_socket* csnet_socket_new(int rb_size, int type);
void csnet_socket_free(struct csnet_socket*);
int csnet_socket_recv(struct csnet_socket*);
int csnet_socket_send(struct csnet_socket*, char* buff, int len);
void csnet_socket_reset(struct csnet_socket*);

