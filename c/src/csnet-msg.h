#pragma once

/*
 * Forward declarations
 */
struct csnet_socket;

struct csnet_msg {
	struct csnet_socket* socket;
	int size;
	int offset;
	char data[0];
};

struct csnet_msg* csnet_msg_new(int size, struct csnet_socket* socket);
void csnet_msg_free(struct csnet_msg*);
void csnet_msg_append(struct csnet_msg*, char* data, int len);

