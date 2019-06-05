#pragma once

#include <openssl/ssl.h>

/*
 * Forward declarations
 */
struct socket;

struct csnet_sockset {
	int max_conn;
	struct csnet_socket* set[0];
};

struct csnet_sockset* csnet_sockset_new(int max_conn, int type);
void csnet_sockset_free(struct csnet_sockset*);
struct csnet_socket* csnet_sockset_put(struct csnet_sockset*, int fd);
struct csnet_socket* csnet_sockset_get_socket(struct csnet_sockset*, unsigned int sid);
void csnet_sockset_reset_socket(struct csnet_sockset*, unsigned int fd);

