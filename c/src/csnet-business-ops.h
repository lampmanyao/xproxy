#pragma once

#include <stdint.h>

/*
 * Forward declarations
 */
struct csnet_head;
struct csnet_sock;

typedef int64_t (*rsp_cb) (void* b, struct csnet_head* head, char* body, int body_len);
typedef void (*err_cb) (void* b, struct csnet_sock* sock, struct csnet_head* head);
typedef int64_t (*timeout_cb) (void* b);

struct business_ops {
	rsp_cb rsp;
	err_cb err;
	timeout_cb timeout;
};

