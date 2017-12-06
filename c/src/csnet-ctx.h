#pragma once

#include <pthread.h>
#include <stdint.h>


#define CTX_SIZE 0x1000

/*
 * Forward declarations
 */
struct cs_lfqueue;
struct cs_lfhash;

struct csnet_ctx {
	int64_t ctxid;
	int timeout;
	int prev_wheel;
	int curr_wheel;
	unsigned long curr_time;
	struct cs_lfqueue* q;
	struct cs_lfhash* which_wheel_tbl;
	struct cs_lfhash* wheels_tbl[0];
};

struct csnet_ctx* csnet_ctx_new(int size, int timeout, struct cs_lfqueue* q);
void csnet_ctx_free(struct csnet_ctx*);
int csnet_ctx_insert(struct csnet_ctx*, int64_t ctxid, void* business, int bsize);
int64_t csnet_ctx_ctxid(struct csnet_ctx*);
void csnet_ctx_update(struct csnet_ctx*, int64_t ctxid);
void* csnet_ctx_search(struct csnet_ctx*, int64_t ctxid);
void csnet_ctx_delete(struct csnet_ctx*, int64_t ctxid);
int csnet_ctx_book_keeping(struct csnet_ctx*);

