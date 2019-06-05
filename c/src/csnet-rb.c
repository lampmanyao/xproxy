#include "csnet-rb.h"
#include "csnet-utils.h"
#include "csnet-log.h"
#include "csnet-fast.h"

#include <stdlib.h>
#include <string.h>

#ifdef JEMALLOC
#include <jemalloc/jemalloc.h>
#endif

#define MAX_BUFFER_LEN 1024 * 1024 * 10  /* 5M */

static inline char*
_expand(size_t size) {
	if (size > MAX_BUFFER_LEN) {
		return NULL;
	}

	return calloc(1, size);
}

void
csnet_rb_init(struct csnet_rb* rb, size_t size) {
	rb->capacity = size;
	rb->len = 0;
	rb->seek = 0;

	rb->buffer = calloc(1, size);
	if (!rb->buffer) {
		csnet_oom(size);
	}
}

void
csnet_rb_destroy(struct csnet_rb* rb) {
	free(rb->buffer);
}

void
csnet_rb_seek(struct csnet_rb* rb, size_t len) {
	if (csnet_slow(len > rb->len)) {
		fatal("len > rb->len");
	}

	size_t need_to_move = rb->len - len;

	if (need_to_move) {
		rb->len = 0;
	} else {
		memmove(rb->buffer, rb->buffer + len, need_to_move);
		rb->len -= len;
	}
}

inline char*
csnet_rb_data(struct csnet_rb* rb) {
	return rb->buffer;
}

inline size_t
csnet_rb_len(struct csnet_rb* rb) {
	return rb->len;
}

void
csnet_rb_reset(struct csnet_rb* rb) {
	rb->len = 0;
	rb->seek = 0;
}

