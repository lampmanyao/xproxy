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
_expand(int size) {
	if (size > MAX_BUFFER_LEN) {
		return NULL;
	}

	return calloc(1, size);
}

struct csnet_rb*
csnet_rb_new(unsigned int size) {
	struct csnet_rb* rb = calloc(1, sizeof(*rb));
	if (!rb) {
		csnet_oom(sizeof(*rb));
	}

	rb->capacity = size;
	rb->len = 0;
	rb->seek = 0;

	rb->buffer = calloc(1, size);
	if (!rb->buffer) {
		csnet_oom(size);
	}

	return rb;
}

void
csnet_rb_free(struct csnet_rb* rb) {
	free(rb->buffer);
	free(rb);
}

int
csnet_rb_append(struct csnet_rb* rb, const char* data, unsigned int len) {
	unsigned int remain = rb->capacity - rb->len;

	if (remain < len) {
		/* insufficient space, make a new memory */
		rb->capacity += len;
		char* new_buffer = _expand(rb->capacity);
		if (csnet_slow(!new_buffer)) {
			csnet_oom(rb->capacity + len);
		}

		if (rb->len == 0) {
			memcpy(new_buffer, data, len);
		} else {
			memcpy(new_buffer, rb->buffer, rb->len);
			memcpy(new_buffer + rb->len, data, len);
		}

		free(rb->buffer);
		rb->buffer = new_buffer;
		rb->len += len;
	} else {
		memcpy(rb->buffer + rb->len, data, len);
		rb->len += len;
	}

	return 0;
}

unsigned int
csnet_rb_seek(struct csnet_rb* rb, unsigned int len) {
	if (csnet_slow(len > rb->len)) {
		fatal("len > rb->len");
	}

	if (len == rb->len) {
		rb->len = 0;
	} else {
		rb->len -= len;
		memmove(rb->buffer, rb->buffer + len, rb->len);
	}
	return 0;
}

inline char*
csnet_rb_data(struct csnet_rb* rb) {
	return rb->buffer;
}

inline unsigned int
csnet_rb_len(struct csnet_rb* rb) {
	return rb->len;
}

void
csnet_rb_reset(struct csnet_rb* rb) {
	rb->len = 0;
}

