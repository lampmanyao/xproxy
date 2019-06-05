#include "csnet-sb.h"
#include "csnet-log.h"
#include "csnet-fast.h"
#include "csnet-utils.h"

#include <stdlib.h>
#include <string.h>

#ifdef JEMALLOC
#include <jemalloc/jemalloc.h>
#endif

#define BUFFER_MAX_LEN (1024 * 1024 * 5)  /* 5M */

static inline char*
_expand(size_t size) {
	if (size > BUFFER_MAX_LEN) {
		return NULL;
	}

	return malloc(size);
}

int
csnet_sb_init(struct csnet_sb* sb, size_t capacity) {
	sb->capacity = capacity;
	sb->len = 0;
	sb->buffer = calloc(1, capacity);

	if (!sb->buffer) {
		csnet_oom(capacity);
	}
	return 0;
}

void
csnet_sb_destroy(struct csnet_sb* sb) {
	free(sb->buffer);
}

size_t
csnet_sb_append(struct csnet_sb* sb, const char* data, size_t len) {
	if (sb->capacity - sb->len > len) {
		memcpy(sb->buffer + sb->len, data, len);
		sb->len += len;
		return sb->len;
	}

	char* new_buffer = _expand(sb->capacity * 2);
	if (csnet_fast(new_buffer)) {
		sb->capacity *= 2;
		memcpy(new_buffer, sb->buffer, sb->len);
		memcpy(new_buffer + sb->len, data, len);
		free(sb->buffer);
		sb->buffer = new_buffer;
		sb->len += len;
		return sb->len;
	}
	return 0;
}

size_t 
csnet_sb_seek(struct csnet_sb* sb, size_t len) {
	if (csnet_slow(len > sb->len)) {
		/* TODO: len and seek should be reset ? */
		return 0;
	}

	size_t move_len = sb->len - len;
	if (move_len == 0) {
		sb->len = 0;
		return 0;
	}

	memmove(sb->buffer, sb->buffer + len, move_len);
	sb->len -= len;

	return sb->len;
}

char*
csnet_sb_data(struct csnet_sb* sb) {
	return sb->buffer;
}

size_t
csnet_sb_len(struct csnet_sb* sb) {
	return sb->len;
}

void
csnet_sb_reset(struct csnet_sb* sb) {
	sb->len = 0;
}

