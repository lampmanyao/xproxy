#pragma once

#include <stddef.h>

struct csnet_rb {
	size_t capacity;
	size_t seek;
	size_t len;
	char* buffer;
};

void csnet_rb_init(struct csnet_rb*, size_t size);
void csnet_rb_destroy(struct csnet_rb*);
void csnet_rb_append(struct csnet_rb*, const char* data, size_t len);
void csnet_rb_seek(struct csnet_rb*, size_t len);
void csnet_rb_reset(struct csnet_rb*);
char* csnet_rb_data(struct csnet_rb*);
size_t csnet_rb_len(struct csnet_rb*);

