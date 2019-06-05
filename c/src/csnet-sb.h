#pragma once

#include <stddef.h>

struct csnet_sb {
	size_t capacity;
	size_t len;
	char* buffer;
};

int csnet_sb_init(struct csnet_sb* sb, size_t capacity);
void csnet_sb_destroy(struct csnet_sb*);
size_t csnet_sb_append(struct csnet_sb*, const char* data, size_t len);
size_t csnet_sb_seek(struct csnet_sb*, size_t len);
void csnet_sb_reset(struct csnet_sb*);
char* csnet_sb_data(struct csnet_sb*);
size_t csnet_sb_len(struct csnet_sb*);

