#pragma once

#include "csnet-spinlock.h"

#include <stdint.h>

/*
 * Forward declarations
 */
struct cs_lflist;

struct cs_lfhash {
	unsigned int locked;
	csnet_spinlock_t lock;
	int size;
	uint32_t seed;
	unsigned long count;
	struct cs_lflist* table[0];
};

struct cs_lfhash* cs_lfhash_new(int size);
void cs_lfhash_free(struct cs_lfhash*);
int cs_lfhash_insert(struct cs_lfhash*, int64_t key, void* data);
void* cs_lfhash_search(struct cs_lfhash*, int64_t key);
int cs_lfhash_delete(struct cs_lfhash*, int64_t key);
unsigned long cs_lfhash_count(struct cs_lfhash*);
struct cs_lflist* cs_lfhash_get_all_keys(struct cs_lfhash*);
struct cs_lflist* cs_lfhash_getlist(struct cs_lfhash* ht, int64_t key);

