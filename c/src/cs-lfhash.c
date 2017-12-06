#include "cs-lfhash.h"
#include "csnet-fast.h"
#include "csnet-atomic.h"
#include "cs-lflist.h"

#include <stdlib.h>

static uint32_t do_hash(uint32_t seed, const unsigned char* str, const size_t len);

struct cs_lfhash*
cs_lfhash_new(int size) {
	struct cs_lfhash* ht = calloc(1, sizeof(*ht) + size * sizeof(struct cs_lflist*));
	ht->locked = 0;
	csnet_spinlock_init(&ht->lock);
	ht->size = size;
	ht->seed = random() % UINT32_MAX;
	ht->count = 0;
	for (int i = 0; i < size; i++) {
		ht->table[i] = cs_lflist_new();
	}
	return ht;
}

void
cs_lfhash_free(struct cs_lfhash* ht) {
	for (int i = 0; i < ht->size; i++) {
		cs_lflist_free(ht->table[i]);
	}
	free(ht);
}

int
cs_lfhash_insert(struct cs_lfhash* ht, int64_t key, void* data) {
	if (csnet_slow(ht->locked)) {
		csnet_spinlock_lock(&ht->lock);
	}
	uint32_t hash = do_hash(ht->seed, (void*)&key, sizeof(int64_t));
	int index = hash % ht->size;
	int ret = cs_lflist_insert(ht->table[index], key, data);
	if (ret == 0) {
		INC_ONE_ATOMIC(&ht->count);
	}
	if (csnet_slow(ht->locked)) {
		csnet_spinlock_unlock(&ht->lock);
	}
	return ret;
}

struct cs_lflist*
cs_lfhash_getlist(struct cs_lfhash* ht, int64_t key) {
	if (csnet_slow(ht->locked)) {
		csnet_spinlock_lock(&ht->lock);
	}
	uint32_t hash = do_hash(ht->seed, (void*)&key, sizeof(int64_t));
	int index = hash % ht->size;
	return ht->table[index];
}

void*
cs_lfhash_search(struct cs_lfhash* ht, int64_t key) {
	void* data = NULL;
	if (csnet_slow(ht->locked)) {
		csnet_spinlock_lock(&ht->lock);
	}
	uint32_t hash = do_hash(ht->seed, (void*)&key, sizeof(int64_t));
	int index = hash % ht->size;
	struct cs_lflist_node* node = cs_lflist_search(ht->table[index], key);
	if (node) {
		data = node->data;
	}
	if (csnet_slow(ht->locked)) {
		csnet_spinlock_unlock(&ht->lock);
	}
	return data;
}

int cs_lfhash_delete(struct cs_lfhash* ht, int64_t key) {
	if (csnet_slow(ht->locked)) {
		csnet_spinlock_lock(&ht->lock);
	}
	uint32_t hash = do_hash(ht->seed, (void*)&key, sizeof(int64_t));
	int index = hash % ht->size;
	int ret = cs_lflist_delete(ht->table[index], key);
	if (ret == 0) {
		DEC_ONE_ATOMIC(&ht->count);
	}
	if (csnet_slow(ht->locked)) {
		csnet_spinlock_unlock(&ht->lock);
	}
	return ret;
}

unsigned long
cs_lfhash_count(struct cs_lfhash* ht) {
	return INC_N_ATOMIC(&ht->count, 0);
}

struct cs_lflist*
cs_lfhash_get_all_keys(struct cs_lfhash* ht) {
	ht->locked = 1;
	csnet_spinlock_lock(&ht->lock);
	struct cs_lflist* new_list = cs_lflist_new();
	for (int i = 0; i < ht->size; i++) {
		struct cs_lflist* tmp_list = ht->table[i];
		struct cs_lflist_node* tmp_node = tmp_list->head->next;
		while (tmp_node && tmp_node != tmp_list->tail) {
			cs_lflist_insert(new_list, tmp_node->key, NULL);
			tmp_node = tmp_node->next;
		}
	}
	csnet_spinlock_unlock(&ht->lock);
	ht->locked = 0;
	return new_list;
}

static inline uint32_t
do_hash(uint32_t seed, const unsigned char* str, const size_t len) {
	uint32_t hash = seed + len;
	size_t slen = len;

	while (slen--) {
		hash += *str++;
		hash += (hash << 10);
		hash ^= (hash >> 6);
	}
	hash += (hash << 3);
	hash ^= (hash >> 11);
	return (hash + (hash << 15));
}

