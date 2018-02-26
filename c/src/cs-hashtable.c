#include "cs-hashtable.h"

#include <stdio.h>
#include <stdlib.h>  /* calloc and free */
#include <string.h>  /* memcpy */
#include <assert.h>

/*
 * TODO: resize the hash table. Load factor.
 */

static uint32_t _hash(uint32_t seed, const unsigned char* str, const size_t len);
static struct cs_htlist* cs_htlist_new();
static void cs_htlist_free(struct cs_htlist* l);
static void cs_htlist_insert(struct cs_htlist* l, struct cs_htnode* node);
static void cs_htlist_delete(struct cs_htlist* l, struct cs_htnode* node);

struct cs_ht*
cs_ht_new(void) {
	struct cs_ht* table = calloc(1, sizeof(*table));
	table->size = 709;
	table->key_count = 0;
	table->seed = random() % UINT32_MAX;
	table->lists = (struct cs_htlist**)calloc(table->size, sizeof(struct cs_htlist*));

	for (int i = 0; i < table->size; i++) {
		table->lists[i] = cs_htlist_new();
	}

	return table;
}

void
cs_ht_free(struct cs_ht* table) {
	int size = table->size;
	for (int i = 0; i < size; i++) {
		cs_htlist_free(table->lists[i]);
	}
	free(table->lists);
	free(table);
}

int
cs_ht_insert(struct cs_ht* table, void* key, int key_len, void* value, int value_len) {
	uint32_t hash = _hash(table->seed, key, key_len);
	int index = hash % table->size;

	struct cs_htnode* node = calloc(1, sizeof(*node));
	node->key = key;
	node->value = value;
	node->key_len = key_len;
	node->value_len = value_len;
	node->next = NULL;

	cs_htlist_insert(table->lists[index], node);
	table->key_count++;

	return 0;
}

struct cs_htnode*
cs_ht_search(struct cs_ht* table, void* key, int key_len) {
	uint32_t hash = _hash(table->seed, key, key_len);
	int index = hash % table->size;

	if (!table->lists[index]) {
		return NULL;
	}

	struct cs_htnode* temp = table->lists[index]->head;

	while (temp) {
		while (temp && temp->key_len != key_len) {
			temp = temp->next;
		}

		if (temp) {
			if (!memcmp(temp->key, key, key_len)) {
				return temp;
			} else {
				temp = temp->next;
			}
		}
	}

	return NULL;
}

int
cs_ht_delete(struct cs_ht* table, struct cs_htnode* node) {
	uint32_t hash = _hash(table->seed, node->key, node->key_len);
	int index = hash % table->size;

	if (!table->lists[index]) {
		return -1;
	}

	cs_htlist_delete(table->lists[index], node);
	return 0;
}

static inline uint32_t
_hash(uint32_t seed, const unsigned char* str, const size_t len) {
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

static inline struct cs_htlist*
cs_htlist_new(void) {
	struct cs_htlist* l = calloc(1, sizeof(*l));
	l->head = NULL;
	l->tail = NULL;
	return l;
}

static inline void
cs_htlist_free(struct cs_htlist* l) {
	struct cs_htnode* x = l->head;
	while (x) {
		struct cs_htnode* tmp = x->next;
		free(x);
		x = tmp;
	}
	free(l);
}

static inline void
cs_htlist_insert(struct cs_htlist* l, struct cs_htnode* node) {
	node->next = l->head;
	if (l->head) {
		l->head->prev = node;
	}
	l->head = node;
	node->prev = NULL;
}

static inline void
cs_htlist_delete(struct cs_htlist* l, struct cs_htnode* node) {
	if (node->prev) {
		node->prev->next = node->next;
	} else {
		l->head = node->next;
	}

	if (node->next) {
		node->next->prev = node->prev;
	}
}

