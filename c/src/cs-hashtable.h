#pragma once

#include <stdint.h>

struct cs_htnode {
	int key_len;
	int value_len;
	void* key;
	void* value;
	struct cs_htnode* prev;
	struct cs_htnode* next;
};

struct cs_htlist {
	struct cs_htnode* head;
	struct cs_htnode* tail;
};

struct cs_ht {
	struct cs_htlist** lists;
	uint32_t seed;
	int key_count;
	int size;
};

struct cs_ht* cs_ht_new(void);
void cs_ht_free(struct cs_ht*);
int cs_ht_insert(struct cs_ht*, void* key, int key_len, void* value, int value_len);
struct cs_htnode* cs_ht_search(struct cs_ht*, void* key, int key_len);

/*
 * cs_ht_delete() does not free the memory of node, do it yourself.
 * Both key and vlaue of the node.
 */
int cs_ht_delete(struct cs_ht*, struct cs_htnode* node);

