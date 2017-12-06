#pragma once

#include <stdint.h>

struct cs_lflist_node {
	int64_t key;
	void* data;
	struct cs_lflist_node* next;
};

struct cs_lflist {
	struct cs_lflist_node* head;
	struct cs_lflist_node* tail;
};

struct cs_lflist_node* cs_lflist_node_new(int64_t key, void* data);
void cs_lflist_node_free(struct cs_lflist_node* node);

struct cs_lflist* cs_lflist_new(void);
void cs_lflist_free(struct cs_lflist*);
int cs_lflist_insert(struct cs_lflist*, int64_t key, void* data);
int cs_lflist_delete(struct cs_lflist*, int64_t key);
struct cs_lflist_node* cs_lflist_search(struct cs_lflist*, int64_t key);

