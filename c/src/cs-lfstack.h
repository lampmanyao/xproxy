#pragma once

#include <stdint.h>

struct cs_lfstack_node {
	void* data;
	struct cs_lfstack_node* next;
};

struct cs_tagged_pointer {
	struct cs_lfstack_node* node;
	uint64_t tag;
} __attribute__((aligned(16)));

struct cs_lfstack {
	struct cs_tagged_pointer* top;
};

struct cs_lfstack_node* cs_lfstack_node_new(void* data);
void cs_lfstack_node_free(struct cs_lfstack_node*);

struct cs_lfstack* cs_lfstack_new(void);
void cs_lfstack_free(struct cs_lfstack*);

void cs_lfstack_push(struct cs_lfstack*, void* data);
void* cs_lfstack_pop(struct cs_lfstack*);

