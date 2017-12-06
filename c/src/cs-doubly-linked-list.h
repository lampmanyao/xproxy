#pragma once

struct cs_dlist_node {
	void* data;
	struct cs_dlist_node* prev;
	struct cs_dlist_node* next;
};

struct cs_dlist {
	struct cs_dlist_node* head;
	struct cs_dlist_node* tail;
};

struct cs_dlist_node* cs_dlist_node_new(void* data);
void cs_dlist_node_free(struct cs_dlist_node*);

struct cs_dlist* cs_dlist_new(void);
void cs_dlist_free(struct cs_dlist*);
struct cs_dlist_node* cs_dlist_search(struct cs_dlist*, void* data);
void cs_dlist_insert(struct cs_dlist*, struct cs_dlist_node* x);
void cs_dlist_remove(struct cs_dlist*, struct cs_dlist_node* x);

