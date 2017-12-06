#pragma once

struct cs_slist_node {
	void* data;
	struct cs_slist_node* next;
};

struct cs_slist {
	struct cs_slist_node* head;
};

struct cs_slist_node* cs_slist_node_new(void* data);
void cs_slist_node_free(struct cs_slist_node* node);

struct cs_slist* cs_slist_new(void);
void cs_slist_free(struct cs_slist*);

struct cs_slist_node* cs_slist_search(struct cs_slist*, void* data);
void cs_slist_insert(struct cs_slist*, struct cs_slist_node* x);
void cs_slist_remove(struct cs_slist*, struct cs_slist_node* x);
void cs_slist_reverse(struct cs_slist*);
void cs_slist_print(const struct cs_slist*);

