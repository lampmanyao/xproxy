#include "cs-doubly-linked-list.h"

#include <stdlib.h>

struct cs_dlist_node*
cs_dlist_node_new(void* data) {
	struct cs_dlist_node* node = calloc(1, sizeof(*node));
	node->data = data;
	node->prev = NULL;
	node->next = NULL;
	return node;
}

void
cs_dlist_node_free(struct cs_dlist_node* node) {
	free(node);
}

struct cs_dlist*
cs_dlist_new(void) {
	struct cs_dlist* l = calloc(1, sizeof(*l));
	l->head = NULL;
	l->tail = NULL;
	return l;
}

void
cs_dlist_free(struct cs_dlist* l) {
	struct cs_dlist_node* x = l->head;
	while (x) {
		struct cs_dlist_node* tmp = x->next;
		cs_dlist_node_free(x);
		x = tmp;
	}
	free(l);
}

struct cs_dlist_node*
cs_dlist_search(struct cs_dlist* l, void* data) {
	struct cs_dlist_node* head = l->head;
	while (head && head->data != data) {
		head = head->next;
	}
	return head;
}

void
cs_dlist_insert(struct cs_dlist* l, struct cs_dlist_node* node) {
	node->next = l->head;
	if (l->head) {
		l->head->prev = node;
	}
	l->head = node;
	node->prev = NULL;
}

void
cs_dlist_remove(struct cs_dlist* l, struct cs_dlist_node* node) {
	if (node->prev) {
		node->prev->next = node->next;
	} else {
		l->head = node->next;
	}
	if (node->next) {
		node->next->prev = node->prev;
	}
}

