#include "cs-singly-linked-list.h"

#include <stdio.h>
#include <stdlib.h>

struct cs_slist_node*
cs_slist_node_new(void* data) {
	struct cs_slist_node* node = calloc(1, sizeof(*node));
	node->data = data;
	node->next = NULL;
	return node;
}

void
cs_slist_node_free(struct cs_slist_node* node) {
	free(node);
}

struct cs_slist*
cs_slist_new(void) {
	struct cs_slist* l = calloc(1, sizeof(*l));
	l->head = NULL;
	return l;
}

void
cs_slist_free(struct cs_slist* l) {
	struct cs_slist_node* curr = l->head;
	while (curr) {
		struct cs_slist_node* tmp = curr->next;
		free(curr->data);
		cs_slist_node_free(curr);
		curr = tmp;
	}
	free(l);
}

struct cs_slist_node*
cs_slist_search(struct cs_slist* l, void* data) {
	struct cs_slist_node* curr = l->head;
	while (curr && curr->data != data) {
		curr = curr->next;
	}
	return curr;
}

void
cs_slist_insert(struct cs_slist* l, struct cs_slist_node* node) {
	node->next = l->head;
	l->head = node;
}

void
cs_slist_remove(struct cs_slist* l, struct cs_slist_node* node) {
	struct cs_slist_node* head = l->head;
	struct cs_slist_node* curr = head;
	while (head && head->data != node->data) {
		curr = head;
		head = head->next;
	}
	if (curr) {
		if (curr->data == node->data) {
			l->head = node->next;
		} else {
			curr->next = node->next;
		}

		cs_slist_node_free(node);
	}
}

void
cs_slist_reverse(struct cs_slist* l) {
	struct cs_slist_node* prev = NULL;
	struct cs_slist_node* curr = l->head;
	while (curr) {
		struct cs_slist_node* next = curr->next;
		curr->next = prev;
		prev = curr;
		curr = next;
	}
	l->head = prev;
}

