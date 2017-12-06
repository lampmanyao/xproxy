#include "cs-lflist.h"
#include "csnet-atomic.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

static int
is_marked_reference(intptr_t p) {
	return (int) (p & 0x1L);
}

static intptr_t
get_marked_reference(intptr_t p) {
	return p | 0x1L;
}

static intptr_t
get_unmarked_reference(intptr_t p) {
	return p & ~0x1L;
}

static struct cs_lflist_node* inner_search(struct cs_lflist* l, int64_t key, struct cs_lflist_node** left_node);

struct cs_lflist_node*
cs_lflist_node_new(int64_t key, void* data) {
	struct cs_lflist_node* node = calloc(1, sizeof(*node));
	node->key = key;
	node->data = data;
	node->next = NULL;
	return node;
}

void
cs_lflist_node_free(struct cs_lflist_node* node) {
	free(node);
}

struct cs_lflist*
cs_lflist_new(void) {
	struct cs_lflist* l = calloc(1, sizeof(*l));
	l->head = cs_lflist_node_new(INT64_MIN, NULL);
	l->tail = cs_lflist_node_new(INT64_MAX, NULL);
	l->head->next = l->tail;
	return l;
}

void
cs_lflist_free(struct cs_lflist* l) {
	struct cs_lflist_node* head = l->head->next;
	struct cs_lflist_node* tmp;
	while (head != l->tail) {
		tmp = head->next;
		cs_lflist_node_free(head);
		head = tmp;
	}
	cs_lflist_node_free(l->head);
	cs_lflist_node_free(l->tail);
	free(l);
}

int
cs_lflist_insert(struct cs_lflist* l, int64_t key, void* data) {
	struct cs_lflist_node* new_node = cs_lflist_node_new(key, data);
	struct cs_lflist_node* right_node = NULL;
	struct cs_lflist_node* left_node = NULL;

	while (1) {
		right_node = inner_search(l, key, &left_node);
		if ((right_node != l->tail) && (right_node->key == key)) {
			free(new_node);
			return -1;
		}
		new_node->next = right_node;
		if (CAS(&(left_node->next), right_node, new_node)) {
			return 0;
		}
	}
}

int
cs_lflist_delete(struct cs_lflist* l, int64_t key) {
	struct cs_lflist_node* right_node = NULL;
	struct cs_lflist_node* right_node_next = NULL;
	struct cs_lflist_node* left_node = NULL;

	while (1) {
		right_node = inner_search(l, key, &left_node);
		if ((right_node == l->tail) || right_node->key != key) {
			return -1;
		}

		right_node_next = right_node->next;
		if (!is_marked_reference((intptr_t)right_node_next)) {
			if (CAS(&(right_node->next), right_node_next, get_marked_reference((intptr_t)right_node_next))) {
				break;
			}
		}
	}

	if (!CAS(&(left_node->next), right_node, right_node_next)) {
		right_node = inner_search(l, right_node->key, &left_node);
	}
	cs_lflist_node_free(right_node);

	return 0;
}

struct cs_lflist_node*
cs_lflist_search(struct cs_lflist* l, int64_t key) {
	struct cs_lflist_node* right_node = NULL;
	struct cs_lflist_node* left_node = NULL;
	right_node = inner_search(l, key, &left_node);

	if ((right_node == l->tail) || (right_node->key != key)) {
		return NULL;
	} else {
		return right_node;
	}
}

static inline struct cs_lflist_node*
inner_search(struct cs_lflist* l, int64_t key, struct cs_lflist_node** left_node) {
	struct cs_lflist_node* left_node_next = NULL;
	struct cs_lflist_node* right_node = NULL;

	while (1) {
		struct cs_lflist_node* t = l->head;
		struct cs_lflist_node* t_next = l->head->next;
		do {
			if (!is_marked_reference((intptr_t)t_next)) {
				(*left_node) = t;
				left_node_next = t_next;
			}
			t = (struct cs_lflist_node*)get_unmarked_reference((intptr_t)t_next);

			if (t == l->tail) {
				break;
			}

			t_next = t->next;
		} while (is_marked_reference((intptr_t)t_next) || (t->key < key));

		right_node = t;

		if (left_node_next == right_node) {
			if ((right_node != l->tail) && is_marked_reference((intptr_t)right_node->next)) {
				continue;
			} else {
				return right_node;
			}
		} else {
			if (CAS(&(*left_node)->next, left_node_next, right_node)) {
				if ((right_node != l->tail) && is_marked_reference((intptr_t)right_node->next)) {
					continue;
				} else {
					return right_node;
				}
			}
		}
	}
}

