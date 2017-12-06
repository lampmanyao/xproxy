#include "cs-priority-queue.h"

#include <stdio.h>
#include <stdlib.h>

static struct cs_pqnode* _minimum_node(struct cs_pqnode* node);
static void _transplant(struct cs_pqueue* q, struct cs_pqnode* u, struct cs_pqnode* v);
static void _inorder_walk(struct cs_pqnode* node);
static void _pqueue_free(struct cs_pqnode* node);
static struct cs_pqnode* _cs_pqueue_minimum(struct cs_pqueue* q);
static struct cs_pqnode* _cs_pqueue_maximum(struct cs_pqueue* q);

struct cs_pqueue*
cs_pqueue_new(cs_pqueue_mode_t mode) {
	struct cs_pqueue* q = calloc(1, sizeof(*q));
	q->mode = mode;
	q->root = NULL;
	q->lowest = NULL;
	q->highest = NULL;
	return q;
}

void
cs_pqueue_free(struct cs_pqueue* q) {
	_pqueue_free(q->root);
	free(q);
}

int
cs_pqueue_push(struct cs_pqueue* q, int priority, char* value) {
	struct cs_pqnode* new_node = calloc(1, sizeof(*new_node));
	new_node->priority = priority;
	new_node->value = value;
	new_node->parent = NULL;
	new_node->left = NULL;
	new_node->right = NULL;

	struct cs_pqnode* tmp = NULL;
	struct cs_pqnode* root = q->root;

	while (root) {
		tmp = root;
		if (priority < root->priority) {
			root = root->left;
		} else {
			root = root->right;
		}
	}

	new_node->parent = tmp;
	if (!tmp) {
		q->root = new_node;
		q->lowest = new_node;
		q->highest = new_node;
	} else if (priority < tmp->priority) {
		tmp->left = new_node;
		if (priority < q->lowest->priority) {
			q->lowest = new_node;
		}
	} else {
		tmp->right = new_node;
		if (priority > q->highest->priority) {
			q->highest = new_node;
		}
	}

	return 0;
}

/* Pop the highest priority node */
struct cs_pqnode*
cs_pqueue_pop(struct cs_pqueue* q) {
	if (q->mode == CS_PQ_LOWEST_PRIORITY) {
		return q->lowest;
	} else {
		return q->highest;
	}
}

void
cs_pqueue_delete(struct cs_pqueue* q, struct cs_pqnode* node) {
	if (!node->left) {
		_transplant(q, node, node->right);
	} else if (!node->right) {
		_transplant(q, node, node->left);
	} else {
		struct cs_pqnode* tmp = _minimum_node(node->right);
		if (tmp->parent != node) {
			_transplant(q, tmp, tmp->right);
			tmp->right = node->right;
			tmp->right->parent = tmp;
		}

		_transplant(q, node, tmp);
		tmp->left = node->left;
		tmp->left->parent = tmp;
	}

	if (q->mode == CS_PQ_LOWEST_PRIORITY) {
		q->lowest = _cs_pqueue_minimum(q);
	} else {
		q->highest = _cs_pqueue_maximum(q);
	}

	free(node);
}

void
cs_pqueue_inorder_walk(struct cs_pqueue* q) {
	_inorder_walk(q->root);
}

static inline struct cs_pqnode*
_cs_pqueue_minimum(struct cs_pqueue* q) {
	struct cs_pqnode* node = q->root;
	while (node && node->left) {
		node = node->left;
	}
	return node;
}

static inline struct cs_pqnode*
_cs_pqueue_maximum(struct cs_pqueue* q) {
	struct cs_pqnode* node = q->root;
	while (node && node->right) {
		node = node->right;
	}
	return node;
}

static inline struct cs_pqnode*
_minimum_node(struct cs_pqnode* node) {
	struct cs_pqnode* min_node = node;
	while (node && min_node->left) {
		min_node = min_node->left;
	}
	return min_node;
}

static inline void
_transplant(struct cs_pqueue* q, struct cs_pqnode* u, struct cs_pqnode* v) {
	if (!u->parent) {
		q->root = v;
	} else if (u == u->parent->left) {
		u->parent->left = v;
	} else {
		u->parent->right = v;
	}

	if (v) {
		v->parent = u->parent;
	}
}

static inline void
_inorder_walk(struct cs_pqnode* node) {
	if (node) {
		_inorder_walk(node->left);
		printf("node->priority: %d\n", node->priority);
		_inorder_walk(node->right);
	}
}

static inline void
_pqueue_free(struct cs_pqnode* node) {
	if (node) {
		_pqueue_free(node->left);
		_pqueue_free(node->right);
		free(node->value);
		free(node);
	}
}

