#include "cs-binary-search-tree.h"

#include <stdio.h>
#include <stdlib.h>

static struct cs_bsnode* _minimum_node(struct cs_bsnode* node);
static struct cs_bsnode* _successor(struct cs_bsnode* node);
static void _transplant(struct cs_bstree* t, struct cs_bsnode* u, struct cs_bsnode* v);
static void _inorder_walk(struct cs_bsnode* node);
static void _bstree_free(struct cs_bsnode* node);
static struct cs_bsnode* _invert(struct cs_bsnode* node);

struct cs_bstree*
cs_bstree_new(void) {
	struct cs_bstree* t = calloc(1, sizeof(*t));
	t->root = NULL;
	return t;
}

void
cs_bstree_free(struct cs_bstree* t) {
	_bstree_free(t->root);
	free(t);
}

int
cs_bstree_insert(struct cs_bstree* t, int key, int value) {
	struct cs_bsnode* new_node = calloc(1, sizeof(*new_node));
	new_node->key = key;
	new_node->value = value;
	new_node->parent = NULL;
	new_node->left = NULL;
	new_node->right = NULL;

	struct cs_bsnode* tmp = NULL;
	struct cs_bsnode* root = t->root;

	while (root) {
		tmp = root;
		if (key < root->key) {
			root = root->left;
		} else {
			root = root->right;
		}
	}

	new_node->parent = tmp;
	if (!tmp) {
		/* empty tree */
		t->root = new_node;
	} else if (key < tmp->key) {
		tmp->left = new_node;
	} else {
		tmp->right = new_node;
	}

	return 0;
}

struct cs_bsnode*
cs_bstree_search(struct cs_bstree* t, int key) {
	struct cs_bsnode* node = t->root;
	while (node && (key != node->key)) {
		if (key < node->key) {
			node = node->left;
		} else {
			node = node->right;
		}
	}
	return node;
}

void
cs_bstree_delete(struct cs_bstree* t, struct cs_bsnode* node) {
	if (!node->left) {
		_transplant(t, node, node->right);
	} else if (!node->right) {
		_transplant(t, node, node->left);
	} else {
		struct cs_bsnode* tmp = _minimum_node(node->right);

		if (tmp->parent != node) {
			_transplant(t, tmp, tmp->right);
			tmp->right = node->right;
			tmp->right->parent = tmp;
		}

		_transplant(t, node, tmp);
		tmp->left = node->left;
		tmp->left->parent = tmp;
	}
	free(node);
}

void
cs_bstree_inorder_walk(struct cs_bstree* t) {
	_inorder_walk(t->root);
}

struct cs_bsnode*
cs_bstree_minimum(struct cs_bstree* t) {
	struct cs_bsnode* node = t->root;
	while (node && node->left) {
		node = node->left;
	}
	return node;
}

struct cs_bsnode*
cs_bstree_maximum(struct cs_bstree* t) {
	struct cs_bsnode* node = t->root;
	while (node && node->right) {
		node = node->right;
	}
	return node;

}

void
cs_bstree_invert(struct cs_bstree* t) {
	_invert(t->root);
}

static inline struct cs_bsnode*
_minimum_node(struct cs_bsnode* node) {
	struct cs_bsnode* min_node = node;
	while (node && min_node->left) {
		min_node = min_node->left;
	}
	return min_node;
}

static inline struct cs_bsnode*
_successor(struct cs_bsnode* node) {
	if (node->right) {
		/* If node's right node is nonempty,
		   the minimum node of right tree is its successor */
		return _minimum_node(node->right);
	}

	struct cs_bsnode* parent = node->parent;
	while (parent && (node == parent->right)) {
		node = parent;
		parent = parent->parent;
	}
	return parent;
}

static inline void
_transplant(struct cs_bstree* t, struct cs_bsnode* u, struct cs_bsnode* v) {
	if (!u->parent) {
		t->root = v;
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
_inorder_walk(struct cs_bsnode* node) {
	if (node) {
		_inorder_walk(node->left);
		printf("node->key: %d\n", node->key);
		_inorder_walk(node->right);
	}
}

static inline void
_bstree_free(struct cs_bsnode* node) {
	if (node) {
		_bstree_free(node->left);
		_bstree_free(node->right);
		free(node);
	}
}

static inline struct cs_bsnode*
_invert(struct cs_bsnode* node) {
	if (!node) {
		return NULL;
	}
	struct cs_bsnode* tmp = node->left;
	node->left = _invert(node->right);
	node->right = _invert(tmp);
	return node;
}

