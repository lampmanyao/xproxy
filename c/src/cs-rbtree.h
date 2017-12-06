#pragma once

struct cs_rbnode {
	int color;
	int key;
	int value;
	struct cs_rbnode* parent;
	struct cs_rbnode* left;
	struct cs_rbnode* right;
};

struct cs_rbtree {
	struct cs_rbnode* root;
	struct cs_rbnode* sentinel;
};

struct cs_rbnode* cs_rbnode_new(int key, int value);

struct cs_rbtree* cs_rbtree_new(void);
void cs_rbtree_free(struct cs_rbtree*);
void cs_rbtree_insert(struct cs_rbtree*, struct cs_rbnode* z);
void cs_rbtree_delete(struct cs_rbtree*, struct cs_rbnode* z);
struct cs_rbnode* cs_rbtree_search(struct cs_rbtree*, int key);
void cs_rbtree_inorder_walk(struct cs_rbtree*);

