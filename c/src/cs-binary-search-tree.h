#pragma once

struct cs_bsnode {
	int key;
	int value;
	struct cs_bsnode* parent;
	struct cs_bsnode* left;
	struct cs_bsnode* right;
};

struct cs_bstree {
	struct cs_bsnode* root;
};

struct cs_bstree* cs_bstree_new(void);
void cs_bstree_free(struct cs_bstree*);
int cs_bstree_insert(struct cs_bstree*, int key, int value);
struct cs_bsnode* cs_bstree_search(struct cs_bstree*, int key);
void cs_bstree_delete(struct cs_bstree*, struct cs_bsnode* node);
void cs_bstree_inorder_walk(struct cs_bstree*);
struct cs_bsnode* cs_bstree_minimum(struct cs_bstree*);
struct cs_bsnode* cs_bstree_maximum(struct cs_bstree*);
void cs_bstree_invert(struct cs_bstree*);

