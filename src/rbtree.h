#pragma once

struct tcp_connection;

struct rbnode {
	int color;
	int key;
	struct tcp_connection *value;
	struct rbnode *parent;
	struct rbnode *left;
	struct rbnode *right;
};

struct rbtree {
	struct rbnode *root;
	struct rbnode *sentinel;
};

struct rbnode* rbnode_new(int key, struct tcp_connection *value);

struct rbtree* rbtree_new();
void rbtree_free(struct rbtree *);
void rbtree_insert(struct rbtree *, struct rbnode *z);
void rbtree_delete(struct rbtree*, struct rbnode *z);
struct rbnode *rbtree_search(struct rbtree *, int key);

