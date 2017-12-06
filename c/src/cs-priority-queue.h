#pragma once

typedef enum {
	CS_PQ_LOWEST_PRIORITY,  /* lowest key have highest priorit */
	CS_PQ_HIGHEST_PRIORITY  /* highest key have highest priorit */
} cs_pqueue_mode_t;

struct cs_pqnode {
	int priority;
	char* value;
	struct cs_pqnode* parent;
	struct cs_pqnode* left;
	struct cs_pqnode* right;
};

struct cs_pqueue {
	int mode;
	struct cs_pqnode* root;
	struct cs_pqnode* lowest;
	struct cs_pqnode* highest;
};

struct cs_pqueue* cs_pqueue_new(cs_pqueue_mode_t mode);
void cs_pqueue_free(struct cs_pqueue*);
int cs_pqueue_push(struct cs_pqueue*, int priority, char* value);

/* Pop the highest priority node */
struct cs_pqnode* cs_pqueue_pop(struct cs_pqueue*);
void cs_pqueue_delete(struct cs_pqueue*, struct cs_pqnode* node);
void cs_pqueue_inorder_walk(struct cs_pqueue*);

