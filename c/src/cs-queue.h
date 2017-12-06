#pragma once

struct cs_queue_node {
	int data;
	struct cs_queue_node* next;
};

struct cs_queue {
	struct cs_queue_node* head;
	struct cs_queue_node* tail;
};

struct cs_queue_node* cs_queue_node_new(int data);
void cs_queue_node_free(struct cs_queue_node* node);

struct cs_queue* cs_queue_new(void);
void cs_queue_free(struct cs_queue*);
void cs_queue_enq(struct cs_queue*, struct cs_queue_node* node);
struct cs_queue_node* cs_queue_deq(struct cs_queue*);

