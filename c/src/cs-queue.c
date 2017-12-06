#include "cs-queue.h"

#include <stdlib.h>

struct cs_queue_node*
cs_queue_node_new(int data) {
	struct cs_queue_node* node = calloc(1, sizeof(*node));
	node->data = data;
	node->next = NULL;
	return node;
}

void
cs_queue_node_free(struct cs_queue_node* node) {
	free(node);
}

struct cs_queue*
cs_queue_new(void) {
	struct cs_queue* q = calloc(1, sizeof(*q));
	q->head = NULL;
	q->tail = NULL;
	return q;
}

void
cs_queue_free(struct cs_queue* q) {
	struct cs_queue_node* head = q->head;
	while (head) {
		struct cs_queue_node* tmp = head->next;
		free(head);
		head = tmp;
	}
	free(q);
}

void
cs_queue_enq(struct cs_queue* q, struct cs_queue_node* node) {
	if (!q->head) {
		q->head = node;
	}
	if (q->tail) {
		q->tail->next = node;
	}
	q->tail = node;
}

struct cs_queue_node*
cs_queue_deq(struct cs_queue* q) {
	struct cs_queue_node* result;
	if (!q->head) {
		return NULL;
	}
	result = q->head;
	q->head = result->next;
	if (!q->head) {
		q->tail = NULL;
	}
	return result;
}

