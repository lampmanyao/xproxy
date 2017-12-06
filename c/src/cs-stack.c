#include "cs-stack.h"

#include <stdlib.h>

struct cs_stack_node*
cs_stack_node_new(int data) {
	struct cs_stack_node* node = calloc(1, sizeof(*node));
	node->data = data;
	node->next = NULL;
	return node;
}

void
cs_stack_node_free(struct cs_stack_node* node) {
	free(node);
}

struct cs_stack*
cs_stack_new(void) {
	struct cs_stack* s = calloc(1, sizeof(*s));
	s->top = NULL;
	return s;
}

void
cs_stack_free(struct cs_stack* s) {
	struct cs_stack_node* x = s->top;
	while (x) {
		struct cs_stack_node* tmp = x->next;
		cs_stack_node_free(x);
		x = tmp;
	}
	free(s);
}

struct cs_stack_node*
cs_stack_pop(struct cs_stack* s) {
	struct cs_stack_node* node = s->top;
	if (s->top) {
		s->top = s->top->next;
	}
	return node;
}

void
cs_stack_push(struct cs_stack* s, struct cs_stack_node* x) {
	if (!s->top) {
		s->top = x;
	} else {
		x->next = s->top;
		s->top = x;
	}
}

