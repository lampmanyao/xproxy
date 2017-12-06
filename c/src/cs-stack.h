#pragma once

struct cs_stack_node {
	int data;
	struct cs_stack_node* next;
};

struct cs_stack {
	struct cs_stack_node* top;
};

struct cs_stack_node* cs_stack_node_new(int data);
void cs_stack_node_free(struct cs_stack_node* node);

struct cs_stack* cs_stack_new(void);
void cs_stack_free(struct cs_stack*);
struct cs_stack_node* cs_stack_pop(struct cs_stack*);
void cs_stack_push(struct cs_stack*, struct cs_stack_node* node);

