#include "cs-lfstack.h"

#include <stdio.h>
#include <stdlib.h>

static unsigned char
dwcas(struct cs_tagged_pointer* ptr, struct cs_lfstack_node* old,
      uint64_t oldtag, struct cs_lfstack_node* new, uint64_t newtag) {
	unsigned char cas_result;
	__asm__ __volatile__(
		"lock;"            /* make cmpxchg16b atomic */
		"cmpxchg16b %0;"   /* cmpxchg16b set ZF on success */
		"setz %3;"         /* if ZF set, set cas_result to 1 */
		/* output */
		: "+m" (*ptr), "+a" (old), "+d" (oldtag), "=q" (cas_result)
		/* input */
		: "b" (new), "c" (newtag)
		/* clobbered */
		: "cc", "memory"
	);
	return cas_result;
}

inline struct cs_lfstack_node*
cs_lfstack_node_new(void* data) {
	struct cs_lfstack_node* node = calloc(1, sizeof(*node));
	node->next = NULL;
	node->data = data;
	return node;
}

inline void
cs_lfstack_node_free(struct cs_lfstack_node* node) {
	free(node);
}

struct cs_lfstack*
cs_lfstack_new(void) {
	struct cs_lfstack* s = calloc(1, sizeof(*s));
	s->top = calloc(1, sizeof(*s->top));
	s->top->node = NULL;
	s->top->tag = 0;
	return s;
}

void
cs_lfstack_free(struct cs_lfstack* s) {
	free(s->top);
	free(s);
}

void
cs_lfstack_push(struct cs_lfstack* s, void* data) {
	struct cs_lfstack_node* node = cs_lfstack_node_new(data);
	while (1) {
		struct cs_lfstack_node* oldtop = s->top->node;
		uint64_t oldtag = s->top->tag;
		node->next = oldtop;

		if (dwcas(s->top, oldtop, oldtag, node, oldtag + 1)) {
			return;
		}
	}
}

void*
cs_lfstack_pop(struct cs_lfstack* s) {
	struct cs_lfstack_node* oldtop;
	while (1) {
		oldtop = s->top->node;
		uint64_t oldtag = s->top->tag;

		if (!oldtop) {
			return NULL;
		}

		if (s->top->node != oldtop) {
			continue;
		}

		if (dwcas(s->top, oldtop, oldtag, oldtop->next, oldtag + 1)) {
			break;
		}
	}
	if (oldtop) {
		void* data = oldtop->data;
		cs_lfstack_node_free(oldtop);
		return data;
	}
	return NULL;
}

