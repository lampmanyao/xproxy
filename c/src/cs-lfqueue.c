#include "cs-lfqueue.h"
#include "csnet-atomic.h"

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#define R(hp) (unsigned int)((hp->H) / 2)  /* threshold R */
#define L 128

struct hp_list {
	int count;
	void* array[L];
};

struct cs_hp {
	int H;
	cs_hp_record_t* head_hp_record;
};

#if defined(__linux__)
static __thread cs_hp_record_t* my_record = NULL;
#endif

static struct hp_list* hp_list_new();
static void hp_list_free(struct hp_list* l);
static int hp_list_insert(struct hp_list* l, void* node);
static void* hp_list_pop(struct hp_list* l);
static int hp_list_lookup(struct hp_list* l, void* node);
static int hp_list_popall(struct hp_list* l, void** output);

static void scan(cs_hp_t* hp, cs_hp_record_t* private_record);
static void help_scan(cs_hp_t* hp, cs_hp_record_t* private_record);

static cs_hp_record_t* hp_record_new();
static void hp_record_free(cs_hp_record_t* record);
static cs_hp_t* hp_new();
static void hp_free(cs_hp_t* hp);
static void retire_node(cs_hp_t* hp, cs_hp_record_t* private_record, void* node);
static cs_lfqnode_t* new_qnode(void* data);

/*
 * Each thread call this to allocate a private hp record
 */
void cs_lfqueue_register_thread(cs_lfqueue_t* q) {
#if defined(__APPLE__)
	int tid = pthread_mach_thread_np(pthread_self());
	int idx = tid % MY_RECORD_SIZE;
#endif

	/* First try to reuse a retired HP record */
	for (cs_hp_record_t* record = q->HP->head_hp_record; record; record = record->next) {
		if (record->active || !CAS(&record->active, 0, 1)) {
			continue;
		}
#if defined(__APPLE__)
		q->my_record[idx] = record;
#else
		my_record = record;
#endif
		return;
	}

	/* No HP records avaliable for resue.
	   Increment H, then allocate a new HP and push it */
	INC_N_ATOMIC(&q->HP->H, K);
	cs_hp_record_t* new_record = hp_record_new();
	cs_hp_record_t* old_record;

	do {
		old_record = q->HP->head_hp_record;
		new_record->next = old_record;
	} while (!CAS(&q->HP->head_hp_record, old_record, new_record));

#if defined(__APPLE__)
	q->my_record[idx] = new_record;
#else
	my_record = new_record;
#endif
}

cs_lfqueue_t*
cs_lfqueue_new(void) {
	cs_lfqueue_t* q = calloc(1, sizeof(*q));
	q->head = q->tail = new_qnode(NULL);
	q->HP = hp_new();
	return q;
}

void
cs_lfqueue_free(cs_lfqueue_t* q) {
	cs_lfqnode_t* head = q->head;
	while (head) {
		cs_lfqnode_t* tmp = head->next;
		free(head);
		head = tmp;
	}
	hp_free(q->HP);
	free(q);
}

int
cs_lfqueue_enq(cs_lfqueue_t* q, void* data) {
	cs_lfqnode_t* node = new_qnode(data);
	cs_lfqnode_t* tail;
	cs_lfqnode_t* next;

#if defined(__APPLE__)
	int tid = pthread_mach_thread_np(pthread_self());
	int idx = tid % MY_RECORD_SIZE;
#endif

	while (1) {
		tail = q->tail;
#if defined(__APPLE__)
		q->my_record[idx]->hp[0] = tail;
#else
		my_record->hp[0] = tail;
#endif

		if (q->tail != tail) {
			continue;
		}

		next = tail->next;
		if (q->tail != tail) {
			continue;
		}

		if (next) {
			CAS(&q->tail, tail, next);
			continue;
		}

		if (CAS(&tail->next, NULL, node)) {
			break;
		}
	}

	CAS(&q->tail, tail, node);
#if defined(__APPLE__)
	q->my_record[idx]->hp[0] = tail;
#else
	my_record->hp[0] = NULL;
#endif
	return 0;
}

int
cs_lfqueue_deq(cs_lfqueue_t* q, void** data) {
	cs_lfqnode_t* head;
	cs_lfqnode_t* tail;
	cs_lfqnode_t* next;

#if defined(__APPLE__)
	int tid = pthread_mach_thread_np(pthread_self());
	int idx = tid % MY_RECORD_SIZE;
#endif

	while (1) {
		head = q->head;
#if defined(__APPLE__)
		q->my_record[idx]->hp[0] = head;
#else
		my_record->hp[0] = head;
#endif

		if (q->head != head) {
			continue;
		}

		tail = q->tail;
		next = head->next;
#if defined(__APPLE__)
		q->my_record[idx]->hp[0] = tail;
#else
		my_record->hp[1] = next;
#endif

		if (q->head != head) {
			continue;
		}

		if (!next) {
			return -1;
		}

		if (head == tail) {
			CAS(&q->tail, tail, next);
			continue;
		}

		*data = next->data;
		if (CAS(&q->head, head, next)) {
			break;
		}
	}

#if defined(__APPLE__)
	retire_node(q->HP, q->my_record[idx], (void*)head);
	q->my_record[idx]->hp[0] = NULL;
	q->my_record[idx]->hp[1] = NULL;
#else
	retire_node(q->HP, my_record, (void*)head);
	my_record->hp[0] = NULL;
	my_record->hp[1] = NULL;
#endif

	return 0;
}

static inline struct
hp_list* hp_list_new(void) {
	struct hp_list* l = calloc(1, sizeof(*l));
	return l;
}

static inline void
hp_list_free(struct hp_list* l) {
	free(l);
}

static inline int
hp_list_insert(struct hp_list* l, void* node) {
	int count = l->count;
	if (count < L) {
		l->array[count] = node;
		l->count++;
		return count;
	}
	return -1;
}

static inline void*
hp_list_pop(struct hp_list* l) {
	void* value = NULL;
	int count = l->count - 1;
	if (count > 0) {
		value = l->array[count];
		l->array[count] = NULL;
		l->count--;
		return value;
	}
	return value;
}

static inline int
hp_list_lookup(struct hp_list* l, void* node) {
	for (int i = 0; i < L; i++) {
		if (l->array[i] == node) {
			return 1;
		}
	}
	return 0;
}

static inline int
hp_list_popall(struct hp_list* l, void** output) {
	int count = l->count;
	for (int i = 0; i < count; i++) {
		output[i] = l->array[i];
	}
	l->count = 0;
	return count;
}

static void
scan(cs_hp_t* hp, cs_hp_record_t* private_record) {
	/* Stage 1: Scan HP lists and insert non-null values in plist */
	struct hp_list* plist = hp_list_new();
	cs_hp_record_t* head = hp->head_hp_record;

	while (head) {
		for (int i = 0; i < K; i++) {
			if (head->hp[i]) {
				hp_list_insert(plist, head->hp[i]);
			}
		}
		head = head->next;
	}

	/* Stage 2: Search plist */
	void** tmplist = (void**)calloc(private_record->rlist->count, sizeof(void*));
	int length = hp_list_popall(private_record->rlist, tmplist);
	private_record->rcount = 0;
	for (int i = 0; i < length; i++) {
		if (hp_list_lookup(plist, tmplist[i])) {
			hp_list_insert(private_record->rlist, tmplist[i]);
			private_record->rcount++;
		} else {
			free(tmplist[i]);
		}
	}

	hp_list_free(plist);
	free(tmplist);
}

static void
help_scan(cs_hp_t* hp, cs_hp_record_t* private_record) {
	cs_hp_record_t* head_record = hp->head_hp_record;
	for (; head_record; head_record = head_record->next) {
		if (head_record->active || !CAS(&head_record->active, 0, 1)) {
			continue;
		}

		while (head_record->rcount > 0) {
			void* node = hp_list_pop(head_record->rlist);
			head_record->rcount--;
			hp_list_insert(private_record->rlist, node);
			private_record->rcount++;

			if (private_record->rcount >= R(hp)) {
				scan(hp, private_record);
			}
		}

		head_record->active = 0;
  	}
}

static cs_hp_record_t*
hp_record_new(void) {
	cs_hp_record_t* record = calloc(1, sizeof(*record));
	record->active = 1;
	record->rcount = 0;
	record->rlist = hp_list_new();
	return record;
}

static inline void
hp_record_free(cs_hp_record_t* record) {
	hp_list_free(record->rlist);
	free(record);
}

static inline cs_hp_t*
hp_new(void) {
	cs_hp_t* hp = calloc(1, sizeof(*hp));
	return hp;
}

static void
hp_free(cs_hp_t* hp) {
	cs_hp_record_t* head = hp->head_hp_record;
	while (head) {
		cs_hp_record_t* tmp = head->next;
		hp_record_free(head);
		head = tmp;
	}
	free(hp);
}

static void
retire_node(cs_hp_t* hp, cs_hp_record_t* private_record, void* node) {
	for (int i = 0; i < K; i++) {
		if (private_record->hp[i] == node) {
			hp_list_insert(private_record->rlist, node);
			private_record->rcount++;
			private_record->hp[i] = NULL;

			if (private_record->rcount >= R(hp)) {
				scan(hp, private_record);
				help_scan(hp, private_record);
			}
			break;
		}
	}
}

static inline cs_lfqnode_t*
new_qnode(void* data) {
	cs_lfqnode_t* node = calloc(1, sizeof(*node));
	node->data = data;
	return node;
}

