#pragma once

/*
 * Lock-free queue based hazard pointers
 * Hazard Pointers: Safe Memory Reclamation for Lock-Free Objects
 * IEEE TRANSACTIONS ON PARALLEL AND DISTRIBUTED SYSTEMS, VOL. 15, NO. 6, JUNE 2004
 */

#define K 2  /* Each thread has K hazard pointers */

typedef struct cs_hp cs_hp_t;
typedef struct cs_hp_record cs_hp_record_t;
typedef struct cs_lfqnode cs_lfqnode_t;
typedef struct cs_lfqueue cs_lfqueue_t;

struct cs_hp_record {
	unsigned int active;
	unsigned int rcount;   /* Retired count */
	struct hp_list* rlist; /* Retired list  */
	cs_hp_record_t* next;
	void* hp[K];
};

struct cs_lfqnode {
	void* data;
	cs_lfqnode_t* next;
};

struct cs_lfqueue {
#if defined(__APPLE__)
	#define MY_RECORD_SIZE 65536
	cs_hp_record_t* my_record[MY_RECORD_SIZE];
#endif
	cs_lfqnode_t* head;
	cs_lfqnode_t* tail;
	cs_hp_t* HP;
};

cs_lfqueue_t* cs_lfqueue_new(void);
void cs_lfqueue_free(cs_lfqueue_t*);

/* Each thread call this to allocate a private hp record */
void cs_lfqueue_register_thread(cs_lfqueue_t*);
int cs_lfqueue_enq(cs_lfqueue_t*, void* data);
int cs_lfqueue_deq(cs_lfqueue_t*, void** data);

