#ifndef el_h
#define el_h

#include <pthread.h>

struct tcp_connection;

struct el {
	int poller;
	pthread_t tid;
};

struct el *el_new();
void el_free(struct el *);
void el_watch(struct el *, struct tcp_connection*);
void el_unwatch(struct el *, struct tcp_connection*);
void el_run(struct el *);

#endif  /* el_h */

