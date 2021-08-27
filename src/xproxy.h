#ifndef xproxy_h
#define xproxy_h

#include <pthread.h>

#include "el.h"

struct xproxy;

typedef void (*accept_callback) (struct xproxy *xproxy, int lfd);

struct xproxy {
	int poller;
	int sfd;
	int nthread;
	pthread_t tid;
	accept_callback accept_cb;
	struct el *els[0];
};

struct xproxy *xproxy_new(int sfd, int nthread, accept_callback accept_cb);
void xproxy_free(struct xproxy *);
void xproxy_loop(struct xproxy *, int timeout);
const char *xproxy_version(void);

#endif  /* xproxy_h */

