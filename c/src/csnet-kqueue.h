#pragma once

#if defined(__APPLE__)

#include "csnet-log.h"
#include "csnet-utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <math.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>

typedef struct kevent64_s csnet_epoller_event_t;
typedef int csnet_ep_t;

struct csnet_event {
	bool read;
	bool write;
	bool eof;
	bool error;
	void* ptr;
};

static int
csnet_ep_open() {
	int fd = kqueue();
	if (fd == -1) {
		debug("kqueue() error: %s", strerror(errno));
		return -1;
	}

	return fd;
}

static void
csnet_ep_close(csnet_ep_t ep) {
	close(ep);
}

static int
csnet_ep_add(csnet_ep_t ep, int fd, void* ud) {
	struct kevent64_s ke;

	EV_SET64(&ke, fd, EVFILT_READ, EV_ADD, 0, 0, (intptr_t)ud, 0, 0);
	kevent64(ep, &ke, 1, NULL, 0, 0, NULL);

	EV_SET64(&ke, fd, EVFILT_WRITE, EV_ADD | EV_DISABLE, 0, 0, (intptr_t)ud, 0, 0);
	kevent64(ep, &ke, 1, NULL, 0, 0, NULL);
	return 0;
}

static int
csnet_ep_del(csnet_ep_t ep, int fd, void* ud) {
	struct kevent64_s ke;
	EV_SET64(&ke, fd, EVFILT_READ, EV_DELETE, 0, 0, (intptr_t)ud, 0, 0);
	kevent64(ep, &ke, 1, NULL, 0, 0, NULL);
	EV_SET64(&ke, fd, EVFILT_WRITE, EV_DELETE, 0, 0, (intptr_t)ud, 0, 0);
	kevent64(ep, &ke, 1, NULL, 0, 0, NULL);
	return 0;
}

static int
csnet_ep_r(csnet_ep_t ep, int fd, void* ud) {
	struct kevent64_s ke;
	EV_SET64(&ke, fd, EVFILT_READ, EV_ENABLE, 0, 0, (intptr_t)ud, 0, 0);
	kevent64(ep, &ke, 1, NULL, 0, 0, NULL);
	return 0;
}

static int
csnet_ep_w(csnet_ep_t ep, int fd, void* ud) {
	struct kevent64_s ke;
	EV_SET64(&ke, fd, EVFILT_WRITE, EV_ENABLE, 0, 0, (intptr_t)ud, 0, 0);
	kevent64(ep, &ke, 1, NULL, 0, 0, NULL);
	return 0;
}

static int
csnet_ep_rw(csnet_ep_t ep, int fd, void* ud) {
	struct kevent64_s ke;
	EV_SET64(&ke, fd, EVFILT_READ, EV_ENABLE, 0, 0, (intptr_t)ud, 0, 0);
	kevent64(ep, &ke, 1, NULL, 0, 0,  NULL);

	EV_SET64(&ke, fd, EVFILT_WRITE, EV_ENABLE, 0, 0, (intptr_t)ud, 0, 0);
	kevent64(ep, &ke, 1, NULL, 0, 0, NULL);
	return 0;
}

static int
csnet_ep_wait(csnet_ep_t ep,  struct csnet_event* ev, int max, int milliseconds) {
	struct kevent64_s ke[max];
	int r;

	if (milliseconds <= 0) {
		r = kevent64(ep, NULL, 0, ke, max, 0, NULL);
	} else {
		struct timespec tspec = {
			.tv_sec = milliseconds / 1000,
			.tv_nsec = (milliseconds % 1000) * 1000000
		};
		r = kevent64(ep, NULL, 0, ke, max, 0, &tspec);
	}

	for (int i = 0; i < r; i++) {
		ev[i].ptr = (void*)ke[i].udata;
		int16_t filter = ke[i].filter;
		bool eof = (ke[i].flags & EV_EOF) != 0;
		ev[i].read = (filter == EVFILT_READ);
		ev[i].write = (filter == EVFILT_WRITE) && (!eof);
		ev[i].error = (ke[i].flags & EV_ERROR) != 0;
		ev[i].eof = eof;
	}

	return r;
}

#endif

