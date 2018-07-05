#pragma once

#if defined(__APPLE__)

#include "csnet-log.h"
#include "csnet-utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <math.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>

typedef struct kevent64_s csnet_epoller_event_t;

struct csnet_epoller {
	int fd;
	int max_events;
	csnet_epoller_event_t* events;
};

static struct csnet_epoller*
csnet_epoller_new(int max_events) {
	struct csnet_epoller* epoller = calloc(1, sizeof(*epoller));
	if (!epoller) {
		csnet_oom(sizeof(*epoller));
	}

	epoller->fd = kqueue();
	if (epoller->fd == -1) {
		debug("epoll_create(): %s", strerror(errno));
		free(epoller);
		return NULL;
	}

	epoller->max_events = max_events;
	epoller->events = calloc(max_events, sizeof(csnet_epoller_event_t));

	if (!epoller->events) {
		csnet_oom(max_events * sizeof(csnet_epoller_event_t));
	}

	return epoller;
}

static void
csnet_epoller_free(struct csnet_epoller* epoller) {
	close(epoller->fd);
	free(epoller->events);
	free(epoller);
}

static int
csnet_epoller_add(struct csnet_epoller* epoller, int fd, unsigned int sid) {
	struct kevent64_s ke;

	memset(&ke, 0, sizeof(ke));
	EV_SET64(&ke, fd, EVFILT_READ, EV_ADD, 0, 0, sid, 0, 0);
	kevent64(epoller->fd, &ke, 1, NULL, 0, 0, NULL);

	memset(&ke, 0, sizeof(ke));
	EV_SET64(&ke, fd, EVFILT_WRITE, EV_ADD, 0, 0, sid, 0, 0);
	kevent64(epoller->fd, &ke, 1, NULL, 0, 0, NULL);

	memset(&ke, 0, sizeof(ke));
	EV_SET64(&ke, fd, EVFILT_WRITE, EV_DISABLE, 0, 0, sid, 0, 0);
	kevent64(epoller->fd, &ke, 1, NULL, 0, 0, NULL);

	return 0;
}

static int
csnet_epoller_del(struct csnet_epoller* epoller, int fd, unsigned int sid) {
	struct kevent64_s ke;

	memset(&ke, 0, sizeof(ke));
	EV_SET64(&ke, fd, EVFILT_READ, EV_DELETE, 0, 0, sid, 0, 0);
	kevent64(epoller->fd, &ke, 1, NULL, 0, 0, NULL);
	return 0;
}

static int
csnet_epoller_r(struct csnet_epoller* epoller, int fd, unsigned int sid) {
	struct kevent64_s ke;

	memset(&ke, 0, sizeof(ke));
	EV_SET64(&ke, fd, EVFILT_READ, EV_ENABLE, 0, 0, sid, 0, 0);
	kevent64(epoller->fd, &ke, 1, NULL, 0, 0, NULL);
	return 0;

}

static int
csnet_epoller_w(struct csnet_epoller* epoller, int fd, unsigned int sid) {
	struct kevent64_s ke;

	memset(&ke, 0, sizeof(ke));
	EV_SET64(&ke, fd, EVFILT_WRITE, EV_ENABLE, 0, 0, sid, 0, 0);
	kevent64(epoller->fd, &ke, 1, NULL, 0, 0, NULL);
	return 0;
}

static int
csnet_epoller_rw(struct csnet_epoller* epoller, int fd, unsigned int sid) {
	struct kevent64_s ke;

	memset(&ke, 0, sizeof(ke));
	EV_SET64(&ke, fd, EVFILT_READ, EV_ENABLE, 0, 0, sid, 0, 0);
	kevent64(epoller->fd, &ke, 1, NULL, 0, 0,  NULL);
	
	memset(&ke, 0, sizeof(ke));
	EV_SET64(&ke, fd, EVFILT_WRITE, EV_ENABLE, 0, 0, sid, 0, 0);
	kevent64(epoller->fd, &ke, 1, NULL, 0, 0, NULL);
	return 0;
}

static int
csnet_epoller_wait(struct csnet_epoller* epoller, int milliseconds) {
	if (milliseconds <= 0) {
		return kevent64(epoller->fd, NULL, 0, epoller->events,
				epoller->max_events, 0, NULL);
	} else {
		struct timespec ts;
		ts.tv_sec = milliseconds / 1000;
		ts.tv_nsec = (milliseconds % 1000) * 1000000;
		return kevent64(epoller->fd, NULL, 0, epoller->events,
				epoller->max_events, 0, (const struct timespec*)&ts);
	}
}

static csnet_epoller_event_t*
csnet_epoller_get_event(struct csnet_epoller* epoller, int index) {
	if (index < epoller->max_events) {
		return &epoller->events[index];
	}
	return NULL;
}

static bool
csnet_epoller_event_is_r(csnet_epoller_event_t* event) {
	return event->flags & EVFILT_READ;
}

static bool
csnet_epoller_event_is_w(csnet_epoller_event_t* event) {
	return event->flags & EVFILT_WRITE;
}

static bool
csnet_epoller_event_is_e(csnet_epoller_event_t* event) {
	return (event->flags & EV_ERROR) || (event->flags & EV_EOF);
}

static int
csnet_epoller_event_fd(csnet_epoller_event_t* event) {
	return event->ident;
}

static unsigned int
csnet_epoller_event_sid(csnet_epoller_event_t* event) {
	return event->udata;
}

#endif

