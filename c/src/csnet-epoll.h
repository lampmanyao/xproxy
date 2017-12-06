#pragma once

#if defined(__linux__)

#include "csnet-log.h"
#include "csnet-utils.h"

#include <math.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <sys/epoll.h>

typedef struct epoll_event csnet_epoller_event_t;

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

	epoller->fd = epoll_create(1024);
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
	struct epoll_event ev = {
		.events = EPOLLIN | EPOLLET,
		.data.u64 = (unsigned long)fd << 32 | sid
	};
	return epoll_ctl(epoller->fd, EPOLL_CTL_ADD, fd, &ev);
}

static int
csnet_epoller_del(struct csnet_epoller* epoller, int fd, unsigned int sid) {
	struct epoll_event ev = {
		.events = EPOLLIN | EPOLLET,
		.data.u64 = (unsigned long)fd << 32 | sid
	};
	return epoll_ctl(epoller->fd, EPOLL_CTL_DEL, fd, &ev);
}

static int
csnet_epoller_mod_read(struct csnet_epoller* epoller, int fd, unsigned int sid) {
	struct epoll_event ev = {
		.events = EPOLLOUT | EPOLLET,
		.data.u64 = (unsigned long)fd << 32 | sid
	};
	return epoll_ctl(epoller->fd, EPOLL_CTL_MOD, fd, &ev);
}

static int
csnet_epoller_mod_write(struct csnet_epoller* epoller, int fd, unsigned int sid) {
	struct epoll_event ev = {
		.events = EPOLLOUT | EPOLLET,
		.data.u64 = (unsigned long)fd << 32 | sid
	};
	return epoll_ctl(epoller->fd, EPOLL_CTL_MOD, fd, &ev);
}

static int
csnet_epoller_mod_rw(struct csnet_epoller* epoller, int fd, unsigned int sid) {
	struct epoll_event ev = {
		.events = EPOLLIN | EPOLLOUT | EPOLLET,
		.data.u64 = (unsigned long)fd << 32 | sid
	};
	return epoll_ctl(epoller->fd, EPOLL_CTL_MOD, fd, &ev);
}

static int
csnet_epoller_wait(struct csnet_epoller* epoller, int milliseconds) {
	return epoll_wait(epoller->fd, epoller->events, epoller->max_events, milliseconds);
}

static csnet_epoller_event_t*
csnet_epoller_get_event(struct csnet_epoller* epoller, int index) {
	if (index < epoller->max_events) {
		return &epoller->events[index];
	}
	return NULL;
}

static bool
csnet_epoller_event_is_readable(csnet_epoller_event_t* event) {
	return event->events & EPOLLIN;
}

static bool
csnet_epoller_event_is_writeable(csnet_epoller_event_t* event) {
	return event->events & EPOLLOUT;
}

static bool
csnet_epoller_event_is_error(csnet_epoller_event_t* event) {
	return event->events & (EPOLLERR | EPOLLHUP);
}

static int
csnet_epoller_event_fd(csnet_epoller_event_t* event) {
	return event->data.u64 >> 32;
}

static unsigned int
csnet_epoller_event_sid(csnet_epoller_event_t* event) {
	return event->data.u64 & 0xffffUL;
}

#endif

