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
	int fd = epoll_create(1024);
	if (fd == -1) {
		debug("epoll_create() error: %s", strerror(errno));
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
	struct epoll_event ev = {
		.events = EPOLLIN | EPOLLRDHUP | EPOLLET,
		.data.ptr = ud
	};
	return epoll_ctl(ep, EPOLL_CTL_ADD, fd, &ev);
}

static int
csnet_ep_del(csnet_ep_t ep, int fd, void* ud) {
	struct epoll_event ev = {
		.events = EPOLLIN | EPOLLET,
		.data.ptr = ud
	};
	return epoll_ctl(ep, EPOLL_CTL_DEL, fd, &ev);
}

static int
csnet_ep_r(csnet_ep_t ep, int fd, void* ud) {
	struct epoll_event ev = {
		.events = EPOLLIN | EPOLLRDHUP | EPOLLET,
		.data.ptr = ud
	};
	return epoll_ctl(ep, EPOLL_CTL_MOD, fd, &ev);
}

static int
csnet_ep_w(csnet_ep_t ep, int fd, void* ud) {
	struct epoll_event ev = {
		.events = EPOLLOUT | EPOLLRDHUP | EPOLLET,
		.data.ptr = ud
	};
	return epoll_ctl(ep, EPOLL_CTL_MOD, fd, &ev);
}

static int
csnet_ep_rw(csnet_ep_t ep, int fd, void* ud) {
	struct epoll_event ev = {
		.events = EPOLLIN | EPOLLRDHUP |  EPOLLOUT | EPOLLET,
		.data.ptr = ud
	};
	return epoll_ctl(ep, EPOLL_CTL_MOD, fd, &ev);
}

static int
csnet_ep_wait(csnet_ep_t ep, struct csnet_event* e, int max, int ms) {
	struct epoll_event ev[max];
	int r = epoll_wait(ep, ev, max, ms);
	for (int i = 0; i < r; i++) {
		e[i].ptr = ev[i].data.ptr;
		unsigned flag = ev[i].events;
		e[i].eof = (flag & EPOLLRDHUP) != 0;
		e[i].write = (flag & EPOLLOUT) != 0;
		e[i].read = (flag & EPOLLIN) != 0;
		e[i].error = (flag & EPOLLERR) != 0;
	}
	return r;
}

#endif

