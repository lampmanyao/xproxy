#pragma once

#include "log.h"
#include "utils.h"

#include <math.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>

struct poller_event {
	bool read;
	bool write;
	bool eof;
	bool error;
	void *ptr;
};

#if defined(__linux__)

#include <sys/epoll.h>

static int
poller_open() {
	int fd = epoll_create(1024);
	if (fd == -1) {
		FATAL("epoll_create() error: %s", strerror(errno));
	}
	return fd;
}

static void
poller_close(int poller) {
	close(poller);
}

static int
poller_add(int poller, int fd, void *ud) {
	struct epoll_event ev = {
		.events = EPOLLIN | EPOLLRDHUP | EPOLLET,
		.data.ptr = ud
	};
	return epoll_ctl(poller, EPOLL_CTL_ADD, fd, &ev);
}

static int
poller_enable_read(int poller, int fd, void *ud) {
	struct epoll_event ev = {
		.events = EPOLLIN | EPOLLRDHUP | EPOLLET,
		.data.ptr = ud
	};
	return epoll_ctl(poller, EPOLL_CTL_MOD, fd, &ev);
}

static int
poller_disable_read(int poller, int fd, void *ud) {
	struct epoll_event ev = {
		.events = EPOLLRDHUP | EPOLLET,
		.data.ptr = ud
	};
	return epoll_ctl(poller, EPOLL_CTL_MOD, fd, &ev);
}

static int
poller_enable_write(int poller, int fd, void *ud) {
	struct epoll_event ev = {
		.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET,
		.data.ptr = ud
	};
	return epoll_ctl(poller, EPOLL_CTL_MOD, fd, &ev);
}

static int
poller_disable_write(int poller, int fd, void *ud) {
	struct epoll_event ev = {
		.events = EPOLLIN | EPOLLRDHUP | EPOLLET,
		.data.ptr = ud
	};
	return epoll_ctl(poller, EPOLL_CTL_MOD, fd, &ev);
}

static int
poller_del(int poller, int fd, void *ud) {
	struct epoll_event ev = {
		.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET,
		.data.ptr = ud
	};
	return epoll_ctl(poller, EPOLL_CTL_DEL, fd, &ev);
}

static int
poller_wait(int poller, struct poller_event *e, int max, int ms) {
	struct epoll_event ev[max];
	int r = epoll_wait(poller, ev, max, ms);
	for (int i = 0; i < r; i++) {
		e[i].ptr = ev[i].data.ptr;
		unsigned events = ev[i].events;
		e[i].read  = events & EPOLLIN;
		e[i].write = events & EPOLLOUT;
		e[i].eof   = events & EPOLLRDHUP;
		e[i].error = events & EPOLLERR;
	}
	return r;
}

#else

#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>

static int
poller_open() {
	int fd = kqueue();
	if (fd == -1) {
		FATAL("keueue() error: %s", strerror(errno));
	}

	return fd;
}

static void
poller_close(int poller) {
	close(poller);
}

static int
poller_add(int poller, int fd, void *ud) {
	struct kevent64_s ke;

	EV_SET64(&ke, fd, EVFILT_READ, EV_ADD, 0, 0, (intptr_t)ud, 0, 0);
	kevent64(poller, &ke, 1, NULL, 0, 0, NULL);

	EV_SET64(&ke, fd, EVFILT_WRITE, EV_ADD, 0, 0, (intptr_t)ud, 0, 0);
	kevent64(poller, &ke, 1, NULL, 0, 0, NULL);

	EV_SET64(&ke, fd, EVFILT_WRITE, EV_DISABLE, 0, 0, (intptr_t)ud, 0, 0);
	kevent64(poller, &ke, 1, NULL, 0, 0, NULL);

	return 0;
}

static int
poller_enable_read(int poller, int fd, void *ud) {
	struct kevent64_s ke;

	EV_SET64(&ke, fd, EVFILT_READ, EV_ENABLE, 0, 0, (intptr_t)ud, 0, 0);
	kevent64(poller, &ke, 1, NULL, 0, 0, NULL);

	return 0;
}

static int
poller_disable_read(int poller, int fd, void *ud) {
	struct kevent64_s ke;

	EV_SET64(&ke, fd, EVFILT_READ, EV_DISABLE, 0, 0, (intptr_t)ud, 0, 0);
	kevent64(poller, &ke, 1, NULL, 0, 0, NULL);

	return 0;
}

static int
poller_enable_write(int poller, int fd, void *ud) {
	struct kevent64_s ke;

	EV_SET64(&ke, fd, EVFILT_WRITE, EV_ENABLE, 0, 0, (intptr_t)ud, 0, 0);
	kevent64(poller, &ke, 1, NULL, 0, 0, NULL);

	return 0;
}

static int
poller_disable_write(int poller, int fd, void *ud) {
	struct kevent64_s ke;

	EV_SET64(&ke, fd, EVFILT_WRITE, EV_DISABLE, 0, 0, (intptr_t)ud, 0, 0);
	kevent64(poller, &ke, 1, NULL, 0, 0, NULL);

	return 0;
}

static int
poller_del(int poller, int fd, void *ud) {
	struct kevent64_s ke;

	EV_SET64(&ke, fd, EVFILT_READ, EV_DELETE, 0, 0, (intptr_t)ud, 0, 0);
	kevent64(poller, &ke, 1, NULL, 0, 0, NULL);

	EV_SET64(&ke, fd, EVFILT_WRITE, EV_DELETE, 0, 0, (intptr_t)ud, 0, 0);
	kevent64(poller, &ke, 1, NULL, 0, 0, NULL);

	return 0;
}

static int
poller_wait(int poller,  struct poller_event *ev, int max, int ms) {
	struct kevent64_s ke[max];
	int r;

	if (ms <= 0) {
		r = kevent64(poller, NULL, 0, ke, max, 0, NULL);
	} else {
		struct timespec tspec = {
			.tv_sec = ms / 1000,
			.tv_nsec = (ms % 1000) * 1000000
		};
		r = kevent64(poller, NULL, 0, ke, max, 0, &tspec);
	}

	for (int i = 0; i < r; i++) {
		int16_t filter = ke[i].filter;
		uint16_t flags = ke[i].flags;
		ev[i].read  = (filter == EVFILT_READ);
		ev[i].write = (filter == EVFILT_WRITE);
		ev[i].eof   = flags & EV_EOF;
		ev[i].error = flags & EV_ERROR;
		ev[i].ptr   = (void *)ke[i].udata;
	}

	return r;
}
#endif

