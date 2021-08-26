#pragma once

#include <stdbool.h>

struct poller_event {
	bool read;
	bool write;
	bool eof;
	bool error;
	void *ptr;
};

int poller_open();
void poller_close(int poller);
int poller_add(int poller, int fd, void *ud);
int poller_del(int poller, int fd, void *ud);
int poller_wait(int poller, struct poller_event *e, int max, int ms);
int poller_enable_read(int poller, int fd, void *ud);
int poller_disable_read(int poller, int fd, void *ud);
int poller_enable_write(int poller, int fd, void *ud);
int poller_disable_write(int poller, int fd, void *ud);
