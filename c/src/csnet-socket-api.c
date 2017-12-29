#include "csnet-socket-api.h"
#include "csnet-log.h"

#include <stdio.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#if defined(__APPLE__)
#  include <sys/event.h>
#elif defined(__linux__)
#  include <sys/epoll.h>
#else
#  error "Unknown OS. Only support linux or macos!"
#endif

#define BACKLOG 65535

int
csnet_set_nonblocking(int sfd) {
	int flags = fcntl(sfd, F_GETFL, 0);
	if (flags == -1) {
		return -1;
	}
	flags |= O_NONBLOCK;
	return fcntl(sfd, F_SETFL, flags);
}

int
csnet_listen_port(int port) {
	int lfd;
	struct sockaddr_in serv_addr;

	lfd = socket(AF_INET, SOCK_STREAM, 0);
	if (lfd == -1) {
		debug("socket(): %s", strerror(errno));
		return -1;
	}

	int reuse = 1;
	setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &reuse, (socklen_t)sizeof(reuse));
	/* setsockopt(lfd, SOL_SOCKET, SO_REUSEPORT, &reuse, (socklen_t)sizeof(reuse)); */

	bzero(&serv_addr, sizeof(struct sockaddr_in));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(port);

	if (bind(lfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1) {
		debug("bind(): %s", strerror(errno));
		close(lfd);
		return -1;
	}

	if (listen(lfd, BACKLOG) == -1) {
		debug("listen(): %s", strerror(errno));
		close(lfd);
		return -1;
	}

	return lfd;
}

int
csnet_connect_without_timeout(const char* host, int port) {
	struct sockaddr_in ipv4addr;
	struct addrinfo hints;
	struct addrinfo* result;
	struct addrinfo* rp;
	int sock;

	if (inet_aton(host, &ipv4addr.sin_addr) == 1) {
		ipv4addr.sin_family = AF_INET;
		ipv4addr.sin_port = htons(port);
		sock = socket(AF_INET, SOCK_STREAM, 0);
		if (sock < 0) {
			return -1;
		}
		if (connect(sock, (const struct sockaddr*)&ipv4addr,
			   sizeof(struct sockaddr)) < 0) {
			close(sock);
			return -1;
		}
		return sock;
	}

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	char portptr[6];
	snprintf(portptr, 6, "%d", port);

	if (getaddrinfo(host, portptr, &hints, &result) != 0) {
		return -1;
	}

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sock == -1) {
			continue;
		}

		if (connect(sock, rp->ai_addr, rp->ai_addrlen) != -1) {
			break;
		}

		close(sock);
	}

	freeaddrinfo(result);
	return (rp == NULL) ? -1 : sock;
}

int
csnet_connect_with_timeout(const char* host, int port, int milliseconds) {
	struct sockaddr_in ipv4addr;
	struct addrinfo hints;
	struct addrinfo* result;
	struct addrinfo* rp;
	int sock;

	if (inet_aton(host, &ipv4addr.sin_addr) == 1) {
		ipv4addr.sin_family = AF_INET;
		ipv4addr.sin_port = htons(port);
		sock = socket(AF_INET, SOCK_STREAM, 0);
		if (sock < 0) {
			return -1;
		}
		if (connect(sock, (const struct sockaddr*)&ipv4addr,
			   sizeof(struct sockaddr)) < 0) {
			close(sock);
			return -1;
		}
		return sock;
	}

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	char portptr[6];
	snprintf(portptr, 6, "%d", port);

	if (getaddrinfo(host, portptr, &hints, &result) != 0) {
		return -1;
	}

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sock == -1) {
			continue;
		}

		csnet_set_nonblocking(sock);

		if (connect(sock, rp->ai_addr, rp->ai_addrlen) == -1) {
			if (errno == EINPROGRESS) {
				struct pollfd pollfd;
				pollfd.fd = sock;
				pollfd.events = POLLIN | POLLOUT;

				/* If the remote host is down or network issue,
				   poll() will block `milliseconds` here */

				int nready = poll(&pollfd, 1, milliseconds);
				if (nready < 0) {
					debug("poll(): %s. %s:%d", strerror(errno), host, port);
					close(sock);
					continue;
				}

				if (nready == 0) {
					debug("poll() timeout: 100 milliseconds. %s:%d", host, port);
					close(sock);
					continue;
				}

				int result;
				socklen_t result_len = sizeof(result);

				if (getsockopt(pollfd.fd, SOL_SOCKET, SO_ERROR, &result, &result_len) < 0) {
					close(sock);
					continue;
				}

				if (result != 0) {
					debug("SO_ERROR: %d. %s:%d", result, host, port);
					close(sock);
					continue;
				}
				break;
			} else {
				debug("connect to host: %s, port: %d error: %s", host, port, strerror(errno));
				close(sock);
				continue;
			}
		}
	}

	freeaddrinfo(result);
	return (rp == NULL) ? -1 : sock;
}

void
csnet_wait_milliseconds(int milliseconds) {
	poll(NULL, 0, milliseconds);
}

/*
void
csnet_epoll_modin(int epfd, int socket, unsigned int sid) {
	struct epoll_event ev = {
		.events = EPOLLIN,
		.data.u32 = sid
	};
	epoll_ctl(epfd, EPOLL_CTL_MOD, socket, &ev);
}

void
csnet_epoll_modout(int epfd, int socket, unsigned int sid) {
	struct epoll_event ev = {
		.events = EPOLLOUT,
		.data.u32 = sid
	};
	epoll_ctl(epfd, EPOLL_CTL_MOD, socket, &ev);
}

void
csnet_epoll_modinout(int epfd, int socket, unsigned int sid) {
	struct epoll_event ev = {
		.events = EPOLLIN | EPOLLOUT,
		.data.u32 = sid
	};
	epoll_ctl(epfd, EPOLL_CTL_MOD, socket, &ev);
}

void
csnet_epoll_modadd(int epfd, int socket, unsigned int sid) {
	struct epoll_event ev = {
		.events = EPOLLIN,
		.data.u32 = sid
	};
	epoll_ctl(epfd, EPOLL_CTL_ADD, socket, &ev);
}

void
csnet_epoll_moddel(int epfd, int socket, unsigned int sid) {
	struct epoll_event ev = {
		.events = EPOLLIN,
		.data.u32 = sid
	};
	epoll_ctl(epfd, EPOLL_CTL_DEL, socket, &ev);
}
*/

