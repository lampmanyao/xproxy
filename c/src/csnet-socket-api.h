#pragma once

int csnet_set_nonblocking(int sfd);
int csnet_listen_port(int port);

/* host can be a doname or an ip address  */
int csnet_connect_without_timeout(const char* host, int port);

/* host can be a doname or an ip address  */
int csnet_connect_with_timeout(const char* host, int port, int milliseconds);

void csnet_wait_milliseconds(int milliseconds);

void csnet_epoll_modin(int epfd, int socket, unsigned int sid);
void csnet_epoll_modout(int epfd, int socket, unsigned int sid);
void csnet_epoll_modinout(int epfd, int socket, unsigned int sid);
void csnet_epoll_modadd(int epfd, int socket, unsigned int sid);
void csnet_epoll_moddel(int epfd, int socket, unsigned int sid);

