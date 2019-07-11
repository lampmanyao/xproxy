#include "btgfw.h"
#include "socks5.h"
#include "el.h"
#include "tcp-connection.h"
#include "log.h"
#include "config.h"
#include "poller.h"
#include "crypt.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define RANDOM_SIZE sizeof(int64_t)

static void accept_cb(struct btgfw *btgfw, int lfd);
static void recvfrom_client_cb(struct el *el, struct tcp_connection *tcp_conn);
static void sendto_client_cb(struct el *el, struct tcp_connection *tcp_conn);
static void recvfrom_remote_cb(struct el *el, struct tcp_connection *tcp_conn);
static void sendto_remote_cb(struct el *el, struct tcp_connection *tcp_conn);

struct local_config {
	char *password;
	char *local_addr;
	int local_port;
	char *remote_addr;
	int remote_port;
	int nthread;
	int maxfiles;
	int verbose;
} configuration;

struct cfgopts cfg_opts[] = {
	{ "password", TYP_STRING, &configuration.password, {0, "pa$$w0rld"} },
	{ "local_addr", TYP_STRING, &configuration.local_addr, {0, "127.0.0.1"} },
	{ "local_port", TYP_INT4, &configuration.local_port, {10086, NULL} },
	{ "remote_addr", TYP_STRING, &configuration.remote_addr, {0, "127.0.0.1"} },
	{ "remote_port", TYP_INT4, &configuration.remote_port, {20086, NULL} },
	{ "nthread", TYP_INT4, &configuration.nthread, {4, NULL} },
	{ "maxfiles", TYP_INT4, &configuration.maxfiles, {1024, NULL} },
	{ "verbose", TYP_INT4, &configuration.verbose, {0, NULL} },
	{ NULL, 0, NULL, {0, NULL} }
};

static void
accept_cb(struct btgfw *btgfw, int lfd)
{
	int fd;
	struct tcp_connection *tcp_conn;
	struct sockaddr_in sock_addr;
	socklen_t addr_len = sizeof(struct sockaddr_in);
	bzero(&sock_addr, addr_len);
	fd = accept(lfd, (struct sockaddr*)&sock_addr, &addr_len);

	if (fd > 0) {
		if (configuration.verbose)
			DEBUG("accept incoming from %s:%d with client %d", inet_ntoa(sock_addr.sin_addr), ntohs(sock_addr.sin_port), fd);

		set_nonblocking(fd);
		tcp_conn = new_tcp_connection(fd, 8192, recvfrom_client_cb, sendto_client_cb);
		el_watch(btgfw->els[fd % btgfw->nthread], tcp_conn);
	} else {
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			ERROR("accept(): %s", strerror(errno));
			return;
		}
	}
}

static void
client_exchange_method(struct el *el, struct tcp_connection *client)
{
	char *data = client->rbuf;
	size_t dlen = client->rbuf_len;
	int8_t version, nmethods, methods;
	char *sbuf;
	size_t sbuf_len;
	ssize_t s;

	if (slow(dlen <= 2)) {
		return;
	}

	version = data[0];
	nmethods = data[1];
	methods = data[2];

	if (slow(version != SOCKS5_VER)) {
		ERROR("unsupport version: %d", version);
		el_stop_watch(el, client);
		free_tcp_connection(client);
		return;
	}

	if (slow(dlen < (size_t)(nmethods + 2))) {
		return;
	}

	tcp_connection_rbuf_seek(client, (size_t)(2 + nmethods));

	tcp_connection_sbuf_append(client, (char *)&version, 1);
	tcp_connection_sbuf_append(client, (char *)&methods, 1);

	sbuf = client->sbuf;
	sbuf_len = client->sbuf_len;

	s = send(client->fd, sbuf, sbuf_len, 0);

	if (fast(s > 0)) {
		tcp_connection_sbuf_seek(client, (size_t)s);
		client->stage = SOCKS5_STAGE_EXCHG_HOST;
	} else if (s == 0) {
		el_stop_watch(el, client);
		free_tcp_connection(client);
	} else {
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			el_stop_watch(el, client);
			free_tcp_connection(client);
		}
	}
}

static void
client_exchange_host(struct el *el, struct tcp_connection *client)
{
	struct tcp_connection *remote;
	char *data = client->rbuf;
	size_t dlen = client->rbuf_len;

	char *ciphertext;
	int8_t version, cmd, atyp;

	if (slow(dlen < SOCKS5_REQ_HEAD_SIZE)) {
		return;
	}

	version = data[0];
	cmd = data[1];
	atyp = data[3];

	if (slow(version != SOCKS5_VER)) {
		ERROR("unsupport version: %d", version);
		el_stop_watch(el, client);
		free_tcp_connection(client);
		return;
	}

	if (slow(cmd != SOCKS5_CMD_CONNECT)) {
		ERROR("unsupport command: %d", cmd);
		el_stop_watch(el, client);
		free_tcp_connection(client);
		return;
	}

	if (atyp == SOCKS5_ATYP_IPv4) {
		if (slow(dlen < SOCKS5_IPV4_REQ_SIZE)) {
			return;
		}

		char ipv4[32];
		uint16_t nport;
		char request[512];
		int fd;

		if (!inet_ntop(AF_INET, data + 4, ipv4, INET_ADDRSTRLEN)) {
			ERROR("inet_ntop(): %s", strerror(errno));
			el_stop_watch(el, client);
			free_tcp_connection(client);
			return;
		}

		memcpy(&nport, data + SOCKS5_REQ_HEAD_SIZE + 4, 2);

		fd = connect_with_timeout(configuration.remote_addr, configuration.remote_port, 1000);
		if (slow(fd < 0)) {
			ERROR("connect to remote host failed.");
			el_stop_watch(el, client);
			free_tcp_connection(client);
			return;
		}

		if (configuration.verbose)
			DEBUG("client %d connect to remote %d", client->fd, fd);

		set_nonblocking(fd);
		remote = new_tcp_connection(fd, 8192, recvfrom_remote_cb, sendto_remote_cb);
		el_watch(el, remote);

		memcpy(client->host, ipv4, strlen(ipv4));
		client->host[strlen(ipv4)] = '\0';

		memcpy(remote->host, ipv4, strlen(ipv4));
		remote->host[strlen(ipv4)] = '\0';
		remote->peer_tcp_conn = client;
		client->peer_tcp_conn = remote;

		int64_t randnum = random();

		memcpy(request, &randnum, RANDOM_SIZE);
		memcpy(request + RANDOM_SIZE, data, SOCKS5_IPV4_REQ_SIZE);

		int ciphertext_len = crypt_128cfb_encrypt(&ciphertext,
							  request,
							  SOCKS5_IPV4_REQ_SIZE + RANDOM_SIZE,
							  configuration.password);
		if (ciphertext_len < 0) {
			ERROR("encryption failure.");
			el_stop_watch(el, client);
			free_tcp_connection(client);

			if (remote) {
				el_stop_watch(el, remote);
				free_tcp_connection(remote);
			}
			return;
		}

		/* skip already handled */
		tcp_connection_rbuf_seek(client, SOCKS5_IPV4_REQ_SIZE);

		client->stage = SOCKS5_STAGE_STREAM;
		remote->stage = SOCKS5_STAGE_EXCHG_HOST;

		tcp_connection_sbuf_append(remote, (char*)&ciphertext_len, 4);
		tcp_connection_sbuf_append(remote, ciphertext, (size_t)ciphertext_len);

		goto forword_to_remote;
	} else if (atyp == SOCKS5_ATYP_DONAME) {
		uint8_t domain_name_len;
		char domain_name[256];
		uint16_t nport;
		char request[515];
		int req_len;
		int fd;

		domain_name_len = (uint8_t)data[SOCKS5_REQ_HEAD_SIZE];
		req_len = SOCKS5_REQ_HEAD_SIZE + 1 + domain_name_len + SOCKS5_PORT_SIZE;

		if (slow(dlen < (size_t)req_len)) {
			return;
		}

		memcpy(domain_name, data + SOCKS5_REQ_HEAD_SIZE + 1, domain_name_len);
		domain_name[domain_name_len] = '\0';

		memcpy(&nport,
		       data + SOCKS5_REQ_HEAD_SIZE + 1 + domain_name_len,
		       SOCKS5_PORT_SIZE);

		fd = connect_with_timeout(configuration.remote_addr, configuration.remote_port, 1000);

		if (fd < 0) {
			ERROR("exchg host: connect to remote host failure");
			el_stop_watch(el, client);
			free_tcp_connection(client);
			return;
		}

		set_nonblocking(fd);
		remote = new_tcp_connection(fd, 8192, recvfrom_remote_cb, sendto_remote_cb);
		el_watch(el, remote);

		memcpy(client->host, domain_name, domain_name_len);
		client->host[domain_name_len] = '\0';
		memcpy(remote->host, domain_name, domain_name_len);
		remote->host[domain_name_len] = '\0';

		if (configuration.verbose)
			DEBUG("client %d connect to remote %d. %s", client->fd, fd, remote->host);

		remote->peer_tcp_conn = client;
		client->peer_tcp_conn = remote;

		int64_t randnum = random();
		memcpy(request, &randnum, RANDOM_SIZE);
		memcpy(request + RANDOM_SIZE, data, req_len);

		int ciphertext_len = crypt_128cfb_encrypt(&ciphertext,
							   request,
							   req_len + RANDOM_SIZE,
							   configuration.password);
		if (ciphertext_len < 0) {
			ERROR("encryption failed.");
			el_stop_watch(el, client);
			free_tcp_connection(client);
			el_stop_watch(el, remote);
			free_tcp_connection(remote);
			return;
		}

		/* skip already handled */
		tcp_connection_rbuf_seek(client, (size_t)req_len);

		remote->stage = SOCKS5_STAGE_EXCHG_HOST;
		client->stage = SOCKS5_STAGE_EXCHG_HOST;

		tcp_connection_sbuf_append(remote, (char*)&ciphertext_len, 4);
		tcp_connection_sbuf_append(remote, ciphertext, (size_t)ciphertext_len);

		goto forword_to_remote;
	} else if (atyp == SOCKS5_ATYP_IPv6) {
		/* TODO: support IPv6 */
		ERROR("unsupport IPv6");
		el_stop_watch(el, client);
		free_tcp_connection(client);
		return;
	} else {
		ERROR("unknown address type");
		el_stop_watch(el, client);
		free_tcp_connection(client);
		return;
	}

forword_to_remote:
	free(ciphertext);
	char *sbuf = remote->sbuf;
	size_t sbuf_len = remote->sbuf_len;
	ssize_t s = send(remote->fd, sbuf, sbuf_len, 0);

	if (fast(s > 0)) {
		tcp_connection_sbuf_seek(remote, (size_t)s);

		if (slow((size_t)s < sbuf_len)) {
			poller_disable_read(el->poller, client->fd, client);
			poller_enable_write(el->poller, remote->fd, remote);
		}
	} else if (s == 0) {
		el_stop_watch(el, client);
		free_tcp_connection(client);

		el_stop_watch(el, remote);
		free_tcp_connection(remote);
	} else {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			poller_disable_read(el->poller, client->fd, client);
			poller_enable_write(el->poller, remote->fd, remote);
		} else {
			el_stop_watch(el, client);
			free_tcp_connection(client);

			el_stop_watch(el, remote);
			free_tcp_connection(remote);
		}
	}
}

static void
client_stream_to_remote(struct el *el, struct tcp_connection *client,
			struct tcp_connection *remote)
{
	char *data = client->rbuf;
	size_t dlen = client->rbuf_len;

	tcp_connection_sbuf_append(remote, data, dlen);
	tcp_connection_rbuf_seek(client, dlen);

	char *sbuf = remote->sbuf;
	size_t sbuf_len = remote->sbuf_len;
	ssize_t s = send(remote->fd, sbuf, sbuf_len, 0);

	if (fast(s > 0)) {
		tcp_connection_sbuf_seek(remote, (size_t)s);
		if ((size_t)s < sbuf_len) {
			poller_disable_read(el->poller, client->fd, client);
			poller_enable_write(el->poller, remote->fd, remote);
		}
	} else if (s == 0) {
		if (configuration.verbose)
			DEBUG("send() zero to remote %d (%s)", remote->fd, remote->host);

		el_stop_watch(el, client);
		free_tcp_connection(client);
		if (remote) {
			el_stop_watch(el, remote);
			free_tcp_connection(remote);
		}
	} else {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			if (configuration.verbose)
				DEBUG("send() to remote %d (%s) eagain", remote->fd, remote->host);

			poller_disable_read(el->poller, client->fd, client);
			poller_enable_write(el->poller, remote->fd, remote);
		} else {
			if (configuration.verbose)
				DEBUG("send() to remote %d (%s) error", remote->fd, remote->host);

			el_stop_watch(el, client);
			free_tcp_connection(client);
			if (remote) {
				el_stop_watch(el, remote);
				free_tcp_connection(remote);
			}
		}
	}
}

static void
recvfrom_client_cb(struct el *el, struct tcp_connection *client)
{
	struct tcp_connection *remote;
	size_t need_read;
	char *rbuf;
	ssize_t r = 0;

	remote = client->peer_tcp_conn;
	need_read = client->rbuf_size - client->rbuf_len;
	rbuf = client->rbuf + client->rbuf_len;

	r = recv(client->fd, rbuf, need_read, 0);

	if (fast(r > 0)) {
		client->rbuf_len += (size_t)r;

		switch (client->stage) {
		case SOCKS5_STAGE_STREAM:
			client_stream_to_remote(el, client, remote);
			break;

		case SOCKS5_STAGE_EXCHG_METHOD:
			client_exchange_method(el, client);
			break;

		case SOCKS5_STAGE_EXCHG_HOST:
			client_exchange_host(el, client);
			break;

		default:
			break;
		}
	} else if (r == 0) {
		if (configuration.verbose)
			DEBUG("client %d (%s) closed", client->fd, client->host);

		client->closed = 1;
		poller_disable_read(el->poller, client->fd, client);
	} else {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			if (configuration.verbose)
				DEBUG("recv() from client %d (%s) eagain", client->fd, client->host);
		} else {
			if (configuration.verbose)
				DEBUG("recv() from client %d (%s) error", client->fd, client->host);

			el_stop_watch(el, client);
			free_tcp_connection(client);

			if (remote) {
				el_stop_watch(el, remote);
				free_tcp_connection(remote);
			}
		}
	}
}

static void
sendto_client_cb(struct el *el, struct tcp_connection *client)
{
	struct tcp_connection *remote = client->peer_tcp_conn;
	char *sbuf = client->sbuf;
	size_t sbuf_len = client->sbuf_len;

	if (slow(sbuf_len <= 0)) {
		return;
	}

	ssize_t s = send(client->fd, sbuf, sbuf_len, 0);

	if (fast(s > 0)) {
		tcp_connection_sbuf_seek(client, (size_t)s);

		if (fast((size_t)s == sbuf_len)) {
			poller_enable_read(el->poller, remote->fd, remote);
			poller_disable_write(el->poller, client->fd, client);
		} else {
			if (configuration.verbose)
				DEBUG("send() to client %d (%s) partially", client->fd, client->host);

			poller_disable_read(el->poller, remote->fd, remote);
			poller_enable_write(el->poller, client->fd, client);
		}
	} else if (s == 0) {
		if (configuration.verbose)
			DEBUG("send() zero to client %d (%s) ", client->fd, client->host);

		el_stop_watch(el, client);
		free_tcp_connection(client);
		if (remote) {
			el_stop_watch(el, remote);
			free_tcp_connection(remote);
		}
	} else {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			if (configuration.verbose)
				DEBUG("send() to client %d (%s) eagain", client->fd, client->host);

			poller_disable_read(el->poller, remote->fd, remote);
			poller_enable_write(el->poller, client->fd, client);
		} else {
			if (configuration.verbose)
				DEBUG("send() to client %d (%s) error", client->fd, client->host);

			el_stop_watch(el, client);
			free_tcp_connection(client);
			if (remote) {
				el_stop_watch(el, remote);
				free_tcp_connection(remote);
			}
		}
	}
}

static void
remote_exchange_host(struct el *el, struct tcp_connection *remote)
{
	struct tcp_connection *client = remote->peer_tcp_conn;
	char *data = remote->rbuf;
	size_t dlen = remote->rbuf_len;

	int ciphertext_len;
	int plaintext_len;
	char *plaintext;
	char reply[256];

	if (slow(dlen < 4)) {
		return;
	}

	memcpy((char*)&ciphertext_len, data, 4);

	if (slow(dlen < (size_t)(4 + ciphertext_len))) {
		return;
	}

	plaintext_len = crypt_128cfb_decrypt(&plaintext,
					      data + 4,
					      (unsigned int)ciphertext_len,
					      configuration.password);
	if (plaintext_len < 0) {
		el_stop_watch(el, client);
		free_tcp_connection(client);
		el_stop_watch(el, remote);
		free_tcp_connection(remote);
		return;
	}

	/* skip already handled */
	tcp_connection_rbuf_seek(remote, (size_t)(4 + ciphertext_len));

	uint8_t ver = plaintext[0 + RANDOM_SIZE];
	uint8_t rsp = plaintext[1 + RANDOM_SIZE];
	uint8_t rsv = plaintext[2 + RANDOM_SIZE];
	uint8_t typ = plaintext[3 + RANDOM_SIZE];

	if (typ == SOCKS5_ATYP_IPv4) {
		memcpy(reply, plaintext + RANDOM_SIZE, 10);
		tcp_connection_sbuf_append(client, reply, 10);
		goto reply_to_client;
	} else if (typ == SOCKS5_ATYP_DONAME) {
		uint8_t domain_name_len = plaintext[SOCKS5_RSP_HEAD_SIZE + RANDOM_SIZE];
		memcpy(reply, plaintext + RANDOM_SIZE, SOCKS5_RSP_HEAD_SIZE + 1 + domain_name_len + SOCKS5_PORT_SIZE);
		tcp_connection_sbuf_append(client, reply, SOCKS5_RSP_HEAD_SIZE + 1 + domain_name_len + SOCKS5_PORT_SIZE);
		goto reply_to_client;
	} else if (typ == SOCKS5_ATYP_IPv6) {
		el_stop_watch(el, client);
		free_tcp_connection(client);
		el_stop_watch(el, remote);
		free_tcp_connection(remote);
		return;
	}

reply_to_client:
	free(plaintext);
	char *sbuf = client->sbuf;
	size_t sbuf_len = client->sbuf_len;
	ssize_t s = send(client->fd, sbuf, sbuf_len, 0);

	if (fast(s > 0)) {
		/* skip already sent */
		tcp_connection_sbuf_seek(client, (size_t)s);

		if ((size_t)s < sbuf_len) {
			if (configuration.verbose)
				DEBUG("send() to client %d (%s) partially", client->fd, client->host);

			poller_enable_write(el->poller, client->fd, client);
			poller_disable_read(el->poller, remote->fd, remote);
		} else {
			client->stage = SOCKS5_STAGE_STREAM;
			remote->stage = SOCKS5_STAGE_STREAM;
		}
	} else if (s == 0) {
		if (configuration.verbose)
			DEBUG("send() zero to client %d (%s)", client->fd, client->host);

		el_stop_watch(el, client);
		free_tcp_connection(client);
		el_stop_watch(el, remote);
		free_tcp_connection(remote);
	} else {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			if (configuration.verbose)
				DEBUG("send() to client %d (%s) eagain", client->fd, client->host);

			poller_enable_write(el->poller, client->fd, client);
			poller_disable_read(el->poller, remote->fd, remote);
		} else {
			if (configuration.verbose)
				DEBUG("send() to client %d (%s) error", client->fd, client->host);

			el_stop_watch(el, client);
			free_tcp_connection(client);
			el_stop_watch(el, remote);
			free_tcp_connection(remote);
		}
	}
}

static void
remote_stream_back_to_client(struct el *el, struct tcp_connection *remote)
{
	struct tcp_connection *client = remote->peer_tcp_conn;
	char *data = remote->rbuf;
	size_t dlen = remote->rbuf_len;

	tcp_connection_sbuf_append(client, data, dlen);
	tcp_connection_rbuf_seek(remote, dlen);

	char *sbuf = client->sbuf;
	size_t sbuf_len = client->sbuf_len;
	ssize_t s = send(client->fd, sbuf, sbuf_len, 0);

	if (fast(s > 0)) {
		tcp_connection_sbuf_seek(client, (size_t)s);
		if (slow((size_t)s < sbuf_len)) {
			if (configuration.verbose)
				DEBUG("send() to client %d (%s) partially. Sent %zu bytes, remaining %zu bytes", client->fd, client->host, s, sbuf_len - s);

			poller_disable_read(el->poller, remote->fd, remote);
			poller_enable_write(el->poller, client->fd, client);
		} else {
			poller_enable_read(el->poller, remote->fd, remote);
		}
	} else if (s == 0) {
		el_stop_watch(el, client);
		free_tcp_connection(client);
		el_stop_watch(el, remote);
		free_tcp_connection(remote);
	} else {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			if (configuration.verbose)
				DEBUG("send() to client %d (%s) eagain. Remaining %zu bytes", client->fd, client->host, sbuf_len);

			poller_disable_read(el->poller, remote->fd, remote);
			poller_enable_write(el->poller, client->fd, client);
		} else {
			if (configuration.verbose)
				DEBUG("send() to client %d (%s) error", client->fd, client->host);

			el_stop_watch(el, client);
			free_tcp_connection(client);
			el_stop_watch(el, remote);
			free_tcp_connection(remote);
		}
	}
}

static void
recvfrom_remote_cb(struct el *el, struct tcp_connection *remote)
{
	struct tcp_connection *client;
	char *rbuf;
	size_t need_read;
	ssize_t r = 0;

	client = remote->peer_tcp_conn;
	rbuf = remote->rbuf + remote->rbuf_len;
	need_read = remote->rbuf_size - remote->rbuf_len;

	r = recv(remote->fd, rbuf, need_read, 0);

	if (fast(r > 0)) {
		remote->rbuf_len += (size_t)r;

		switch (remote->stage) {
		case SOCKS5_STAGE_EXCHG_HOST:
			remote_exchange_host(el, remote);
			break;

		case SOCKS5_STAGE_STREAM:
			remote_stream_back_to_client(el, remote);
			break;

		default:
			break;
		}
	} else if (r == 0) {
		if (configuration.verbose)
			DEBUG("recv() zero from remote %d (%s)", remote->fd, remote->host);

		el_stop_watch(el, remote);
		free_tcp_connection(remote);

		el_stop_watch(el, client);
		free_tcp_connection(client);
	} else {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			if (configuration.verbose)
				DEBUG("recv() from remote %d (%s) eagain", remote->fd, remote->host);
		} else {
			if (configuration.verbose)
				DEBUG("recv() from remote %d (%s) error", remote->fd, remote->host);

			el_stop_watch(el, remote);
			free_tcp_connection(remote);

			el_stop_watch(el, client);
			free_tcp_connection(client);
		}
	}
}

static void
sendto_remote_cb(struct el *el, struct tcp_connection *remote)
{
	struct tcp_connection *client = remote->peer_tcp_conn;
	char *sbuf = remote->sbuf;
	size_t sbuf_len = remote->sbuf_len;

	if (sbuf_len <= 0) {
		return;
	}

	ssize_t s = send(remote->fd, sbuf, sbuf_len, 0);

	if (fast(s > 0)) {
		tcp_connection_sbuf_seek(remote, (size_t)s);
		if (client->closed == 0) {
			poller_enable_read(el->poller, client->fd, client);
		}

		if ((size_t)s == sbuf_len) {
			poller_disable_write(el->poller, remote->fd, remote);
		} else {
			poller_enable_write(el->poller, remote->fd, remote);
		}
	} else if (s == 0) {
		if (configuration.verbose)
			DEBUG("send() zero to remote %d (%s)", remote->fd, remote->host);

		el_stop_watch(el, remote);
		free_tcp_connection(remote);

		el_stop_watch(el, client);
		free_tcp_connection(client);
	} else {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			if (configuration.verbose)
				DEBUG("send() to remote %d (%s) eagain", remote->fd, remote->host);

			if (client->closed == 0) {
				poller_enable_read(el->poller, client->fd, client);
			}
			poller_enable_write(el->poller, remote->fd, remote);
		} else {
			if (configuration.verbose)
				DEBUG("send() to remote %d (%s) error", remote->fd, remote->host);

			el_stop_watch(el, remote);
			free_tcp_connection(remote);

			el_stop_watch(el, client);
			free_tcp_connection(client);
		}
	}
}

static void
usage(void)
{
	printf("Usage: local-btgfw [-h] [-v] [-c config]\n");
	exit(-1);
}

int main(int argc, char **argv)
{
	int ch;
	int vflag = 0;
	int cflag = 0;
	int hflag = 0;
	const char *conf_file;

	while ((ch = getopt(argc, argv, "vc:h")) != -1) {
		switch (ch) {
		case 'v':
			vflag = 1;
			break;

		case 'c':
			cflag = 1;
			conf_file = optarg;
			break;

		case 'h':
			hflag = 1;
			break;

		case '?':
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (vflag) {
		printf("btgfw version: %s\n\n", btgfw_version());
	}

	if (hflag) {
		usage();
	}

	signals_init();
	coredump_init();
	crypt_setup();
	rand();

	int sfd;
	struct btgfw *btgfw;

	config_init(conf_file, cfg_opts);

	if (openfiles_init(configuration.maxfiles) != 0) {
		fatal("set max open files to %d failed: %s",
		      configuration.maxfiles, strerror(errno));
	}

	sfd = listen_and_bind(configuration.local_addr, configuration.local_port);
	if (sfd < 0) {
		fatal("listen_and_bind(): %s", strerror(errno));
	}

	DEBUG("Listening on %d", configuration.local_port);

	crypt_set_iv(configuration.password);

	btgfw = btgfw_new(sfd, configuration.nthread, accept_cb);

	DEBUG("Server started ...");

	btgfw_loop(btgfw, -1);

	close(sfd);
	btgfw_free(btgfw);

        return 0;
}

