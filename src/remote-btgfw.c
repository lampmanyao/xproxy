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
static void recvfrom_target_cb(struct el *el, struct tcp_connection *tcp_conn);
static void sendto_target_cb(struct el *el, struct tcp_connection *tcp_conn);

struct remote_config {
	char *password;
	char *local_addr;
	int local_port;
	int nthread;
	int maxfiles;
	int verbose;
} configuration;

struct cfgopts cfg_opts[] = {
	{ "local_addr", TYP_STRING, &configuration.local_addr, {0, "0.0.0.0"} },
	{ "local_port", TYP_INT4, &configuration.local_port, {20086, NULL} },
	{ "nthread", TYP_INT4, &configuration.nthread, {4, NULL} },
	{ "maxfiles", TYP_INT4, &configuration.maxfiles, {1024, NULL} },
	{ "password", TYP_STRING, &configuration.password, {0, "pa$$w0rld"} },
	{ "verbose", TYP_INT4, &configuration.verbose, {1, NULL} },
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
		DEBUG("accept incoming from %s:%d with client %d",
		      inet_ntoa(sock_addr.sin_addr), ntohs(sock_addr.sin_port), fd);
		set_nonblocking(fd);
		tcp_conn = new_tcp_connection(fd, 8192, recvfrom_client_cb, sendto_client_cb);
		el_watch(btgfw->els[fd % btgfw->nthread], tcp_conn);
	} else {
		if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
			return;
		} else {
			ERROR("accept(): %s", strerror(errno));
			return;
		}
	}
}

static void
client_exchange_host(struct el *el, struct tcp_connection *client)
{
	struct tcp_connection *target;
	char *data = client->rbuf;
	size_t len = client->rbuf_len;

	unsigned int ciphertext_len;
	int plaintext_len;
	char *plaintext;

	if (slow(len < 4)) {
		return;
	}

	memcpy((char*)&ciphertext_len, data, 4);
	if (slow(len < 4 + ciphertext_len)) {
		return;
	}

	plaintext_len = crypt_128cfb_decrypt(&plaintext,
					      data + 4,
					      ciphertext_len,
					      configuration.password);
	if (slow(plaintext_len < 0)) {
		ERROR("decrypt failed");
		el_stop_watch(el, client);
		free_tcp_connection(client);
		return;
	}

	uint8_t ver = plaintext[0 + RANDOM_SIZE];
	uint8_t cmd = plaintext[1 + RANDOM_SIZE];
	uint8_t rsv = plaintext[2 + RANDOM_SIZE];
	uint8_t typ = plaintext[3 + RANDOM_SIZE];

	if (typ == SOCKS5_ATYP_IPv4) {
		char reply[256];
		char ipv4[32];
		uint16_t nport;
		uint16_t hsport;
		int fd;
		char *cipher_reply;
		int cipher_reply_len;

		if (!inet_ntop(AF_INET, plaintext + 4 + RANDOM_SIZE, ipv4, INET_ADDRSTRLEN)) {
			ERROR("inet_ntop(): %s", strerror(errno));
			free(plaintext);
			el_stop_watch(el, client);
			free_tcp_connection(client);
			return;
		}

		memcpy((char*)&nport, plaintext + RANDOM_SIZE + 8, SOCKS5_PORT_SIZE);
		hsport = ntohs(nport);

		fd = connect_with_timeout(ipv4, hsport, 1000);
		if (fd < 0) {
			ERROR("connect to %s:%d failed", ipv4, hsport);
			free(plaintext);
			el_stop_watch(el, client);
			free_tcp_connection(client);
			return;
		}

		if (configuration.verbose)
			DEBUG("client %d connected to %s with target %d", client->fd, ipv4, fd);

		set_nonblocking(fd);
		target = new_tcp_connection(fd, 8192, recvfrom_target_cb, sendto_target_cb);
		el_watch(el, target);

		memcpy(client->host, ipv4, sizeof(ipv4));
		client->host[sizeof(ipv4)] = '\0';
		memcpy(target->host, ipv4, sizeof(ipv4));
		target->host[sizeof(ipv4)] = '\0';

		int64_t randnum = random();
		memcpy(reply, &randnum, RANDOM_SIZE);
		reply[0 + RANDOM_SIZE] = ver;
		reply[1 + RANDOM_SIZE] = SOCKS5_RSP_SUCCEED;
		reply[2 + RANDOM_SIZE] = SOCKS5_RSV;
		reply[3 + RANDOM_SIZE] = SOCKS5_ATYP_IPv4;
		memcpy(reply + 4 + RANDOM_SIZE, plaintext + 4 + RANDOM_SIZE, 4);
		memcpy(reply + 4 + 4 + RANDOM_SIZE, (char*)&nport, SOCKS5_PORT_SIZE);

		cipher_reply_len = crypt_128cfb_encrypt(&cipher_reply,
						        reply,
							SOCKS5_IPV4_REQ_SIZE + RANDOM_SIZE,
							configuration.password);

		if (slow(cipher_reply_len < 0)) {
			ERROR("encrypt failed");
			free(plaintext);
			el_stop_watch(el, client);
			free_tcp_connection(client);
			el_stop_watch(el, target);
			free_tcp_connection(target);
			return;
		}

		tcp_connection_rbuf_seek(client, 4 + ciphertext_len);

		tcp_connection_sbuf_append(client, (char*)&cipher_reply_len, 4);
		tcp_connection_sbuf_append(client, cipher_reply, (size_t)cipher_reply_len);
		free(cipher_reply);

		goto reply_to_client;
	} else if (typ == SOCKS5_ATYP_DONAME) {
		uint8_t domain_name_len;
		char domain_name[256];
		uint16_t nport;
		uint16_t hsport;
		int fd;
		char reply[256];
		char *cipher_reply;
		int cipher_reply_len;

		domain_name_len = plaintext[SOCKS5_REQ_HEAD_SIZE + RANDOM_SIZE];
		memcpy(domain_name, plaintext + SOCKS5_REQ_HEAD_SIZE + 1 + RANDOM_SIZE, domain_name_len);
		domain_name[domain_name_len] = '\0';
		memcpy((char*)&nport, plaintext + SOCKS5_REQ_HEAD_SIZE + 1 + domain_name_len + RANDOM_SIZE, SOCKS5_PORT_SIZE);
		hsport = ntohs(nport);

		fd = connect_with_timeout(domain_name, hsport, 1000);
		if (slow(fd < 0)) {
			ERROR("connect to %s failed", domain_name);
			free(plaintext);
			el_stop_watch(el, client);
			free_tcp_connection(client);
			return;
		}

		if (configuration.verbose)
			DEBUG("client %d connected to %s with target %d", client->fd, domain_name, fd);

		set_nonblocking(fd);
		target = new_tcp_connection(fd, 8192, recvfrom_target_cb, sendto_target_cb);
		el_watch(el, target);

		memcpy(client->host, domain_name, domain_name_len);
		client->host[domain_name_len] = '\0';
		memcpy(target->host, domain_name, domain_name_len);
		target->host[domain_name_len] = '\0';

		int64_t randnum = random();
		memcpy(reply, &randnum, RANDOM_SIZE);

		reply[0 + RANDOM_SIZE] = ver;
		reply[1 + RANDOM_SIZE] = SOCKS5_RSP_SUCCEED;
		reply[2 + RANDOM_SIZE] = SOCKS5_RSV;
		reply[3 + RANDOM_SIZE] = SOCKS5_ATYP_DONAME;
		reply[4 + RANDOM_SIZE] = domain_name_len;
		memcpy(reply + 5 + RANDOM_SIZE, domain_name, domain_name_len);
		memcpy(reply + 5 + domain_name_len + RANDOM_SIZE, (char*)&nport, SOCKS5_PORT_SIZE);

		cipher_reply_len = crypt_128cfb_encrypt(&cipher_reply,
							reply,
							5 + domain_name_len + SOCKS5_PORT_SIZE + RANDOM_SIZE,
							configuration.password);

		if (cipher_reply_len < 0) {
			ERROR("encrypt failed");
			free(plaintext);
			el_stop_watch(el, client);
			free_tcp_connection(client);
			el_stop_watch(el, target);
			free_tcp_connection(target);
			return;
		}

		tcp_connection_rbuf_seek(client, 4 + ciphertext_len);

		tcp_connection_sbuf_append(client, (char*)&cipher_reply_len, 4);
		tcp_connection_sbuf_append(client, cipher_reply, (size_t)cipher_reply_len);
		free(cipher_reply);

		goto reply_to_client;
	} else if (typ == SOCKS5_ATYP_IPv6) {
		ERROR("unsupport IPv6 yet");
		return;
	} else {
		ERROR("unknown address type");
		return;
	}

reply_to_client:
	free(plaintext);

	char *sbuf = client->sbuf;
	size_t sbuf_len = client->sbuf_len;
	ssize_t s = send(client->fd, sbuf, sbuf_len, 0);

	if (fast(s > 0)) {
		tcp_connection_sbuf_seek(client, (size_t)s);
		client->peer_tcp_conn = target;
		client->stage = SOCKS5_STAGE_STREAM;

		target->peer_tcp_conn = client;
		target->stage = SOCKS5_STAGE_STREAM;

		if ((size_t)s < sbuf_len) {
			poller_disable_read(el->poller, target->fd, target);
			poller_enable_write(el->poller, client->fd, client);
			return;
		}
	} else if (s == 0) {
		el_stop_watch(el, client);
		free_tcp_connection(client);
		el_stop_watch(el, target);
		free_tcp_connection(target);
	} else {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			poller_disable_read(el->poller, target->fd, target);
			poller_enable_write(el->poller, client->fd, client);
		} else {
			el_stop_watch(el, client);
			free_tcp_connection(client);
			el_stop_watch(el, target);
			free_tcp_connection(target);
		}
	}
}

static void
client_stream_to_target(struct el *el, struct tcp_connection *client,
			struct tcp_connection *target)
{
	char *data = client->rbuf;
	size_t dlen = client->rbuf_len;

	tcp_connection_sbuf_append(target, data, dlen);
	tcp_connection_rbuf_seek(client, dlen);

	char *sbuf = target->sbuf;
	size_t sbuf_len = target->sbuf_len;

	ssize_t s = send(target->fd, sbuf, sbuf_len, 0);

	if (fast(s > 0)) {
		tcp_connection_sbuf_seek(target, (size_t)s);
		if ((size_t)s < sbuf_len) {
			poller_disable_read(el->poller, client->fd, client);
			poller_enable_write(el->poller, target->fd, target);
		}
	} else if (s == 0) {
		client->peer_tcp_conn = NULL;
		el_stop_watch(el, client);
		free_tcp_connection(client);
		el_stop_watch(el, target);
		free_tcp_connection(target);
	} else {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			if (configuration.verbose)
				DEBUG("send() to target %d (%s) eagain", target->fd, target->host);

			poller_disable_read(el->poller, client->fd, client);
			poller_enable_write(el->poller, target->fd, target);
		} else {
			if (configuration.verbose)
				DEBUG("send() to target %d (%s) error", target->fd, target->host);

			client->peer_tcp_conn = NULL;
			el_stop_watch(el, client);
			free_tcp_connection(client);
			el_stop_watch(el, target);
			free_tcp_connection(target);
		}
	}
}

static void
recvfrom_client_cb(struct el *el, struct tcp_connection *client)
{
	struct tcp_connection *target = client->peer_tcp_conn;;
	size_t need_read;
	char *rbuf;
	ssize_t r = 0;

	need_read = client->rbuf_size - client->rbuf_len;
	rbuf = client->rbuf + client->rbuf_len;
	r = recv(client->fd, rbuf, need_read, 0);

	if (fast(r > 0)) {
		client->rbuf_len += (size_t)r;

		switch (client->stage) {
		case SOCKS5_STAGE_STREAM:
			client_stream_to_target(el, client, target);
			break;

		case SOCKS5_STAGE_EXCHG_METHOD:
			client_exchange_host(el, client);
			break;

		default:
			break;
		}
	} else if (r == 0) {
		client->peer_tcp_conn = NULL;
		el_stop_watch(el, client);
		free_tcp_connection(client);
		if (target) {
			el_stop_watch(el, target);
			free_tcp_connection(target);
		}
	} else {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			if (configuration.verbose)
				DEBUG("recv() from client %d (%s) eagain", client->fd, client->host);
		} else {
			if (configuration.verbose)
				DEBUG("recv() from client %d (%s) error", client->fd, client->host);

			client->peer_tcp_conn = NULL;
			el_stop_watch(el, client);
			free_tcp_connection(client);
			if (target) {
				el_stop_watch(el, target);
				free_tcp_connection(target);
			}
		}
	}
}

static void
sendto_client_cb(struct el *el, struct tcp_connection *client)
{
	struct tcp_connection *target = client->peer_tcp_conn;
	char *sbuf = client->sbuf;
	size_t sbuf_len = client->sbuf_len;
	ssize_t s;

	if (sbuf_len <= 0) {
		return;
	}

	s = send(client->fd, sbuf, sbuf_len, 0);

	if (fast(s > 0)) {
		tcp_connection_sbuf_seek(client, (size_t)s);
		if ((size_t)s == sbuf_len) {
			poller_disable_write(el->poller, client->fd, client);
			poller_enable_read(el->poller, target->fd, target);
		}
	} else if (s == 0) {
		if (configuration.verbose)
			DEBUG("send() zero to client %d (%s), closing", client->fd, client->host);

		client->peer_tcp_conn = NULL;
		el_stop_watch(el, client);
		free_tcp_connection(client);
		if (target) {
			el_stop_watch(el, target);
			free_tcp_connection(target);
		}
	} else {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			if (configuration.verbose)
				DEBUG("send() to client %d (%s) eagain", client->fd, client->host);

			poller_disable_read(el->poller, target->fd, target);
			poller_enable_write(el->poller, client->fd, client);
		} else {
			if (configuration.verbose)
				DEBUG("send() to client %d (%s) error", client->fd, client->host);

			client->peer_tcp_conn = NULL;
			el_stop_watch(el, client);
			free_tcp_connection(client);
			if (target) {
				el_stop_watch(el, target);
				free_tcp_connection(target);
			}
		}
	}
}

static void
recvfrom_target_cb(struct el *el, struct tcp_connection *target)
{
	struct tcp_connection *client = target->peer_tcp_conn;
	char *rbuf;
	size_t need_read;
	ssize_t r = 0;

	rbuf = target->rbuf + target->rbuf_len;
	need_read = target->rbuf_size - target->rbuf_len;
	r = recv(target->fd, rbuf, need_read, 0);

	if (fast(r > 0)) {
		target->rbuf_len += (size_t)r;

		char *data = target->rbuf;
		size_t len = target->rbuf_len;

		tcp_connection_sbuf_append(client, data, len);
		tcp_connection_rbuf_seek(target, len);

		char *sbuf = client->sbuf;
		size_t sbuf_len = client->sbuf_len;
		ssize_t s = send(client->fd, sbuf, sbuf_len, 0);

		if (fast(s > 0)) {
			tcp_connection_sbuf_seek(client, (size_t)s);
			if ((size_t)s < sbuf_len) {
				poller_disable_read(el->poller, target->fd, target);
				poller_enable_write(el->poller, client->fd, client);
			} else {
				poller_enable_read(el->poller, target->fd, target);
				poller_disable_write(el->poller, client->fd, client);
			}
		} else if (s == 0) {
			if (configuration.verbose)
				DEBUG("send() zero to client %d (%s)", client->fd, client->host);

			target->peer_tcp_conn = NULL;
			el_stop_watch(el, target);
			free_tcp_connection(target);
			el_stop_watch(el, client);
			free_tcp_connection(client);
		} else {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				if (configuration.verbose)
					DEBUG("send() to client %d (%s) eagain. Remaining %zu bytes", client->fd, client->host, sbuf_len);

				poller_disable_read(el->poller, target->fd, target);
				poller_enable_write(el->poller, client->fd, client);
			} else {
				if (configuration.verbose)
					DEBUG("send() to client %d (%s) error", client->fd, client->host);

				target->peer_tcp_conn = NULL;
				el_stop_watch(el, target);
				free_tcp_connection(target);
				el_stop_watch(el, client);
				free_tcp_connection(client);
			}
		}
	} else if (r == 0) {
		if (configuration.verbose)
			DEBUG("recv() zero from target %d (%s)", target->fd, target->host);

		target->peer_tcp_conn = NULL;
		el_stop_watch(el, target);
		free_tcp_connection(target);
		if (client) {
			el_stop_watch(el, client);
			free_tcp_connection(client);
		}
	} else {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			if (configuration.verbose)
				DEBUG("recv() from target %d (%s) eagain", target->fd, target->host);

			poller_enable_read(el->poller, target->fd, target);
		} else {
			if (configuration.verbose)
				DEBUG("recv() from target %d (%s) error", target->fd, target->host);

			target->peer_tcp_conn = NULL;
			el_stop_watch(el, target);
			free_tcp_connection(target);
			if (client) {
				el_stop_watch(el, client);
				free_tcp_connection(client);
			}
		}
	}
}

static void
sendto_target_cb(struct el *el, struct tcp_connection *target)
{
	struct tcp_connection *client = target->peer_tcp_conn;
	char *sbuf = target->sbuf;
	size_t sbuf_len = target->sbuf_len;

	if (sbuf_len <= 0) {
		return;
	}

	ssize_t s = send(target->fd, sbuf, sbuf_len, 0);

	if (s > 0) {
		tcp_connection_sbuf_seek(target, (size_t)s);
		if ((size_t)s == sbuf_len) {
			poller_enable_read(el->poller, client->fd, client);
			poller_disable_write(el->poller, target->fd, target);
		} else {
			poller_enable_write(el->poller, target->fd, target);
		}
	} else if (s == 0) {
		if (configuration.verbose)
			DEBUG("send() zero to target %d (%s)", target->fd, target->host);

		target->peer_tcp_conn = NULL;
		el_stop_watch(el, target);
		free_tcp_connection(target);
		if (client) {
			el_stop_watch(el, client);
			free_tcp_connection(client);
		}
	} else {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			if (configuration.verbose)
				DEBUG("send() to target %d (%s) eagain", target->fd, target->host);
			poller_enable_write(el->poller, target->fd, target);
		} else {
			if (configuration.verbose)
				DEBUG("send() to target %d (%s) error", target->fd, target->host);

			target->peer_tcp_conn = NULL;
			el_stop_watch(el, target);
			free_tcp_connection(target);
			if (client) {
				el_stop_watch(el, client);
				free_tcp_connection(client);
			}
		}
	}
}

static void
usage(void)
{
	printf("Usage: remote-btgfw [-h] [-v] [-c config]\n");
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

	DEBUG("Listening on %d ...", configuration.local_port);

	crypt_set_iv(configuration.password);
	btgfw = btgfw_new(sfd, configuration.nthread, accept_cb);

	DEBUG("Server started ...");

	btgfw_loop(btgfw, 1000);

	close(sfd);
	btgfw_free(btgfw);

        return 0;
}

