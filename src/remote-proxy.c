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

#include "xproxy.h"
#include "socks5.h"
#include "el.h"
#include "tcp-connection.h"
#include "log.h"
#include "cfg.h"
#include "poller.h"
#include "crypt.h"
#include "utils.h"

static void accept_cb(struct xproxy *xproxy, int lfd);
static int recvfrom_client_cb(struct el *el, struct tcp_connection *tcp_conn);
static int sendto_client_cb(struct el *el, struct tcp_connection *tcp_conn);
static int recvfrom_target_cb(struct el *el, struct tcp_connection *tcp_conn);
static int sendto_target_cb(struct el *el, struct tcp_connection *tcp_conn);

static struct cryptor cryptor;

struct remote_config {
	char *password;
	char *method;
	char *local_addr;
	int local_port;
	int nthread;
	int maxfiles;
	int verbose;
} configuration;

struct cfgopts cfg_opts[] = {
	{ "password", TYP_STRING, &configuration.password, {0, "helloworld"} },
	{ "method", TYP_STRING, &configuration.method, {0, "aes-256-cfb"} },
	{ "local_addr", TYP_STRING, &configuration.local_addr, {0, "0.0.0.0"} },
	{ "local_port", TYP_INT4, &configuration.local_port, {20086, NULL} },
	{ "nthread", TYP_INT4, &configuration.nthread, {4, NULL} },
	{ "maxfiles", TYP_INT4, &configuration.maxfiles, {1024, NULL} },
	{ "verbose", TYP_INT4, &configuration.verbose, {0, NULL} },
	{ NULL, 0, NULL, {0, NULL} }
};

static void accept_cb(struct xproxy *xproxy, int lfd)
{
	int fd;
	struct tcp_connection *tcp_conn;
	struct sockaddr_in sock_addr;

	socklen_t addr_len = sizeof(struct sockaddr_in);
	bzero(&sock_addr, addr_len);
	fd = accept(lfd, (struct sockaddr*)&sock_addr, &addr_len);

	if (fd > 0) {
		INFO("Accept incoming from %s:%d.",
		      inet_ntoa(sock_addr.sin_addr), ntohs(sock_addr.sin_port));
		set_nonblocking(fd);
		tcp_conn = new_tcp_connection(fd, 4096, recvfrom_client_cb, sendto_client_cb);
		el_watch(xproxy->els[fd % xproxy->nthread], tcp_conn);
	} else {
		return;
	}
}

static int client_exchange_host(struct el *el, struct tcp_connection *client)
{
	struct tcp_connection *target;
	char *data = client->rxbuf;
	size_t len = client->rxbuf_length;

	unsigned int ciphertext_len;
	int plaintext_len;
	uint8_t *plaintext;

	if (slow(len < 4))
		return 0;

	memcpy((char*)&ciphertext_len, data, 4);
	if (slow(len < 4 + ciphertext_len))
		return 0;

	plaintext_len = cryptor.decrypt(&cryptor, (char**)&plaintext, data + 4, ciphertext_len);
	if (slow(plaintext_len < 0)) {
		ERROR("Decryption failure.");
		return -1;
	}

	uint8_t ver = plaintext[0];
	uint8_t cmd = plaintext[1];
	uint8_t rsv = plaintext[2];
	uint8_t typ = plaintext[3];

	SHUTUP_WARNING(cmd);
	SHUTUP_WARNING(rsv);

	if (typ == SOCKS5_ATYP_IPv4) {
		uint8_t reply[256];
		char ipv4[32];
		uint16_t nport;
		uint16_t hsport;
		int fd;
		char *cipher_reply;
		int cipher_reply_len;

		if (!inet_ntop(AF_INET, plaintext + 4, ipv4, INET_ADDRSTRLEN)) {
			ERROR("inet_ntop(): %s", strerror(errno));
			free(plaintext);
			return -1;
		}

		memcpy((char*)&nport, plaintext + 8, SOCKS5_PORT_SIZE);
		hsport = ntohs(nport);

		fd = connect_with_timeout(ipv4, hsport, 1000);
		if (fd < 0) {
			ERROR("Cannot connect to server (%s:%d).", ipv4, hsport);
			free(plaintext);
			return -1;
		}

		set_nonblocking(fd);
		target = new_tcp_connection(fd, 4096, recvfrom_target_cb, sendto_target_cb);
		el_watch(el, target);

		INFO("Connected to server (%s:%d).", ipv4, hsport);

		target->peer_tcp_conn = client;
		client->peer_tcp_conn = target;

		memcpy(client->host, ipv4, sizeof(ipv4));
		client->host[sizeof(ipv4)] = '\0';
		memcpy(target->host, ipv4, sizeof(ipv4));
		target->host[sizeof(ipv4)] = '\0';

		reply[0] = ver;
		reply[1] = SOCKS5_RSP_SUCCEED;
		reply[2] = SOCKS5_RSV;
		reply[3] = SOCKS5_ATYP_IPv4;
		memcpy(reply + 4, plaintext + 4, 4);
		memcpy(reply + 4 + 4, (char*)&nport, SOCKS5_PORT_SIZE);

		cipher_reply_len = cryptor.encrypt(&cryptor, &cipher_reply,
						   (char *)reply,
						   SOCKS5_IPV4_REQ_SIZE);

		if (slow(cipher_reply_len < 0)) {
			ERROR("encrypt failed");
			free(plaintext);
			return -1;
		}

		tcp_connection_reset_rxbuf(client);

		tcp_connection_append_txbuf(client, (char*)&cipher_reply_len, 4);
		tcp_connection_append_txbuf(client, cipher_reply, (size_t)cipher_reply_len);
		free(cipher_reply);

		goto reply_to_client;
	} else if (typ == SOCKS5_ATYP_DONAME) {
		uint8_t domain_name_len;
		char domain_name[256];
		uint16_t nport;
		uint16_t hsport;
		int fd;
		uint8_t reply[256];
		char *cipher_reply;
		int cipher_reply_len;

		domain_name_len = plaintext[SOCKS5_REQ_HEAD_SIZE];
		memcpy(domain_name, plaintext + SOCKS5_REQ_HEAD_SIZE + 1, domain_name_len);
		domain_name[domain_name_len] = '\0';
		memcpy((char*)&nport, plaintext + SOCKS5_REQ_HEAD_SIZE + 1 + domain_name_len,
			SOCKS5_PORT_SIZE);
		hsport = ntohs(nport);

		fd = connect_with_timeout(domain_name, hsport, 1000);
		if (slow(fd <= 0)) {
			ERROR("Cannot connect to server (%s:%d)", domain_name, hsport);
			free(plaintext);
			return -1;
		}

		set_nonblocking(fd);
		target = new_tcp_connection(fd, 4096, recvfrom_target_cb, sendto_target_cb);
		el_watch(el, target);

		client->peer_tcp_conn = target;
		target->peer_tcp_conn = client;

		INFO("Connected to server (%s:%d).", domain_name, hsport);

		memcpy(client->host, domain_name, domain_name_len);
		client->host[domain_name_len] = '\0';
		memcpy(target->host, domain_name, domain_name_len);
		target->host[domain_name_len] = '\0';

		reply[0] = ver;
		reply[1] = SOCKS5_RSP_SUCCEED;
		reply[2] = SOCKS5_RSV;
		reply[3] = SOCKS5_ATYP_DONAME;
		reply[4] = domain_name_len;
		memcpy(reply + 5, domain_name, domain_name_len);
		memcpy(reply + 5 + domain_name_len, (char*)&nport, SOCKS5_PORT_SIZE);

		cipher_reply_len = cryptor.encrypt(&cryptor, &cipher_reply,
						   (char *)reply,
						   5 + domain_name_len + SOCKS5_PORT_SIZE);

		if (cipher_reply_len < 0) {
			ERROR("Encryption failure.");
			free(plaintext);
			return -1;
		}

		tcp_connection_reset_rxbuf(client);

		tcp_connection_append_txbuf(client, (char*)&cipher_reply_len, 4);
		tcp_connection_append_txbuf(client, cipher_reply, (size_t)cipher_reply_len);
		free(cipher_reply);

		goto reply_to_client;
	} else if (typ == SOCKS5_ATYP_IPv6) {
		ERROR("Unsupport IPv6 yet.");
		return -1;
	} else {
		ERROR("Unknown address type: %d.", typ);
		return -1;
	}

reply_to_client:
	free(plaintext);

	ssize_t tx = send(client->fd, client->txbuf, client->txbuf_length, 0);

	if (fast(tx > 0)) {
		tcp_connection_reset_txbuf(client);
		client->stage = SOCKS5_STAGE_STREAM;
		target->stage = SOCKS5_STAGE_STREAM;
		return 0;
	} else {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			poller_disable_read(el->poller, target->fd, target);
			poller_enable_write(el->poller, client->fd, client);
			return 0;
		} else {
			return -1;
		}
	}
}

static int client_stream_to_target(struct el *el, struct tcp_connection *client)
{
	struct tcp_connection *target = client->peer_tcp_conn;;
	char *data = NULL;
	size_t data_len = 0;
	int ciphertext_len = 0;
	int plaintext_len = 0;
	char *plaintext = NULL;
	ssize_t tx = 0;

try_again:
	data = client->rxbuf;
	data_len = client->rxbuf_length;

	if (slow(data_len < 4))
		return 0;

	memcpy((char *)&ciphertext_len, data, 4);

	if (slow(data_len < 4 + (size_t)ciphertext_len))
		return 0;

	plaintext_len = cryptor.decrypt(&cryptor, &plaintext, data + 4, (unsigned int)ciphertext_len);

	if (plaintext_len < 0) {
		ERROR("Decryption failure.");
		return -1;
	}

	tcp_connection_append_txbuf(target, plaintext, (size_t)plaintext_len);
	free(plaintext);

	if (data_len == 4 + (size_t)ciphertext_len) {
		tcp_connection_reset_rxbuf(client);
	} else {
		tcp_connection_move_rxbuf(client, 4 + (size_t)ciphertext_len);
	}

	tx = send(target->fd, target->txbuf, target->txbuf_length, 0);

	if (fast(tx > 0)) {
		if ((size_t)tx == target->txbuf_length) {
			tcp_connection_reset_txbuf(target);
			goto try_again;
		} else {
			poller_disable_read(el->poller, client->fd, client);
			poller_enable_write(el->poller, target->fd, target);
			tcp_connection_move_txbuf(target, (size_t)tx);
		}
		return 0;
	} else {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			poller_disable_read(el->poller, client->fd, client);
			poller_enable_write(el->poller, target->fd, target);
			return 0;
		} else {
			return -1;
		}
	}
}

static int recvfrom_client_cb(struct el *el, struct tcp_connection *client)
{
	int ret = -1;
	while (1) {
		char buf[4096];
		ssize_t rx = recv(client->fd, buf, sizeof(buf), 0);
		if (fast(rx > 0)) {
			tcp_connection_append_rxbuf(client, buf, (size_t)rx);
		} else if (rx < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				break;
			} else {
				break;
			}
		} else {
			break;
		}
	}


	if (slow(client->rxbuf_length == 0))
		return -1;

	switch (client->stage) {
	case SOCKS5_STAGE_EXCHG_METHOD:
		ret = client_exchange_host(el, client);
		break;

	case SOCKS5_STAGE_STREAM:
		ret = client_stream_to_target(el, client);
		break;

	default:
		ret = -1;
		break;
	}

	return ret;
}

static int sendto_client_cb(struct el *el, struct tcp_connection *client)
{
	struct tcp_connection *target = client->peer_tcp_conn;
	ssize_t tx = send(client->fd, client->txbuf, client->txbuf_length, 0);

	if (fast(tx > 0)) {
		if ((size_t)tx == client->txbuf_length) {
			tcp_connection_reset_txbuf(client);
			poller_enable_read(el->poller, target->fd, target);
			poller_disable_write(el->poller, client->fd, client);
		} else {
			tcp_connection_move_txbuf(client, (size_t)tx);
		}
		return 0;
	} else {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return 0;
		} else {
			return -1;
		}
	}
}

static int recvfrom_target_cb(struct el *el, struct tcp_connection *target)
{
	struct tcp_connection *client = target->peer_tcp_conn;

	while (1) {
		char buf[4096];
		ssize_t rx = recv(target->fd, buf, sizeof(buf), 0);
		if (fast(rx > 0)) {
			tcp_connection_append_rxbuf(target, buf, (size_t)rx);
		} else if (rx < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				break;
			} else {
				break;
			}
		} else {
			break;
		}
	}

	if (slow(target->rxbuf_length == 0))
		return -1;

	char *ciphertext;
	int ciphertext_len;
	ciphertext_len = cryptor.encrypt(&cryptor, &ciphertext,
					 target->rxbuf, (unsigned int)target->rxbuf_length);

	if (ciphertext_len < 0) {
		ERROR("Encryption failure.");
		return -1;
	}

	tcp_connection_append_txbuf(client, (char *)&ciphertext_len, 4);
	tcp_connection_append_txbuf(client, ciphertext, (size_t)ciphertext_len);
	tcp_connection_reset_rxbuf(target);
	free(ciphertext);

	ssize_t tx = send(client->fd, client->txbuf, client->txbuf_length, 0);

	if (fast(tx > 0)) {
		if ((size_t)tx == client->txbuf_length) {
			tcp_connection_reset_txbuf(client);
		} else {
			poller_disable_read(el->poller, target->fd, target);
			poller_enable_write(el->poller, client->fd, client);
			tcp_connection_move_txbuf(client, (size_t)tx);
		}
		return 0;
	} else {
		return -1;
	}
}

static int sendto_target_cb(struct el *el, struct tcp_connection *target)
{
	struct tcp_connection *client = target->peer_tcp_conn;
	ssize_t tx = send(target->fd, target->txbuf, target->txbuf_length, 0);

	if (fast(tx > 0)) {
		if ((size_t)tx == target->txbuf_length) {
			poller_enable_read(el->poller, client->fd, client);
			tcp_connection_reset_txbuf(target);
		} else {
			tcp_connection_move_txbuf(target, (size_t)tx);
		}
		return 0;
	} else {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return 0;
		} else {
			return -1;
		}
	}
}

static void usage(void) {
	printf("Usage:\n");
	printf("    remote-xproxy\n");
	printf("        -c <config>           Use configure file to start.\n");
	printf("        -b <local-address>    Local address to bind: 127.0.0.1 or 0.0.0.0.\n");
	printf("        -l <local-port>       Port number for listen.\n");
	printf("        -k <password>         Password.\n");
	printf("        [-e <method>]         Cipher suite: aes-128-cfb, aes-192-cfb, aes-256-cfb.\n");
	printf("        [-t <nthread>         I/O thread number. Defaults to 8.\n");
	printf("        [-m <max-open-files>  Max open files number. Defaults to 1024.\n");
	printf("        [-v]                  Print version and quit.\n");
	printf("        [-h]                  Print this message and quit.\n");
	exit(-1);
}

int main(int argc, char **argv)
{
	int ch;
	int bflag = 0;
	int lflag = 0;
	int kflag = 0;
	int vflag = 0;  /* version */
	int cflag = 0;
	int hflag = 0;

	const char *conf_file;

	cfg_load_defaults(cfg_opts);

	while ((ch = getopt(argc, argv, "b:l:k:e:t:m:c:vVh")) != -1) {
		switch (ch) {
		case 'b':
			bflag = 1;
			configuration.local_addr = optarg;
			break;

		case 'l':
			lflag = 1;
			configuration.local_port = atoi(optarg);
			break;

		case 'k':
			kflag = 1;
			configuration.password = optarg;
			break;

		case 'e':
			configuration.method = optarg;
			break;

		case 't':
			configuration.nthread = atoi(optarg);
			break;

		case 'm':
			configuration.maxfiles = atoi(optarg);
			break;

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
		printf("xproxy, version %s\n", xproxy_version());
		return 0;
	}

	if (hflag)
		usage();

	/* We load the config file first. */
	if (cflag) {
		cfg_load_file(conf_file, cfg_opts);
	} else {
		if (!bflag || !lflag || !kflag)
			usage();
	}

	signals_init();
	coredump_init();
	crypt_setup();

	if (cryptor_init(&cryptor, configuration.method, configuration.password) == -1) {
		ERROR("Unsupport method: %s.", configuration.method);
		return -1;
	}

	int sfd;
	struct xproxy *xproxy;

	if (openfiles_init(configuration.maxfiles) != 0) {
		FATAL("Set max open files to %d failed: %s.",
		      configuration.maxfiles, strerror(errno));
	}

	sfd = listen_and_bind(configuration.local_addr, configuration.local_port);
	if (sfd < 0) {
		FATAL("listen_and_bind(): %s", strerror(errno));
	}

	INFO("Listening on port %d.", configuration.local_port);

	xproxy = xproxy_new(sfd, configuration.nthread, accept_cb);
	xproxy_loop(xproxy, 1000);

	cryptor_deinit(&cryptor);
	close(sfd);
	xproxy_free(xproxy);
	crypt_cleanup();

        return 0;
}

