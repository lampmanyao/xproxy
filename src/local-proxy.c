#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
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
static int recvfrom_remote_cb(struct el *el, struct tcp_connection *tcp_conn);
static int sendto_remote_cb(struct el *el, struct tcp_connection *tcp_conn);

static struct cryptor cryptor;

struct local_config {
	char *password;
	char *method;
	char *local_addr;
	int local_port;
	char *remote_addr;
	int remote_port;
	int nthread;
	int maxfiles;
	int verbose;
} configuration;

struct cfgopts cfg_opts[] = {
	{ "password", TYP_STRING, &configuration.password, {0, "helloworld"} },
	{ "method", TYP_STRING, &configuration.method, {0, "aes-256-cfb"} },
	{ "local_addr", TYP_STRING, &configuration.local_addr, {0, "127.0.0.1"} },
	{ "local_port", TYP_INT4, &configuration.local_port, {1080, NULL} },
	{ "remote_addr", TYP_STRING, &configuration.remote_addr, {0, NULL} },
	{ "remote_port", TYP_INT4, &configuration.remote_port, {0, NULL} },
	{ "nthread", TYP_INT4, &configuration.nthread, {8, NULL} },
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
		if (errno != EAGAIN && errno != EWOULDBLOCK)
			ERROR("accept(): %s", strerror(errno));
	}
}

static int client_exchange_method(struct tcp_connection *client)
{
	char *data = client->rxbuf;
	size_t data_len = client->rxbuf_length;
	int8_t version, nmethods, methods;
	char *txbuf;
	size_t txbuf_len;
	ssize_t tx;

	if (slow(data_len <= 2))
		return 0;

	version = data[0];
	nmethods = data[1];
	methods = data[2];

	if (slow(version != SOCKS5_VER)) {
		ERROR("Unsupport version: %d.", version);
		return -1;
	}

	if (slow(data_len < (size_t)(nmethods + 2)))
		return 0;

	tcp_connection_reset_rxbuf(client);

	tcp_connection_append_txbuf(client, (char *)&version, 1);
	tcp_connection_append_txbuf(client, (char *)&methods, 1);

	txbuf = client->txbuf;
	txbuf_len = client->txbuf_length;

	tx = send(client->fd, txbuf, txbuf_len, 0);

	if (fast(tx > 0)) {
		tcp_connection_reset_txbuf(client);
		client->stage = SOCKS5_STAGE_EXCHG_HOST;
		return 0;
	} else {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return 0;
		return -1;
	}
}

static int client_exchange_host(struct el *el, struct tcp_connection *client)
{
	struct tcp_connection *remote;
	char *data = client->rxbuf;
	size_t data_len = client->rxbuf_length;

	char *ciphertext;
	int8_t version, cmd, atyp;

	if (slow(data_len < SOCKS5_REQ_HEAD_SIZE))
		return 0;

	version = data[0];
	cmd = data[1];
	atyp = data[3];

	if (slow(version != SOCKS5_VER)) {
		ERROR("Unsupport version: %d.", version);
		return -1;
	}

	if (slow(cmd != SOCKS5_CMD_CONNECT)) {
		ERROR("Unsupport command: %d.", cmd);
		return -1;
	}

	if (atyp == SOCKS5_ATYP_IPv4) {
		if (slow(data_len < SOCKS5_IPV4_REQ_SIZE))
			return 0;

		char ipv4[32];
		uint16_t nport;
		char request[512];
		int fd;

		if (!inet_ntop(AF_INET, data + 4, ipv4, INET_ADDRSTRLEN)) {
			ERROR("inet_ntop(): %s", strerror(errno));
			return -1;
		}

		memcpy(&nport, data + SOCKS5_REQ_HEAD_SIZE + 4, 2);
		fd = connect_with_timeout(configuration.remote_addr, configuration.remote_port, 3000);
		if (slow(fd < 0)) {
			ERROR("connect to remote host failed: %s", strerror(errno));
			return -1;
		} else if (fd == 0) {
			ERROR("connect to remote host timeout");
			return -1;
		}

		INFO("Connected to remote-proxy (%s).", configuration.remote_addr);

		remote = new_tcp_connection(fd, 4096, recvfrom_remote_cb, sendto_remote_cb);
		el_watch(el, remote);

		memcpy(client->host, ipv4, strlen(ipv4));
		client->host[strlen(ipv4)] = '\0';

		memcpy(remote->host, ipv4, strlen(ipv4));
		remote->host[strlen(ipv4)] = '\0';
		remote->peer_tcp_conn = client;
		client->peer_tcp_conn = remote;

		memcpy(request, data, SOCKS5_IPV4_REQ_SIZE);

		int ciphertext_len = cryptor.encrypt(&cryptor, &ciphertext, request, SOCKS5_IPV4_REQ_SIZE);
		if (ciphertext_len < 0) {
			ERROR("Encryption failure.");
			return -1;
		}

		tcp_connection_reset_rxbuf(client);

		client->stage = SOCKS5_STAGE_STREAM;
		remote->stage = SOCKS5_STAGE_EXCHG_HOST;

		tcp_connection_append_txbuf(remote, (char*)&ciphertext_len, 4);
		tcp_connection_append_txbuf(remote, ciphertext, (size_t)ciphertext_len);

		goto forword_to_remote;
	} else if (atyp == SOCKS5_ATYP_DONAME) {
		uint8_t domain_name_len;
		char domain_name[256];
		uint16_t nport;
		char request[515];
		unsigned int req_len;
		int fd;

		domain_name_len = (uint8_t)data[SOCKS5_REQ_HEAD_SIZE];
		req_len = SOCKS5_REQ_HEAD_SIZE + 1 + domain_name_len + SOCKS5_PORT_SIZE;

		if (slow(data_len < (size_t)req_len))
			return 0;

		memcpy(domain_name, data + SOCKS5_REQ_HEAD_SIZE + 1, domain_name_len);
		domain_name[domain_name_len] = '\0';

		memcpy(&nport,
		       data + SOCKS5_REQ_HEAD_SIZE + 1 + domain_name_len,
		       SOCKS5_PORT_SIZE);

		fd = connect_with_timeout(configuration.remote_addr, configuration.remote_port, 3000);

		if (fd < 0) {
			ERROR("Connect to remote host failure: %s.", strerror(errno));
			return -1;
		} else if (fd == 0) {
			ERROR("Connect to remote host timeout.");
			return -1;
		}

		INFO("Connected to remote-proxy (%s).", configuration.remote_addr);

		remote = new_tcp_connection(fd, 4096, recvfrom_remote_cb, sendto_remote_cb);
		el_watch(el, remote);

		memcpy(client->host, domain_name, domain_name_len);
		client->host[domain_name_len] = '\0';
		memcpy(remote->host, domain_name, domain_name_len);
		remote->host[domain_name_len] = '\0';

		remote->peer_tcp_conn = client;
		client->peer_tcp_conn = remote;

		memcpy(request, data, req_len);

		int ciphertext_len = cryptor.encrypt(&cryptor, &ciphertext, request, req_len);

		if (ciphertext_len < 0) {
			ERROR("Encryption failure.");
			return -1;
		}

		tcp_connection_reset_rxbuf(client);

		remote->stage = SOCKS5_STAGE_EXCHG_HOST;
		client->stage = SOCKS5_STAGE_EXCHG_HOST;

		tcp_connection_append_txbuf(remote, (char *)&ciphertext_len, 4);
		tcp_connection_append_txbuf(remote, ciphertext, (size_t)ciphertext_len);

		goto forword_to_remote;
	} else if (atyp == SOCKS5_ATYP_IPv6) {
		/* TODO: support IPv6 */
		ERROR("Unsupport IPv6.");
		return -1;
	} else {
		ERROR("Unknown address type.");
		return -1;
	}

forword_to_remote:
	free(ciphertext);
	ssize_t tx = send(remote->fd, remote->txbuf, remote->txbuf_length, 0);

	if (fast(tx > 0)) {
		if ((size_t)tx == remote->txbuf_length) {
			tcp_connection_reset_txbuf(remote);
		} else {
			poller_disable_read(el->poller, client->fd, client);
			poller_enable_write(el->poller, remote->fd, remote);
			tcp_connection_move_txbuf(remote, (size_t)tx);
		}
		return 0;
	} else {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			poller_disable_read(el->poller, client->fd, client);
			poller_enable_write(el->poller, remote->fd, remote);
			return 0;
		} else {
			return -1;
		}
	}
}

static int client_stream_to_remote(struct el *el, struct tcp_connection *client,
				   struct tcp_connection *remote)
{
	char *ciphertext;
	int ciphertext_len;
	ciphertext_len = cryptor.encrypt(&cryptor, &ciphertext,
					 client->rxbuf, (unsigned int)client->rxbuf_length);

	if (ciphertext_len < 0) {
		ERROR("Encryption failuer.");
		return -1;
	}

	tcp_connection_append_txbuf(remote, (char*)&ciphertext_len, 4);
	tcp_connection_append_txbuf(remote, ciphertext, (size_t)ciphertext_len);

	tcp_connection_reset_rxbuf(client);
	free(ciphertext);

	ssize_t tx = send(remote->fd, remote->txbuf, remote->txbuf_length, 0);

	if (fast(tx > 0)) {
		if ((size_t)tx == remote->txbuf_length) {
			tcp_connection_reset_txbuf(remote);
		} else {
			poller_disable_read(el->poller, client->fd, client);
			poller_enable_write(el->poller, remote->fd, remote);
			tcp_connection_move_txbuf(remote, (size_t)tx);
		}
		return 0;
	} else {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			poller_disable_read(el->poller, client->fd, client);
			poller_enable_write(el->poller, remote->fd, remote);
			return 0;
		} else {
			return -1;
		}
	}
}

static int recvfrom_client_cb(struct el *el, struct tcp_connection *client)
{
	int ret = -1;
	struct tcp_connection *remote = NULL;

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
		ret = client_exchange_method(client);
		break;
	
	case SOCKS5_STAGE_EXCHG_HOST:
		ret = client_exchange_host(el, client);
		break;

	case SOCKS5_STAGE_STREAM:
		remote = client->peer_tcp_conn;
		ret = client_stream_to_remote(el, client, remote);
		break;

	default:
		break;
	}

	return ret;
}

static int sendto_client_cb(struct el *el, struct tcp_connection *client)
{
	struct tcp_connection *remote = client->peer_tcp_conn;
	ssize_t tx = send(client->fd, client->txbuf, client->txbuf_length, 0);

	if (fast(tx > 0)) {
		if (fast((size_t)tx == client->txbuf_length)) {
			tcp_connection_reset_txbuf(client);
			poller_enable_read(el->poller, remote->fd, remote);
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

static int remote_exchange_host(struct el *el, struct tcp_connection *remote)
{
	struct tcp_connection *client = remote->peer_tcp_conn;

	char *data = remote->rxbuf;
	size_t data_len = remote->rxbuf_length;

	int ciphertext_len;
	int plaintext_len;
	uint8_t *plaintext;
	uint8_t reply[256];

	if (slow(data_len < 4))
		return 0;

	memcpy((char*)&ciphertext_len, data, 4);

	if (slow(data_len < (size_t)(4 + ciphertext_len)))
		return 0;

	plaintext_len = cryptor.decrypt(&cryptor, (char **)&plaintext, data + 4,
					(unsigned int)ciphertext_len);
	if (plaintext_len < 0) {
		ERROR("Decryption failure.");
		return -1;
	}

	tcp_connection_reset_rxbuf(remote);

	uint8_t ver = plaintext[0];
	uint8_t rsp = plaintext[1];
	uint8_t rsv = plaintext[2];
	uint8_t typ = plaintext[3];

	SHUTUP_WARNING(ver);
	SHUTUP_WARNING(rsp);
	SHUTUP_WARNING(rsv);

	if (typ == SOCKS5_ATYP_IPv4) {
		memcpy(reply, plaintext, 10);
		tcp_connection_append_txbuf(client, (char *)reply, 10);
		goto reply_to_client;
	} else if (typ == SOCKS5_ATYP_DONAME) {
		uint8_t domain_name_len = (uint8_t)plaintext[SOCKS5_RSP_HEAD_SIZE];
		memcpy(reply, plaintext, SOCKS5_RSP_HEAD_SIZE + 1 + domain_name_len + SOCKS5_PORT_SIZE);
		tcp_connection_append_txbuf(client, (char *)reply,
					    SOCKS5_RSP_HEAD_SIZE + 1 + domain_name_len + SOCKS5_PORT_SIZE);
		goto reply_to_client;
	} else if (typ == SOCKS5_ATYP_IPv6) {
		return -1;
	}

reply_to_client:
	free(plaintext);
	char *txbuf = client->txbuf;
	size_t txbuf_len = client->txbuf_length;
	ssize_t tx = send(client->fd, txbuf, txbuf_len, 0);

	if (fast(tx > 0)) {
		tcp_connection_reset_txbuf(client);
		client->stage = SOCKS5_STAGE_STREAM;
		remote->stage = SOCKS5_STAGE_STREAM;
		return 0;
	} else {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			poller_enable_write(el->poller, client->fd, client);
			poller_disable_read(el->poller, remote->fd, remote);
			return 0;
		} else {
			return -1;
		}
	}
}

static int remote_stream_back_to_client(struct el *el, struct tcp_connection *remote)
{
	struct tcp_connection *client = remote->peer_tcp_conn;
	char *data = NULL;
	size_t data_len = 0;
	int ciphertext_len = 0;
	int plaintext_len = 0;
	char *plaintext = NULL;
	ssize_t tx = 0;

try_again:
	data = remote->rxbuf;
	data_len = remote->rxbuf_length;

	if (slow(data_len < 4))
		return 0;

	memcpy((char*)&ciphertext_len, data, 4);

	if (slow(data_len < 4 + (size_t)ciphertext_len))
		return 0;

	plaintext_len = cryptor.decrypt(&cryptor, &plaintext, data + 4,
					(unsigned int)ciphertext_len);
	if (plaintext_len < 0) {
		ERROR("Decryption failure.");
		return -1;
	}

	tcp_connection_append_txbuf(client, plaintext, (size_t)plaintext_len);
	free(plaintext);

	if (data_len == 4 + (size_t)ciphertext_len) {
		tcp_connection_reset_rxbuf(remote);
	} else {
		tcp_connection_move_rxbuf(remote, 4 + (size_t)ciphertext_len);
	}


	tx = send(client->fd, client->txbuf, client->txbuf_length, 0);

	if (fast(tx > 0)) {
		if ((size_t)tx == client->txbuf_length) {
			tcp_connection_reset_txbuf(client);
			goto try_again;
		} else {
			poller_disable_read(el->poller, remote->fd, remote);
			poller_enable_write(el->poller, client->fd, client);
			tcp_connection_move_txbuf(client, (size_t)tx);
		}
		return 0;
	} else {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			poller_disable_read(el->poller, remote->fd, remote);
			poller_enable_write(el->poller, client->fd, client);
			return 0;
		} else {
			return -1;
		}
	}
}

static int recvfrom_remote_cb(struct el *el, struct tcp_connection *remote)
{
	int ret = -1;
	while (1) {
		char buf[4096];
		ssize_t rx = recv(remote->fd, buf, sizeof(buf), 0);
		if (fast(rx > 0)) {
			tcp_connection_append_rxbuf(remote, buf, (size_t)rx);
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

	if (slow(remote->rxbuf_length == 0))
		return -1;

	switch (remote->stage) {
	case SOCKS5_STAGE_EXCHG_HOST:
		ret = remote_exchange_host(el, remote);
		break;

	case SOCKS5_STAGE_STREAM:
		ret = remote_stream_back_to_client(el, remote);
		break;

	default:
		ret = -1;
		break;
	}

	return ret;
}

static int sendto_remote_cb(struct el *el, struct tcp_connection *remote)
{
	struct tcp_connection *client = remote->peer_tcp_conn;
	ssize_t tx = send(remote->fd, remote->txbuf, remote->txbuf_length, 0);

	if (fast(tx > 0)) {
		if ((size_t)tx == remote->txbuf_length) {
			tcp_connection_reset_txbuf(remote);
			poller_enable_read(el->poller, client->fd, client);
		} else {
			tcp_connection_move_txbuf(remote, (size_t)tx);
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

static void usage(void)
{
	printf("Usage:\n");
	printf("    local-xproxy\n");
	printf("        -c <config>           Use configure file to start.\n");
	printf("        -b <local-address>    Local address to bind: 127.0.0.1 or 0.0.0.0.\n");
	printf("        -l <local-port>       Port number for listen.\n");
	printf("        -r <remote-address>   Host name or IP address of remote xproxy.\n");
	printf("        -p <remote-port>      Port number of remote xproxy.\n");
	printf("        -k <password>         Password.\n");
	printf("        [-e <method>]         Cipher suite: aes-128-cfb, aes-192-cfb, aes-256-cfb.\n");
	printf("        [-t <nthread>         I/O thread number. Defaults to 8.\n");
	printf("        [-m <max-open-files>  Max open files number. Defaults to 1024.\n");
	printf("        [-v]                  Print version info and quit.\n");
	printf("        [-h]                  Print this message and quit.\n");
	exit(-1);
}

int main(int argc, char **argv)
{
	int ch;
	int bflag = 0;
	int lflag = 0;
	int rflag = 0;
	int pflag = 0;
	int kflag = 0;
	int vflag = 0;  /* version */
	int cflag = 0;
	int hflag = 0;

	const char *conf_file;

	cfg_load_defaults(cfg_opts);

	while ((ch = getopt(argc, argv, "b:l:r:p:k:e:t:m:c:vh")) != -1) {
		switch (ch) {
		case 'b':
			bflag = 1;
			configuration.local_addr = optarg;
			break;

		case 'l':
			lflag = 1;
			configuration.local_port = atoi(optarg);
			break;

		case 'r':
			rflag = 1;
			configuration.remote_addr = optarg;
			break;

		case 'p':
			pflag = 1;
			configuration.remote_port = atoi(optarg);
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

	/*  We load the config file first. */
	if (cflag) {
		cfg_load_file(conf_file, cfg_opts);
	} else {
		if (!bflag || !lflag || !rflag || !pflag || !kflag)
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
		FATAL("set max open files to %d failed: %s.",
		      configuration.maxfiles, strerror(errno));
	}

	sfd = listen_and_bind(configuration.local_addr, configuration.local_port);
	if (sfd < 0)
		FATAL("listen_and_bind(): %s.", strerror(errno));

	INFO("Listening on port %d.", configuration.local_port);

	xproxy = xproxy_new(sfd, configuration.nthread, accept_cb);
	xproxy_loop(xproxy, -1);

	cryptor_deinit(&cryptor);
	close(sfd);
	xproxy_free(xproxy);
	crypt_cleanup();

        return 0;
}

