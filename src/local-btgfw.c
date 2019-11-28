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
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static void accept_cb(struct btgfw *btgfw, int lfd);
static int recvfrom_client_cb(struct el *el, struct tcp_connection *tcp_conn);
static int sendto_client_cb(struct el *el, struct tcp_connection *tcp_conn);
static int recvfrom_remote_cb(struct el *el, struct tcp_connection *tcp_conn);
static int sendto_remote_cb(struct el *el, struct tcp_connection *tcp_conn);

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

static struct cryptor cryptor;

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
		INFO("accept incoming from %s:%d with client %d",
		      inet_ntoa(sock_addr.sin_addr), ntohs(sock_addr.sin_port), fd);

		set_nonblocking(fd);
		tcp_conn = new_tcp_connection(fd, 8192, recvfrom_client_cb, sendto_client_cb);
		el_watch(btgfw->els[fd % btgfw->nthread], tcp_conn);
	} else {
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			ERROR("accept(): %s", strerror(errno));
		}
	}
}

static int
client_exchange_method(struct el *el, struct tcp_connection *client)
{
	char *data = client->rbuf;
	size_t dlen = client->rbuf_len;
	int8_t version, nmethods, methods;
	char *sbuf;
	size_t sbuf_len;
	ssize_t s;

	if (slow(dlen <= 2)) {
		return 0;
	}

	version = data[0];
	nmethods = data[1];
	methods = data[2];

	if (slow(version != SOCKS5_VER)) {
		ERROR("unsupport version: %d", version);
		return -1;
	}

	if (slow(dlen < (size_t)(nmethods + 2))) {
		return 0;
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
		return 0;
	} else if (s == 0) {
		return -1;
	} else {
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			return -1;
		}
		return 0;
	}
}

static int
client_exchange_host(struct el *el, struct tcp_connection *client)
{
	struct tcp_connection *remote;
	char *data = client->rbuf;
	size_t dlen = client->rbuf_len;

	char *ciphertext;
	int8_t version, cmd, atyp;

	if (slow(dlen < SOCKS5_REQ_HEAD_SIZE)) {
		return 0;
	}

	version = data[0];
	cmd = data[1];
	atyp = data[3];

	if (slow(version != SOCKS5_VER)) {
		ERROR("unsupport version: %d", version);
		return -1;
	}

	if (slow(cmd != SOCKS5_CMD_CONNECT)) {
		ERROR("unsupport command: %d", cmd);
		return -1;
	}

	if (atyp == SOCKS5_ATYP_IPv4) {
		if (slow(dlen < SOCKS5_IPV4_REQ_SIZE)) {
			return 0;
		}

		char ipv4[32];
		uint16_t nport;
		char request[512];
		int fd;

		if (!inet_ntop(AF_INET, data + 4, ipv4, INET_ADDRSTRLEN)) {
			ERROR("inet_ntop(): %s", strerror(errno));
			return -1;
		}

		memcpy(&nport, data + SOCKS5_REQ_HEAD_SIZE + 4, 2);

		fd = connect_with_timeout(configuration.remote_addr, configuration.remote_port, 1000);
		if (slow(fd < 0)) {
			ERROR("connect to remote host failed.");
			return -1;
		}

		INFO("client %d connected to remote %d", client->fd, fd);

		set_nonblocking(fd);
		remote = new_tcp_connection(fd, 8192, recvfrom_remote_cb, sendto_remote_cb);
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
			ERROR("encryption failure.");
			return -1;
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
		unsigned int req_len;
		int fd;

		domain_name_len = (uint8_t)data[SOCKS5_REQ_HEAD_SIZE];
		req_len = SOCKS5_REQ_HEAD_SIZE + 1 + domain_name_len + SOCKS5_PORT_SIZE;

		if (slow(dlen < (size_t)req_len)) {
			return 0;
		}

		memcpy(domain_name, data + SOCKS5_REQ_HEAD_SIZE + 1, domain_name_len);
		domain_name[domain_name_len] = '\0';

		memcpy(&nport,
		       data + SOCKS5_REQ_HEAD_SIZE + 1 + domain_name_len,
		       SOCKS5_PORT_SIZE);

		fd = connect_with_timeout(configuration.remote_addr, configuration.remote_port, 1000);

		if (fd < 0) {
			ERROR("exchg host: connect to remote host failure");
			return -1;
		}

		set_nonblocking(fd);
		remote = new_tcp_connection(fd, 8192, recvfrom_remote_cb, sendto_remote_cb);
		el_watch(el, remote);

		memcpy(client->host, domain_name, domain_name_len);
		client->host[domain_name_len] = '\0';
		memcpy(remote->host, domain_name, domain_name_len);
		remote->host[domain_name_len] = '\0';

		INFO("client %d connected to remote %d (%s)", client->fd, fd, remote->host);

		remote->peer_tcp_conn = client;
		client->peer_tcp_conn = remote;

		memcpy(request, data, req_len);

		int ciphertext_len = cryptor.encrypt(&cryptor, &ciphertext, request, req_len);

		if (ciphertext_len < 0) {
			ERROR("encryption failed.");
			return -1;
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
		return -1;
	} else {
		ERROR("unknown address type");
		return -1;
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
		return 0;
	} else if (s == 0) {
		return -1;
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

static int
client_stream_to_remote(struct el *el, struct tcp_connection *client,
			struct tcp_connection *remote)
{
	if (!remote) return -1;

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
		return 0;
	} else if (s == 0) {
		if (configuration.verbose) {
			ERROR("send() error: %s", strerror(errno));
		}
		return -1;
	} else {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			if (configuration.verbose) {
				DEBUG("send() busy");
			}

			poller_disable_read(el->poller, client->fd, client);
			poller_enable_write(el->poller, remote->fd, remote);
			return 0;
		} else {
			if (configuration.verbose) {
				ERROR("send() error: %s", strerror(errno));
			}

			return -1;
		}
	}
}

static int
recvfrom_client_cb(struct el *el, struct tcp_connection *client)
{
	int ret = -1;
	struct tcp_connection *remote = NULL;
	size_t need_read = 0;
	char *rbuf = NULL;
	ssize_t r = 0;

	remote = client->peer_tcp_conn;
	need_read = client->rbuf_size - client->rbuf_len;
	rbuf = client->rbuf + client->rbuf_len;

	r = recv(client->fd, rbuf, need_read, 0);

	if (fast(r > 0)) {
		client->rbuf_len += (size_t)r;

		switch (client->stage) {
		case SOCKS5_STAGE_EXCHG_METHOD:
			ret = client_exchange_method(el, client);
			break;
	
		case SOCKS5_STAGE_EXCHG_HOST:
			ret = client_exchange_host(el, client);
			break;

		case SOCKS5_STAGE_STREAM:
			ret = client_stream_to_remote(el, client, remote);
			break;

		default:
			break;
		}
	} else if (r == 0) {
		if (configuration.verbose) {
			ERROR("peer has closed");
		}

		ret = -1;
	} else {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			if (configuration.verbose) {
				DEBUG("recv() busy");
			}
			ret = 0;
		} else {
			if (configuration.verbose) {
				ERROR("recv() error: %s", strerror(errno));
			}

			ret = -1;
		}
	}

	return ret;
}

static int
sendto_client_cb(struct el *el, struct tcp_connection *client)
{
	struct tcp_connection *remote = client->peer_tcp_conn;
	char *sbuf = client->sbuf;
	size_t sbuf_len = client->sbuf_len;

	if (slow(sbuf_len <= 0)) {
		return 0;
	}

	ssize_t s = send(client->fd, sbuf, sbuf_len, 0);

	if (fast(s > 0)) {
		tcp_connection_sbuf_seek(client, (size_t)s);

		if (fast((size_t)s == sbuf_len)) {
			poller_enable_read(el->poller, remote->fd, remote);
			poller_disable_write(el->poller, client->fd, client);
		} else {
			if (configuration.verbose) {
				DEBUG("send() busy");
			}

			poller_disable_read(el->poller, remote->fd, remote);
			poller_enable_write(el->poller, client->fd, client);
		}
		return 0;
	} else if (s == 0) {
		if (configuration.verbose) {
			ERROR("send() error: %s", strerror(errno));
		}

		return -1;
	} else {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			if (configuration.verbose) {
				DEBUG("send() busy");
			}

			poller_disable_read(el->poller, remote->fd, remote);
			poller_enable_write(el->poller, client->fd, client);
			return 0;
		} else {
			if (configuration.verbose) {
				ERROR("send() error: %s", strerror(errno));
			}

			return -1;
		}
	}
}

static int
remote_exchange_host(struct el *el, struct tcp_connection *remote)
{
	struct tcp_connection *client = remote->peer_tcp_conn;

	if (!client) return -1;

	char *data = remote->rbuf;
	size_t dlen = remote->rbuf_len;

	int ciphertext_len;
	int plaintext_len;
	char *plaintext;
	char reply[256];

	if (slow(dlen < 4)) {
		return 0;
	}

	memcpy((char*)&ciphertext_len, data, 4);

	if (slow(dlen < (size_t)(4 + ciphertext_len))) {
		return 0;
	}

	plaintext_len = cryptor.decrypt(&cryptor, &plaintext, data + 4, (unsigned int)ciphertext_len);
	if (plaintext_len < 0) {
		return -1;
	}

	/* skip already handled */
	tcp_connection_rbuf_seek(remote, (size_t)(4 + ciphertext_len));

	uint8_t ver = plaintext[0];
	uint8_t rsp = plaintext[1];
	uint8_t rsv = plaintext[2];
	uint8_t typ = plaintext[3];

	if (typ == SOCKS5_ATYP_IPv4) {
		memcpy(reply, plaintext, 10);
		tcp_connection_sbuf_append(client, reply, 10);
		goto reply_to_client;
	} else if (typ == SOCKS5_ATYP_DONAME) {
		uint8_t domain_name_len = plaintext[SOCKS5_RSP_HEAD_SIZE];
		memcpy(reply, plaintext, SOCKS5_RSP_HEAD_SIZE + 1 + domain_name_len + SOCKS5_PORT_SIZE);
		tcp_connection_sbuf_append(client, reply, SOCKS5_RSP_HEAD_SIZE + 1 + domain_name_len + SOCKS5_PORT_SIZE);
		goto reply_to_client;
	} else if (typ == SOCKS5_ATYP_IPv6) {
		return -1;
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
			if (configuration.verbose) {
				DEBUG("send() busy");
			}

			poller_enable_write(el->poller, client->fd, client);
			poller_disable_read(el->poller, remote->fd, remote);
		} else {
			client->stage = SOCKS5_STAGE_STREAM;
			remote->stage = SOCKS5_STAGE_STREAM;
		}
		return 0;
	} else if (s == 0) {
		if (configuration.verbose) {
			ERROR("send() error: %s", strerror(errno));
		}

		return -1;
	} else {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			if (configuration.verbose) {
				DEBUG("send() busy");
			}

			poller_enable_write(el->poller, client->fd, client);
			poller_disable_read(el->poller, remote->fd, remote);
			return 0;
		} else {
			if (configuration.verbose) {
				ERROR("send() error: %s", strerror(errno));
			}

			return -1;
		}
	}
}

static int
remote_stream_back_to_client(struct el *el, struct tcp_connection *remote)
{
	struct tcp_connection *client = remote->peer_tcp_conn;

	if (!client) return -1;

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
			poller_disable_read(el->poller, remote->fd, remote);
			poller_enable_write(el->poller, client->fd, client);
		} else {
			poller_enable_read(el->poller, remote->fd, remote);
		}
		return 0;
	} else if (s == 0) {
		return -1;
	} else {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			if (configuration.verbose) {
				DEBUG("send() busy");
			}

			poller_disable_read(el->poller, remote->fd, remote);
			poller_enable_write(el->poller, client->fd, client);
			return 0;
		} else {
			if (configuration.verbose) {
				ERROR("send() error: %s", strerror(errno));
			}

			return -1;
		}
	}
}

static int
recvfrom_remote_cb(struct el *el, struct tcp_connection *remote)
{
	int ret;
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
			ret = remote_exchange_host(el, remote);
			break;

		case SOCKS5_STAGE_STREAM:
			ret = remote_stream_back_to_client(el, remote);
			break;

		default:
			ret = -1;
			break;
		}
	} else if (r == 0) {
		if (configuration.verbose) {
			ERROR("peer has closed");
		}

		ret = -1;
	} else {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			if (configuration.verbose) {
				DEBUG("recv() busy");
			}
			ret = 0;
		} else {
			if (configuration.verbose) {
				ERROR("recv() error: %s", strerror(errno));
			}

			ret = -1;
		}
	}

	return ret;
}

static int
sendto_remote_cb(struct el *el, struct tcp_connection *remote)
{
	struct tcp_connection *client = remote->peer_tcp_conn;
	char *sbuf = remote->sbuf;
	size_t sbuf_len = remote->sbuf_len;

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
		return 0;
	} else if (s == 0) {
		if (configuration.verbose) {
			ERROR("send() error: %s", strerror(errno));
		}

		return -1;
	} else {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			if (configuration.verbose) {
				DEBUG("send() busy");
			}

			if (client->closed == 0) {
				poller_enable_read(el->poller, client->fd, client);
			}
			poller_enable_write(el->poller, remote->fd, remote);
			return 0;
		} else {
			if (configuration.verbose) {
				ERROR("send() error: %s", strerror(errno));
			}

			return -1;
		}
	}
}

static void
usage(void)
{
	printf("\nusage:\n");
	printf("    local-btgfw\n");
	printf("        -b <local-address>    Local address to bind: 127.0.0.1 or 0.0.0.0.\n");
	printf("        -l <local-port>       Port number for listen.\n");
	printf("        -r <remote-address>   Host name or IP address of remote btgfw.\n");
	printf("        -p <remote-port>      Port number of remote btgfw.\n");
	printf("        -k <password>         Password.\n");
	printf("        [-e <method>]         Cipher suite: aes-128-cfb, aes-192-cfb, aes-256-cfb.\n");
	printf("        [-t <nthread>         I/O thread number. Default value is 8.\n");
	printf("        [-m <max-open-files>  Max open files number. Default value is 1024.\n");
	printf("        [-v]                  Verbose mode.\n");
	printf("        [-V]                  Version. Print version info.\n");
	printf("        [-h]                  Help. Print this usage.\n");
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
	int Vflag = 0;  /* version */
	int cflag = 0;
	int hflag = 0;

	const char *conf_file;

	config_load_defaults(cfg_opts);

	while ((ch = getopt(argc, argv, "b:l:r:p:k:e:t:m:c:vVh")) != -1) {
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
			configuration.verbose = 1;
			break;

		case 'V':
			Vflag = 1;
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

	if (Vflag) {
		printf("\nbtgfw version: %s\n\n", btgfw_version());
	}

	if (hflag) {
		usage();
	}	

	/*  We load the config file first. */
	if (cflag) {
		config_load_file(conf_file, cfg_opts);
	} else {
		if (!bflag || !lflag || !rflag || !pflag || !kflag) {
			usage();
		}
	}

	signals_init();
	coredump_init();
	crypt_setup();

	if (cryptor_init(&cryptor, configuration.method, configuration.password) == -1) {
		ERROR("unsupport method: %s", configuration.method);
		return -1;
	}

	int sfd;
	struct btgfw *btgfw;

	if (openfiles_init(configuration.maxfiles) != 0) {
		FATAL("set max open files to %d failed: %s",
		      configuration.maxfiles, strerror(errno));
	}

	sfd = listen_and_bind(configuration.local_addr, configuration.local_port);
	if (sfd < 0) {
		FATAL("listen_and_bind(): %s", strerror(errno));
	}

	INFO("Listening on %d", configuration.local_port);

	btgfw = btgfw_new(sfd, configuration.nthread, accept_cb);
	btgfw_loop(btgfw, -1);

	cryptor_deinit(&cryptor);
	close(sfd);
	btgfw_free(btgfw);

        return 0;
}

