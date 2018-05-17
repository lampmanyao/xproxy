#include "libcsnet.h"

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>

#define RANDOM_SIZE sizeof(int64_t)

static int client_handler(struct csnet_socket* client_sock, int state, char* data, int data_len);
static int remote_handler(struct csnet_socket* remote_sock, int state, char* data, int data_len);

struct csnet_log* LOG = NULL;
struct cs_lfqueue* Q = NULL;
struct csnet_conntor* CONNTOR = NULL;
char* remote_host;
int remote_port;
char* passwd;

int
business_init(struct csnet_conntor* conntor, struct cs_lfqueue* q,
	      struct csnet_log* log, struct csnet_config* config) {
	CONNTOR = conntor;
	LOG = log;
	Q = q;

	rand();

	char* host = csnet_config_find(config, "remote_host", strlen("remote_host"));
	char* port = csnet_config_find(config, "remote_port", strlen("remote_port"));
	passwd = csnet_config_find(config, "password", strlen("password"));

	if (!host) {
		log_fatal(LOG, "cant find `remote_host` in config file");
	}

	if (!port) {
		log_fatal(LOG, "cant find `remote_port` in config file");
	}

	if (!passwd) {
		log_fatal(LOG, "cant find `password` in config file");
	}

	remote_host = host;
	remote_port = atoi(port);

	csnet_crypt_set_iv(passwd);

	log_info(log, "business init done ...");

	return 0;
}

void
business_term(void) {

}

int
business_entry(struct csnet_socket* socket, int state, char* data, int data_len) {
	if (socket->type == BTGFW_CLIENT) {
		return client_handler(socket, state, data, data_len);
	} else {
		return remote_handler(socket, state, data, data_len);
	}
}

static int
client_handler(struct csnet_socket* client_sock, int state, char* data, int data_len) {
	int ret = 0;

	switch (state) {
	case SOCKS5_ST_EXMETHOD: {
		if (csnet_slow(data_len <= 2)) {
			log_debug(LOG, "not complete data, wait for more");
			ret = 0;
			break;
		}

		int8_t ver = data[0];
		int8_t nmethods = data[1];

		if (csnet_slow(ver != SOCKS5_VER)) {
			log_error(LOG, "not socks5, close connection");
			ret = -1;
			break;
		}

		if (csnet_slow(data_len < nmethods + 2)) {
			log_debug(LOG, "not complete data, wait for more");
			ret = 0;
			break;
		}

		/*
		 * FIXME:
		 *   We don't follow the Socks Protocol Version 5 spec here,
		 *   because we know that we setup a system-wide Socks5
		 *   proxy setting without authentication.
		 *   More details here is: nmethods is XX'01' and methods[0]
		 *   is XX'00'. We just reply two bytes XX'05' and XX'00' to
		 *   the client.
		 */

		int8_t methods = data[2];

		struct csnet_msg* msg = csnet_msg_new(2, client_sock);
		csnet_msg_append(msg, (char*)&ver, 1);
		csnet_msg_append(msg, (char*)&methods, 1);
		csnet_sendto(Q, msg);

		client_sock->state = SOCKS5_ST_EXHOST;
		ret = 2 + nmethods;
		break;
	}

	case SOCKS5_ST_EXHOST: {
		if (csnet_slow(data_len < SOCKS5_REQ_HEAD_SIZE)) {
			log_debug(LOG, "not comlete data, wait for more");
			ret = 0;
			break;
		}

		int8_t ver = data[0];
		int8_t cmd = data[1];
		int8_t rsv = data[2];
		int8_t atyp = data[3];

		if (csnet_slow(ver != SOCKS5_VER)) {
			log_error(LOG, "not socks5, close connection");
			ret = -1;
			break;
		}

		if (cmd != SOCKS5_CMD_CONNECT) {
			log_error(LOG, "only support CMD: connect");
			ret = -1;
			break;
		}

		if (atyp == SOCKS5_ATYP_IPv4) {
			if (data_len < SOCKS5_IPV4_REQ_SIZE) {
				log_debug(LOG, "not comlete data, wait for more");
				ret = 0;
				break;
			}

			char ipv4[32];
			uint16_t nport;
			char request[512];
			struct csnet_socket* remote_sock;

			uint8_t p0 = data[4];
			uint8_t p1 = data[5];
			uint8_t p2 = data[6];
			uint8_t p3 = data[7];

			int ipv4_str_len = sprintf(ipv4, "%d.%d.%d.%d", p0, p1, p2, p3);
			memcpy(&nport, data + SOCKS5_REQ_HEAD_SIZE + 4, 2);

			remote_sock = csnet_conntor_connectto(CONNTOR,
							      remote_host,
							      remote_port);
			if (!remote_sock) {
				log_error(LOG, "failed to connect remote server");
				ret = -1;
				break;
			}

			memcpy(client_sock->host, ipv4, ipv4_str_len);
			client_sock->host[ipv4_str_len] = '\0';
			memcpy(remote_sock->host, ipv4, ipv4_str_len);
			remote_sock->host[ipv4_str_len] = '\0';
			remote_sock->sock = client_sock;
			client_sock->sock = remote_sock;

			int64_t randnum = random();

			memcpy(request, &randnum, RANDOM_SIZE);
			memcpy(request + RANDOM_SIZE, data, SOCKS5_IPV4_REQ_SIZE);

			char* cipher_data;
			int cipher_data_len = csnet_128cfb_encrypt(&cipher_data,
								   request,
								   SOCKS5_IPV4_REQ_SIZE + RANDOM_SIZE,
								   passwd);
			if (cipher_data_len < 0) {
				log_error(LOG, "encrypt error");
				ret = -1;
			}

			struct csnet_msg* msg = csnet_msg_new(4 + cipher_data_len,
							      remote_sock);
			csnet_msg_append(msg, (char*)&cipher_data_len, 4);
			csnet_msg_append(msg, cipher_data, cipher_data_len);
			csnet_sendto(Q, msg);

			free(cipher_data);

			client_sock->state = SOCKS5_ST_STREAMING;
			remote_sock->state = SOCKS5_ST_EXHOST;

			ret = SOCKS5_IPV4_REQ_SIZE;
		} else if (atyp == SOCKS5_ATYP_DONAME) {
			int8_t domain_name_len;
			char domain_name[256];
			uint16_t nport;
			char request[515];
			struct csnet_socket* remote_sock;
			int exhost_data_len;

			domain_name_len = data[SOCKS5_REQ_HEAD_SIZE];

			exhost_data_len = SOCKS5_REQ_HEAD_SIZE + 1 + domain_name_len + SOCKS5_PORT_SIZE;

			if (data_len < exhost_data_len) {
				log_debug(LOG, "not complete data, wait for more");
				ret = 0;
				break;
			}

			memcpy(domain_name, data + SOCKS5_REQ_HEAD_SIZE + 1, domain_name_len);
			domain_name[domain_name_len] = '\0';

			memcpy(&nport,
			       data + SOCKS5_REQ_HEAD_SIZE + 1 + domain_name_len,
			       SOCKS5_PORT_SIZE);

			remote_sock = csnet_conntor_connectto(CONNTOR,
							      remote_host,
							      remote_port);
			if (!remote_sock) {
				ret = -1;
				break;
			}

			memcpy(client_sock->host, domain_name, domain_name_len);
			client_sock->host[domain_name_len] = '\0';
			memcpy(remote_sock->host, domain_name, domain_name_len);
			remote_sock->host[domain_name_len] = '\0';

			log_debug(LOG, "exhost: socket %d ---> socket %d (%s)",
				  client_sock->fd, remote_sock->fd, domain_name);

			remote_sock->sock = client_sock;
			client_sock->sock = remote_sock;

			int64_t randnum = random();
			memcpy(request, &randnum, RANDOM_SIZE);
			memcpy(request + RANDOM_SIZE, data, exhost_data_len);

			char* cipher_data;
			int cipher_data_len = csnet_128cfb_encrypt(&cipher_data,
								   request,
								   exhost_data_len + RANDOM_SIZE,
								   passwd);
			if (cipher_data_len < 0) {
				log_error(LOG, "encrypt error. socket %d ---> socket %d (%s)",
					  client_sock->fd, remote_sock->fd, domain_name);
				ret = -1;
				break;
			}

			struct csnet_msg* msg = csnet_msg_new(4 + cipher_data_len, remote_sock);
			csnet_msg_append(msg, (char*)&cipher_data_len, 4);
			csnet_msg_append(msg, cipher_data, cipher_data_len);
			csnet_sendto(Q, msg);

			free(cipher_data);

			remote_sock->state = SOCKS5_ST_EXHOST;
			client_sock->state = SOCKS5_ST_STREAMING;
			ret = exhost_data_len;
		} else if (atyp == SOCKS5_ATYP_IPv6) {
			log_debug(LOG, "address type is IPv6, not support yet");
			ret = -1;
		} else {
			log_error(LOG, "unknown address type: %d, close connection", atyp);
			ret = -1;
		}
		break;
	}

	case SOCKS5_ST_STREAMING: {
		struct csnet_socket* remote_sock = client_sock->sock;
		struct csnet_msg* msg;
		msg = csnet_msg_new(data_len, remote_sock);
		csnet_msg_append(msg, data, data_len);
		csnet_sendto(Q, msg);

		log_debug(LOG, "streaming: socket %d ---> socket %d (%s)",
			  client_sock->fd, remote_sock->fd, remote_sock->host);

		ret = data_len;
		break;
	}

	default:
		log_warn(LOG, "unknown state: %d", state);
		ret = -1;
		break;
	}

	log_debug(LOG, "socket %d, recv %d bytes, handle %d bytes, remains %d bytes",
		  client_sock->fd, data_len, ret, data_len - ret);

	return ret;
}

static int
remote_handler(struct csnet_socket* remote_sock, int state, char* data, int data_len) {
	int ret = 0;
	struct csnet_socket* client_sock = remote_sock->sock;

	switch (state) {
	case SOCKS5_ST_EXHOST: {
		int cipher_data_len;
		int plain_data_len;
		char* plain_data;
		char reply[256];
		struct csnet_msg* msg;

		if (data_len < 4) {
			log_debug(LOG, "not complete data, wait for more");
			ret = 0;
			break;
		}

		memcpy((char*)&cipher_data_len, data, 4);

		if (data_len < 4 + cipher_data_len) {
			log_debug(LOG, "not complete data, wait for more");
			ret = 0;
			break;
		}

		plain_data_len = csnet_128cfb_decrypt(&plain_data,
						      data + 4,
						      cipher_data_len,
						      passwd);
		if (plain_data_len < 0) {
			log_error(LOG, "decrypt error. exhost: %d <--- socket %d (%s)",
				  client_sock->fd, remote_sock->fd, remote_sock->host);
			ret = -1;
			break;
		}

		uint8_t ver = plain_data[0 + RANDOM_SIZE];
		uint8_t rsp = plain_data[1 + RANDOM_SIZE];
		uint8_t rsv = plain_data[2 + RANDOM_SIZE];
		uint8_t typ = plain_data[3 + RANDOM_SIZE];

		if (typ == SOCKS5_ATYP_IPv4) {
			memcpy(reply, plain_data + RANDOM_SIZE, 10);
			msg = csnet_msg_new(10, client_sock);
			csnet_msg_append(msg, reply, 10);
			csnet_sendto(Q, msg);
		} else if (typ == SOCKS5_ATYP_DONAME) {
			uint8_t domain_name_len = plain_data[SOCKS5_RSP_HEAD_SIZE + RANDOM_SIZE];
			ret = SOCKS5_RSP_HEAD_SIZE + 1 + domain_name_len + SOCKS5_PORT_SIZE;
			memcpy(reply, plain_data + RANDOM_SIZE, ret);
			msg = csnet_msg_new(ret, client_sock);
			csnet_msg_append(msg, reply, ret);
			csnet_sendto(Q, msg);
			log_debug(LOG, "exhost: socket %d <--- socket %d (%s)",
				  client_sock->fd, remote_sock->fd, remote_sock->host);
		} else if (typ == SOCKS5_ATYP_IPv6) {
			ret = -1;
			break;
		}

		free(plain_data);

		client_sock->state = SOCKS5_ST_STREAMING;
		remote_sock->state = SOCKS5_ST_STREAMING;
		ret = 4 + cipher_data_len;
 		break;
	}

	case SOCKS5_ST_STREAMING: {
		struct csnet_msg* msg;
		msg = csnet_msg_new(data_len, client_sock);
		csnet_msg_append(msg, data, data_len);
		csnet_sendto(Q, msg);

		log_debug(LOG, "streaming: socket %d <--- socket %d (%s)",
			  client_sock->fd, remote_sock->fd, remote_sock->host);
		ret = data_len;
		break;
	}

	default:
		ret = -1;
		break;
	}

	log_debug(LOG, "socket %d, recv %d bytes, handle %d bytes, remains %d bytes",
		  remote_sock->fd, data_len, ret, data_len - ret);

	return ret;
}

