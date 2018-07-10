#include "libcsnet.h"

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>

#define RANDOM_SIZE sizeof(int64_t)

static int client_handler(struct csnet_socket* client_sock, int stage, char* data, int len);
static int remote_handler(struct csnet_socket* remote_sock, int stage, char* data, int len);

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
		log_f(LOG, "cant find `remote_host` in config file");
	}

	if (!port) {
		log_f(LOG, "cant find `remote_port` in config file");
	}

	if (!passwd) {
		log_f(LOG, "cant find `password` in config file");
	}

	remote_host = host;
	remote_port = atoi(port);

	csnet_crypt_set_iv(passwd);

	log_i(log, "business init done ...");

	return 0;
}

void
business_term(void) {

}

int
business_entry(struct csnet_socket* socket, int stage, char* data, int len) {
	if (socket->type == BTGFW_CLIENT) {
		return client_handler(socket, stage, data, len);
	} else {
		return remote_handler(socket, stage, data, len);
	}
}

static int
client_handler(struct csnet_socket* client_sock, int stage, char* data, int len) {
	int ret = 0;

	switch (stage) {
	case SOCKS5_STAGE_EXMETHOD: {
		if (csnet_slow(len <= 2)) {
			ret = 0;
			break;
		}

		int8_t ver = data[0];
		int8_t nmethods = data[1];

		if (csnet_slow(ver != SOCKS5_VER)) {
			log_e(LOG, "not socks5, close connection");
			ret = -1;
			break;
		}

		if (csnet_slow(len < nmethods + 2)) {
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

		client_sock->stage = SOCKS5_STAGE_EXHOST;
		ret = 2 + nmethods;
		break;
	}

	case SOCKS5_STAGE_EXHOST: {
		if (csnet_slow(len < SOCKS5_REQ_HEAD_SIZE)) {
			ret = 0;
			break;
		}

		int8_t ver = data[0];
		int8_t cmd = data[1];
		int8_t rsv = data[2];
		int8_t atyp = data[3];

		if (csnet_slow(ver != SOCKS5_VER)) {
			log_e(LOG, "not socks5, close connection");
			ret = -1;
			break;
		}

		if (cmd != SOCKS5_CMD_CONNECT) {
			log_e(LOG, "only support CMD: connect");
			ret = -1;
			break;
		}

		if (atyp == SOCKS5_ATYP_IPv4) {
			if (csnet_slow(len < SOCKS5_IPV4_REQ_SIZE)) {
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
				log_e(LOG, "failed to connect remote server");
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

			char* ciphertext;
			int ciphertext_len = csnet_128cfb_encrypt(&ciphertext,
								   request,
								   SOCKS5_IPV4_REQ_SIZE + RANDOM_SIZE,
								   passwd);
			if (ciphertext_len < 0) {
				log_e(LOG, "encrypt error");
				ret = -1;
			}

			struct csnet_msg* msg = csnet_msg_new(4 + ciphertext_len,
							      remote_sock);
			csnet_msg_append(msg, (char*)&ciphertext_len, 4);
			csnet_msg_append(msg, ciphertext, ciphertext_len);
			csnet_sendto(Q, msg);

			free(ciphertext);

			client_sock->stage = SOCKS5_STAGE_STREAM;
			remote_sock->stage = SOCKS5_STAGE_EXHOST;

			ret = SOCKS5_IPV4_REQ_SIZE;
		} else if (atyp == SOCKS5_ATYP_DONAME) {
			int8_t domain_name_len;
			char domain_name[256];
			uint16_t nport;
			char request[515];
			struct csnet_socket* remote_sock;
			int exhosttext_len;

			domain_name_len = data[SOCKS5_REQ_HEAD_SIZE];

			exhosttext_len = SOCKS5_REQ_HEAD_SIZE + 1 + domain_name_len + SOCKS5_PORT_SIZE;

			if (csnet_slow(len < exhosttext_len)) {
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

			log_d(LOG, "exhost: socket %d >>> socket %d (%s)",
				  client_sock->fd, remote_sock->fd, domain_name);

			remote_sock->sock = client_sock;
			client_sock->sock = remote_sock;

			int64_t randnum = random();
			memcpy(request, &randnum, RANDOM_SIZE);
			memcpy(request + RANDOM_SIZE, data, exhosttext_len);

			char* ciphertext;
			int ciphertext_len = csnet_128cfb_encrypt(&ciphertext,
								   request,
								   exhosttext_len + RANDOM_SIZE,
								   passwd);
			if (ciphertext_len < 0) {
				log_e(LOG, "encrypt error. socket %d >>> socket %d (%s)",
					  client_sock->fd, remote_sock->fd, domain_name);
				ret = -1;
				break;
			}

			struct csnet_msg* msg = csnet_msg_new(4 + ciphertext_len, remote_sock);
			csnet_msg_append(msg, (char*)&ciphertext_len, 4);
			csnet_msg_append(msg, ciphertext, ciphertext_len);
			csnet_sendto(Q, msg);

			free(ciphertext);

			remote_sock->stage = SOCKS5_STAGE_EXHOST;
			client_sock->stage = SOCKS5_STAGE_STREAM;
			ret = exhosttext_len;
		} else if (atyp == SOCKS5_ATYP_IPv6) {
			log_d(LOG, "address type is IPv6, not support yet");
			ret = -1;
		} else {
			log_e(LOG, "unknown address type: %d, close connection", atyp);
			ret = -1;
		}
		break;
	}

	case SOCKS5_STAGE_STREAM: {
		struct csnet_socket* remote_sock = client_sock->sock;
		struct csnet_msg* msg;
		msg = csnet_msg_new(len, remote_sock);
		csnet_msg_append(msg, data, len);
		csnet_sendto(Q, msg);

		log_d(LOG, "stream: socket %d >>> socket %d (%s)",
			  client_sock->fd, remote_sock->fd, remote_sock->host);

		ret = len;
		break;
	}

	default:
		log_w(LOG, "unknown stage: %d", stage);
		ret = -1;
		break;
	}

	return ret;
}

static int
remote_handler(struct csnet_socket* remote_sock, int stage, char* data, int len) {
	int ret = 0;
	struct csnet_socket* client_sock = remote_sock->sock;

	switch (stage) {
	case SOCKS5_STAGE_EXHOST: {
		int ciphertext_len;
		int plaintext_len;
		char* plaintext;
		char reply[256];
		struct csnet_msg* msg;

		if (csnet_slow(len < 4)) {
			ret = 0;
			break;
		}

		memcpy((char*)&ciphertext_len, data, 4);

		if (csnet_slow(len < 4 + ciphertext_len)) {
			ret = 0;
			break;
		}

		plaintext_len = csnet_128cfb_decrypt(&plaintext,
						      data + 4,
						      ciphertext_len,
						      passwd);
		if (plaintext_len < 0) {
			log_e(LOG, "decrypt error. exhost: %d <<< socket %d (%s)",
				  client_sock->fd, remote_sock->fd, remote_sock->host);
			ret = -1;
			break;
		}

		uint8_t ver = plaintext[0 + RANDOM_SIZE];
		uint8_t rsp = plaintext[1 + RANDOM_SIZE];
		uint8_t rsv = plaintext[2 + RANDOM_SIZE];
		uint8_t typ = plaintext[3 + RANDOM_SIZE];

		if (typ == SOCKS5_ATYP_IPv4) {
			memcpy(reply, plaintext + RANDOM_SIZE, 10);
			msg = csnet_msg_new(10, client_sock);
			csnet_msg_append(msg, reply, 10);
			csnet_sendto(Q, msg);
		} else if (typ == SOCKS5_ATYP_DONAME) {
			uint8_t domain_name_len = plaintext[SOCKS5_RSP_HEAD_SIZE + RANDOM_SIZE];
			ret = SOCKS5_RSP_HEAD_SIZE + 1 + domain_name_len + SOCKS5_PORT_SIZE;
			memcpy(reply, plaintext + RANDOM_SIZE, ret);
			msg = csnet_msg_new(ret, client_sock);
			csnet_msg_append(msg, reply, ret);
			csnet_sendto(Q, msg);
			log_d(LOG, "exhost: socket %d <<< socket %d (%s)",
				  client_sock->fd, remote_sock->fd, remote_sock->host);
		} else if (typ == SOCKS5_ATYP_IPv6) {
			ret = -1;
			break;
		}

		free(plaintext);

		client_sock->stage = SOCKS5_STAGE_STREAM;
		remote_sock->stage = SOCKS5_STAGE_STREAM;
		ret = 4 + ciphertext_len;
 		break;
	}

	case SOCKS5_STAGE_STREAM: {
		struct csnet_msg* msg;
		msg = csnet_msg_new(len, client_sock);
		csnet_msg_append(msg, data, len);
		csnet_sendto(Q, msg);

		log_d(LOG, "stream: socket %d <<< socket %d (%s)",
			  client_sock->fd, remote_sock->fd, remote_sock->host);
		ret = len;
		break;
	}

	default:
		ret = -1;
		break;
	}

	return ret;
}

