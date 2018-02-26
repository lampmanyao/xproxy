#include "libcsnet.h"

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <arpa/inet.h>

#define RANDOM_LENGTH 9

static int client_handler(struct csnet_socket* socket, int state, char* data, int data_len);
static int remote_handler(struct csnet_socket* socket, int state, char* data, int data_len);

struct csnet_log* LOG = NULL;
struct cs_lfqueue* Q = NULL;
struct csnet_conntor* CONNTOR = NULL;
char* passwd;

int
business_init(struct csnet_conntor* conntor, struct cs_lfqueue* q,
	      struct csnet_log* log, struct csnet_config* config) {
	CONNTOR = conntor;
	LOG = log;
	Q = q;

	passwd = csnet_config_find(config, "password", strlen("password"));
	if (!passwd) {
		log_fatal(LOG, "cant find `password` in config file");
	}

	log_debug(log, "business init done ...");
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
client_handler(struct csnet_socket* socket, int state, char* data, int data_len) {
	int ret = 0;

	switch (state) {
	case SOCKS5_ST_EXMETHOD: {
		int cipher_data_len;
		int plain_data_len;
		char* plain_data;

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

		plain_data_len = csnet_128cfb_decrypt(&plain_data, data + 4, cipher_data_len, passwd);
		if (plain_data_len < 0) {
			log_error(LOG, "decrypt error. exhost.");
			ret = -1;
			break;
		}

		uint8_t ver = plain_data[0 + RANDOM_LENGTH];
		uint8_t cmd = plain_data[1 + RANDOM_LENGTH];
		uint8_t rsv = plain_data[2 + RANDOM_LENGTH];
		uint8_t typ = plain_data[3 + RANDOM_LENGTH];

		if (typ == SOCKS5_ATYP_IPv4) {
			log_error(LOG, "unsupport IPv4 yet");
			return -1;
		} else if (typ == SOCKS5_ATYP_DONAME) {
			uint8_t domain_name_len;
			char domain_name[256];
			uint16_t nport;
			uint16_t hsport;
			struct csnet_socket* target_sock;
			char reply[512];
			char* cipher_reply;
			int cipher_reply_len;
			struct csnet_msg* msg;

			domain_name_len = plain_data[SOCKS5_REQ_HEAD_SIZE + RANDOM_LENGTH];
			memcpy(domain_name, plain_data + SOCKS5_REQ_HEAD_SIZE + 1 + RANDOM_LENGTH, domain_name_len);
			domain_name[domain_name_len] = '\0';
			memcpy((char*)&nport, plain_data + SOCKS5_REQ_HEAD_SIZE + 1 + domain_name_len + RANDOM_LENGTH, SOCKS5_PORT_SIZE);
			hsport = ntohs(nport);

			target_sock = csnet_conntor_connectto(CONNTOR, domain_name, hsport);
			if (!target_sock) {
				free(plain_data);
				return -1;
			}

			memcpy(socket->host, domain_name, domain_name_len);
			socket->host[domain_name_len] = '\0';
			memcpy(target_sock->host, domain_name, domain_name_len);
			target_sock->host[domain_name_len] = '\0';

			log_debug(LOG, "exhost: socket %d ---> socket %d (%s)",
				  socket->fd, target_sock->fd, domain_name);

			memcpy(reply, "123456789", RANDOM_LENGTH);

			reply[0 + RANDOM_LENGTH] = ver;
			reply[1 + RANDOM_LENGTH] = SOCKS5_RSP_SUCCEED;
			reply[2 + RANDOM_LENGTH] = SOCKS5_RSV;
			reply[3 + RANDOM_LENGTH] = SOCKS5_ATYP_DONAME;
			reply[4 + RANDOM_LENGTH] = domain_name_len;
			memcpy(reply + 5 + RANDOM_LENGTH, domain_name, domain_name_len);
			memcpy(reply + 5 + domain_name_len + RANDOM_LENGTH, (char*)&nport, SOCKS5_PORT_SIZE);

			cipher_reply_len = csnet_128cfb_encrypt(&cipher_reply, reply,
								5 + domain_name_len + SOCKS5_PORT_SIZE + RANDOM_LENGTH,
								passwd);
			if (cipher_reply_len < 0) {
				log_error(LOG, "encrypt error. exhost: socket %d ---> socket %d (%s)",
					  socket->fd, target_sock->fd, domain_name);
				free(plain_data);
				return -1;
			}

			msg = csnet_msg_new(4 + cipher_reply_len, socket);
			csnet_msg_append(msg, (char*)&cipher_reply_len, 4);
			csnet_msg_append(msg, cipher_reply, cipher_reply_len);
			csnet_sendto(Q, msg);

			log_debug(LOG, "exhost: socket %d <--- socket %d (%s)",
				  socket->fd, target_sock->fd, domain_name);

			socket->sock = target_sock;
			target_sock->sock = socket;

			free(cipher_reply);
			free(plain_data);

			socket->state = SOCKS5_ST_STREAMING;
			socket->sock->state = SOCKS5_ST_STREAMING;

			ret = 4 + cipher_data_len;
		} else if (typ == SOCKS5_ATYP_IPv6) {
			log_error(LOG, "unsupport IPv6 yet");
			ret = -1;
		} else {
			log_error(LOG, "unknown address type");
			ret = -1;
		}
		break;
	}

	case SOCKS5_ST_STREAMING: {
		log_debug(LOG, "streaming: socket %d ---> socket %d (%s)",
			  socket->fd, socket->sock->fd, socket->sock->host);
		struct csnet_msg* msg;
		msg = csnet_msg_new(data_len, socket->sock);
		csnet_msg_append(msg, data, data_len);
		csnet_sendto(Q, msg);
		ret = data_len;
		break;
	}

	default:
		ret = -1;
		break;
	}

	log_debug(LOG, "socket %d, recv %d bytes, handle %d bytes, remains %d bytes",
		  socket->fd, data_len, ret, data_len - ret);

	return ret;
}

static int
remote_handler(struct csnet_socket* socket, int state, char* data, int data_len) {
	struct csnet_msg* msg;
	msg = csnet_msg_new(data_len, socket->sock);
	csnet_msg_append(msg, data, data_len);
	csnet_sendto(Q, msg);

	log_debug(LOG, "streaming: socket %d <--- socket %d (%s)",
		  socket->sock->fd, socket->fd, socket->host);

	log_debug(LOG, "socket %d, recv %d bytes, handle %d bytes, remains %d bytes",
		  socket->fd, data_len, data_len, data_len - data_len);

	return data_len;
}

