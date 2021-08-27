#ifndef socks5_h
#define socks5_h

#define SOCKS5_VER    5
#define SOCKS5_RSV    0

#define SOCKS5_METHOD_NOAUTH    0
#define SOCKS5_METHOD_GSSAPI    1
#define SOCKS5_USERNAME_PASSWD  2

#define SOCKS5_CMD_CONNECT   1
#define SOCKS5_CMD_BIND      2
#define SOCKS5_CMD_UDP       3

#define SOCKS5_ATYP_IPv4     1
#define SOCKS5_ATYP_DONAME   3
#define SOCKS5_ATYP_IPv6     4

#define SOCKS5_RSP_SUCCEED      0
#define SOCKS5_RSP_SRV_ERR      1
#define SOCKS5_RSP_DENY_ERR     2
#define SOCKS5_RSP_NETWORK_ERR  3
#define SOCKS5_RSP_HOST_ERR     4
#define SOCKS5_RSP_REFUSED_ERR  5
#define SOCKS5_RSP_TTL_ERR      6
#define SOCKS5_RSP_CMD_ERR      7
#define SOCKS5_RSP_ATYP_ERR     8

#define SOCKS5_STAGE_EXCHG_METHOD   0
#define SOCKS5_STAGE_EXCHG_AUTH0    1
#define SOCKS5_STAGE_EXCHG_AUTH1    2
#define SOCKS5_STAGE_EXCHG_HOST     3
#define SOCKS5_STAGE_EXCHG_HOST1    4
#define SOCKS5_STAGE_STREAM         5

#define SOCKS5_PORT_SIZE      2U
#define SOCKS5_REQ_HEAD_SIZE  4U
#define SOCKS5_RSP_HEAD_SIZE  4U
#define SOCKS5_IPV4_REQ_SIZE  10U

#endif  /* socks5_h */

