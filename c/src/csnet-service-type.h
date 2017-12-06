#pragma once

/*
 * Server type should be redefine dependence on your real situation.
 */

typedef enum csnet_server_type {
	ST_RETISTATION_SERVER = 26,
	ST_MIDD_SERVER = 27,
	ST_EDGE_SERVER = 28,
	ST_SSL_SERVER = 29,
} csnet_server_type_t;

