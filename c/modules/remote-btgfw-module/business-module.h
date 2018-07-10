#pragma once

#include "cs-lfqueue.h"
#include "csnet-log.h"
#include "csnet-config.h"
#include "csnet-conntor.h"

int business_init(struct csnet_conntor* conntor, struct cs_lfqueue* q, struct csnet_log* log, struct csnet_config* config);
int business_entry(struct csnet_socket* sock, int state, char* data, int len);
void business_timeout();
void business_term(void);
