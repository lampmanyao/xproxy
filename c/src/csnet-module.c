#include "csnet-module.h"
#include "csnet-atomic.h"
#include "csnet-utils.h"
#include "csnet-config.h"
#include "cs-lfqueue.h"
#include "csnet-socket.h"
#include "csnet-log.h"

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

struct csnet_module*
csnet_module_new(void) {
	struct csnet_module* m = calloc(1, sizeof(*m));
	if (!m) {
		csnet_oom(sizeof(*m));
	}
	m->ref_count = 0;
	return m;
}

void
csnet_module_init(struct csnet_module* m, void* conntor, struct cs_lfqueue* q,
                  struct csnet_log* log, struct csnet_config* config) {
	m->conntor = conntor;
	m->q = q;
	m->log = log;
	m->config = config;
}

void
csnet_module_term(struct csnet_module* m) {
	m->business_term();
}

void
csnet_module_load(struct csnet_module* m, const char* module) {
	m->module = dlopen(module, RTLD_NOW | RTLD_LOCAL);
	if (!m->module) {
		log_fatal(m->log, "%s", dlerror());
	}

	m->business_init = dlsym(m->module, "business_init");
	if (!m->business_init) {
		log_fatal(m->log, "%s", dlerror());
	}

	m->business_entry = dlsym(m->module, "business_entry");
	if (!m->business_entry) {
		log_fatal(m->log, "%s", dlerror());
	}

	m->business_term = dlsym(m->module, "business_term");
	if (!m->business_term) {
		log_fatal(m->log, "%s", dlerror());
	}

	csnet_md5sum(module, m->md5);
	m->md5[16] = '\0';
	m->business_init(m->conntor, m->q, m->log, m->config);
}

void
csnet_module_ref_increment(struct csnet_module* m) {
	INC_ONE_ATOMIC(&m->ref_count);
}

void
csnet_module_ref_decrement(struct csnet_module* m) {
	DEC_ONE_ATOMIC(&m->ref_count);
}

int
csnet_module_entry(struct csnet_module* m, struct csnet_socket* socket, int state, char* data, int data_len) {
	return m->business_entry(socket, state, data, data_len);
}

void
csnet_module_free(struct csnet_module* m) {
	dlclose(m->module);
	free(m);
}

