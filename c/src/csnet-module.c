#include "csnet-module.h"
#include "csnet-atomic.h"
#include "csnet-utils.h"
#include "csnet-config.h"
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
	return m;
}

void
csnet_module_init(struct csnet_module* m, void* conntor,
                  struct csnet_log* log, struct csnet_config* config) {
	m->conntor = conntor;
	m->log = log;
	m->config = config;
}

void
csnet_module_load(struct csnet_module* m, const char* module) {
	m->module = dlopen(module, RTLD_NOW | RTLD_LOCAL);
	if (!m->module) {
		log_f(m->log, "%s", dlerror());
	}

	m->business_init = dlsym(m->module, "business_init");
	if (!m->business_init) {
		log_f(m->log, "%s", dlerror());
	}

	m->business_entry = dlsym(m->module, "business_entry");
	if (!m->business_entry) {
		log_f(m->log, "%s", dlerror());
	}

	m->business_init(m->conntor, m->log, m->config);
}

int
csnet_module_entry(struct csnet_module* m, struct csnet_socket* socket, int stage, char* data, int len) {
	return m->business_entry(socket, stage, data, len);
}

void
csnet_module_free(struct csnet_module* m) {
	dlclose(m->module);
	free(m);
}

