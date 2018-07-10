#pragma once

/*
 * Forward declarations
 */
struct csnet_config;
struct csnet_socket;
struct cs_lfqueue;
struct csnet_log;

typedef int (*module_init_cb) (void* conntor, struct cs_lfqueue* q, struct csnet_log* log, struct csnet_config* config);
typedef int (*module_entry_cb) (struct csnet_socket* socket, int stage, char* data, int len);

struct csnet_module {
	module_init_cb business_init;
	module_entry_cb business_entry;
	void* module;
	void* conntor;
	struct cs_lfqueue* q;
	struct csnet_log* log;
	struct csnet_config* config;
};

struct csnet_module* csnet_module_new(void);
void csnet_module_init(struct csnet_module*, void* conntor, struct cs_lfqueue* q, struct csnet_log* log, struct csnet_config* config);
void csnet_module_load(struct csnet_module*, const char* module);
int csnet_module_entry(struct csnet_module*, struct csnet_socket* socket, int stage, char* data, int len);
void csnet_module_free(struct csnet_module*);

