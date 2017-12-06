#pragma once

/*
 * Forward declarations
 */
struct csnet_config;
struct csnet_socket;
struct cs_lfqueue;
struct csnet_log;

typedef int (*module_init_cb) (void* conntor, struct cs_lfqueue* q, struct csnet_log* log, struct csnet_config* config);
typedef int (*module_entry_cb) (struct csnet_socket* socket, int state, char* data, int data_len);
typedef void (*module_term_cb) (void);

struct csnet_module {
	unsigned char md5[17];
	long long ref_count;
	module_init_cb business_init;
	module_entry_cb business_entry;
	module_term_cb business_term;
	void* module;
	void* conntor;
	struct cs_lfqueue* q;
	struct csnet_log* log;
	struct csnet_config* config;
};

struct csnet_module* csnet_module_new(void);
void csnet_module_init(struct csnet_module*, void* conntor, struct cs_lfqueue* q, struct csnet_log* log, struct csnet_config* config);
void csnet_module_term(struct csnet_module*);
void csnet_module_load(struct csnet_module*, const char* module);
void csnet_module_ref_increment(struct csnet_module*);
void csnet_module_ref_decrement(struct csnet_module*);
int csnet_module_entry(struct csnet_module*, struct csnet_socket* socket,
                        int state, char* data, int data_len);
void csnet_module_free(struct csnet_module*);

