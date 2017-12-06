#pragma once

/*
 * Forward declarations
 */
struct cs_ht;

struct csnet_config {
	struct cs_ht* hashtbl;
};

struct csnet_config* csnet_config_new(void);
void csnet_config_free(struct csnet_config*);
void csnet_config_load(struct csnet_config*, const char* file);
void* csnet_config_find(struct csnet_config*, void* key, int key_len);

