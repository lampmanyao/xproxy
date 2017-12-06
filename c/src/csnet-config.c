#include "csnet-config.h"
#include "csnet-utils.h"
#include "cs-hashtable.h"

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

struct csnet_config*
csnet_config_new(void) {
	struct csnet_config* conf = calloc(1, sizeof(*conf));
	if (!conf) {
		csnet_oom(sizeof(*conf));
	}
	conf->hashtbl = cs_ht_new();
	return conf;
}

void
csnet_config_free(struct csnet_config* conf) {
	cs_ht_free(conf->hashtbl);
	free(conf);
}

void
csnet_config_load(struct csnet_config* conf, const char* file) {
	FILE* f = fopen(file, "r");
	assert(f != NULL);

	char line[512] = {0};
	while (fgets(line, 512, f)) {
		if (line[0] == '#' || line[0] == '\n') {
			continue;
		}

		line[strlen(line) - 1] = '\0';
		char* p = strchr(line, '=');
		if (!p) {
			fprintf(stderr, "WARNING: `%s` line does no contain '=' in `%s`\n", line, file);
			fflush(stderr);
			continue;
		}

		*p = '\0';

		char* tmp1 = csnet_trim(line);
		char* tmp2 = csnet_trim(p + 1);
		int key_len = strlen(tmp1);
		int value_len = strlen(tmp2);
		char* key = calloc(1, key_len + 1);
		char* value = calloc(1, value_len + 1);

		if (!key) {
			csnet_oom(key_len);
		}

		if (!value) {
			csnet_oom(value_len);
		}

		strcpy(key, tmp1);
		strcpy(value, tmp2);
		cs_ht_insert(conf->hashtbl, key, key_len, value, value_len);
	}

	fclose(f);
}

void*
csnet_config_find(struct csnet_config* conf, void* key, int key_len) {
	if (!key) {
		return NULL;
	}

	struct cs_htnode* htnode = cs_ht_search(conf->hashtbl, key, key_len);
	if (htnode) {
		return htnode->value;
	} else {
		return NULL;
	}
}

