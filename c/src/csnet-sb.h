#pragma once

struct csnet_sb {
	int capacity;
	int data_len;
	char* buffer;
};

struct csnet_sb* csnet_sb_new(int size);
void csnet_sb_free(struct csnet_sb*);
int csnet_sb_append(struct csnet_sb*, const char* data, int len);
int csnet_sb_seek(struct csnet_sb*, int len);
void csnet_sb_reset(struct csnet_sb*);
char* csnet_sb_data(struct csnet_sb*);
int csnet_sb_data_len(struct csnet_sb*);

