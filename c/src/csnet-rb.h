#pragma once

struct csnet_rb {
	unsigned int capacity;
	unsigned int data_len;
	unsigned int seek;
	char* buffer;
};

struct csnet_rb* csnet_rb_new(unsigned int size);
void csnet_rb_free(struct csnet_rb*);
int csnet_rb_append(struct csnet_rb*, const char* data, unsigned int len);
unsigned int csnet_rb_seek(struct csnet_rb*, unsigned int len);
void csnet_rb_reset(struct csnet_rb*);
char* csnet_rb_data(struct csnet_rb*);
unsigned int csnet_rb_data_len(struct csnet_rb*);

