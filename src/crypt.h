#ifndef crypt_h
#define crypt_h

void crypt_setup(void);
void crypt_cleanup(void);

struct cryptor {
	unsigned char *key;
	int key_size;
	unsigned char *iv;
	int iv_size;
	int (*encrypt)(struct cryptor *c, char **, char *, unsigned int);
	int (*decrypt)(struct cryptor *c, char **, char *, unsigned int);
};

int cryptor_init(struct cryptor *c, const char *method, const char *password);
void cryptor_deinit(struct cryptor *c);

#endif  /* crypt_h */

