#pragma once

void crypt_setup(void);
void crypt_cleanup(void);
void crypt_set_iv(const char *password);

struct cryptor {
	char* password;
	unsigned char iv[17];
	int (*encrypt)(struct cryptor *c, char **ciphertext, char *plaintext, unsigned int length);
	int (*decrypt)(struct cryptor *c, char **plaintext, char *cihpertext, unsigned int length);
};

int cryptor_init(struct cryptor *c, const char* method, const char* password);
void cryptor_deinit(struct cryptor *c);

/*
 * Return value:
 * >0 : encrypt succeed. The `ciphertext` must call free() to free the memory.
 * -1 : encrypt failed.
 */
int crypt_128cfb_encrypt(char **ciphertext, char *plaintext, unsigned int length, const char *key);

/*
 * Return value:
 * >0 : decrypt succeed. The `plaintext` must call free() to free the memory.
 * -1 : decrypt failed.
 */
int crypt_128cfb_decrypt(char **plaintext, char *cihpertext, unsigned int length, const char *key);

