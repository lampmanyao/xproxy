#pragma once

void csnet_crypt_setup(void);
void csnet_crypt_cleanup(void);
void csnet_crypt_set_iv(const char* password);

/*
 * Return value:
 * >0 : encrypt succeed. The `ciphertext` must call free() to free the memory.
 * -1 : encrypt failed.
 */
int csnet_128cfb_encrypt(char** ciphertext, char* plaintext, unsigned int length, const char* key);

/*
 * Return value:
 * >0 : decrypt succeed. The `plaintext` must call free() to free the memory.
 * -1 : decrypt failed.
 */
int csnet_128cfb_decrypt(char** plaintext, char* cihpertext, unsigned int length, const char* key);

