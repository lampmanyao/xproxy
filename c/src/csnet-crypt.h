#pragma once

void csnet_crypt_setup(void);
void csnet_crypt_cleanup(void);
void csnet_crypt_set_iv(const char* password);

/*
 * Return value:
 * >0 : encrypt succeed. The `cipherdata` must call free() to free the memory.
 * -1 : encrypt failed.
 */
int csnet_128cfb_encrypt(char** cipherdata, char* plaindata, unsigned int length, const char* key);

/*
 * Return value:
 * >0 : decrypt succeed. The `plaindata` must call free() to free the memory.
 * -1 : decrypt failed.
 */
int csnet_128cfb_decrypt(char** plaindata, char* cihperdata, unsigned int length, const char* key);

