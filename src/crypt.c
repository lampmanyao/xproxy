#include "crypt.h"
#include "utils.h"

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include <openssl/md5.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>

static unsigned char IV[17];
static pthread_mutex_t *lock_cs;
static long *lock_count;

static void
pthreads_locking_callback(int mode, int type, char *file, int line)
{
	if (mode & CRYPTO_LOCK) {
		pthread_mutex_lock(&lock_cs[type]);
		lock_count[type]++;
	} else {
		pthread_mutex_unlock(&lock_cs[type]);
	}
}

static unsigned long
pthreads_thread_id(void)
{
	unsigned long ret = (unsigned long)pthread_self();
	return ret;
}

static int
md5(const char *str, unsigned char *buff) {
	MD5_CTX md5_ctx;
	MD5_Init(&md5_ctx);
	MD5_Update(&md5_ctx, str, strlen(str));
	MD5_Final(buff, &md5_ctx);
	return 0;
}

void
crypt_setup(void)
{
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	int num_locks = CRYPTO_num_locks();

	lock_cs = OPENSSL_malloc(num_locks * (int)sizeof(pthread_mutex_t));
	lock_count = (long *)OPENSSL_malloc(num_locks * (int)sizeof(long));

	if (!lock_cs || !lock_count) {
		if (lock_cs) {
			OPENSSL_free(lock_cs);
		}
		if (lock_count) {
			OPENSSL_free(lock_count);
		}
		return;
	}
	for (int i = 0; i < num_locks; i++) {
		lock_count[i] = 0;
		pthread_mutex_init(&lock_cs[i], NULL);
	}
	CRYPTO_set_id_callback((unsigned long (*)())pthreads_thread_id);
	CRYPTO_set_locking_callback((void (*)(int, int, const char*, int))pthreads_locking_callback);
}

void
crypt_cleanup(void)
{
	CRYPTO_set_locking_callback(NULL);

	for (int i = 0; i < CRYPTO_num_locks(); i++) {
		pthread_mutex_destroy(&(lock_cs[i]));
	}

	OPENSSL_free(lock_cs);
	OPENSSL_free(lock_count);
	ERR_free_strings();
}

void
crypt_set_iv(const char *password)
{
	md5(password, IV);
	IV[16] = '\0';
}

static int
encrypt_128cfb(struct cryptor *c, char **ciphertext,
		char *plaintext, unsigned int length);

static int
decrypt_128cfb(struct cryptor *c, char **plaintext,
		char *ciphertext, unsigned int length);


int
cryptor_init(struct cryptor *c, const char* method, const char* password)
{
	assert(c != NULL);
	assert(method != NULL);
	assert(password != NULL);

	c->password = strdup(password);
	md5(c->password, c->iv);
	c->iv[16] = '\0';
	c->encrypt = encrypt_128cfb;
	c->decrypt = decrypt_128cfb;

	return 0;
}

void
cryptor_deinit(struct cryptor *c)
{
	free(c->password);
}

static int
encrypt_128cfb(struct cryptor *c, char **ciphertext,
		char *plaintext, unsigned int length)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

	if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cfb(), NULL,
			       (const unsigned char*)c->password, c->iv) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}

	int len = 0;
	int ciphertext_len = 0;
	*ciphertext = malloc(length + EVP_MAX_BLOCK_LENGTH);

	if (EVP_EncryptUpdate(ctx, (unsigned char*)*ciphertext, &len,
			      (unsigned char*)plaintext, (int)length) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		free(*ciphertext);
		return -1;
	}

	ciphertext_len = len;
	if (EVP_EncryptFinal_ex(ctx, (unsigned char*)(*ciphertext) + len, &len) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		free(*ciphertext);
		return -1;
	}

	ciphertext_len += len;
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

static int
decrypt_128cfb(struct cryptor *c, char **plaintext,
		char *ciphertext, unsigned int length)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

	if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cfb(), NULL,
			       (const unsigned char*)c->password, c->iv) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}

	int len = 0;
	int plaintext_len = 0;
	*plaintext = malloc(length + EVP_MAX_BLOCK_LENGTH);

	if (EVP_DecryptUpdate(ctx, (unsigned char*)*plaintext, &len,
			      (unsigned char*)ciphertext, (int)length) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		free(*plaintext);
		return -1;
	}

	plaintext_len = len;
	if (EVP_DecryptFinal_ex(ctx, (unsigned char*)(*plaintext) + len, &len) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		free(*plaintext);
		return -1;
	}

	plaintext_len += len;
	EVP_CIPHER_CTX_free(ctx);

	return plaintext_len;
}

int
crypt_128cfb_encrypt(char **ciphertext, char *plaintext,
		     unsigned int length, const char *key)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

	if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cfb(), NULL,
			       (const unsigned char*)key, IV) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}

	int len = 0;
	int ciphertext_len = 0;
	*ciphertext = malloc(length + EVP_MAX_BLOCK_LENGTH);

	if (EVP_EncryptUpdate(ctx, (unsigned char*)*ciphertext, &len,
			      (unsigned char*)plaintext, (int)length) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		free(*ciphertext);
		return -1;
	}

	ciphertext_len = len;
	if (EVP_EncryptFinal_ex(ctx, (unsigned char*)(*ciphertext) + len, &len) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		free(*ciphertext);
		return -1;
	}

	ciphertext_len += len;
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

int
crypt_128cfb_decrypt(char **plaintext, char *ciphertext,
		     unsigned int length, const char *key)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

	if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cfb(), NULL,
			       (const unsigned char*)key, IV) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}

	int len = 0;
	int plaintext_len = 0;
	*plaintext = malloc(length + EVP_MAX_BLOCK_LENGTH);

	if (EVP_DecryptUpdate(ctx, (unsigned char*)*plaintext, &len,
			      (unsigned char*)ciphertext, (int)length) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		free(*plaintext);
		return -1;
	}

	plaintext_len = len;
	if (EVP_DecryptFinal_ex(ctx, (unsigned char*)(*plaintext) + len, &len) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		free(*plaintext);
		return -1;
	}

	plaintext_len += len;
	EVP_CIPHER_CTX_free(ctx);

	return plaintext_len;
}


#if defined CRYPT_MAIN_TEST

// compile:
// macos: gcc -DCRYPT_MAIN_TEST -o a.out crypt.c -I/usr/local/Cellar/openssl/1.0.2s/include -L/usr/local/Cellar/openssl/1.0.2s/lib -lssl -lcrypto
// linux: gcc -DCRYPT_MAIN_TEST -o a.out crypt.c -lssl -lcrypto

int main()
{
	crypt_setup();
	char *key = "helloworld";
	crypt_set_iv(key);

	{
		char *plaintext = "ASDASDSADASDASDASD";
		int length = strlen(plaintext);
		printf("plaintext length = %d\n", length);
		char *ciphertext;
		int ciphertext_len = crypt_128cfb_encrypt(&ciphertext, plaintext, length, key);
		printf("encrypted text length = %d\n", ciphertext_len);

		char *rawtext;
		int rawtext_len = crypt_128cfb_decrypt(&rawtext, ciphertext, ciphertext_len, key);

		printf("decrypted text length = %d\n", rawtext_len);
		printf("before encrypted: %s\n", plaintext);
		printf("atfer decrypted: %s\n", rawtext);

		free(ciphertext);
		free(rawtext);
	}

	{
		struct cryptor c;
		cryptor_init(&c, "hel", key);

		char *plaintext = "ASDASDSADASDASDASD";
		int length = strlen(plaintext);
		printf("plaintext length = %d\n", length);
		char *ciphertext;
		int ciphertext_len = c.encrypt(&c, &ciphertext, plaintext, length);
		printf("encrypted text length = %d\n", ciphertext_len);

		char *rawtext;
		int rawtext_len = c.decrypt(&c, &rawtext, ciphertext, ciphertext_len);

		printf("decrypted text length = %d\n", rawtext_len);
		printf("before encrypted: %s\n", plaintext);
		printf("atfer decrypted: %s\n", rawtext);

		free(ciphertext);
		free(rawtext);

		cryptor_deinit(&c);
	}

	crypt_cleanup();

	return 0;
}

#endif

