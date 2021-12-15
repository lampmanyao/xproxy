#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include <openssl/md5.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "crypt.h"
#include "utils.h"
#include "log.h"

/*
 * Using openssl in multi-threaded applications:
 * https://www.openssl.org/blog/blog/2017/02/21/threads/
 */
#if (OPENSSL_VERSION_NUMBER <= 0x10002000l)
static pthread_mutex_t *lock_cs;
static long *lock_count;

static void pthreads_locking_callback(int mode, int type, char *file, int line)
{
	SHUTUP_WARNING(file);
	SHUTUP_WARNING(line);
	if (mode & CRYPTO_LOCK) {
		pthread_mutex_lock(&lock_cs[type]);
		lock_count[type]++;
	} else {
		pthread_mutex_unlock(&lock_cs[type]);
	}
}

static unsigned long pthreads_thread_id(void)
{
	unsigned long ret = (unsigned long)pthread_self();
	return ret;
}
#endif

void crypt_setup(void)
{
/*
 * SSL_library_init() and OpenSSL_add_all_algorithms() were deprecated since 1.1.0
 */
#if (OPENSSL_VERSION_NUMBER < 0x10100000l)
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
#else
	if (OPENSSL_init_ssl(OPENSSL_INIT_ENGINE_ALL_BUILTIN, NULL) != 1)
		FATAL("openssl init failed");
#endif

#if (OPENSSL_VERSION_NUMBER <= 0x10002000l)
	int num_locks = CRYPTO_num_locks();

	lock_cs = OPENSSL_malloc((size_t)num_locks * sizeof(pthread_mutex_t));
	lock_count = (long *)OPENSSL_malloc((size_t)num_locks * sizeof(long));

	if (!lock_cs || !lock_count) {
		if (lock_cs)
			OPENSSL_free(lock_cs);

		if (lock_count)
			OPENSSL_free(lock_count);

		return;
	}

	for (int i = 0; i < num_locks; i++) {
		lock_count[i] = 0;
		pthread_mutex_init(&lock_cs[i], NULL);
	}

	CRYPTO_set_id_callback((unsigned long (*)())pthreads_thread_id);
	CRYPTO_set_locking_callback((void (*)(int, int, const char *, int))pthreads_locking_callback);
#endif
}

void crypt_cleanup(void)
{
#if (OPENSSL_VERSION_NUMBER <= 0x10002000l)
	CRYPTO_set_locking_callback(NULL);
	for (int i = 0; i < CRYPTO_num_locks(); i++)
		pthread_mutex_destroy(&(lock_cs[i]));

	OPENSSL_free(lock_cs);
	OPENSSL_free(lock_count);
#endif

#if (OPENSSL_VERSION_NUMBER < 0x10100000l)
	ERR_free_strings();
#endif
}

static int encrypt_128cfb(struct cryptor *c, char **ciphertext, char *plaintext, unsigned int length);
static int decrypt_128cfb(struct cryptor *c, char **plaintext, char *ciphertext, unsigned int length);

static int encrypt_192cfb(struct cryptor *c, char **ciphertext, char *plaintext, unsigned int length);
static int decrypt_192cfb(struct cryptor *c, char **plaintext, char *ciphertext, unsigned int length);

static int encrypt_256cfb(struct cryptor *c, char **ciphertext, char *plaintext, unsigned int length);
static int decrypt_256cfb(struct cryptor *c, char **plaintext, char *ciphertext, unsigned int length);


static void generate_key(unsigned char *key, int key_size, const char *password)
{
	int i, j;
	unsigned char buffer[MD5_DIGEST_LENGTH] = {0};
	MD5_CTX md5_ctx;
	MD5_Init(&md5_ctx);
	MD5_Update(&md5_ctx, password, strlen(password));
	MD5_Final(buffer, &md5_ctx);

	i = MD5_DIGEST_LENGTH;
	j = 0;

	while (i--)
		key[i] = buffer[j++];

	j = 0;
	for (i = MD5_DIGEST_LENGTH; i < key_size; i++)
		key[i] = buffer[j++];

	key[key_size] = '\0';
}

static void generate_iv(unsigned char *iv, int iv_size, const unsigned char *str, unsigned long len)
{
	int i;
	unsigned char buffer[MD5_DIGEST_LENGTH] = {0};
	MD5_CTX md5_ctx;
	MD5_Init(&md5_ctx);
	MD5_Update(&md5_ctx, str, len);
	MD5_Final(buffer, &md5_ctx);

	for (i = 0; i < MD5_DIGEST_LENGTH; i++)
		iv[i] = buffer[i];

	while (i++ < iv_size - 1)
		iv[i] = buffer[i - MD5_DIGEST_LENGTH];
}

struct cipher {
	const char *name;
	int key_size;
	int iv_size;
	int (*encrypt)(struct cryptor *c, char **, char *, unsigned int);
	int (*decrypt)(struct cryptor *c, char **, char *, unsigned int);
};

static struct cipher ciphers[] = {
	/* name         key_size iv_size encrypt_cb      decrypt_cb */
	{"aes-128-cfb", 16,      16,     encrypt_128cfb, decrypt_128cfb},
	{"aes-192-cfb", 24,      24,     encrypt_192cfb, decrypt_192cfb},
	{"aes-256-cfb", 32,      32,     encrypt_256cfb, decrypt_256cfb},
	{NULL,          0,       0,      NULL,           NULL}
};

int cryptor_init(struct cryptor *c, const char *method, const char *password)
{
	assert(c != NULL);
	assert(method != NULL);
	assert(password != NULL);

	const struct cipher* cipher = ciphers;

	while (cipher->name) {
		if (strncmp(cipher->name, method, strlen(method)) == 0)
			break;
		cipher++;
	}

	if (!cipher->name)
		return -1;

	c->key = malloc((size_t)cipher->key_size + 1);
	c->key_size = cipher->key_size;
	generate_key(c->key, c->key_size, password);


	c->iv = malloc((size_t)cipher->iv_size);
	c->iv_size = cipher->iv_size;
	generate_iv(c->iv, c->iv_size, c->key, (unsigned long)cipher->key_size);

	c->encrypt = cipher->encrypt;
	c->decrypt = cipher->decrypt;

	return 0;
}

void cryptor_deinit(struct cryptor *c)
{
	assert(c != NULL);
	free(c->key);
	free(c->iv);
}

static int encrypt_128cfb(struct cryptor *c, char **ciphertext,
			  char *plaintext, unsigned int length)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

	if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cfb(), NULL,
			       (const unsigned char *)c->key,
			       (const unsigned char *)c->iv) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}

	int len = 0;
	int ciphertext_len = 0;
	*ciphertext = malloc(length + EVP_MAX_BLOCK_LENGTH);

	if (EVP_EncryptUpdate(ctx, (unsigned char *)*ciphertext, &len,
			      (unsigned char *)plaintext, (int)length) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		free(*ciphertext);
		return -1;
	}

	ciphertext_len = len;
	if (EVP_EncryptFinal_ex(ctx, (unsigned char *)(*ciphertext) + len, &len) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		free(*ciphertext);
		return -1;
	}

	ciphertext_len += len;
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

static int decrypt_128cfb(struct cryptor *c, char **plaintext,
			  char *ciphertext, unsigned int length)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

	if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cfb(), NULL,
			       (const unsigned char *)c->key,
			       (const unsigned char *)c->iv) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}

	int len = 0;
	int plaintext_len = 0;
	*plaintext = malloc(length + EVP_MAX_BLOCK_LENGTH);

	if (EVP_DecryptUpdate(ctx, (unsigned char *)*plaintext, &len,
			      (unsigned char *)ciphertext, (int)length) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		free(*plaintext);
		return -1;
	}

	plaintext_len = len;
	if (EVP_DecryptFinal_ex(ctx, (unsigned char *)(*plaintext) + len, &len) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		free(*plaintext);
		return -1;
	}

	plaintext_len += len;
	EVP_CIPHER_CTX_free(ctx);

	return plaintext_len;
}

static int encrypt_192cfb(struct cryptor *c, char **ciphertext,
			  char *plaintext, unsigned int length)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

	if (EVP_EncryptInit_ex(ctx, EVP_aes_192_cfb(), NULL,
			       (const unsigned char *)c->key,
			       (const unsigned char *)c->iv) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}

	int len = 0;
	int ciphertext_len = 0;
	*ciphertext = malloc(length + EVP_MAX_BLOCK_LENGTH);

	if (EVP_EncryptUpdate(ctx, (unsigned char *)*ciphertext, &len,
			      (unsigned char *)plaintext, (int)length) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		free(*ciphertext);
		return -1;
	}

	ciphertext_len = len;
	if (EVP_EncryptFinal_ex(ctx, (unsigned char *)(*ciphertext) + len, &len) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		free(*ciphertext);
		return -1;
	}

	ciphertext_len += len;
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

static int decrypt_192cfb(struct cryptor *c, char **plaintext,
			  char *ciphertext, unsigned int length)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

	if (EVP_DecryptInit_ex(ctx, EVP_aes_192_cfb(), NULL,
			       (const unsigned char *)c->key,
			       (const unsigned char *)c->iv) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}

	int len = 0;
	int plaintext_len = 0;
	*plaintext = malloc(length + EVP_MAX_BLOCK_LENGTH);

	if (EVP_DecryptUpdate(ctx, (unsigned char *)*plaintext, &len,
			      (unsigned char *)ciphertext, (int)length) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		free(*plaintext);
		return -1;
	}

	plaintext_len = len;
	if (EVP_DecryptFinal_ex(ctx, (unsigned char *)(*plaintext) + len, &len) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		free(*plaintext);
		return -1;
	}

	plaintext_len += len;
	EVP_CIPHER_CTX_free(ctx);

	return plaintext_len;
}

static int encrypt_256cfb(struct cryptor *c, char **ciphertext,
			  char *plaintext, unsigned int length)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cfb(), NULL,
			       (const unsigned char *)c->key,
			       (const unsigned char *)c->iv) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}

	int len = 0;
	int ciphertext_len = 0;
	*ciphertext = malloc(length + EVP_MAX_BLOCK_LENGTH);

	if (EVP_EncryptUpdate(ctx, (unsigned char *)*ciphertext, &len,
			      (unsigned char *)plaintext, (int)length) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		free(*ciphertext);
		return -1;
	}

	ciphertext_len = len;
	if (EVP_EncryptFinal_ex(ctx, (unsigned char *)(*ciphertext) + len, &len) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		free(*ciphertext);
		return -1;
	}

	ciphertext_len += len;
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

static int decrypt_256cfb(struct cryptor *c, char **plaintext,
			  char *ciphertext, unsigned int length)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cfb(), NULL,
			       (const unsigned char *)c->key,
			       (const unsigned char *)c->iv) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}

	int len = 0;
	int plaintext_len = 0;
	*plaintext = malloc(length + EVP_MAX_BLOCK_LENGTH);

	if (EVP_DecryptUpdate(ctx, (unsigned char *)*plaintext, &len,
			      (unsigned char *)ciphertext, (int)length) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		free(*plaintext);
		return -1;
	}

	plaintext_len = len;
	if (EVP_DecryptFinal_ex(ctx, (unsigned char *)(*plaintext) + len, &len) != 1) {
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
// macOS: gcc -DCRYPT_MAIN_TEST -o a.out crypt.c -I/usr/local/Cellar/openssl/1.0.2s/include -L/usr/local/Cellar/openssl/1.0.2s/lib -lssl -lcrypto
// Linux: gcc -DCRYPT_MAIN_TEST -o a.out crypt.c -lssl -lcrypto

void aes_128_cfb_test(void)
{
	char *pass= "1234567887654321";
	char *plaintext = "Hey, this is an aes-128-cfb encryption/decryption test.";

	struct cryptor c1;
	struct cryptor c2;

	cryptor_init(&c1, "aes-128-cfb", pass);
	cryptor_init(&c2, "aes-128-cfb", pass);

	int length = strlen(plaintext);
	char *ciphertext;
	int ciphertext_len = c1.encrypt(&c1, &ciphertext, plaintext, length);

	char *rawtext;
	int rawtext_len = c2.decrypt(&c2, &rawtext, ciphertext, ciphertext_len);

	if (memcmp(plaintext, rawtext, rawtext_len) == 0) {
		printf("aes-128-cfb test pass\n");
	} else {
		printf("aes-128-cfb test failed\n");
	}

	free(ciphertext);
	free(rawtext);

	cryptor_deinit(&c1);
	cryptor_deinit(&c2);
}

void aes_192_cfb_test(void)
{
	char *pass= "1234567887654321";
	char *plaintext = "Hey, this is an aes-192-cfb encryption/decryption test.";

	struct cryptor c1;
	struct cryptor c2;

	cryptor_init(&c1, "aes-192-cfb", pass);
	cryptor_init(&c2, "aes-192-cfb", pass);

	int length = strlen(plaintext);
	char *ciphertext;
	int ciphertext_len = c1.encrypt(&c1, &ciphertext, plaintext, length);

	char *rawtext;
	int rawtext_len = c2.decrypt(&c2, &rawtext, ciphertext, ciphertext_len);

	if (memcmp(plaintext, rawtext, rawtext_len) == 0) {
		printf("aes-192-cfb test pass\n");
	} else {
		printf("aes-192-cfb test failed\n");
	}

	free(ciphertext);
	free(rawtext);

	cryptor_deinit(&c1);
	cryptor_deinit(&c2);
}

void aes_256_cfb_test(void)
{
	char *pass= "12345678asdfasfasdfasdfasdfasdfasdfadsfasdfasf";
	char *plaintext = "Hey, this is an aes-256-cfb encryption/decryption test.";

	struct cryptor c1;
	struct cryptor c2;

	cryptor_init(&c1, "aes-256-cfb", pass);
	cryptor_init(&c2, "aes-256-cfb", pass);

	int length = strlen(plaintext);
	char *ciphertext;
	int ciphertext_len = c1.encrypt(&c1, &ciphertext, plaintext, length);

	char *rawtext;
	int rawtext_len = c2.decrypt(&c2, &rawtext, ciphertext, ciphertext_len);

	if (memcmp(plaintext, rawtext, rawtext_len) == 0) {
		printf("aes-256-cfb test pass\n");
	} else {
		printf("aes-256-cfb test failed\n");
	}

	free(ciphertext);
	free(rawtext);

	cryptor_deinit(&c1);
	cryptor_deinit(&c2);
}

int main()
{
	crypt_setup();

	aes_128_cfb_test();
	aes_192_cfb_test();
	aes_256_cfb_test();

	crypt_cleanup();

	return 0;
}

#endif

