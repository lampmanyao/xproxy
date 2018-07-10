#include "csnet-crypt.h"
#include "csnet-utils.h"

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>

static unsigned char IV[17];
static pthread_mutex_t* lock_cs;
static long* lock_count;

static void
pthreads_locking_callback(int mode, int type, char* file, int line) {
	if (mode & CRYPTO_LOCK) {
		pthread_mutex_lock(&lock_cs[type]);
		lock_count[type]++;
	} else {
		pthread_mutex_unlock(&lock_cs[type]);
	}
}

static unsigned long
pthreads_thread_id(void) {
	unsigned long ret = (unsigned long)pthread_self();
	return ret;
}

void
csnet_crypt_setup(void) {
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	lock_cs = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
	lock_count = (long*)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(long));

	if (!lock_cs || !lock_count) {
		if (lock_cs) {
			OPENSSL_free(lock_cs);
		}
		if (lock_count) {
			OPENSSL_free(lock_count);
		}
		return;
	}
	for (int i = 0; i < CRYPTO_num_locks(); i++) {
		lock_count[i] = 0;
		pthread_mutex_init(&lock_cs[i], NULL);
	}
	CRYPTO_set_id_callback((unsigned long (*)())pthreads_thread_id);
	CRYPTO_set_locking_callback((void (*)(int, int, const char*, int))pthreads_locking_callback);
}

void
csnet_crypt_cleanup(void) {
	CRYPTO_set_locking_callback(NULL);

	for (int i = 0; i < CRYPTO_num_locks(); i++) {
		pthread_mutex_destroy(&(lock_cs[i]));
	}

	OPENSSL_free(lock_cs);
	OPENSSL_free(lock_count);
	ERR_free_strings();
}

void
csnet_crypt_set_iv(const char* password) {
	csnet_md5(password, IV);
	IV[16] = '\0';
}

int
csnet_128cfb_encrypt(char** ciphertext,
		     char* plaintext, unsigned int length, const char* key) {
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

	if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cfb(), NULL, (const unsigned char*)key, IV) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}

	int len = 0;
	int ciphertext_len = 0;
	*ciphertext = malloc(length + EVP_MAX_BLOCK_LENGTH);

	if (EVP_EncryptUpdate(ctx, (unsigned char*)*ciphertext, &len,
			      (unsigned char*)plaintext, length) != 1) {
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
csnet_128cfb_decrypt(char** plaintext,
		     char* ciphertext, unsigned int length, const char* key) {
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

	if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cfb(), NULL, (const unsigned char*)key, IV) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}

	int len = 0;
	int plaintext_len = 0;
	*plaintext = malloc(length + EVP_MAX_BLOCK_LENGTH);

	if (EVP_DecryptUpdate(ctx, (unsigned char*)*plaintext, &len,
			      (unsigned char*)ciphertext, length) != 1) {
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


#if defined CRYPt_MAIN_TEST

// compile:
// macos: gcc -DTEST -o a.out csnet-crypt.c -I/usr/local/Cellar/openssl/1.0.1j/include -L/usr/local/Cellar/openssl/1.0.1j/lib -lssl -lcrypto
// linux: gcc -DTEST -o a.out csnet-crypt.c -lssl -lcrypto

int main()
{
	csnet_crypt_setup();
	char* key = "helloworld";
	csnet_crypt_set_iv(key);
	char* plaintext = "ASDASDSADASDASDASD";
	int length = strlen(plaintext);
	printf("plaintext length = %d\n", length);
	char* ciphertext;
	int ciphertext_len = csnet_128cfb_encrypt(&ciphertext, plaintext, length, key);
	printf("encrypted text length = %d\n", ciphertext_len);

	char* rawtext;
	int rawtext_len = csnet_128cfb_decrypt(&rawtext, ciphertext, ciphertext_len, key);

	printf("decrypted text length = %d\n", rawtext_len);
	printf("before encrypted: %s\n", plaintext);
	printf("atfer decrypted: %s\n", rawtext);

	free(ciphertext);
	free(rawtext);
	csnet_crypt_cleanup();

	return 0;
}

#endif

