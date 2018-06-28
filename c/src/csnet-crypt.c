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
csnet_128cfb_encrypt(char** cipherdata,
		     char* plaindata, unsigned int length, const char* key) {
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

	if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cfb(), NULL, (const unsigned char*)key, IV) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}

	int len = 0;
	int cipherdata_len = 0;
	*cipherdata = malloc(length + EVP_MAX_BLOCK_LENGTH);

	if (EVP_EncryptUpdate(ctx, (unsigned char*)*cipherdata, &len,
			      (unsigned char*)plaindata, length) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		free(*cipherdata);
		return -1;
	}
	cipherdata_len = len;
	if (EVP_EncryptFinal_ex(ctx, (unsigned char*)(*cipherdata) + len, &len) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		free(*cipherdata);
		return -1;
	}
	cipherdata_len += len;
	EVP_CIPHER_CTX_free(ctx);
	return cipherdata_len;
}

int
csnet_128cfb_decrypt(char** plaindata,
		     char* cipherdata, unsigned int length, const char* key) {
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

	if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cfb(), NULL, (const unsigned char*)key, IV) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}

	int len = 0;
	int plaindata_len = 0;
	*plaindata = malloc(length + EVP_MAX_BLOCK_LENGTH);

	if (EVP_DecryptUpdate(ctx, (unsigned char*)*plaindata, &len,
			      (unsigned char*)cipherdata, length) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		free(*plaindata);
		return -1;
	}
	plaindata_len = len;
	if (EVP_DecryptFinal_ex(ctx, (unsigned char*)(*plaindata) + len, &len) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		free(*plaindata);
		return -1;
	}
	plaindata_len += len;
	EVP_CIPHER_CTX_free(ctx);
	return plaindata_len;
}


#if defined TEST

// compile:
// macos: gcc -DTEST -o a.out csnet-crypt.c -I/usr/local/Cellar/openssl/1.0.1j/include -L/usr/local/Cellar/openssl/1.0.1j/lib -lssl -lcrypto
// linux: gcc -DTEST -o a.out csnet-crypt.c -lssl -lcrypto

int main()
{
	csnet_crypt_setup();
	char* key = "helloworld";
	char* plaindata = "ASDASDSADASDASDASD";
	int length = strlen(plaindata);
	printf("plain data length = %d\n", length);
	char* cipherdata;
	int cipherdata_len = csnet_128cfb_encrypt(&cipherdata, plaindata, length, key);
	printf("encrypted data length = %d\n", cipherdata_len);

	char* rawdata;
	int rawdata_len = csnet_128cfb_decrypt(&rawdata, cipherdata, cipherdata_len, key);

	printf("decrypted data length = %d\n", rawdata_len);
	printf("before encrypted: %s\n", plaindata);
	printf("atfer decrypted: %s\n", rawdata);

	free(cipherdata);
	free(rawdata);
	csnet_crypt_cleanup();

	return 0;
}

#endif

