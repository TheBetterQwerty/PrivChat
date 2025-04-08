#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/rand.h>
#include <string.h>

#include "aes.h"

#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE 32 

static void handleError(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

int generate_random_iv(unsigned char* iv) {
    if (!RAND_bytes(iv, AES_BLOCK_SIZE)) {
        fprintf(stderr, "[!] Error generating random bytes!\n");
        return 1;
    }
    return 0;
}

void get_key(unsigned char* key) {
    printf("[+] Enter AES Key: ");
    fgets((char*) key, AES_KEY_SIZE , stdin);
    key[strcspn((const char*) key, "\n")] = '\0';
    
    int len = strlen((const char*) key);
    if (len < AES_KEY_SIZE)
        memset(key + len, 'X', AES_KEY_SIZE - len);

    key[AES_KEY_SIZE - 1] = '\0';
}

int encrypt(unsigned char* plaintext, int plain_len, unsigned char* key,
             unsigned char* iv, unsigned char* ciphertext) {
    
    EVP_CIPHER_CTX* ctx;
    int len = 0, cipher_len = 0;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleError();

    if (!(EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)))
        handleError();

    if(!(EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plain_len)))
        handleError();
    cipher_len = len;

    if (!(EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)))
        handleError();
    cipher_len += len;

    EVP_CIPHER_CTX_free(ctx);
    
    return cipher_len;
}

int decrypt(unsigned char* ciphertext, int cipher_len, unsigned char* key, 
            unsigned char* iv, unsigned char* plaintext) {
    
    if (cipher_len <= 0 || ciphertext == NULL) {
        printf("[!] Invalid cipherlen or ciphertext!\n");
        return -1;
    }
    
    EVP_CIPHER_CTX* ctx;
    int len = 0, plaintext_len = 0;

    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleError();

    if (!(EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)))
        handleError();

    if (!(EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, cipher_len)))
        handleError();
    plaintext_len = len;

    if (!(EVP_DecryptFinal_ex(ctx, plaintext + len, &len)))
        handleError();
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

