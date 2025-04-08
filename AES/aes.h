#ifndef AES_H
#define AES_H

#define AES_KEY_SIZE 32
#define AES_BLOCK_SIZE 16

int generate_random_iv(unsigned char* iv);

void get_key(unsigned char* key);

int encrypt(unsigned char* plaintext, int plain_len, unsigned char* key, 
        unsigned char* iv, unsigned char* ciphertext);


int decrypt(unsigned char* ciphertext, int cipher_len, unsigned char* key,
        unsigned char* iv, unsigned char* plaintext);

#endif  // AES_H
