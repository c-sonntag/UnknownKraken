#ifndef UNKNOWNECHO_AES_ENCRYPT_H
#define UNKNOWNECHO_AES_ENCRYPT_H

#include <unknownecho/bool.h>

bool ue_aes_encrypt_256_cbc(unsigned char *plaintext, int plaintext_len, unsigned char *key,
	unsigned char *iv, unsigned char *ciphertext, int *ciphertext_len);

int ue_aes_decrypt_256_cbc(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
	unsigned char *iv, unsigned char *plaintext, int *plaintext_len);

#endif
