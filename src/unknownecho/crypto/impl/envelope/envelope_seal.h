#ifndef UNKNOWNECHO_ENVELOPE_SEAL_H
#define UNKNOWNECHO_ENVELOPE_SEAL_H

#include <openssl/evp.h>

#include <unknownecho/bool.h>

bool envelope_seal_buffer(EVP_PKEY *pub_key, unsigned char *plaintext, int plaintext_len,
	unsigned char **encrypted_key, int *encrypted_key_len, unsigned char **iv, int *iv_len,
	unsigned char **ciphertext, int *ciphertext_len, const char *cipher_name);

#endif
