#ifndef UNKNOWNECHO_ENVELOPE_OPEN_H
#define UNKNOWNECHO_ENVELOPE_OPEN_H

#include <openssl/evp.h>

#include <unknownecho/bool.h>

bool envelope_open_buffer(EVP_PKEY *priv_key, unsigned char *ciphertext, int ciphertext_len,
	unsigned char *encrypted_key, int encrypted_key_len, unsigned char *iv,
	unsigned char **plaintext, int *plaintext_len, const char *cipher_name);

#endif
