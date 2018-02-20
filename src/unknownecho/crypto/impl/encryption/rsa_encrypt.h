#ifndef UNKNOWNECHO_RSA_ENCRYPT_H
#define UNKNOWNECHO_RSA_ENCRYPT_H

#include <unknownecho/crypto/api/key/public_key.h>
#include <unknownecho/crypto/api/key/private_key.h>

#include <stddef.h>
#include <openssl/rsa.h>

unsigned char *ue_rsa_encrypt(RSA *pub_key, unsigned char *plaintext, int plaintext_len, int *ciphertext_len);

unsigned char *ue_rsa_decrypt(RSA *priv_key, unsigned char *ciphertext, int ciphertext_len, int *plaintext_len);

unsigned char *ue_rsa_public_encrypt(ue_public_key *pk, unsigned char *plaintext, int plaintext_len, int *ciphertext_len, const char *padding);

unsigned char *ue_rsa_private_decrypt(ue_private_key *sk, unsigned char *ciphertext, int ciphertext_len, int *plaintext_len, const char *padding);

unsigned char *ue_rsa_private_encrypt(ue_private_key *sk, unsigned char *plaintext, int plaintext_len, int *ciphertext_len, const char *padding);

unsigned char *ue_rsa_public_decrypt(ue_public_key *pk, unsigned char *ciphertext, int ciphertext_len, int *plaintext_len, const char *padding);

#endif
