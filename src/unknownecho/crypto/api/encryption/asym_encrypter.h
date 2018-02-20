#ifndef UNKNOWNECHO_ASYM_ENCRYPTER_H
#define UNKNOWNECHO_ASYM_ENCRYPTER_H

#include <unknownecho/crypto/api/key/public_key.h>
#include <unknownecho/crypto/api/key/private_key.h>
#include <unknownecho/bool.h>

#include <stddef.h>

typedef struct {
	char *algorithm;
	ue_public_key *pk;
	ue_private_key *sk;
} ue_asym_encrypter;

ue_asym_encrypter *ue_asym_encrypter_create();

void ue_asym_encrypter_destroy(ue_asym_encrypter *encrypter);

void ue_asym_encrypter_destroy_all(ue_asym_encrypter *encrypter);

bool ue_asym_encrypter_init(ue_asym_encrypter *encrypter, const char *algorithm);

bool ue_asym_encrypter_set_pk(ue_asym_encrypter *encrypter, ue_public_key *pk);

bool ue_asym_encrypter_set_sk(ue_asym_encrypter *encrypter, ue_private_key *sk);

unsigned char *ue_asym_encrypter_public_encrypt(ue_asym_encrypter *encrypter, unsigned char *plaintext, size_t plaintext_size, size_t *ciphered_text_size);

unsigned char *ue_asym_encrypter_private_decrypt(ue_asym_encrypter *encrypter, unsigned char *ciphered_text, size_t ciphered_text_size, size_t *plaintext_size);

unsigned char *ue_asym_encrypter_private_encrypt(ue_asym_encrypter *encrypter, unsigned char *plaintext, size_t plaintext_size, size_t *ciphered_text_size);

unsigned char *ue_asym_encrypter_public_decrypt(ue_asym_encrypter *encrypter, unsigned char *ciphered_text, size_t ciphered_text_size, size_t *plaintext_size);

#endif
