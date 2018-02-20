#ifndef UNKNOWNECHO_SYM_ENCRYPTER_H
#define UNKNOWNECHO_SYM_ENCRYPTER_H

#include <unknownecho/crypto/api/key/sym_key.h>
#include <unknownecho/bool.h>

#include <stddef.h>

typedef enum {
	AES
} ue_sym_encryption_type;

typedef enum {
	AES_CBC
} ue_sym_encryption_mode;

typedef enum {
	BITS_256
} ue_sym_encryption_key_size;

typedef enum {
	BITS_0,
	BITS_128
} ue_block_cipher_iv_size;

typedef struct {
	ue_sym_encryption_type type;
	ue_sym_encryption_mode mode;
	ue_sym_encryption_key_size key_size;
	ue_block_cipher_iv_size iv_size;
	ue_sym_key *key;
} ue_sym_encrypter;

ue_sym_encrypter *ue_sym_encrypter_create();

void ue_sym_encrypter_destroy(ue_sym_encrypter *encrypter);

void ue_sym_encrypter_destroy_all(ue_sym_encrypter *encrypter);

bool ue_sym_encrypter_set_key(ue_sym_encrypter *encrypter, ue_sym_key *key);

size_t ue_sym_encrypter_get_iv_size(ue_sym_encrypter *encrypter);

unsigned char *ue_sym_encrypter_encrypt(ue_sym_encrypter *encrypter, unsigned char *plaintext, size_t plaintext_size, unsigned char *iv, unsigned int iv_size, size_t *ciphertext_size);

unsigned char *ue_sym_encrypter_decrypt(ue_sym_encrypter *encrypter, unsigned char *ciphertext, size_t ciphertext_size, unsigned char *iv, unsigned int iv_size, size_t *plaintext_size);

#endif
