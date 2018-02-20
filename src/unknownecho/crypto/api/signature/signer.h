#ifndef UNKNOWNECHO_SIGNER_H
#define UNKNOWNECHO_SIGNER_H

#include <unknownecho/crypto/api/encryption/asym_encrypter.h>
#include <unknownecho/crypto/api/hash/hasher.h>
#include <unknownecho/bool.h>

#include <stddef.h>

typedef struct {
	ue_asym_encrypter *encrypter;
	ue_hasher *h;
} ue_signer;

ue_signer *ue_signer_create();

void ue_signer_destroy(ue_signer *s);

void ue_signer_destroy_all(ue_signer *s);

bool ue_signer_init(ue_signer *s, ue_asym_encrypter *encrypter, ue_hasher *h);

unsigned char *ue_signer_sign_buffer(ue_signer *s, const unsigned char *buf, size_t buf_length, size_t *signature_length);

bool ue_signer_verify_buffer(ue_signer *s, const unsigned char *buf, size_t buf_length, unsigned char *signature, size_t signature_length);

#endif
