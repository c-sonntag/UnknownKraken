#ifndef UNKNOWNECHO_CRYPTO_METADATA_H
#define UNKNOWNECHO_CRYPTO_METADATA_H

#include <unknownecho/crypto/api/key/sym_key.h>
#include <unknownecho/crypto/api/key/public_key.h>
#include <unknownecho/crypto/api/key/private_key.h>
#include <unknownecho/bool.h>

typedef struct {
    ue_sym_key *sym_key;
    ue_public_key *cipher_pk, *signer_pk;
    ue_private_key *cipher_sk, *signer_sk;
    const char *cipher_name;
    const char *digest_name;
} ue_crypto_metadata;

ue_crypto_metadata *ue_crypto_metadata_create_empty();

void ue_crypto_metadata_destroy(ue_crypto_metadata *metadata);

void ue_crypto_metadata_destroy_all(ue_crypto_metadata *metadata);

ue_sym_key *ue_crypto_metadata_get_sym_key(ue_crypto_metadata *metadata);

bool ue_crypto_metadata_set_sym_key(ue_crypto_metadata *metadata, ue_sym_key *key);

ue_public_key *ue_crypto_metadata_get_cipher_public_key(ue_crypto_metadata *metadata);

bool ue_crypto_metadata_set_cipher_public_key(ue_crypto_metadata *metadata, ue_public_key *pk);

ue_private_key *ue_crypto_metadata_get_cipher_private_key(ue_crypto_metadata *metadata);

bool ue_crypto_metadata_set_cipher_private_key(ue_crypto_metadata *metadata, ue_private_key *sk);

ue_public_key *ue_crypto_metadata_get_signer_public_key(ue_crypto_metadata *metadata);

bool ue_crypto_metadata_set_signer_public_key(ue_crypto_metadata *metadata, ue_public_key *pk);

ue_private_key *ue_crypto_metadata_get_signer_private_key(ue_crypto_metadata *metadata);

bool ue_crypto_metadata_set_signer_private_key(ue_crypto_metadata *metadata, ue_private_key *sk);

const char *ue_crypto_metadata_get_cipher_name(ue_crypto_metadata *metadata);

bool ue_crypto_metadata_set_cipher_name(ue_crypto_metadata *metadata, const char *cipher_name);

const char *ue_crypto_metadata_get_digest_name(ue_crypto_metadata *metadata);

bool ue_crypto_metadata_set_digest_name(ue_crypto_metadata *metadata, const char *digest_name);

#endif
