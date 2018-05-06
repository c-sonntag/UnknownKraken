#include <unknownecho/crypto/api/crypto_metadata.h>
#include <unknownecho/crypto/api/key/sym_key.h>
#include <unknownecho/crypto/api/key/public_key.h>
#include <unknownecho/crypto/api/key/private_key.h>
#include <unknownecho/alloc.h>
#include <unknownecho/errorHandling/check_parameter.h>

ue_crypto_metadata *ue_crypto_metadata_create_empty() {
    ue_crypto_metadata *metadata;

    ue_safe_alloc(metadata, ue_crypto_metadata, 1);
    metadata->cipher_name = NULL;
    metadata->cipher_pk = NULL;
    metadata->cipher_sk = NULL;
    metadata->digest_name = NULL;
    metadata->signer_pk = NULL;
    metadata->signer_sk = NULL;
    metadata->sym_key = NULL;

    return metadata;
}

void ue_crypto_metadata_destroy(ue_crypto_metadata *metadata) {
    if (metadata) {
        ue_safe_free(metadata->cipher_name);
        ue_safe_free(metadata->digest_name);
        ue_safe_free(metadata);
    }
}

void ue_crypto_metadata_destroy_all(ue_crypto_metadata *metadata) {
    if (metadata) {
        ue_safe_free(metadata->cipher_name);
        ue_safe_free(metadata->digest_name);
        ue_public_key_destroy(metadata->cipher_pk);
        ue_private_key_destroy(metadata->cipher_sk);
        ue_public_key_destroy(metadata->signer_pk);
        ue_private_key_destroy(metadata->signer_sk);
        ue_sym_key_destroy(metadata->sym_key);
        ue_safe_free(metadata);
    }
}

ue_sym_key *ue_crypto_metadata_get_sym_key(ue_crypto_metadata *metadata) {
    ue_check_parameter_or_return(metadata);

    return metadata->sym_key;
}

bool ue_crypto_metadata_set_sym_key(ue_crypto_metadata *metadata, ue_sym_key *key) {
    ue_check_parameter_or_return(metadata);
    ue_check_parameter_or_return(key);

    metadata->sym_key = key;

    return true;
}

ue_public_key *ue_crypto_metadata_get_cipher_public_key(ue_crypto_metadata *metadata) {
    ue_check_parameter_or_return(metadata);

    return metadata->cipher_pk;
}

bool ue_crypto_metadata_set_cipher_public_key(ue_crypto_metadata *metadata, ue_public_key *pk) {
    ue_check_parameter_or_return(metadata);
    ue_check_parameter_or_return(pk);

    metadata->cipher_pk = pk;

    return true;
}

ue_private_key *ue_crypto_metadata_get_cipher_private_key(ue_crypto_metadata *metadata) {
    ue_check_parameter_or_return(metadata);

    return metadata->cipher_sk;
}

bool ue_crypto_metadata_set_cipher_private_key(ue_crypto_metadata *metadata, ue_private_key *sk) {
    ue_check_parameter_or_return(metadata);
    ue_check_parameter_or_return(sk);

    metadata->cipher_sk = sk;

    return true;
}

ue_public_key *ue_crypto_metadata_get_signer_public_key(ue_crypto_metadata *metadata) {
    ue_check_parameter_or_return(metadata);

    return metadata->signer_pk;
}

bool ue_crypto_metadata_set_signer_public_key(ue_crypto_metadata *metadata, ue_public_key *pk) {
    ue_check_parameter_or_return(metadata);
    ue_check_parameter_or_return(pk);

    metadata->signer_pk = pk;

    return true;
}

ue_private_key *ue_crypto_metadata_get_signer_private_key(ue_crypto_metadata *metadata) {
    ue_check_parameter_or_return(metadata);

    return metadata->signer_sk;
}

bool ue_crypto_metadata_set_signer_private_key(ue_crypto_metadata *metadata, ue_private_key *sk) {
    ue_check_parameter_or_return(metadata);
    ue_check_parameter_or_return(sk);

    metadata->signer_sk = sk;

    return true;
}

const char *ue_crypto_metadata_get_cipher_name(ue_crypto_metadata *metadata) {
    ue_check_parameter_or_return(metadata);

    return metadata->cipher_name;
}

bool ue_crypto_metadata_set_cipher_name(ue_crypto_metadata *metadata, const char *cipher_name) {
    ue_check_parameter_or_return(metadata);
    ue_check_parameter_or_return(cipher_name);

    metadata->cipher_name = cipher_name;

    return true;
}

const char *ue_crypto_metadata_get_digest_name(ue_crypto_metadata *metadata) {
    ue_check_parameter_or_return(metadata);

    return metadata->digest_name;
}

bool ue_crypto_metadata_set_digest_name(ue_crypto_metadata *metadata, const char *digest_name) {
    ue_check_parameter_or_return(metadata);
    ue_check_parameter_or_return(digest_name);

    metadata->digest_name = digest_name;

    return true;
}
