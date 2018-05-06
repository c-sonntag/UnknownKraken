#include <unknownecho/crypto/factory/crypto_metadata_factory.h>
#include <unknownecho/crypto/factory/rsa_asym_key_factory.h>
#include <unknownecho/crypto/factory/sym_key_factory.h>
#include <unknownecho/crypto/api/key/asym_key.h>
#include <unknownecho/string/string_utility.h>
#include <unknownecho/defines.h>

ue_crypto_metadata *ue_crypto_metadata_create_default() {
    ue_crypto_metadata *crypto_metadata;
    ue_asym_key *cipher_keys, *signer_keys;

    crypto_metadata = ue_crypto_metadata_create_empty();

    cipher_keys = ue_rsa_asym_key_create(UNKNOWNECHO_DEFAULT_RSA_KEY_BITS);
    signer_keys = ue_rsa_asym_key_create(UNKNOWNECHO_DEFAULT_RSA_KEY_BITS);

    crypto_metadata->cipher_pk = cipher_keys->pk;
    crypto_metadata->cipher_sk = cipher_keys->sk;
    crypto_metadata->signer_pk = signer_keys->pk;
    crypto_metadata->signer_sk = signer_keys->sk;

    ue_asym_key_destroy(cipher_keys);
    ue_asym_key_destroy(signer_keys);

    crypto_metadata->digest_name = ue_string_create_from(UNKNOWNECHO_DEFAULT_DIGEST_NAME);
    crypto_metadata->cipher_name = ue_string_create_from(UNKNOWNECHO_DEFAULT_CIPHER_NAME);

    crypto_metadata->sym_key = ue_sym_key_create_random();

    return crypto_metadata;
}
