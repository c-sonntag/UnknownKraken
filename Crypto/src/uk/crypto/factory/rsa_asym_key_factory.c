/*******************************************************************************
 * Copyright (C) 2018 Charly Lamothe                                           *
 *                                                                             *
 * This file is part of LibUnknownEchoCryptoModule.                            *
 *                                                                             *
 *   Licensed under the Apache License, Version 2.0 (the "License");           *
 *   you may not use this file except in compliance with the License.          *
 *   You may obtain a copy of the License at                                   *
 *                                                                             *
 *   http://www.apache.org/licenses/LICENSE-2.0                                *
 *                                                                             *
 *   Unless required by applicable law or agreed to in writing, software       *
 *   distributed under the License is distributed on an "AS IS" BASIS,         *
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  *
 *   See the License for the specific language governing permissions and       *
 *   limitations under the License.                                            *
 *******************************************************************************/

#include <uk/crypto/factory/rsa_asym_key_factory.h>
#include <uk/crypto/impl/errorHandling/openssl_error_handling.h>
#include <uk/crypto/impl/key/rsa_keypair_generation.h>
#include <uk/crypto/utils/crypto_random.h>
#include <uk/utils/ei.h>
#include <uk/utils/ueum.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/bn.h>

#include <stdio.h>
#include <limits.h>

static bool uk_crypto_rsa_get_string_from_keypair(RSA *keypair, char **pub_key, char **priv_key, size_t *pub_key_length, size_t *priv_key_length) {
    bool succeed;
    int priv_key_length_tmp, pub_key_length_tmp;
    BIO *priv, *pub;
    char *pub_key_tmp, *priv_key_tmp, *error_buffer;

    succeed = false;
    priv = NULL;
    pub = NULL;
    pub_key_tmp = NULL;
    priv_key_tmp = NULL;
    error_buffer = NULL;

    if ((priv = BIO_new(BIO_s_mem())) == NULL) {
        uk_crypto_openssl_error_handling(error_buffer, "BIO_new private key");
        goto clean_up;
    }

    if ((pub = BIO_new(BIO_s_mem())) == NULL) {
        uk_crypto_openssl_error_handling(error_buffer, "BIO_new public key");
        goto clean_up;
    }

    if (!(PEM_write_bio_RSAPrivateKey(priv, keypair, NULL, NULL, 0, NULL, NULL))) {
        uk_crypto_openssl_error_handling(error_buffer, "PEM_write_bio_RSAPrivateKey");
        goto clean_up;
    }

    if (!(PEM_write_bio_RSAPublicKey(pub, keypair))) {
        uk_crypto_openssl_error_handling(error_buffer, "PEM_write_bio_RSAPublicKey");
        goto clean_up;
    }

    priv_key_length_tmp = BIO_pending(priv);
    pub_key_length_tmp = BIO_pending(pub);

    uk_utils_safe_alloc(priv_key_tmp, char, priv_key_length_tmp + 1);
    uk_utils_safe_alloc(pub_key_tmp, char, pub_key_length_tmp + 1);

    if (BIO_read(priv, priv_key_tmp, priv_key_length_tmp) < 0) {
        uk_crypto_openssl_error_handling(error_buffer, "BIO_read private key");
        goto clean_up;
    }

    if (BIO_read(pub, pub_key_tmp, pub_key_length_tmp) < 0) {
        uk_crypto_openssl_error_handling(error_buffer, "BIO_read public key");
        goto clean_up;
    }

    priv_key_tmp[priv_key_length_tmp] = '\0';
    pub_key_tmp[pub_key_length_tmp] = '\0';

    *priv_key = priv_key_tmp;
    *pub_key = pub_key_tmp;
    *pub_key_length = (size_t)pub_key_length_tmp;
    *priv_key_length = (size_t)priv_key_length_tmp;

    succeed = true;

clean_up:
    BIO_free_all(pub);
    BIO_free_all(priv);
    return succeed;
}

static bool uk_crypto_rsa_get_pub_key_from_file(const char *file_name, RSA **pub_key) {
    FILE *fd;
    char *error_buffer;

    fd = NULL;
    error_buffer = NULL;

    if ((fd = fopen(file_name, "rb")) == NULL) {
        uk_utils_stacktrace_push_errno();
        return false;
    }

    *pub_key = RSA_new();

    if ((*pub_key = PEM_read_RSA_PUBKEY(fd, pub_key, NULL, NULL)) == NULL) {
        RSA_free(*pub_key);
        fclose(fd);
        uk_crypto_openssl_error_handling(error_buffer, "PEM_read_RSA_PUBKEY");
        return false;
    }

    fclose(fd);
    return true;
}

static bool uk_crypto_rsa_get_priv_key_from_file(const char *file_name, RSA **priv_key) {
    FILE *fd;
    char *error_buffer;

    fd = NULL;
    error_buffer = NULL;

    if ((fd = fopen(file_name, "rb")) == NULL) {
        uk_utils_stacktrace_push_errno();
        return false;
    }

    *priv_key = RSA_new();

    if ((*priv_key = PEM_read_RSAPrivateKey(fd, priv_key, NULL, NULL)) == NULL) {
        RSA_free(*priv_key);
        fclose(fd);
        uk_crypto_openssl_error_handling(error_buffer, "PEM_read_RSAPrivateKey");
        return false;
    }

    fclose(fd);
    return true;
}

uk_crypto_asym_key *uk_crypto_rsa_asym_key_create(int bits) {
    uk_crypto_asym_key *akey;
    RSA *uk_crypto_rsa_key_pair, *uk_crypto_rsa_pk, *uk_crypto_rsa_sk;
    BIO *uk_crypto_rsa_pk_bio, *uk_crypto_rsa_sk_bio;
    char *pub_key_buf, *priv_key_buf;
    size_t pub_key_buf_length, priv_key_buf_length;
    uk_crypto_private_key *sk;
    uk_crypto_public_key *pk;

    akey = NULL;
    uk_crypto_rsa_key_pair = NULL;
    uk_crypto_rsa_pk = NULL;
    uk_crypto_rsa_sk = NULL;
    uk_crypto_rsa_pk_bio = NULL;
    uk_crypto_rsa_sk_bio = NULL;
    pub_key_buf = NULL;
    priv_key_buf = NULL;
    sk = NULL;
    pk = NULL;

    if ((uk_crypto_rsa_key_pair = uk_crypto_rsa_keypair_gen(bits)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to gen openssl RSA keypair");
        goto clean_up;
    }

    if (!(uk_crypto_rsa_get_string_from_keypair(uk_crypto_rsa_key_pair, &pub_key_buf, &priv_key_buf, &pub_key_buf_length, &priv_key_buf_length))) {
        uk_utils_stacktrace_push_msg("Failed to get string from openssl RSA keypair");
        goto clean_up;
    }

    if (pub_key_buf_length > UINT_MAX) {
        uk_utils_stacktrace_push_msg("BIO_new_mem_buf() need a length in int, however pub_key_buf_length is > UINT_MAX");
        goto clean_up;
    }

    /* It's safe to cast pub_key_buf_length to int as we compare it's value with UINT_MAX */
    if ((uk_crypto_rsa_pk_bio = BIO_new_mem_buf(pub_key_buf, (int)pub_key_buf_length)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to init new mem BIO for pub key buf");
        goto clean_up;
    }

    if ((uk_crypto_rsa_pk = PEM_read_bio_RSAPublicKey(uk_crypto_rsa_pk_bio, NULL, NULL, NULL)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to build openssl rsa pk from string");
        goto clean_up;
    }

    if ((pk = uk_crypto_public_key_create(RSA_PUBLIC_KEY, (void *)uk_crypto_rsa_pk, bits)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to create new rsa public key");
        goto clean_up;
    }

    if (priv_key_buf_length > UINT_MAX) {
        uk_utils_stacktrace_push_msg("BIO_new_mem_buf() need a length in int, however priv_key_buf_length is > UINT_MAX");
        goto clean_up;
    }

    /* It's safe to cast priv_key_buf_length to int as we compare it's value with UINT_MAX */
    if ((uk_crypto_rsa_sk_bio = BIO_new_mem_buf(priv_key_buf, (int)priv_key_buf_length)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to init new mem BIO for priv key buf");
        goto clean_up;
    }

    if ((uk_crypto_rsa_sk = PEM_read_bio_RSAPrivateKey(uk_crypto_rsa_sk_bio, NULL, NULL, NULL)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to build openssl rsa sk from string");
        goto clean_up;
    }

    if ((sk = uk_crypto_private_key_create(RSA_PRIVATE_KEY, (void *)uk_crypto_rsa_sk, bits)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to create new rsa private key");
        goto clean_up;
    }

    if ((akey = uk_crypto_asym_key_create(pk, sk)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to create asym key");
        goto clean_up;
    }

clean_up:
    uk_utils_safe_free(pub_key_buf);
    uk_utils_safe_free(priv_key_buf);
    BIO_free_all(uk_crypto_rsa_pk_bio);
    BIO_free_all(uk_crypto_rsa_sk_bio);
    RSA_free(uk_crypto_rsa_key_pair);
    RSA_free(uk_crypto_rsa_pk);
    RSA_free(uk_crypto_rsa_sk);
    return akey;
}

uk_crypto_public_key *uk_crypto_rsa_public_key_create_pk_from_file(char *file_path) {
    uk_crypto_public_key *pk;
    RSA *uk_crypto_rsa_pk;

    pk = NULL;
    uk_crypto_rsa_pk = NULL;

    if (!(uk_crypto_rsa_get_pub_key_from_file(file_path, &uk_crypto_rsa_pk))) {
        uk_utils_stacktrace_push_msg("Failed to read openssl rsa public key from file");
        return NULL;
    }

    if ((pk = uk_crypto_public_key_create(RSA_PUBLIC_KEY, (void *)uk_crypto_rsa_pk, RSA_size(uk_crypto_rsa_pk))) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to build public key from openssl rsa public key");
        RSA_free(uk_crypto_rsa_pk);
        return NULL;
    }

    return pk;
}

uk_crypto_private_key *uk_crypto_rsa_private_key_create_sk_from_file(char *file_path) {
    uk_crypto_private_key *sk;
    RSA *uk_crypto_rsa_sk;

    sk = NULL;
    uk_crypto_rsa_sk = NULL;

    if ((uk_crypto_rsa_get_priv_key_from_file(file_path, &uk_crypto_rsa_sk)) == false) {
        uk_utils_stacktrace_push_msg("Failed to read openssl rsa private key from file");
        return NULL;
    }

    if ((sk = uk_crypto_private_key_create(RSA_PRIVATE_KEY, (void *)uk_crypto_rsa_sk, RSA_size(uk_crypto_rsa_sk))) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to build private key from openssl rsa private key");
        RSA_free(uk_crypto_rsa_sk);
        return NULL;
    }

    return sk;
}

uk_crypto_asym_key *uk_crypto_rsa_asym_key_create_from_files(char *pk_file_path, char *sk_file_path) {
    uk_crypto_asym_key *akey;

    akey = NULL;

    if ((akey = uk_crypto_asym_key_create(uk_crypto_rsa_public_key_create_pk_from_file(pk_file_path),
        uk_crypto_rsa_private_key_create_sk_from_file(sk_file_path))) == NULL) {

        uk_utils_stacktrace_push_msg("Failed to create asym key");
        return NULL;
    }

    return akey;
}

uk_crypto_public_key *uk_crypto_rsa_public_key_from_x509_certificate(uk_crypto_x509_certificate *certificate) {
    uk_crypto_public_key *public_key;
    EVP_PKEY *public_key_impl;
    RSA *rsa;

    public_key = NULL;
    public_key_impl = NULL;
    rsa = NULL;

    uk_utils_check_parameter_or_return(certificate);
    uk_utils_check_parameter_or_return(uk_crypto_x509_certificate_get_impl(certificate));

    public_key_impl = X509_get_pubkey(uk_crypto_x509_certificate_get_impl(certificate));
    rsa = EVP_PKEY_get1_RSA(public_key_impl);
    EVP_PKEY_free(public_key_impl);

    if ((public_key = uk_crypto_public_key_create(RSA_PUBLIC_KEY, (void *)rsa, RSA_size(rsa))) == NULL) {
        RSA_free(rsa);
        uk_utils_stacktrace_push_msg("Failed to build public key from openssl rsa public key");
        return NULL;
    }

    RSA_free(rsa);

    return public_key;
}

uk_crypto_private_key *uk_crypto_rsa_private_key_from_key_certificate(const char *file_name) {
    BIO *bio;
    uk_crypto_private_key *private_key;
    EVP_PKEY *private_key_impl;
    RSA *rsa;

    bio = NULL;
    private_key = NULL;
    private_key_impl = NULL;
    rsa = NULL;

    bio = BIO_new(BIO_s_file());
    if (!BIO_read_filename(bio, file_name)) {
        goto clean_up;
    }
    private_key_impl = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!private_key_impl) {
        goto clean_up;
    }

    rsa = EVP_PKEY_get1_RSA(private_key_impl);

    if ((private_key = uk_crypto_private_key_create(RSA_PRIVATE_KEY, (void *)rsa, RSA_size(rsa))) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to build RSA private key from key certificate file");
        goto clean_up;
    }

clean_up:
    EVP_PKEY_free(private_key_impl);
    RSA_free(rsa);
    BIO_free_all(bio);
    return private_key;
}
