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

#include <uecm/factory/rsa_asym_key_factory.h>
#include <uecm/impl/errorHandling/openssl_error_handling.h>
#include <uecm/impl/key/rsa_keypair_generation.h>
#include <uecm/utils/crypto_random.h>
#include <ei/ei.h>
#include <ueum/ueum.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/bn.h>

#include <stdio.h>
#include <limits.h>

static bool uecm_rsa_get_string_from_keypair(RSA *keypair, char **pub_key, char **priv_key, size_t *pub_key_length, size_t *priv_key_length) {
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
        uecm_openssl_error_handling(error_buffer, "BIO_new private key");
        goto clean_up;
    }

    if ((pub = BIO_new(BIO_s_mem())) == NULL) {
        uecm_openssl_error_handling(error_buffer, "BIO_new public key");
        goto clean_up;
    }

    if (!(PEM_write_bio_RSAPrivateKey(priv, keypair, NULL, NULL, 0, NULL, NULL))) {
        uecm_openssl_error_handling(error_buffer, "PEM_write_bio_RSAPrivateKey");
        goto clean_up;
    }

    if (!(PEM_write_bio_RSAPublicKey(pub, keypair))) {
        uecm_openssl_error_handling(error_buffer, "PEM_write_bio_RSAPublicKey");
        goto clean_up;
    }

    priv_key_length_tmp = BIO_pending(priv);
    pub_key_length_tmp = BIO_pending(pub);

    ueum_safe_alloc(priv_key_tmp, char, priv_key_length_tmp + 1);
    ueum_safe_alloc(pub_key_tmp, char, pub_key_length_tmp + 1);

    if (BIO_read(priv, priv_key_tmp, priv_key_length_tmp) < 0) {
        uecm_openssl_error_handling(error_buffer, "BIO_read private key");
        goto clean_up;
    }

    if (BIO_read(pub, pub_key_tmp, pub_key_length_tmp) < 0) {
        uecm_openssl_error_handling(error_buffer, "BIO_read public key");
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

static bool uecm_rsa_get_pub_key_from_file(const char *file_name, RSA **pub_key) {
    FILE *fd;
    char *error_buffer;

    fd = NULL;
    error_buffer = NULL;

    if ((fd = fopen(file_name, "rb")) == NULL) {
        ei_stacktrace_push_errno();
        return false;
    }

    *pub_key = RSA_new();

    if ((*pub_key = PEM_read_RSA_PUBKEY(fd, pub_key, NULL, NULL)) == NULL) {
        RSA_free(*pub_key);
        fclose(fd);
        uecm_openssl_error_handling(error_buffer, "PEM_read_RSA_PUBKEY");
        return false;
    }

    fclose(fd);
    return true;
}

static bool uecm_rsa_get_priv_key_from_file(const char *file_name, RSA **priv_key) {
    FILE *fd;
    char *error_buffer;

    fd = NULL;
    error_buffer = NULL;

    if ((fd = fopen(file_name, "rb")) == NULL) {
        ei_stacktrace_push_errno();
        return false;
    }

    *priv_key = RSA_new();

    if ((*priv_key = PEM_read_RSAPrivateKey(fd, priv_key, NULL, NULL)) == NULL) {
        RSA_free(*priv_key);
        fclose(fd);
        uecm_openssl_error_handling(error_buffer, "PEM_read_RSAPrivateKey");
        return false;
    }

    fclose(fd);
    return true;
}

uecm_asym_key *uecm_rsa_asym_key_create(int bits) {
    uecm_asym_key *akey;
    RSA *uecm_rsa_key_pair, *uecm_rsa_pk, *uecm_rsa_sk;
    BIO *uecm_rsa_pk_bio, *uecm_rsa_sk_bio;
    char *pub_key_buf, *priv_key_buf;
    size_t pub_key_buf_length, priv_key_buf_length;
    uecm_private_key *sk;
    uecm_public_key *pk;

    akey = NULL;
    uecm_rsa_key_pair = NULL;
    uecm_rsa_pk = NULL;
    uecm_rsa_sk = NULL;
    uecm_rsa_pk_bio = NULL;
    uecm_rsa_sk_bio = NULL;
    pub_key_buf = NULL;
    priv_key_buf = NULL;
    sk = NULL;
    pk = NULL;

    if ((uecm_rsa_key_pair = uecm_rsa_keypair_gen(bits)) == NULL) {
        ei_stacktrace_push_msg("Failed to gen openssl RSA keypair");
        goto clean_up;
    }

    if (!(uecm_rsa_get_string_from_keypair(uecm_rsa_key_pair, &pub_key_buf, &priv_key_buf, &pub_key_buf_length, &priv_key_buf_length))) {
        ei_stacktrace_push_msg("Failed to get string from openssl RSA keypair");
        goto clean_up;
    }

    if (pub_key_buf_length > UINT_MAX) {
        ei_stacktrace_push_msg("BIO_new_mem_buf() need a length in int, however pub_key_buf_length is > UINT_MAX");
        goto clean_up;
    }

    /* It's safe to cast pub_key_buf_length to int as we compare it's value with UINT_MAX */
    if ((uecm_rsa_pk_bio = BIO_new_mem_buf(pub_key_buf, (int)pub_key_buf_length)) == NULL) {
        ei_stacktrace_push_msg("Failed to init new mem BIO for pub key buf");
        goto clean_up;
    }

    if ((uecm_rsa_pk = PEM_read_bio_RSAPublicKey(uecm_rsa_pk_bio, NULL, NULL, NULL)) == NULL) {
        ei_stacktrace_push_msg("Failed to build openssl rsa pk from string");
        goto clean_up;
    }

    if ((pk = uecm_public_key_create(RSA_PUBLIC_KEY, (void *)uecm_rsa_pk, bits)) == NULL) {
        ei_stacktrace_push_msg("Failed to create new rsa public key");
        goto clean_up;
    }

    if (priv_key_buf_length > UINT_MAX) {
        ei_stacktrace_push_msg("BIO_new_mem_buf() need a length in int, however priv_key_buf_length is > UINT_MAX");
        goto clean_up;
    }

    /* It's safe to cast priv_key_buf_length to int as we compare it's value with UINT_MAX */
    if ((uecm_rsa_sk_bio = BIO_new_mem_buf(priv_key_buf, (int)priv_key_buf_length)) == NULL) {
        ei_stacktrace_push_msg("Failed to init new mem BIO for priv key buf");
        goto clean_up;
    }

    if ((uecm_rsa_sk = PEM_read_bio_RSAPrivateKey(uecm_rsa_sk_bio, NULL, NULL, NULL)) == NULL) {
        ei_stacktrace_push_msg("Failed to build openssl rsa sk from string");
        goto clean_up;
    }

    if ((sk = uecm_private_key_create(RSA_PRIVATE_KEY, (void *)uecm_rsa_sk, bits)) == NULL) {
        ei_stacktrace_push_msg("Failed to create new rsa private key");
        goto clean_up;
    }

    if ((akey = uecm_asym_key_create(pk, sk)) == NULL) {
        ei_stacktrace_push_msg("Failed to create asym key");
        goto clean_up;
    }

clean_up:
    ueum_safe_free(pub_key_buf);
    ueum_safe_free(priv_key_buf);
    BIO_free_all(uecm_rsa_pk_bio);
    BIO_free_all(uecm_rsa_sk_bio);
    RSA_free(uecm_rsa_key_pair);
    RSA_free(uecm_rsa_pk);
    RSA_free(uecm_rsa_sk);
    return akey;
}

uecm_public_key *uecm_rsa_public_key_create_pk_from_file(char *file_path) {
    uecm_public_key *pk;
    RSA *uecm_rsa_pk;

    pk = NULL;
    uecm_rsa_pk = NULL;

    if (!(uecm_rsa_get_pub_key_from_file(file_path, &uecm_rsa_pk))) {
        ei_stacktrace_push_msg("Failed to read openssl rsa public key from file");
        return NULL;
    }

    if ((pk = uecm_public_key_create(RSA_PUBLIC_KEY, (void *)uecm_rsa_pk, RSA_size(uecm_rsa_pk))) == NULL) {
        ei_stacktrace_push_msg("Failed to build public key from openssl rsa public key");
        RSA_free(uecm_rsa_pk);
        return NULL;
    }

    return pk;
}

uecm_private_key *uecm_rsa_private_key_create_sk_from_file(char *file_path) {
    uecm_private_key *sk;
    RSA *uecm_rsa_sk;

    sk = NULL;
    uecm_rsa_sk = NULL;

    if ((uecm_rsa_get_priv_key_from_file(file_path, &uecm_rsa_sk)) == false) {
        ei_stacktrace_push_msg("Failed to read openssl rsa private key from file");
        return NULL;
    }

    if ((sk = uecm_private_key_create(RSA_PRIVATE_KEY, (void *)uecm_rsa_sk, RSA_size(uecm_rsa_sk))) == NULL) {
        ei_stacktrace_push_msg("Failed to build private key from openssl rsa private key");
        RSA_free(uecm_rsa_sk);
        return NULL;
    }

    return sk;
}

uecm_asym_key *uecm_rsa_asym_key_create_from_files(char *pk_file_path, char *sk_file_path) {
    uecm_asym_key *akey;

    akey = NULL;

    if ((akey = uecm_asym_key_create(uecm_rsa_public_key_create_pk_from_file(pk_file_path),
        uecm_rsa_private_key_create_sk_from_file(sk_file_path))) == NULL) {

        ei_stacktrace_push_msg("Failed to create asym key");
        return NULL;
    }

    return akey;
}

uecm_public_key *uecm_rsa_public_key_from_x509_certificate(uecm_x509_certificate *certificate) {
    uecm_public_key *public_key;
    EVP_PKEY *public_key_impl;
    RSA *rsa;

    public_key = NULL;
    public_key_impl = NULL;
    rsa = NULL;

    ei_check_parameter_or_return(certificate);
    ei_check_parameter_or_return(uecm_x509_certificate_get_impl(certificate));

    public_key_impl = X509_get_pubkey(uecm_x509_certificate_get_impl(certificate));
    rsa = EVP_PKEY_get1_RSA(public_key_impl);
    EVP_PKEY_free(public_key_impl);

    if ((public_key = uecm_public_key_create(RSA_PUBLIC_KEY, (void *)rsa, RSA_size(rsa))) == NULL) {
        RSA_free(rsa);
        ei_stacktrace_push_msg("Failed to build public key from openssl rsa public key");
        return NULL;
    }

    RSA_free(rsa);

    return public_key;
}

uecm_private_key *uecm_rsa_private_key_from_key_certificate(const char *file_name) {
    BIO *bio;
    uecm_private_key *private_key;
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

    if ((private_key = uecm_private_key_create(RSA_PRIVATE_KEY, (void *)rsa, RSA_size(rsa))) == NULL) {
        ei_stacktrace_push_msg("Failed to build RSA private key from key certificate file");
        goto clean_up;
    }

clean_up:
    EVP_PKEY_free(private_key_impl);
    RSA_free(rsa);
    BIO_free_all(bio);
    return private_key;
}
