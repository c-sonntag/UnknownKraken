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

#include <uk/crypto/api/key/private_key.h>
#include <uk/crypto/impl/errorHandling/openssl_error_handling.h>
#include <uk/utils/ueum.h>
#include <uk/utils/ei.h>

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

struct uk_crypto_private_key {
    uk_crypto_private_key_type type;
    EVP_PKEY *impl;
    int bits;
};

uk_crypto_private_key *uk_crypto_private_key_create_from_impl(void *impl) {
    EVP_PKEY *key_impl;
    RSA *rsa;
    uk_crypto_private_key *sk;

    key_impl = (EVP_PKEY *)impl;
    if (EVP_PKEY_base_id(key_impl) == EVP_PKEY_RSA) {
        rsa = EVP_PKEY_get1_RSA(key_impl);
        sk = uk_crypto_private_key_create(RSA_PRIVATE_KEY, rsa, RSA_size(rsa));
        RSA_free(rsa);
        return sk;
    } else {
        uk_utils_stacktrace_push_msg("Specified key type is not supported");
    }

    return NULL;
}

uk_crypto_private_key *uk_crypto_private_key_create(uk_crypto_private_key_type key_type, void *impl, int bits) {
    uk_crypto_private_key *sk;

    sk = NULL;

    uk_utils_safe_alloc(sk, uk_crypto_private_key, 1);

    sk->impl = EVP_PKEY_new();

    if (key_type == RSA_PRIVATE_KEY) {
        EVP_PKEY_set1_RSA(sk->impl, (RSA *)impl);
        sk->type = RSA_PRIVATE_KEY;
    } else {
        uk_crypto_private_key_destroy(sk);
        uk_utils_stacktrace_push_msg("Specified key type is unknown");
        return NULL;
    }

    sk->bits = bits;

    /*if (!uk_crypto_private_key_is_valid(sk)) {
        uk_crypto_private_key_destroy(sk);
        return NULL;
    }*/

    return sk;
}

void uk_crypto_private_key_destroy(uk_crypto_private_key *sk) {
    if (sk) {
        if (sk->impl) {
            EVP_PKEY_free(sk->impl);
        }
        uk_utils_safe_free(sk);
    }
}

int uk_crypto_private_key_size(uk_crypto_private_key *sk) {
    if (sk->type == RSA_PRIVATE_KEY) {
        return RSA_size((RSA *)sk->impl);
    }

    uk_utils_stacktrace_push_msg("Not implemented key type");

    return -1;
}

/*bool uk_crypto_private_key_is_valid(uk_crypto_private_key *sk) {
    return true;

    if (sk->type == RSA_PRIVATE_KEY) {
        return RSA_check_key(EVP_PKEY_get1_RSA(sk->impl)) && uk_crypto_private_key_size(sk) == sk->bits;
    }

    uk_utils_stacktrace_push_msg("Not implemented key type");

    return false;
}*/

void *uk_crypto_private_key_get_impl(uk_crypto_private_key *sk) {
    if (!sk) {
        uk_utils_stacktrace_push_msg("Specified sk ptr is null");
        return NULL;
    }

    if (!sk->impl) {
        uk_utils_stacktrace_push_msg("Specified sk have no implementation");
        return NULL;
    }

    return sk->impl;
}

void *uk_crypto_private_key_get_rsa_impl(uk_crypto_private_key *sk) {
    if (!sk) {
        uk_utils_stacktrace_push_msg("Specified private key ptr is null");
        return NULL;
    }

    if (!sk->impl) {
        uk_utils_stacktrace_push_msg("This private key has no implementation");
        return NULL;
    }
    return EVP_PKEY_get1_RSA(sk->impl);
}

bool uk_crypto_private_key_print(uk_crypto_private_key *sk, FILE *out_fd, char *passphrase) {
    char *error_buffer;

    error_buffer = NULL;

    if (!passphrase) {
        if (PEM_write_PrivateKey(out_fd, sk->impl, NULL, NULL, 0, NULL, NULL) == 0) {
            uk_crypto_openssl_error_handling(error_buffer, "PEM_write_PrivateKey");
            return false;
        }
    } else {
        if (PEM_write_PrivateKey(out_fd, sk->impl, EVP_aes_256_cbc(), (unsigned char *)passphrase, (int)strlen(passphrase), NULL, NULL) == 0) {
            uk_crypto_openssl_error_handling(error_buffer, "PEM_write_PrivateKey with passphrase");
            return false;
        }
    }

    return true;
}
