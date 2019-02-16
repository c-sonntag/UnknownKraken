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

#include <uecm/api/key/private_key.h>
#include <uecm/impl/errorHandling/openssl_error_handling.h>
#include <ueum/ueum.h>
#include <ei/ei.h>

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

struct uecm_private_key {
    uecm_private_key_type type;
    EVP_PKEY *impl;
    int bits;
};

uecm_private_key *uecm_private_key_create_from_impl(void *impl) {
    EVP_PKEY *key_impl;
    RSA *rsa;
    uecm_private_key *sk;

    key_impl = (EVP_PKEY *)impl;
    if (EVP_PKEY_base_id(key_impl) == EVP_PKEY_RSA) {
        rsa = EVP_PKEY_get1_RSA(key_impl);
        sk = uecm_private_key_create(RSA_PRIVATE_KEY, rsa, RSA_size(rsa));
        RSA_free(rsa);
        return sk;
    } else {
        ei_stacktrace_push_msg("Specified key type is not supported");
    }

    return NULL;
}

uecm_private_key *uecm_private_key_create(uecm_private_key_type key_type, void *impl, int bits) {
    uecm_private_key *sk;

    sk = NULL;

    ueum_safe_alloc(sk, uecm_private_key, 1);

    sk->impl = EVP_PKEY_new();

    if (key_type == RSA_PRIVATE_KEY) {
        EVP_PKEY_set1_RSA(sk->impl, (RSA *)impl);
        sk->type = RSA_PRIVATE_KEY;
    } else {
        uecm_private_key_destroy(sk);
        ei_stacktrace_push_msg("Specified key type is unknown");
        return NULL;
    }

    sk->bits = bits;

    /*if (!uecm_private_key_is_valid(sk)) {
        uecm_private_key_destroy(sk);
        return NULL;
    }*/

    return sk;
}

void uecm_private_key_destroy(uecm_private_key *sk) {
    if (sk) {
        if (sk->impl) {
            EVP_PKEY_free(sk->impl);
        }
        ueum_safe_free(sk);
    }
}

int uecm_private_key_size(uecm_private_key *sk) {
    if (sk->type == RSA_PRIVATE_KEY) {
        return RSA_size((RSA *)sk->impl);
    }

    ei_stacktrace_push_msg("Not implemented key type");

    return -1;
}

/*bool uecm_private_key_is_valid(uecm_private_key *sk) {
    return true;

    if (sk->type == RSA_PRIVATE_KEY) {
        return RSA_check_key(EVP_PKEY_get1_RSA(sk->impl)) && uecm_private_key_size(sk) == sk->bits;
    }

    ei_stacktrace_push_msg("Not implemented key type");

    return false;
}*/

void *uecm_private_key_get_impl(uecm_private_key *sk) {
    if (!sk) {
        ei_stacktrace_push_msg("Specified sk ptr is null");
        return NULL;
    }

    if (!sk->impl) {
        ei_stacktrace_push_msg("Specified sk have no implementation");
        return NULL;
    }

    return sk->impl;
}

void *uecm_private_key_get_rsa_impl(uecm_private_key *sk) {
    if (!sk) {
        ei_stacktrace_push_msg("Specified private key ptr is null");
        return NULL;
    }

    if (!sk->impl) {
        ei_stacktrace_push_msg("This private key has no implementation");
        return NULL;
    }
    return EVP_PKEY_get1_RSA(sk->impl);
}

bool uecm_private_key_print(uecm_private_key *sk, FILE *out_fd, char *passphrase) {
    char *error_buffer;

    error_buffer = NULL;

    if (!passphrase) {
        if (PEM_write_PrivateKey(out_fd, sk->impl, NULL, NULL, 0, NULL, NULL) == 0) {
            uecm_openssl_error_handling(error_buffer, "PEM_write_PrivateKey");
            return false;
        }
    } else {
        if (PEM_write_PrivateKey(out_fd, sk->impl, EVP_aes_256_cbc(), (unsigned char *)passphrase, (int)strlen(passphrase), NULL, NULL) == 0) {
            uecm_openssl_error_handling(error_buffer, "PEM_write_PrivateKey with passphrase");
            return false;
        }
    }

    return true;
}
