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

#include <uecm/api/key/public_key.h>
#include <uecm/impl/errorHandling/openssl_error_handling.h>
#include <ueum/ueum.h>
#include <ei/ei.h>

#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

struct uecm_public_key {
    uecm_public_key_type type;
    EVP_PKEY *impl;
    int bits;
};

uecm_public_key *uecm_public_key_create(uecm_public_key_type key_type, void *impl, int bits) {
    uecm_public_key *pk;

    pk = NULL;

    ueum_safe_alloc(pk, uecm_public_key, 1);

    pk->impl = EVP_PKEY_new();

    if (key_type == RSA_PUBLIC_KEY) {
        EVP_PKEY_set1_RSA(pk->impl, (RSA *)impl);
        pk->type = RSA_PUBLIC_KEY;
    } else {
        uecm_public_key_destroy(pk);
        ei_stacktrace_push_msg("Specified key type is unknown");
        return NULL;
    }

    pk->bits = bits;

    /*if (!uecm_public_key_is_valid(pk)) {
        uecm_public_key_destroy(pk);
        return NULL;
    }*/

    return pk;
}

void uecm_public_key_destroy(uecm_public_key *pk) {
    if (pk) {
        if (pk->impl) {
            EVP_PKEY_free(pk->impl);
        }
        ueum_safe_free(pk);
    }
}

static bool is_valid_rsa_public_key(RSA *pk) {
    const BIGNUM *n, *e, *d;

    /**
     * from uecm_rsa_ameth.c do_rsa_print : has a public key
     * from uecm_rsa_chk.c RSA_check_key : doesn't have n (modulus) and e (public exponent);
     */

     RSA_get0_key(pk, &n, &e, &d);

    if (!pk || d || !e || !e) {
        return false;
    }

    /**
     * from http://rt.openssl.org/Ticket/Display.html?user=guest&pass=guest&id=1454
     * doesnt have a valid public exponent
     */
    return BN_is_odd(e) && !BN_is_one(e);
}

int uecm_public_key_size(uecm_public_key *pk) {
    if (pk->type == RSA_PUBLIC_KEY) {
        return RSA_size((RSA *)pk->impl);
    }

    ei_stacktrace_push_msg("Not implemented key type");

    return -1;
}

/*bool uecm_public_key_is_valid(uecm_public_key *pk) {
    return true;

    if (pk->type == RSA_PUBLIC_KEY) {
        return is_valid_rsa_public_key(EVP_PKEY_get1_RSA(pk->impl)) && uecm_public_key_size(pk) == pk->bits;
    }

    ei_stacktrace_push_msg("Not implemented key type");

    return false;
}*/

void *uecm_public_key_get_impl(uecm_public_key *pk) {
    return pk->impl;
}

void *uecm_public_key_get_rsa_impl(uecm_public_key *pk) {
    if (!pk->impl) {
        ei_stacktrace_push_msg("Specified public key have no implementation");
        return NULL;
    }
    return EVP_PKEY_get1_RSA(pk->impl);
}

bool uecm_public_key_print(uecm_public_key *pk, FILE *out_fd) {
    RSA *rsa;

    ei_check_parameter_or_return(pk);
    ei_check_parameter_or_return(out_fd);

    rsa = NULL;

    if (EVP_PKEY_id(pk->impl) == EVP_PKEY_RSA) {
        if ((rsa = EVP_PKEY_get1_RSA(pk->impl)) == NULL) {
            return false;
        }
        RSA_print_fp(out_fd, rsa, 0);
        RSA_free(rsa);
        return true;
    }

    return false;
}
