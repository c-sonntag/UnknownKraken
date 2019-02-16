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

#include <uecm/api/signature/signer.h>
#include <uecm/impl/errorHandling/openssl_error_handling.h>
#include <ei/ei.h>
#include <ueum/ueum.h>

#include <openssl/evp.h>

#include <string.h>

struct uecm_signer {
    uecm_public_key *public_key;
    uecm_private_key *private_key;
    const EVP_MD *md;
    EVP_MD_CTX *ctx;
};

uecm_signer *uecm_signer_create(const char *digest_name) {
    uecm_signer *signer;

    signer = NULL;

    ueum_safe_alloc(signer, uecm_signer, 1);
    signer->public_key = NULL;
    signer->private_key = NULL;
    signer->md = EVP_get_digestbyname(digest_name);
    signer->ctx = EVP_MD_CTX_create();

    return signer;
}

void uecm_signer_destroy(uecm_signer *signer) {
    if (signer) {
        if (signer->ctx) {
            EVP_MD_CTX_destroy(signer->ctx);
        }
        ueum_safe_free(signer);
    }
}

bool uecm_signer_set_public_key(uecm_signer *signer, uecm_public_key *public_key) {
    signer->public_key = public_key;
    return true;
}

bool uecm_signer_set_private_key(uecm_signer *signer, uecm_private_key *private_key) {
    signer->private_key = private_key;
    return true;
}

bool uecm_signer_sign_buffer(uecm_signer *signer, const unsigned char *buf, size_t buf_length, unsigned char **signature, size_t *signature_length) {
    bool result;
    char *error_buffer;

    result = false;
    error_buffer = NULL;
    *signature = NULL;

    if (EVP_DigestSignInit(signer->ctx, NULL, signer->md, NULL, uecm_private_key_get_impl(signer->private_key)) != 1) {
        uecm_openssl_error_handling(error_buffer, "DigestSign initialisation");
        goto clean_up;
    }

    if (EVP_DigestSignUpdate(signer->ctx, buf, buf_length) != 1) {
        uecm_openssl_error_handling(error_buffer, "DigestSign update");
        goto clean_up;
    }

    if (EVP_DigestSignFinal(signer->ctx, NULL, signature_length) != 1) {
        uecm_openssl_error_handling(error_buffer, "DigestSign final");
        goto clean_up;
    }

    if ((*signature = OPENSSL_malloc(sizeof(unsigned char) * (*signature_length))) == NULL) {
        uecm_openssl_error_handling(error_buffer, "Alloc signature");
        goto clean_up;
    }

    if (EVP_DigestSignFinal(signer->ctx, *signature, signature_length) != 1) {
        uecm_openssl_error_handling(error_buffer, "DigestSign final after allocation");
        goto clean_up;
    }

    result = true;

clean_up:
    if (*signature && !result) {
        OPENSSL_free(*signature);
        *signature = NULL;
    }
    return result;
}

bool uecm_signer_verify_buffer(uecm_signer *signer, const unsigned char *buf, size_t buf_length, unsigned char *signature, size_t signature_length) {
    char *error_buffer;

    error_buffer = NULL;

    if (EVP_DigestVerifyInit(signer->ctx, NULL, signer->md, NULL, uecm_public_key_get_impl(signer->public_key)) != 1) {
        uecm_openssl_error_handling(error_buffer, "DigestVerify initialisation");
        return false;
    }

    if (EVP_DigestVerifyUpdate(signer->ctx, buf, buf_length) != 1) {
        uecm_openssl_error_handling(error_buffer, "DigestVerify update");
        return false;
    }

    if (EVP_DigestVerifyFinal(signer->ctx, signature, signature_length) != 1) {
        uecm_openssl_error_handling(error_buffer, "DigestVerify final. Buf and signature doesn't matched");
        return false;
    }

    return true;
}
