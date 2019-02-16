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

#include <uecm/api/encryption/sym_encrypter.h>
#include <uecm/impl/errorHandling/openssl_error_handling.h>
#include <ueum/ueum.h>

#include <ei/ei.h>

#include <openssl/evp.h>

#include <limits.h>

struct uecm_sym_encrypter {
    uecm_sym_key *key;
    const EVP_CIPHER *cipher;
};

uecm_sym_encrypter *uecm_sym_encrypter_create(const char *cipher_name) {
    uecm_sym_encrypter *encrypter;
    char *error_buffer;

    encrypter = NULL;

    ueum_safe_alloc(encrypter, uecm_sym_encrypter, 1);
    encrypter->key = NULL;
    if ((encrypter->cipher = EVP_get_cipherbyname(cipher_name)) == NULL) {
        uecm_openssl_error_handling(error_buffer, "Invalid cipher name");
        ueum_safe_free(encrypter);
        return NULL;
    }

    return encrypter;
}

void uecm_sym_encrypter_destroy(uecm_sym_encrypter *encrypter) {
    if (encrypter) {
        ueum_safe_free(encrypter);
    }
}

void uecm_sym_encrypter_destroy_all(uecm_sym_encrypter *encrypter) {
    if (encrypter) {
        uecm_sym_key_destroy(encrypter->key);
        ueum_safe_free(encrypter);
    }
}

uecm_sym_key *uecm_sym_encrypter_get_key(uecm_sym_encrypter *encrypter) {
    return encrypter->key;
}

bool uecm_sym_encrypter_set_key(uecm_sym_encrypter *encrypter, uecm_sym_key *key) {
    ei_check_parameter_or_return(encrypter);

    if (!uecm_sym_key_is_valid(key)) {
        ei_stacktrace_push_msg("Specified key is invalid");
        return false;
    }

    encrypter->key = key;

    return true;
}

size_t uecm_sym_encrypter_get_iv_size(uecm_sym_encrypter *encrypter) {
    return EVP_CIPHER_iv_length(encrypter->cipher);
}

bool uecm_sym_encrypter_encrypt(uecm_sym_encrypter *encrypter, unsigned char *plaintext, size_t plaintext_size,
    unsigned char *iv, unsigned char **ciphertext, size_t *ciphertext_size) {

    int len, rlen;
    EVP_CIPHER_CTX *ctx;
    char *error_buffer;

    error_buffer = NULL;

    ei_check_parameter_or_return(encrypter);
    ei_check_parameter_or_return(plaintext);
    ei_check_parameter_or_return(iv);
    ei_check_parameter_or_return(plaintext_size);

    if (plaintext_size > INT_MAX) {
        ei_stacktrace_push_msg("EVP_EncryptUpdate() need a length in int, however plaintext_size > INT_MAX");
        return false;
    }

    if ((ctx = EVP_CIPHER_CTX_new()) == NULL) {
        uecm_openssl_error_handling(error_buffer, "EVP_CIPHER_CTX_new");
        return false;
    }

    if (EVP_EncryptInit_ex(ctx, encrypter->cipher, NULL, encrypter->key->data, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        uecm_openssl_error_handling(error_buffer, "EVP_EncryptInit_ex");
        return false;
    }

    *ciphertext = NULL;
    ueum_safe_alloc(*ciphertext, unsigned char, plaintext_size + uecm_sym_encrypter_get_iv_size(encrypter));

    /* It's safe to cast plaintext_size to int as we compare it with UINT_MAX */
    if (EVP_EncryptUpdate(ctx, *ciphertext, &len, plaintext, (int)plaintext_size) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        uecm_openssl_error_handling(error_buffer, "EVP_EncryptUpdate");
        return false;
    }

    *ciphertext_size = len;

    if (EVP_EncryptFinal_ex(ctx, *ciphertext + len, &rlen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        uecm_openssl_error_handling(error_buffer, "EVP_EncryptFinal_ex");
        return false;
    }

    *ciphertext_size += rlen;

    EVP_CIPHER_CTX_free(ctx);

    return true;
}

bool uecm_sym_encrypter_decrypt(uecm_sym_encrypter *encrypter, unsigned char *ciphertext, size_t ciphertext_size,
    unsigned char *iv, unsigned char **plaintext, size_t *plaintext_size) {

    EVP_CIPHER_CTX *ctx;
    int len, rlen;
    char *error_buffer;

    if (ciphertext_size > INT_MAX) {
        ei_stacktrace_push_msg("EVP_DecryptUpdate() need a length in int, however ciphertext_size > INT_MAX");
        return false;
    }

    error_buffer = NULL;

    if ((ctx = EVP_CIPHER_CTX_new()) == NULL) {
        uecm_openssl_error_handling(error_buffer, "EVP_CIPHER_CTX_new");
        return false;
    }

    if (EVP_DecryptInit_ex(ctx, encrypter->cipher, NULL, encrypter->key->data, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        uecm_openssl_error_handling(error_buffer, "EVP_DecryptInit_ex");
        return false;
    }

    *plaintext = NULL;
    ueum_safe_alloc(*plaintext, unsigned char, ciphertext_size + uecm_sym_encrypter_get_iv_size(encrypter));

    /* It's safe to cast ciphertext_size to int as we compare it with INT_MAX */
    if (EVP_DecryptUpdate(ctx, *plaintext, &len, ciphertext, (int)ciphertext_size) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        uecm_openssl_error_handling(error_buffer, "EVP_DecryptUpdate");
        return false;
    }

    *plaintext_size = len;

    if (EVP_DecryptFinal_ex(ctx, *plaintext + len, &rlen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        uecm_openssl_error_handling(error_buffer, "EVP_DecryptFinal_ex");
        return false;
    }

    *plaintext_size += rlen;

    EVP_CIPHER_CTX_free(ctx);

    return true;
}
