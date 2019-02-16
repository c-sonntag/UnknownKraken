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

#include <uecm/impl/envelope/envelope_open.h>
#include <uecm/impl/errorHandling/openssl_error_handling.h>
#include <ei/ei.h>

bool envelope_open_buffer(EVP_PKEY *priv_key, unsigned char *ciphertext, int ciphertext_len,
    unsigned char *encrypted_key, int encrypted_key_len, unsigned char *iv,
    unsigned char **plaintext, int *plaintext_len, const char *cipher_name) {

    bool result;
    EVP_CIPHER_CTX *ctx;
    int len;
    const EVP_CIPHER *cipher;
    char *error_buffer;

    ei_check_parameter_or_return(priv_key);
    ei_check_parameter_or_return(ciphertext);
    ei_check_parameter_or_return(ciphertext_len > 0);
    ei_check_parameter_or_return(encrypted_key);
    ei_check_parameter_or_return(encrypted_key_len > 0);
    ei_check_parameter_or_return(cipher_name);

    result = false;
    ctx = NULL;
    error_buffer = NULL;

    if ((cipher = EVP_get_cipherbyname(cipher_name)) == NULL) {
        uecm_openssl_error_handling(error_buffer, "Invalid cipher name");
        goto clean_up;
    }

    if ((ctx = EVP_CIPHER_CTX_new()) == NULL) {
        uecm_openssl_error_handling(error_buffer, "Failed to create new cipher");
        goto clean_up;
    }

    if (EVP_OpenInit(ctx, cipher, encrypted_key, encrypted_key_len, iv, priv_key) != 1) {
        uecm_openssl_error_handling(error_buffer, "Failed to init seal");
        goto clean_up;
    }

    ueum_safe_alloc_or_goto(*plaintext, unsigned char, ciphertext_len + EVP_CIPHER_iv_length(cipher), clean_up);

    if (EVP_OpenUpdate(ctx, *plaintext, &len, ciphertext, ciphertext_len) != 1) {
        uecm_openssl_error_handling(error_buffer, "EVP_SealUpdate");
        goto clean_up;
    }

    *plaintext_len = len;

    if (EVP_OpenFinal(ctx, *plaintext + len, &len) != 1) {
        uecm_openssl_error_handling(error_buffer, "EVP_SealFinal");
        goto clean_up;
    }

    *plaintext_len += len;

    result = true;

clean_up:
    EVP_CIPHER_CTX_free(ctx);
    return result;
}
