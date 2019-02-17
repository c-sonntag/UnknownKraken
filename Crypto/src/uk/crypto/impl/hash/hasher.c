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

#include <uk/crypto/api/hash/hasher.h>
#include <uk/crypto/impl/errorHandling/openssl_error_handling.h>
#include <uk/utils/ei.h>
#include <uk/utils/ueum.h>

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <string.h>

struct uk_crypto_hasher {
    EVP_MD_CTX *md_ctx;
    const EVP_MD *type;
};

uk_crypto_hasher *uk_crypto_hasher_create() {
    uk_crypto_hasher *hasher;

    hasher = NULL;

    uk_utils_safe_alloc(hasher, uk_crypto_hasher, 1);
    hasher->md_ctx = NULL;

    return hasher;
}

void uk_crypto_hasher_destroy(uk_crypto_hasher *hasher) {
    if (hasher) {
        EVP_MD_CTX_destroy(hasher->md_ctx);
        uk_utils_safe_free(hasher);
    }
}

bool uk_crypto_hasher_init(uk_crypto_hasher *hasher, const char *digest_name) {
    char *error_buffer;

    error_buffer = NULL;

    if ((hasher->md_ctx = EVP_MD_CTX_create()) == NULL) {
        uk_crypto_openssl_error_handling(error_buffer, "Initialisation of message digest context");
        return false;
    }

    if ((hasher->type = EVP_get_digestbyname(digest_name)) == NULL) {
        uk_crypto_openssl_error_handling(error_buffer, "Digest wasn't found");
        return false;
    }

    return true;
}

static unsigned char *build_digest(uk_crypto_hasher *hasher, const unsigned char *message, size_t message_len, unsigned int *digest_len) {
    char *error_buffer;
    unsigned char *digest;

    error_buffer = NULL;
    digest = NULL;

    if (EVP_DigestInit_ex(hasher->md_ctx, hasher->type, NULL) != 1) {
        uk_crypto_openssl_error_handling(error_buffer, "Initialisation of message digest function");
        return NULL;
    }

    if (EVP_DigestUpdate(hasher->md_ctx, message, message_len) != 1) {
        uk_crypto_openssl_error_handling(error_buffer, "Digest update");
        return NULL;
    }

    if ((digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(hasher->type))) == NULL) {
        uk_crypto_openssl_error_handling(error_buffer, "Allocation of digest string");
        return NULL;
    }

    if (EVP_DigestFinal_ex(hasher->md_ctx, digest, digest_len) != 1) {
        uk_crypto_openssl_error_handling(error_buffer, "Digest final step");
        return NULL;
    }

    return digest;
}

unsigned char *uk_crypto_hasher_digest(uk_crypto_hasher *hasher, const unsigned char *message, size_t message_len, size_t *digest_len) {
    unsigned char *digest;
    unsigned int digest_len_tmp;

    if ((digest = build_digest(hasher, message, message_len, &digest_len_tmp)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to build digest");
        return NULL;
    }
    *digest_len = (size_t)digest_len_tmp;

    return digest;
}

int uk_crypto_hasher_get_digest_size(uk_crypto_hasher *hasher) {
    return EVP_MD_size(hasher->type);
}
