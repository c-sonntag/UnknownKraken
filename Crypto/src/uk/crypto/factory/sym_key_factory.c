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

#include <uk/crypto/factory/sym_key_factory.h>
#include <uk/crypto/factory/hasher_factory.h>
#include <uk/crypto/utils/crypto_random.h>
#include <uk/crypto/api/hash/hasher.h>
#include <uk/utils/ei.h>
#include <uk/utils/ueum.h>

#include <stddef.h>
#include <string.h>

uk_crypto_sym_key *uk_crypto_sym_key_create_random() {
    uk_crypto_sym_key *key;
    unsigned char *buf;
    size_t buf_size;

    key = NULL;
    buf = NULL;
    buf_size = uk_crypto_sym_key_get_min_size();
    
    uk_utils_safe_alloc(buf, unsigned char, buf_size);

    if (!uk_crypto_crypto_random_bytes(buf, buf_size)) {
        uk_utils_stacktrace_push_msg("Failed to get crypto random bytes");
        uk_utils_safe_free(buf);
        return NULL;
    }

    key = uk_crypto_sym_key_create(buf, buf_size);

    uk_utils_safe_free(buf);

    return key;
}

uk_crypto_sym_key *uk_crypto_sym_key_create_from_file(char *file_path) {
    (void)file_path;
    uk_utils_stacktrace_push_msg("Not implemented");
    return NULL;
}

uk_crypto_sym_key *uk_crypto_sym_key_create_from_string(const char *string) {
    uk_crypto_sym_key *key;
    unsigned char *buf, *digest;
    uk_crypto_hasher *hasher;
    size_t digest_len;

    hasher = uk_crypto_hasher_default_create();

    buf = uk_utils_bytes_create_from_string(string);

    digest = uk_crypto_hasher_digest(hasher, buf, strlen(string), &digest_len);

    key = uk_crypto_sym_key_create(digest, digest_len);

    uk_crypto_hasher_destroy(hasher);
    uk_utils_safe_free(buf);
    uk_utils_safe_free(digest);

    return key;
}
