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

#include <uecm/factory/sym_key_factory.h>
#include <uecm/factory/hasher_factory.h>
#include <uecm/utils/crypto_random.h>
#include <uecm/api/hash/hasher.h>
#include <ei/ei.h>
#include <ueum/ueum.h>

#include <stddef.h>
#include <string.h>

uecm_sym_key *uecm_sym_key_create_random() {
    uecm_sym_key *key;
    unsigned char *buf;
    size_t buf_size;

    key = NULL;
    buf = NULL;
    buf_size = uecm_sym_key_get_min_size();
    
    ueum_safe_alloc(buf, unsigned char, buf_size);

    if (!uecm_crypto_random_bytes(buf, buf_size)) {
        ei_stacktrace_push_msg("Failed to get crypto random bytes");
        ueum_safe_free(buf);
        return NULL;
    }

    key = uecm_sym_key_create(buf, buf_size);

    ueum_safe_free(buf);

    return key;
}

uecm_sym_key *uecm_sym_key_create_from_file(char *file_path) {
    (void)file_path;
    ei_stacktrace_push_msg("Not implemented");
    return NULL;
}

uecm_sym_key *uecm_sym_key_create_from_string(const char *string) {
    uecm_sym_key *key;
    unsigned char *buf, *digest;
    uecm_hasher *hasher;
    size_t digest_len;

    hasher = uecm_hasher_default_create();

    buf = ueum_bytes_create_from_string(string);

    digest = uecm_hasher_digest(hasher, buf, strlen(string), &digest_len);

    key = uecm_sym_key_create(digest, digest_len);

    uecm_hasher_destroy(hasher);
    ueum_safe_free(buf);
    ueum_safe_free(digest);

    return key;
}
