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

#include <uk/crypto/factory/hasher_factory.h>
#include <uk/utils/ei.h>

uk_crypto_hasher *uk_crypto_hasher_sha256_create() {
    uk_crypto_hasher *hasher;

    if ((hasher = uk_crypto_hasher_create()) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to create uk_crypto_hasher");
        return NULL;
    }

    if (!(uk_crypto_hasher_init(hasher, "sha256"))) {
        uk_utils_stacktrace_push_msg("Failed to initialize uk_crypto_hasher with SHA-256 algorithm");
        uk_crypto_hasher_destroy(hasher);
        return NULL;
    }

    return hasher;
}

uk_crypto_hasher *uk_crypto_hasher_default_create() {
    return uk_crypto_hasher_sha256_create();
}
