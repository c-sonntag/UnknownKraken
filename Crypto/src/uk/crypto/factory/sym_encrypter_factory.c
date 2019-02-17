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

#include <uk/crypto/factory/sym_encrypter_factory.h>
#include <uk/utils/ueum.h>
#include <uk/utils/ei.h>
#include <uk/crypto/defines.h>

static uk_crypto_sym_encrypter *uk_crypto_sym_encrypter_create_factory(uk_crypto_sym_key *key, const char *cipher_name) {
    uk_crypto_sym_encrypter *encrypter;

    if (!uk_crypto_sym_key_is_valid(key)) {
        uk_utils_stacktrace_push_msg("Specified key is invalid");
        return NULL;
    }

    if (key->size < uk_crypto_sym_key_get_min_size()) {
        uk_utils_stacktrace_push_msg("Specified key size is invalid. %d bytes is required.", uk_crypto_sym_key_get_min_size());
        return NULL;
    }

    encrypter = uk_crypto_sym_encrypter_create(cipher_name);
    uk_crypto_sym_encrypter_set_key(encrypter, key);

    return encrypter;
}

uk_crypto_sym_encrypter *uk_crypto_sym_encrypter_aes_cbc_create(uk_crypto_sym_key *key) {
    return uk_crypto_sym_encrypter_create_factory(key, UnknownKrakenCrypto_DEFAULT_CIPHER_NAME);
}

uk_crypto_sym_encrypter *uk_crypto_sym_encrypter_rc4_create(uk_crypto_sym_key *key) {
    return uk_crypto_sym_encrypter_create_factory(key, "rc4");
}

uk_crypto_sym_encrypter *uk_crypto_sym_encrypter_default_create(uk_crypto_sym_key *key) {
    return uk_crypto_sym_encrypter_rc4_create(key);
}
