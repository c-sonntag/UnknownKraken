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

#include <uecm/factory/sym_encrypter_factory.h>
#include <ueum/ueum.h>
#include <ei/ei.h>
#include <uecm/defines.h>

static uecm_sym_encrypter *uecm_sym_encrypter_create_factory(uecm_sym_key *key, const char *cipher_name) {
    uecm_sym_encrypter *encrypter;

    if (!uecm_sym_key_is_valid(key)) {
        ei_stacktrace_push_msg("Specified key is invalid");
        return NULL;
    }

    if (key->size < uecm_sym_key_get_min_size()) {
        ei_stacktrace_push_msg("Specified key size is invalid. %d bytes is required.", uecm_sym_key_get_min_size());
        return NULL;
    }

    encrypter = uecm_sym_encrypter_create(cipher_name);
    uecm_sym_encrypter_set_key(encrypter, key);

    return encrypter;
}

uecm_sym_encrypter *uecm_sym_encrypter_aes_cbc_create(uecm_sym_key *key) {
    return uecm_sym_encrypter_create_factory(key, UNKNOWNECHOCRYPTOMODULE_DEFAULT_CIPHER_NAME);
}

uecm_sym_encrypter *uecm_sym_encrypter_rc4_create(uecm_sym_key *key) {
    return uecm_sym_encrypter_create_factory(key, "rc4");
}

uecm_sym_encrypter *uecm_sym_encrypter_default_create(uecm_sym_key *key) {
    return uecm_sym_encrypter_rc4_create(key);
}
