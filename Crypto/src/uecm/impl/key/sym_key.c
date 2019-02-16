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

#include <uecm/api/key/sym_key.h>
#include <ueum/ueum.h>
#include <ei/ei.h>

#define SYM_KEY_MIN_SIZE 32

uecm_sym_key *uecm_sym_key_create(unsigned char *data, size_t size) {
    uecm_sym_key *key;

    ei_check_parameter_or_return(data);
    ei_check_parameter_or_return(size);

    if (size < SYM_KEY_MIN_SIZE) {
        ei_stacktrace_push_msg("Key size is too short. >= %d is required", SYM_KEY_MIN_SIZE);
        return NULL;
    }

    key = NULL;

    ueum_safe_alloc(key, uecm_sym_key, 1);
    key->data = ueum_bytes_create_from_bytes(data, size);
    key->size = size;

    return key;
}

void uecm_sym_key_destroy(uecm_sym_key *key) {
    if (key) {
        ueum_safe_free(key->data);
        ueum_safe_free(key);
    }
}

size_t uecm_sym_key_get_min_size() {
    return SYM_KEY_MIN_SIZE;
}

bool uecm_sym_key_is_valid(uecm_sym_key *key) {
    ei_check_parameter_or_return(key);
    ei_check_parameter_or_return(key->data);

    if (key->size < SYM_KEY_MIN_SIZE) {
        ei_stacktrace_push_msg("Key size is too short. >= %d is required", SYM_KEY_MIN_SIZE);
        return false;
    }

    return true;
}
