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

#include <uk/crypto/utils/friendly_name.h>
#include <uk/utils/ei.h>
#include <uk/utils/ueum.h>

#include <string.h>

unsigned char *uk_crypto_friendly_name_build(unsigned char *nickname, size_t nickname_size, const char *keystore_type, size_t *friendly_name_size) {
    unsigned char *friendly_name;

    uk_utils_check_parameter_or_return(nickname);
    uk_utils_check_parameter_or_return(nickname_size > 0);
    uk_utils_check_parameter_or_return(keystore_type);

    *friendly_name_size = nickname_size + 1 + strlen(keystore_type);
    friendly_name = NULL;

    uk_utils_safe_alloc(friendly_name, unsigned char, *friendly_name_size);
    memcpy(friendly_name, nickname, nickname_size * sizeof(unsigned char));
    memcpy(friendly_name + nickname_size, "_", sizeof(unsigned char));
    memcpy(friendly_name + nickname_size + 1, keystore_type, strlen(keystore_type) * sizeof(unsigned char));

    return friendly_name;
}
