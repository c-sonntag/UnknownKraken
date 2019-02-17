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

#include <uk/crypto/init.h>
#include <uk/crypto/api/crypto_init.h>
#include <uk/utils/ueum.h>

static bool crypto_initialized = false;

int uk_crypto_init() {
    if (!crypto_initialized) {
        crypto_initialized = uk_crypto_crypto_init();
    }

    return crypto_initialized;
}

void uk_crypto_uninit() {
    if (crypto_initialized) {
        uk_crypto_crypto_uninit();
    }
}
