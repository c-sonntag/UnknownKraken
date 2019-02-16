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

#include <uecm/factory/hasher_factory.h>
#include <ei/ei.h>

uecm_hasher *uecm_hasher_sha256_create() {
    uecm_hasher *hasher;

    if ((hasher = uecm_hasher_create()) == NULL) {
        ei_stacktrace_push_msg("Failed to create uecm_hasher");
        return NULL;
    }

    if (!(uecm_hasher_init(hasher, "sha256"))) {
        ei_stacktrace_push_msg("Failed to initialize uecm_hasher with SHA-256 algorithm");
        uecm_hasher_destroy(hasher);
        return NULL;
    }

    return hasher;
}

uecm_hasher *uecm_hasher_default_create() {
    return uecm_hasher_sha256_create();
}
