/*******************************************************************************
 * Copyright (C) 2018 Charly Lamothe                                           *
 *                                                                             *
 * This file is part of LibUnknownEcho.                                        *
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

#include <unknownecho/init.h>
#include <uecm/uecm.h>
#include <ei/ei.h>

static bool errorInterceptor_initialized = false;
static bool crypto_initialized = false;

bool ue_init() {
    if (!errorInterceptor_initialized) {
        errorInterceptor_initialized = ei_init();
    }

    if (errorInterceptor_initialized && !crypto_initialized) {
        crypto_initialized = uecm_crypto_init();
    }

    return errorInterceptor_initialized && crypto_initialized;
}

void ue_uninit() {
    if (crypto_initialized) {
        uecm_crypto_uninit();
    }

    if (errorInterceptor_initialized) {
        ei_uninit();
    }
}
