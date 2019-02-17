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

#include <uk/crypto/impl/errorHandling/openssl_error_handling.h>
#include <uk/utils/ueum.h>

#include <openssl/err.h>

char *uk_crypto_openssl_error_handling_impl(char *begin_msg) {
    unsigned long error_code;
    char *error_buffer;

    error_buffer = NULL;

    error_code = ERR_get_error();
    error_buffer = (char *)ERR_reason_error_string(error_code);
    if (error_buffer) {
        error_buffer = uk_utils_strcat_variadic("ssss", begin_msg, " - failed with error msg `", error_buffer, "`");
    } else {
        error_buffer = uk_utils_strcat_variadic("ssl", begin_msg, " - failed with error code ", error_code);
    }

    return error_buffer;
}
