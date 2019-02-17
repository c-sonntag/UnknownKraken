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

#include <uk/crypto/impl/errorHandling/zlib_error_handling.h>

#undef HAVE_UNISTD_H
#include <zlib.h>

void uk_crypto_zlib_error_handling_impl(int error_code) {
    switch (error_code) {
        case Z_ERRNO:
            if (ferror(stdin)) {
                uk_utils_stacktrace_push_msg("Error reading stdin");
            } else if (ferror(stdout)) {
                uk_utils_stacktrace_push_msg("Error reading stdout");
            }
        break;

        case Z_STREAM_ERROR:
            uk_utils_stacktrace_push_msg("Invalid compression level");
        break;

        case Z_DATA_ERROR:
            uk_utils_stacktrace_push_msg("Invalid or incomplete deflate data");
        break;

        case Z_MEM_ERROR:
            uk_utils_stacktrace_push_msg("Out of memory");
        break;

        case Z_VERSION_ERROR:
            uk_utils_stacktrace_push_msg("Zlib version mismatch");
        break;
    }
}
