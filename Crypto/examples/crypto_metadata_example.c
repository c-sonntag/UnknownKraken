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

#include <uk/crypto/uecm.h>
#include <uk/utils/ueum.h>
#include <uk/utils/ei.h>

int main() {
    uk_crypto_crypto_metadata *our_crypto_metadata, *read_crypto_metadata;

    uk_utils_init_or_die();
    uk_utils_logger_use_symbol_levels();

    our_crypto_metadata = NULL;
    read_crypto_metadata = NULL;

    uk_utils_logger_info("Initializing LibUnknownEchoCryptoModule...");
    if (!uk_crypto_init()) {
        uk_utils_stacktrace_push_msg("Failed to initialize LibUnknownEchoCryptoModule");
        goto clean_up;
    }
    uk_utils_logger_info("LibUnknownEchoCryptoModule is correctly initialized.");

    if ((read_crypto_metadata = uk_crypto_crypto_metadata_create_empty()) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to create new read crypto metadata");
        goto clean_up;
    }

    uk_utils_logger_info("Generating crypto metadata for point A...");
    if ((our_crypto_metadata = uk_crypto_crypto_metadata_create_default()) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to generate default crypto metadata for point A");
        goto clean_up;
    }

    uk_utils_logger_info("Writing our crypto metadata...");
    if (!uk_crypto_crypto_metadata_write(our_crypto_metadata, "out", "uid", "password")) {
        uk_utils_stacktrace_push_msg("Failed to write our crypto metadata");
        goto clean_up;
    }
    uk_utils_logger_info("Successfully wrote our crypto metadata");

    if (!uk_crypto_crypto_metadata_read(read_crypto_metadata, "out", "uid", "password")) {
        uk_utils_stacktrace_push_msg("Failed to read our crypto metadata");
        goto clean_up;
    }
    uk_utils_logger_info("Successfully read our crypto metadata");

    uk_utils_logger_info("Succeed !");

clean_up:
    uk_crypto_crypto_metadata_destroy_all(our_crypto_metadata);
    uk_crypto_crypto_metadata_destroy_all(read_crypto_metadata);
    if (uk_utils_stacktrace_is_filled()) {
        uk_utils_logger_error("Error(s) occurred with the following stacktrace(s):");
        uk_utils_stacktrace_print_all();
    }
    uk_crypto_uninit();
    uk_utils_uninit();
    return 0;
}
