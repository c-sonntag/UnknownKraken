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

#include <uecm/uecm.h>
#include <ueum/ueum.h>
#include <ei/ei.h>

int main() {
    uecm_crypto_metadata *our_crypto_metadata, *read_crypto_metadata;

    ei_init_or_die();
    ei_logger_use_symbol_levels();

    our_crypto_metadata = NULL;
    read_crypto_metadata = NULL;

    ei_logger_info("Initializing LibUnknownEchoCryptoModule...");
    if (!uecm_init()) {
        ei_stacktrace_push_msg("Failed to initialize LibUnknownEchoCryptoModule");
        goto clean_up;
    }
    ei_logger_info("LibUnknownEchoCryptoModule is correctly initialized.");

    if ((read_crypto_metadata = uecm_crypto_metadata_create_empty()) == NULL) {
        ei_stacktrace_push_msg("Failed to create new read crypto metadata");
        goto clean_up;
    }

    ei_logger_info("Generating crypto metadata for point A...");
    if ((our_crypto_metadata = uecm_crypto_metadata_create_default()) == NULL) {
        ei_stacktrace_push_msg("Failed to generate default crypto metadata for point A");
        goto clean_up;
    }

    ei_logger_info("Writing our crypto metadata...");
    if (!uecm_crypto_metadata_write(our_crypto_metadata, "out", "uid", "password")) {
        ei_stacktrace_push_msg("Failed to write our crypto metadata");
        goto clean_up;
    }
    ei_logger_info("Successfully wrote our crypto metadata");

    if (!uecm_crypto_metadata_read(read_crypto_metadata, "out", "uid", "password")) {
        ei_stacktrace_push_msg("Failed to read our crypto metadata");
        goto clean_up;
    }
    ei_logger_info("Successfully read our crypto metadata");

    ei_logger_info("Succeed !");

clean_up:
    uecm_crypto_metadata_destroy_all(our_crypto_metadata);
    uecm_crypto_metadata_destroy_all(read_crypto_metadata);
    if (ei_stacktrace_is_filled()) {
        ei_logger_error("Error(s) occurred with the following stacktrace(s):");
        ei_stacktrace_print_all();
    }
    uecm_uninit();
    ei_uninit();
    return 0;
}
