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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

int main(int argc, char **argv) {
    uecm_pkcs12_keystore *keystore;
    const char *keystore_path;

    keystore = NULL;
    keystore_path = "out/keystore.p12";

    if (argc != 2) {
        fprintf(stderr, "[ERROR] ./%s <passphrase>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    ei_init_or_die();
    ei_logger_use_symbol_levels();

    ei_logger_info("Initializing LibUnknownEchoCryptoModule...");
    if (!uecm_init()) {
        ei_stacktrace_push_msg("Failed to initialize LibUnknownEchoCryptoModule");
        goto clean_up;
    }
    ei_logger_info("LibUnknownEchoCryptoModule is correctly initialized.");

    ei_logger_info("Checking if %s exist...", keystore_path);
    if (!ueum_is_file_exists(keystore_path)) {
        ei_logger_info("%s doesn't exist. Generating random pkcs12 keystore with CN=SWA and friendly name=test...", keystore_path);
        keystore = uecm_pkcs12_keystore_create_random("SWA", "test");
        if (!uecm_pkcs12_keystore_write(keystore, keystore_path, argv[1])) {
            ei_stacktrace_push_msg("Failed to write keystore to 'out/keystore.p12'");
            goto clean_up;
        }
    } else {
        ei_logger_info("Loading pkcs12 keystore %s...", keystore_path);
        if ((keystore = uecm_pkcs12_keystore_load(keystore_path, argv[1])) == NULL) {
            ei_stacktrace_push_msg("Failed to load specified pkcs12 keystore");
            goto clean_up;
        }

        /**
         * Print the plain content of pkcs12 keystore on stdout.
         * Only for debugging purpose.
         */
        ei_logger_info("Print plain content of pkcs12 keystore %s to stdout...", keystore_path);
        if (!uecm_pkcs12_keystore_print(keystore, argv[1])) {
            ei_stacktrace_push_msg("Failed to print plain content keystore to stdout");
            goto clean_up;
        }

        ei_logger_info("Removing %s...", keystore_path);
        errno = 0;
        if (remove(keystore_path) != 0) {
            ei_stacktrace_push_msg("Failed to remove %s with error message: %s", keystore_path, strerror(errno));
            goto clean_up;
        }
    }

    ei_logger_info("Succeed !");

clean_up:
    uecm_pkcs12_keystore_destroy(keystore);
    if (ei_stacktrace_is_filled()) {
        ei_logger_error("Error(s) occurred with the following stacktrace(s):");
        ei_stacktrace_print_all();
    }
    uecm_uninit();
    ei_uninit();
    return EXIT_SUCCESS;
}
