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

#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

void print_usage(char *name) {
    printf("%s <data>\n", name);
}

int main(int argc, char **argv) {
    int exit_code;
    uecm_hasher *hasher;
    unsigned char *message, *digest;
    size_t message_length, digest_length;
    char *hex_digest;

    exit_code = EXIT_FAILURE;
    hasher = NULL;
    message = NULL;
    digest = NULL;
    message_length = 0;
    digest_length = 0;
    hex_digest = NULL;

    if (argc == 1) {
        fprintf(stderr, "[FATAL] An argument is required.\n");
        print_usage(argv[0]);
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

    ei_logger_info("Converting parameter '%s' to bytes...", argv[1]);
    if ((message = ueum_bytes_create_from_string(argv[1])) == NULL) {
        ei_stacktrace_push_msg("Failed to convert arg to bytes")
        goto clean_up;
    }
    ei_logger_info("Succefully converted parameter to bytes");

    message_length = strlen(argv[1]);

    ei_logger_info("Creating new uecm_hasher");
    if ((hasher = uecm_hasher_create()) == NULL) {
        ei_stacktrace_push_msg("Failed to create uecm_hasher")
        goto clean_up;
    }
    ei_logger_info("Has successfully created a new uecm_hasher");

    ei_logger_info("Initializing uecm_hasher with SHA-256 digest algorithm");
    if (!(uecm_hasher_init(hasher, "sha256"))) {
        ei_stacktrace_push_msg("Failed to initialize uecm_hasher with SHA-256 algorithm")
        goto clean_up;
    }
    ei_logger_info("Has successfully initialized uecm_hasher");

    ei_logger_info("Hash processing...");
    if ((digest = uecm_hasher_digest(hasher, message, message_length, &digest_length)) == NULL) {
        ei_stacktrace_push_msg("Failed to hash message with SHA-256 digest algorithm")
        goto clean_up;
    }

    hex_digest = ueum_bytes_to_hex(digest, digest_length);
    ei_logger_info("Message digest of input '%s' is following : %s", argv[1], hex_digest);

    exit_code = EXIT_SUCCESS;

    ei_logger_info("Succeed !");

clean_up:
    if (ei_stacktrace_is_filled()) {
        ei_logger_error("Error(s) occurred with the following stacktrace(s):");
        ei_stacktrace_print_all();
    }
    ueum_safe_free(message)
    ueum_safe_free(digest)
    uecm_hasher_destroy(hasher);
    ueum_safe_free(hex_digest)
    uecm_uninit();
    ei_uninit();
    return exit_code;
}
