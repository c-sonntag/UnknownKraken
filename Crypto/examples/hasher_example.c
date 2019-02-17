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

#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

void print_usage(char *name) {
    printf("%s <data>\n", name);
}

int main(int argc, char **argv) {
    int exit_code;
    uk_crypto_hasher *hasher;
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

    uk_utils_init_or_die();
    uk_utils_logger_use_symbol_levels();

    uk_utils_logger_info("Initializing LibUnknownEchoCryptoModule...");
    if (!uk_crypto_init()) {
        uk_utils_stacktrace_push_msg("Failed to initialize LibUnknownEchoCryptoModule");
        goto clean_up;
    }
    uk_utils_logger_info("LibUnknownEchoCryptoModule is correctly initialized.");

    uk_utils_logger_info("Converting parameter '%s' to bytes...", argv[1]);
    if ((message = uk_utils_bytes_create_from_string(argv[1])) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to convert arg to bytes")
        goto clean_up;
    }
    uk_utils_logger_info("Succefully converted parameter to bytes");

    message_length = strlen(argv[1]);

    uk_utils_logger_info("Creating new uk_crypto_hasher");
    if ((hasher = uk_crypto_hasher_create()) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to create uk_crypto_hasher")
        goto clean_up;
    }
    uk_utils_logger_info("Has successfully created a new uk_crypto_hasher");

    uk_utils_logger_info("Initializing uk_crypto_hasher with SHA-256 digest algorithm");
    if (!(uk_crypto_hasher_init(hasher, "sha256"))) {
        uk_utils_stacktrace_push_msg("Failed to initialize uk_crypto_hasher with SHA-256 algorithm")
        goto clean_up;
    }
    uk_utils_logger_info("Has successfully initialized uk_crypto_hasher");

    uk_utils_logger_info("Hash processing...");
    if ((digest = uk_crypto_hasher_digest(hasher, message, message_length, &digest_length)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to hash message with SHA-256 digest algorithm")
        goto clean_up;
    }

    hex_digest = uk_utils_bytes_to_hex(digest, digest_length);
    uk_utils_logger_info("Message digest of input '%s' is following : %s", argv[1], hex_digest);

    exit_code = EXIT_SUCCESS;

    uk_utils_logger_info("Succeed !");

clean_up:
    if (uk_utils_stacktrace_is_filled()) {
        uk_utils_logger_error("Error(s) occurred with the following stacktrace(s):");
        uk_utils_stacktrace_print_all();
    }
    uk_utils_safe_free(message)
    uk_utils_safe_free(digest)
    uk_crypto_hasher_destroy(hasher);
    uk_utils_safe_free(hex_digest)
    uk_crypto_uninit();
    uk_utils_uninit();
    return exit_code;
}
