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

#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

static void print_usage(char *name) {
    printf("%s <data>\n", name);
}

int main(int argc, char **argv) {
    int exit_code;
    unsigned char *message, *compressed, *decompressed;
    size_t message_length, compressed_length;

    exit_code = EXIT_FAILURE;
    message = NULL;
    compressed = NULL;
    decompressed = NULL;

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
    message_length = strlen(argv[1]);
    uk_utils_logger_info("Succefully converted parameter to bytes");

    uk_utils_logger_info("Compressing message...");
    if ((compressed = uk_crypto_compress_buf(message, message_length, &compressed_length)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to compress message")
        goto clean_up;
    }
    uk_utils_logger_info("Message has been successfully compressed");

    uk_utils_logger_info("Decompressing message...");
    if ((decompressed = uk_crypto_decompress_buf(compressed, compressed_length, message_length)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to decompress message")
        goto clean_up;
    }

    uk_utils_logger_info("Messages comparaison...");
    if (memcmp(decompressed, message, message_length) == 0) {
        uk_utils_logger_info("Message has been successfully decompressed");
    } else {
        uk_utils_logger_error("The message was decompressed but isn't the same as the original");
        uk_utils_stacktrace_push_msg("Failed to decompress message")
        goto clean_up;
    }

    exit_code = EXIT_SUCCESS;

    uk_utils_logger_info("Succeed !");

clean_up:
    uk_utils_safe_free(message)
    uk_utils_safe_free(compressed)
    uk_utils_safe_free(decompressed)
    if (uk_utils_stacktrace_is_filled()) {
        uk_utils_logger_error("Error(s) occurred with the following stacktrace(s):");
        uk_utils_stacktrace_print_all();
    }
    uk_crypto_uninit();
    uk_utils_uninit();
    return exit_code;
}
