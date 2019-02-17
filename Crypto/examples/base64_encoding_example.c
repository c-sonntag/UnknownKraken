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
    unsigned char *message, *encoded, *decoded;
    size_t message_length, encoded_length, decoded_length;

    exit_code = EXIT_FAILURE;
    message = NULL;
    encoded = NULL;
    decoded = NULL;

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
    uk_utils_logger_info("Succefully converted parameter to bytes:");
    uk_utils_hex_print(message, message_length, stdout);

    uk_utils_logger_info("Encoding message with base64...");
    if ((encoded = uk_crypto_base64_encode(message, message_length, &encoded_length)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to encod message")
        goto clean_up;
    }
    uk_utils_logger_info("Message has been successfully encoded:");
    uk_utils_hex_print(encoded, encoded_length, stdout);

    uk_utils_logger_info("Decoding message with base64...");
    if ((decoded = uk_crypto_base64_decode(encoded, encoded_length, &decoded_length)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to decode message")
        goto clean_up;
    }

    uk_utils_logger_info("Messages comparaison...");
    if (memcmp(decoded, message, message_length) != 0) {
        uk_utils_logger_error("The message was decoded but isn't the same as the original");
        uk_utils_stacktrace_push_msg("Failed to decode message")
        goto clean_up;
    }

    uk_utils_logger_info("Message has been successfully decoded:");
    uk_utils_hex_print(decoded, decoded_length, stdout);

    exit_code = EXIT_SUCCESS;

    uk_utils_logger_info("Succeed !");

clean_up:
    uk_utils_safe_free(message)
    uk_utils_safe_free(encoded)
    uk_utils_safe_free(decoded)
    if (uk_utils_stacktrace_is_filled()) {
        uk_utils_logger_error("Error(s) occurred with the following stacktrace(s):");
        uk_utils_stacktrace_print_all();
    }
    uk_crypto_uninit();
    uk_utils_uninit();
    return exit_code;
}
