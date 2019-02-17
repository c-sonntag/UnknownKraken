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

static void print_usage(char *name) {
    printf("%s <data> <cert_path> <key_path>\n", name);
}

int main(int argc, char **argv) {
    unsigned char *plain_data, *cipher_data, *decipher_data;
    size_t plain_data_size, cipher_data_size, decipher_data_size;
    uk_crypto_x509_certificate *certificate;
    uk_crypto_public_key *public_key;
    uk_crypto_private_key *private_key;
    uk_crypto_asym_key *asym_key;

    cipher_data = NULL;
    plain_data = NULL;
    decipher_data = NULL;
    certificate = NULL;
    public_key = NULL;
    private_key = NULL;
    asym_key = NULL;

    if (argc != 4) {
        fprintf(stderr, "[FATAL] Three arguments are required.\n");
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

    if ((plain_data = uk_utils_bytes_create_from_string(argv[1])) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to convert arg to bytes")
        goto clean_up;
    }
    plain_data_size = strlen(argv[1]);

    uk_crypto_x509_certificate_load_from_file(argv[2], &certificate);

    public_key = uk_crypto_rsa_public_key_from_x509_certificate(certificate);

    private_key = uk_crypto_rsa_private_key_from_key_certificate(argv[3]);

    if (!uk_crypto_cipher_plain_data(plain_data, plain_data_size, public_key, private_key, &cipher_data, &cipher_data_size, "aes-256-cbc", "sha256")) {
        uk_utils_stacktrace_push_msg("Failed to cipher plain data");
        goto clean_up;
    }

    if (!uk_crypto_decipher_cipher_data(cipher_data, cipher_data_size, private_key, public_key, &decipher_data, &decipher_data_size,
        "aes-256-cbc", "sha256")) {

        uk_utils_stacktrace_push_msg("Failed to decipher cipher data");
        goto clean_up;
    }

    if (plain_data_size == decipher_data_size && memcmp(decipher_data, plain_data, plain_data_size) == 0) {
        uk_utils_logger_info("Plain data and decipher data match");
    } else {
        uk_utils_logger_error("Plain data and decipher data doesn't match");
    }

clean_up:
    uk_crypto_public_key_destroy(public_key);
    uk_crypto_private_key_destroy(private_key);
    uk_crypto_asym_key_destroy_all(asym_key);
    uk_utils_safe_free(plain_data);
    uk_utils_safe_free(cipher_data);
    uk_utils_safe_free(decipher_data);
    uk_crypto_x509_certificate_destroy(certificate);
    if (uk_utils_stacktrace_is_filled()) {
        uk_utils_logger_error("Error(s) occurred with the following stacktrace(s):");
        uk_utils_stacktrace_print_all();
    }
    uk_crypto_uninit();
    uk_utils_uninit();
    return 0;
}
