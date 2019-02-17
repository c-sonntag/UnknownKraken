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

#include <uk/crypto/uecm.h> /* Include LibUnknownEchoCryptoModule */
#include <uk/utils/ueum.h> /* Include LibUnknownEchoUtilsModule */
#include <uk/utils/ei.h> /* Include LibErrorInterceptor */

#include <stddef.h>
#include <string.h>

int main(int argc, char **argv) {
    unsigned char *plain_data, *cipher_data, *decipher_data;
    size_t plain_data_size, cipher_data_size, decipher_data_size;
    uk_crypto_asym_key *key;
    int key_size;

    /* Initialize LibErrorInterceptor */
    uk_utils_init_or_die();
    uk_utils_logger_use_symbol_levels();

    /* Initialize LibUnknownEchoCryptoModule */
    if (!uk_crypto_init()) {
        uk_utils_stacktrace_push_msg("Failed to initialize LibUnknownEchoCryptoModule");
        goto clean_up;
    }
    uk_utils_logger_info("LibUnknownEchoCryptoModule is correctly initialized.");

    /* Use LibUnknownEchoCryptoModule */

    plain_data = NULL;
    cipher_data = NULL;
    decipher_data = NULL;
    key_size = 4096;

    /* Convert the string input in bytes */
    uk_utils_logger_info("Converting string input in bytes...");
    if ((plain_data = uk_utils_bytes_create_from_string(argv[1])) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to convert arg to bytes")
        goto clean_up;
    }
    plain_data_size = strlen(argv[1]);

    /* Generate a random RSA key pair */
    uk_utils_logger_info("Generating random RSA key pair of size %d...", key_size);
    if ((key = uk_crypto_rsa_asym_key_create(key_size)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to generate random rsa key pair of size %d", key_size);
        goto clean_up;
    }
    
    /**
     * Cipher plain data using both asymmetric (4096-RSA) and
     * symmetric encryption (AES-256-CBC), compression
     * (inflate/deflate of zlib), signing (SHA-256).
     * The private key parameter (key->sk) is optional,
     * and used to sign the cipher data.
     */ 
    uk_utils_logger_info("Ciphering plain data...");
    if (!uk_crypto_cipher_plain_data(plain_data, plain_data_size, key->pk, key->sk, &cipher_data, &cipher_data_size, "aes-256-cbc", "sha256")) {
        uk_utils_stacktrace_push_msg("Failed to cipher plain data");
        goto clean_up;
    }

    /**
     * Decipher cipher data using both asymmetric (4096-RSA) and
     * symmetric encryption (AES-256-CBC), compression
     * (inflate/deflate of zlib), signing (SHA-256).
     * The public key parameter (key->pk) is optional,
     * and used to verify the signature of the cipher data.
     */
    uk_utils_logger_info("Deciphering cipher data...");
    if (!uk_crypto_decipher_cipher_data(cipher_data, cipher_data_size, key->sk, key->pk, &decipher_data, &decipher_data_size,
        "aes-256-cbc", "sha256")) {

        uk_utils_stacktrace_push_msg("Failed to decipher cipher data");
        goto clean_up;
    }

    /* Check if decipher data and plain data are equals */
    uk_utils_logger_info("Comparing decipher data with plain data...");
    if (plain_data_size == decipher_data_size && memcmp(decipher_data, plain_data, plain_data_size) == 0) {
        uk_utils_logger_info("Plain data and decipher data match");
    } else {
        uk_utils_logger_error("Plain data and decipher data doesn't match");
    }

    uk_utils_logger_info("Succeed !");

clean_up:
    /* Clean_up variables */
    uk_utils_safe_free(plain_data);
    uk_utils_safe_free(cipher_data);
    uk_utils_safe_free(decipher_data);
    uk_crypto_asym_key_destroy_all(key);

    /**
     * Each time uk_utils_stacktrace API is used in libueum or libuecm,
     * an error is record to the stacktrace of the current thread.
     */
    if (uk_utils_stacktrace_is_filled()) {
        uk_utils_logger_error("Error(s) occurred with the following stacktrace(s):");
        uk_utils_stacktrace_print_all();
    }

    uk_crypto_uninit(); /* uninitialize LibUnknownEchoCryptoModule */

    uk_utils_uninit(); /* uninitialize LibErrorInterceptor */

    return 0;
}
