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

#include <stdlib.h>
#include <stddef.h>

int main(int argc, char **argv) {
    uk_crypto_sym_key *key;
    unsigned char *iv;
    size_t iv_size;
    char *plain_file_name;

    uk_utils_init_or_die();
    uk_utils_logger_use_symbol_levels();

    uk_utils_logger_info("Initializing LibUnknownEchoCryptoModule...");
    if (!uk_crypto_init()) {
        uk_utils_stacktrace_push_msg("Failed to initialize LibUnknownEchoCryptoModule");
        goto clean_up;
    }
    uk_utils_logger_info("LibUnknownEchoCryptoModule is correctly initialized.");

    key = NULL;
    iv = NULL;
    plain_file_name = NULL;

    uk_utils_logger_info("Generating random key...");
    if ((key = uk_crypto_sym_key_create_random()) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to create random sym key");
        goto clean_up;
    }
    uk_utils_logger_info("Random key generated");

    uk_utils_logger_info("Encrypting file %s...", argv[1]);
    if (!uk_crypto_file_encrypt(argv[1], argv[2], key, &iv, &iv_size)) {
        uk_utils_stacktrace_push_msg("Failed to encrypt file %s", argv[1]);
        goto clean_up;
    }
    uk_utils_logger_info("File encrypted as file %s", argv[2]);

    plain_file_name = uk_utils_strcat_variadic("ss", "plain_", argv[1]);

    uk_utils_logger_info("Decrypting file %s...", argv[2]);
    if (!uk_crypto_file_decrypt(argv[2], plain_file_name, key, iv)) {
        uk_utils_stacktrace_push_msg("Failed to decrypt file %s", argv[2]);
        goto clean_up;
    }
    uk_utils_logger_info("File decrypted as file %s", plain_file_name);

    uk_utils_logger_info("Succeed !");

clean_up:
    if (uk_utils_stacktrace_is_filled()) {
        uk_utils_logger_error("Error(s) occurred with the following stacktrace(s):");
        uk_utils_stacktrace_print_all();
    }
    uk_crypto_sym_key_destroy(key);
    uk_utils_safe_free(iv);
    uk_utils_safe_free(plain_file_name);
    uk_crypto_uninit();
    uk_utils_uninit();
    return 0;
}
