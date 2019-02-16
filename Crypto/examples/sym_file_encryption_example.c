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

#include <stdlib.h>
#include <stddef.h>

int main(int argc, char **argv) {
    uecm_sym_key *key;
    unsigned char *iv;
    size_t iv_size;
    char *plain_file_name;

    ei_init_or_die();
    ei_logger_use_symbol_levels();

    ei_logger_info("Initializing LibUnknownEchoCryptoModule...");
    if (!uecm_init()) {
        ei_stacktrace_push_msg("Failed to initialize LibUnknownEchoCryptoModule");
        goto clean_up;
    }
    ei_logger_info("LibUnknownEchoCryptoModule is correctly initialized.");

    key = NULL;
    iv = NULL;
    plain_file_name = NULL;

    ei_logger_info("Generating random key...");
    if ((key = uecm_sym_key_create_random()) == NULL) {
        ei_stacktrace_push_msg("Failed to create random sym key");
        goto clean_up;
    }
    ei_logger_info("Random key generated");

    ei_logger_info("Encrypting file %s...", argv[1]);
    if (!uecm_file_encrypt(argv[1], argv[2], key, &iv, &iv_size)) {
        ei_stacktrace_push_msg("Failed to encrypt file %s", argv[1]);
        goto clean_up;
    }
    ei_logger_info("File encrypted as file %s", argv[2]);

    plain_file_name = ueum_strcat_variadic("ss", "plain_", argv[1]);

    ei_logger_info("Decrypting file %s...", argv[2]);
    if (!uecm_file_decrypt(argv[2], plain_file_name, key, iv)) {
        ei_stacktrace_push_msg("Failed to decrypt file %s", argv[2]);
        goto clean_up;
    }
    ei_logger_info("File decrypted as file %s", plain_file_name);

    ei_logger_info("Succeed !");

clean_up:
    if (ei_stacktrace_is_filled()) {
        ei_logger_error("Error(s) occurred with the following stacktrace(s):");
        ei_stacktrace_print_all();
    }
    uecm_sym_key_destroy(key);
    ueum_safe_free(iv);
    ueum_safe_free(plain_file_name);
    uecm_uninit();
    ei_uninit();
    return 0;
}
