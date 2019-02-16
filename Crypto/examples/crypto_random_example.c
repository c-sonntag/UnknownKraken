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

int main() {
    unsigned char *buffer;
    size_t buffer_size;

    ei_init_or_die();
    ei_logger_use_symbol_levels();

    buffer = NULL;
    buffer_size = 16;
    
    ei_logger_info("Initializing LibUnknownEchoCryptoModule...");
    if (!uecm_init()) {
        ei_stacktrace_push_msg("Failed to initialize LibUnknownEchoCryptoModule");
        goto clean_up;
    }
    ei_logger_info("LibUnknownEchoCryptoModule is correctly initialized.");

    ei_logger_info("Allocating 16 bytes...");
    ueum_safe_alloc_or_goto(buffer, unsigned char, buffer_size, clean_up);

    ei_logger_info("Buffer content:");
    if (!ueum_hex_print(buffer, buffer_size, stdout)) {
        ei_stacktrace_push_msg("Failed to print buffer content (empty)");
        goto clean_up;
    }

    ei_logger_info("Generating crypto random bytes...");
    if (!uecm_crypto_random_bytes(buffer, buffer_size)) {
        ei_stacktrace_push_msg("Failed to generate crypto random bytes");
        goto clean_up;
    }

    ei_logger_info("Buffer content:");
    if (!ueum_hex_print(buffer, buffer_size, stdout)) {
        ei_stacktrace_push_msg("Failed to print buffer content (filled)");
        goto clean_up;
    }

    ei_logger_info("Succeed !");

clean_up:
    if (ei_stacktrace_is_filled()) {
        ei_logger_error("Error(s) occurred with the following stacktrace(s):");
        ei_stacktrace_print_all();
    }
    uecm_uninit();
    ei_uninit();
    return 0;
}
