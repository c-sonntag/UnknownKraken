/******************************************************************************************
 * Copyright (C) 2018 by Charly Lamothe													  *
 *																						  *
 * This file is part of LibUnknownEchoCryptoModule.										  *
 *																						  *
 *   LibUnknownEchoCryptoModule is free software: you can redistribute it and/or modify   *
 *   it under the terms of the GNU General Public License as published by				  *
 *   the Free Software Foundation, either version 3 of the License, or					  *
 *   (at your option) any later version.												  *
 *																						  *
 *   LibUnknownEchoCryptoModule is distributed in the hope that it will be useful,        *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of						  *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the						  *
 *   GNU General Public License for more details.										  *
 *																						  *
 *   You should have received a copy of the GNU General Public License					  *
 *   along with LibUnknownEchoCryptoModule.  If not, see <http://www.gnu.org/licenses/>.  *
 ******************************************************************************************/

#include <uecm/init.h>
#include <uecm/crypto/api/hash/hasher.h>
#include <uecm/byte/byte_utility.h>
#include <uecm/byte/hex_utility.h>
#include <ei/ei.h>
#include <uecm/alloc.h>

#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

void print_usage(char *name) {
    printf("%s <data>\n", name);
}

int main(int argc, char **argv) {
    int exit_code;
    uecm_hasher *h;
    unsigned char *message, *digest;
    size_t message_length, digest_length;
    char *hex_digest;

    exit_code = EXIT_FAILURE;
    h = NULL;
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

	ei_init();

	if (!uecm_init()) {
		ei_stacktrace_push_msg("Failed to initialize LibUnknownEcho");
		goto clean_up;
	}
    ei_logger_info("UnknownEchoLibCryptoModule is correctly initialized");

    ei_logger_info("Converting parameter '%s' to bytes...", argv[1]);
    if ((message = uecm_bytes_create_from_string(argv[1])) == NULL) {
        ei_stacktrace_push_msg("Failed to convert arg to bytes")
        goto clean_up;
    }
    ei_logger_info("Succefully converted parameter to bytes");

    message_length = strlen(argv[1]);

    ei_logger_info("Creating new uecm_hasher");
    if ((h = uecm_hasher_create()) == NULL) {
        ei_stacktrace_push_msg("Failed to create uecm_hasher")
        goto clean_up;
    }
    ei_logger_info("Has successfully created a new uecm_hasher");

    ei_logger_info("Initializing uecm_hasher with SHA-256 digest algorithm");
    if (!(uecm_hasher_init(h, "sha256"))) {
        ei_stacktrace_push_msg("Failed to initialize uecm_hasher with SHA-256 algorithm")
        goto clean_up;
    }
    ei_logger_info("Has successfully initialized uecm_hasher");

    ei_logger_info("Hash processing...");
    if ((digest = uecm_hasher_digest(h, message, message_length, &digest_length)) == NULL) {
        ei_stacktrace_push_msg("Failed to hash message with SHA-256 digest algorithm")
        goto clean_up;
    }

    hex_digest = uecm_bytes_to_hex(digest, digest_length);
    ei_logger_info("Message digest of input '%s' is following : %s", argv[1], hex_digest);

    exit_code = EXIT_SUCCESS;

clean_up:
    if (ei_stacktrace_is_filled()) {
        ei_logger_error("An error occurred with the following stacktrace :");
        ei_stacktrace_print_all();
    }
    uecm_safe_free(message)
    uecm_safe_free(digest)
    uecm_hasher_destroy(h);
    uecm_safe_free(hex_digest)
    uecm_uninit();
	ei_uninit();
    return exit_code;
}
