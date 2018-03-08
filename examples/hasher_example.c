/*******************************************************************************
 * Copyright (C) 2018 by Charly Lamothe                                        *
 *                                                                             *
 * This file is part of UnknownEchoLib.                                        *
 *                                                                             *
 *   UnknownEchoLib is free software: you can redistribute it and/or modify    *
 *   it under the terms of the GNU General Public License as published by      *
 *   the Free Software Foundation, either version 3 of the License, or         *
 *   (at your option) any later version.                                       *
 *                                                                             *
 *   UnknownEchoLib is distributed in the hope that it will be useful,         *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of            *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the             *
 *   GNU General Public License for more details.                              *
 *                                                                             *
 *   You should have received a copy of the GNU General Public License         *
 *   along with UnknownEchoLib.  If not, see <http://www.gnu.org/licenses/>.   *
 *******************************************************************************/

#include <unknownecho/init.h>
#include <unknownecho/crypto/api/hash/hasher.h>
#include <unknownecho/byte/byte_utility.h>
#include <unknownecho/byte/hex_utility.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/alloc.h>

#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    int exit_code;
    ue_hasher *h;
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
        fprintf(stderr, "[FATAL] An argument is required\n");
        exit(EXIT_FAILURE);
    }

    if (!ue_init()) {
        fprintf(stderr, "[FATAL] Failed to initialize UnknownEchoLib\n");
        exit(EXIT_FAILURE);
    }
    ue_logger_info("UnknownEchoLib is correctly initialized");

    ue_logger_info("Converting parameter '%s' to bytes...", argv[1]);
    if (!(message = ue_bytes_create_from_string(argv[1]))) {
        ue_stacktrace_push_msg("Failed to convert arg to bytes")
        goto clean_up;
    }
    ue_logger_info("Succefully converted parameter to bytes");

    message_length = strlen(argv[1]);

    ue_logger_info("Creating new ue_hasher");
    if (!(h = ue_hasher_create())) {
        ue_stacktrace_push_msg("Failed to create ue_hasher")
        goto clean_up;
    }
    ue_logger_info("Has successfully created a new ue_hasher");

    ue_logger_info("Initializing ue_hasher with SHA-256 digest algorithm");
    if (!(ue_hasher_init(h, "SHA-256"))) {
        ue_stacktrace_push_msg("Failed to initialize ue_hasher with SHA-256 algorithm")
        goto clean_up;
    }
    ue_logger_info("Has successfully initialized ue_hasher");

    ue_logger_info("Hash processing...");
    if (!(digest = ue_hasher_digest(h, message, message_length, &digest_length))) {
        ue_stacktrace_push_msg("Failed to hash message with SHA-256 digest algorithm")
        goto clean_up;
    }

    hex_digest = ue_bytes_to_hex(digest, digest_length);
    ue_logger_info("Message digest of input '%s' is following : %s", argv[1], hex_digest);

    exit_code = EXIT_SUCCESS;

clean_up:
    if (ue_stacktrace_is_filled()) {
        ue_logger_error("An error occurred with the following stacktrace :");
        ue_stacktrace_print_all();
    }
    ue_safe_free(message)
    ue_safe_free(digest)
    ue_hasher_destroy(h);
    ue_safe_free(hex_digest)
    ue_uninit();
    return exit_code;
}
