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
#include <unknownecho/crypto/api/compression/compress.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/byte/byte_utility.h>
#include <unknownecho/alloc.h>

#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

void print_usage(char *name) {
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

    if (!ue_init()) {
        fprintf(stderr, "[FATAL] Failed to initialize LibUnknownEcho\n");
        exit(EXIT_FAILURE);
    }
    ue_logger_info("UnknownEchoLib is correctly initialized.");

    ue_logger_info("Converting parameter '%s' to bytes...", argv[1]);
    if (!(message = ue_bytes_create_from_string(argv[1]))) {
        ue_stacktrace_push_msg("Failed to convert arg to bytes")
        goto clean_up;
    }
    message_length = strlen(argv[1]);
    ue_logger_info("Succefully converted parameter to bytes");

    ue_logger_info("Compressing message...");
    if (!(compressed = ue_compress_buf(message, message_length, &compressed_length))) {
        ue_stacktrace_push_msg("Failed to compress message")
        goto clean_up;
    }
    ue_logger_info("Message has been successfully compressed");

    ue_logger_info("Decompressing message...");
    if (!(decompressed = ue_decompress_buf(compressed, compressed_length, message_length))) {
        ue_stacktrace_push_msg("Failed to decompress message")
        goto clean_up;
    }

    ue_logger_info("Messages comparaison...");
    if (memcmp(decompressed, message, message_length) == 0) {
        ue_logger_info("Message has been successfully decompressed");
    } else {
        ue_logger_error("The message was decompressed but isn't the same as the original");
        ue_stacktrace_push_msg("Failed to decompress message")
        goto clean_up;
    }

    exit_code = EXIT_SUCCESS;

clean_up:
    ue_safe_free(message)
    ue_safe_free(compressed)
    ue_safe_free(decompressed)
    if (ue_stacktrace_is_filled()) {
        ue_logger_error("An error occurred with the following stacktrace :");
        ue_stacktrace_print_all();
    }
    ue_uninit();
    return exit_code;
}
