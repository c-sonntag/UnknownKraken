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

#include <uecm/uecm.h>
#include <ueum/ueum.h>
#include <ei/ei.h>

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

	ei_init_or_die();
    ei_logger_use_symbol_levels();

    ei_logger_info("Initializing LibUnknownEchoCryptoModule...");
    if (!uecm_init()) {
		ei_stacktrace_push_msg("Failed to initialize LibUnknownEchoCryptoModule");
		goto clean_up;
    }
    ei_logger_info("LibUnknownEchoCryptoModule is correctly initialized.");

    ei_logger_info("Converting parameter '%s' to bytes...", argv[1]);
    if ((message = ueum_bytes_create_from_string(argv[1])) == NULL) {
        ei_stacktrace_push_msg("Failed to convert arg to bytes")
        goto clean_up;
    }
    message_length = strlen(argv[1]);
    ei_logger_info("Succefully converted parameter to bytes");

    ei_logger_info("Compressing message...");
    if ((compressed = uecm_compress_buf(message, message_length, &compressed_length)) == NULL) {
        ei_stacktrace_push_msg("Failed to compress message")
        goto clean_up;
    }
    ei_logger_info("Message has been successfully compressed");

    ei_logger_info("Decompressing message...");
    if ((decompressed = uecm_decompress_buf(compressed, compressed_length, message_length)) == NULL) {
        ei_stacktrace_push_msg("Failed to decompress message")
        goto clean_up;
    }

    ei_logger_info("Messages comparaison...");
    if (memcmp(decompressed, message, message_length) == 0) {
        ei_logger_info("Message has been successfully decompressed");
    } else {
        ei_logger_error("The message was decompressed but isn't the same as the original");
        ei_stacktrace_push_msg("Failed to decompress message")
        goto clean_up;
    }

    exit_code = EXIT_SUCCESS;

clean_up:
    ueum_safe_free(message)
    ueum_safe_free(compressed)
    ueum_safe_free(decompressed)
    if (ei_stacktrace_is_filled()) {
        ei_logger_error("An error occurred with the following stacktrace :");
        ei_stacktrace_print_all();
    }
    uecm_uninit();
	ei_uninit();
    return exit_code;
}
