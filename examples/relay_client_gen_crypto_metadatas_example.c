/*******************************************************************************
 * Copyright (C) 2018 by Charly Lamothe                                        *
 *                                                                             *
 * This file is part of LibUnknownEcho.                                        *
 *                                                                             *
 *   LibUnknownEcho is free software: you can redistribute it and/or modify    *
 *   it under the terms of the GNU General Public License as published by      *
 *   the Free Software Foundation, either version 3 of the License, or         *
 *   (at your option) any later version.                                       *
 *                                                                             *
 *   LibUnknownEcho is distributed in the hope that it will be useful,         *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of            *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the             *
 *   GNU General Public License for more details.                              *
 *                                                                             *
 *   You should have received a copy of the GNU General Public License         *
 *   along with LibUnknownEcho.  If not, see <http://www.gnu.org/licenses/>.   *
 *******************************************************************************/

#include <unknownecho/init.h>
#include <ueum/ueum.h>
#include <uecm/uecm.h>
#include <ei/ei.h>

#include <stdlib.h>

#define try_or_clean_up(exp, error_message, label) \
    if (!(exp)) { \
        ei_stacktrace_push_msg("%s", error_message); \
        goto label; \
    } \

int main() {
    uecm_crypto_metadata *crypto_metadata;

    if (!ue_init()) {
        fprintf(stderr, "[FATAL] Failed to initialize LibUnknownEcho\n");
        exit(EXIT_FAILURE);
    }
    ei_logger_info("LibUnknownEcho is correctly initialized.");

    try_or_clean_up(crypto_metadata = uecm_crypto_metadata_write_if_not_exist("out/private", "out/public",
        "client1", "password"), "Failed to write crypto metadata for client1", end);
    uecm_crypto_metadata_destroy(crypto_metadata);

    try_or_clean_up(crypto_metadata = uecm_crypto_metadata_write_if_not_exist("out/private", "out/public",
        "client2", "password"), "Failed to write crypto metadata for client2", end);
    uecm_crypto_metadata_destroy(crypto_metadata);

    try_or_clean_up(crypto_metadata = uecm_crypto_metadata_write_if_not_exist("out/private", "out/public",
        "server1", "password"), "Failed to write crypto metadata for server1", end);
    uecm_crypto_metadata_destroy(crypto_metadata);

    try_or_clean_up(crypto_metadata = uecm_crypto_metadata_write_if_not_exist("out/private", "out/public",
        "server2", "password"), "Failed to write crypto metadata for server2", end);
    uecm_crypto_metadata_destroy(crypto_metadata);

end:
    if (ei_stacktrace_is_filled()) {
        ei_logger_error("An error occurred with the following stacktrace :");
        ei_stacktrace_print_all();
    }
    ue_uninit();
    return EXIT_SUCCESS;
}
