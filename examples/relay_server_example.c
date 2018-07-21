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
#include <unknownecho/protocol/api/relay/relay_server.h>
#include <unknownecho/protocol/api/relay/relay_step.h>
#include <unknownecho/network/api/communication/communication_metadata.h>
#include <unknownecho/network/factory/communication_metadata_factory.h>
#include <ueum/ueum.h>
#include <uecm/uecm.h>
#include <ei/ei.h>

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

bool received_message_callback(void *user_context, ueum_byte_stream *received_message) {
    if (!received_message || ueum_byte_stream_is_empty(received_message)) {
        ei_logger_error("Received message consumer called, but received message ptr is null or message is empty");
        return false;
    }

    ei_logger_info("Received the following message:");
    ueum_byte_stream_print_string(received_message, stdout);

    return true;
}

/**
 * Set the specified callback h to the specified signal sig
 */
static void handle_signal(int sig, void (*h)(int), int options) {
    struct sigaction s;

    s.sa_handler = h;
    sigemptyset(&s.sa_mask);
    s.sa_flags = options;
    if (sigaction(sig, &s, NULL) < 0) {
        ei_stacktrace_push_errno()
    }
}

int main(int argc, char **argv) {
    ue_relay_server *server;
    uecm_crypto_metadata *our_crypto_metadata;
    ue_communication_metadata *our_communication_metadata;

    server = NULL;
    our_crypto_metadata = NULL;
    our_communication_metadata = NULL;

    if (argc != 4) {
        fprintf(stdout, "Usage: %s <server_uid> <server_password> <server_port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    if (!ue_init()) {
        fprintf(stderr, "[FATAL] Failed to initialize LibUnknownEcho\n");
        exit(EXIT_FAILURE);
    }

    if (!(our_crypto_metadata = uecm_crypto_metadata_write_if_not_exist("out/private", "out/public", argv[1], argv[2]))) {
        ei_stacktrace_push_msg("Failed to get crypto metadata");
        goto clean_up;
    }

    if (!(our_communication_metadata = ue_communication_metadata_create_socket_type(argv[1], "127.0.0.1", atoi(argv[3])))) {
        ei_stacktrace_push_msg("Failed to create our communication metadata");
        goto clean_up;
    }

    if (!(server = ue_relay_server_create(our_communication_metadata, NULL,
        our_crypto_metadata, received_message_callback))) {

        ei_stacktrace_push_msg("Failed to create new relay server");
        goto clean_up;
    }

    if (!ue_relay_server_start(server)) {
        ei_stacktrace_push_msg("Failed to start server");
        goto clean_up;
    }

    /* Shutdown the server if ctrl+c if pressed. */
    handle_signal(SIGINT, ue_relay_server_shutdown_signal_callback, 0);
    handle_signal(SIGPIPE, SIG_IGN, SA_RESTART);

    ei_logger_info("Server is listening...");

    if (!ue_relay_server_wait(server)) {
        ei_stacktrace_push_msg("Failed to process server");
    }

clean_up:
    ue_relay_server_destroy(server);
    uecm_crypto_metadata_destroy_all(our_crypto_metadata);
    ue_communication_metadata_destroy(our_communication_metadata);
    if (ei_stacktrace_is_filled()) {
        ei_logger_error("An error occurred with the following stacktrace :");
        ei_stacktrace_print_all();
    }
    ue_uninit();
    return 0;
}
