/*******************************************************************************
 * Copyright (C) 2018 Charly Lamothe                                           *
 *                                                                             *
 * This file is part of LibUnknownEcho.                                        *
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

 /**
  *  @file      channel_server_protocol_example.c
  *  @brief     Create and launch the default channel server.
  *  @author    Charly Lamothe
  *  @copyright GNU Public License.
  */

#include <unknownecho/init.h>
#include <unknownecho/protocol/api/channel/channel_server.h>
#include <unknownecho/protocol/factory/channel_server_factory.h>
#include <ueum/ueum.h>
#include <ei/ei.h>

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

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

int main() {
    char *keystore_password, *key_password;

    /* Initialize LibUnknownEcho */
    if (!ue_init()) {
        fprintf(stderr, "[FATAL] Failed to initialize LibUnknownEcho\n");
        exit(EXIT_FAILURE);
    }

    keystore_password = NULL;
    key_password = NULL;

    /* Set log levels for the screen and the log file */
    ei_logger_set_file_level(ei_logger_manager_get_logger(), ERRORINTERCEPTOR_LOG_TRACE);
    ei_logger_set_print_level(ei_logger_manager_get_logger(), ERRORINTERCEPTOR_LOG_TRACE);

    /* Get the user keystore password. If it's fail, it will add an error message to the stacktrace. */
    if (!(keystore_password = ueum_input_string("Keystore password : "))) {
        ei_stacktrace_push_msg("Specified keystore password isn't valid");
        goto end;
    }

    /* Get the user private keys password. If it's fail, it will add an error message to the stacktrace. */
    if (!(key_password = ueum_input_string("Key password : "))) {
        ei_stacktrace_push_msg("Specified key password isn't valid");
        goto end;
    }

    /**
     * Create a default channel server with only this two passwords in parameter.
     * The other parameters are specified with the default values in defines.h,
     * which are the persistent folder ('out' by default), hosts (localhost) and ports
     * (5001 for the TLS server and 5002 for the CSR server).
     * If it's fail, it will add an error message to the stacktrace.
     */
    if (!ue_channel_server_create_default(keystore_password, key_password)) {
        ei_stacktrace_push_msg("Failed to create server channel");
        goto end;
    }

    /* Shutdown the server if ctrl+c if pressed. */
    handle_signal(SIGINT, ue_channel_server_shutdown_signal_callback, 0);
    handle_signal(SIGPIPE, SIG_IGN, SA_RESTART);

    /**
     * Process the channel server.
     * See README.md for more informations.
     */
    if (!ue_channel_server_process()) {
        ei_stacktrace_push_msg("Failed to start server channel");
        goto end;
    }

end:
    ei_logger_info("Cleaning...");
    /* Remove keystore and key passwords */
    ueum_safe_free(keystore_password);
    ueum_safe_free(key_password);
    /* Log the stacktrace if it exists */
    if (ei_stacktrace_is_filled()) {
        ei_logger_stacktrace("An error occurred with the following stacktrace :");
    }
    /* Clean-up the channel server. */
    ue_channel_server_destroy();
    /* Clean-up LibUnknownEcho */
    ue_uninit();
    return 0;
}
