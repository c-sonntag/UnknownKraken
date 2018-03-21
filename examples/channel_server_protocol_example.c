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

 /**
  *  @file      channel_server_protocol_example.c
  *  @brief     Create and launch the default channel server.
  *  @author    Charly Lamothe
  *  @copyright GNU Public License.
  */

#include <unknownecho/init.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/errorHandling/logger_manager.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/protocol/api/channel/channel_server.h>
#include <unknownecho/protocol/factory/channel_server_factory.h>
#include <unknownecho/input.h>
#include <unknownecho/alloc.h>
#include <unknownecho/string/string_utility.h>

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
        ue_stacktrace_push_errno()
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
	ue_logger_set_file_level(ue_logger_manager_get_logger(), LOG_TRACE);
	ue_logger_set_print_level(ue_logger_manager_get_logger(), LOG_TRACE);

    /* Get the user keystore password. If it's fail, it will add an error message to the stacktrace. */
    if (!(keystore_password = ue_input_string("Keystore password : "))) {
        ue_stacktrace_push_msg("Specified keystore password isn't valid");
        goto end;
    }

    /* Get the user private keys password. If it's fail, it will add an error message to the stacktrace. */
    if (!(key_password = ue_input_string("Key password : "))) {
        ue_stacktrace_push_msg("Specified key password isn't valid");
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
        ue_stacktrace_push_msg("Failed to create server channel");
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
        ue_stacktrace_push_msg("Failed to start server channel");
        goto end;
    }

end:
    /* Remove keystore and key passwords */
    ue_safe_free(keystore_password);
    ue_safe_free(key_password);
    /* Log the stacktrace if it exists */
	if (ue_stacktrace_is_filled()) {
		ue_logger_stacktrace("An error occurred with the following stacktrace :");
	}
    /* Clean-up the channel server. */
    ue_channel_server_destroy();
    /* Clean-up UnknownEchoLib */
    ue_uninit();
    return 0;
}
