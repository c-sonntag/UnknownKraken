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
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/errorHandling/logger_manager.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/protocol/api/channel/channel_server.h>
#include <unknownecho/protocol/factory/channel_server_factory.h>

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#define KEYSTORE_PASSWORD   "password"
#define SERVER_KEY_PASSWORD "passphrase"

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
    if (!ue_init()) {
		printf("[ERROR] Failed to init LibUnknownEcho\n");
		exit(1);
	}

	ue_logger_set_file_level(ue_logger_manager_get_logger(), LOG_TRACE);
	ue_logger_set_print_level(ue_logger_manager_get_logger(), LOG_INFO);

    if (!ue_channel_server_create_default(KEYSTORE_PASSWORD, SERVER_KEY_PASSWORD)) {
        ue_stacktrace_push_msg("Failed to create server channel");
        goto end;
    }

    handle_signal(SIGINT, ue_channel_server_shutdown_signal_callback, 0);
    handle_signal(SIGPIPE, SIG_IGN, SA_RESTART);

    if (!ue_channel_server_process()) {
        ue_stacktrace_push_msg("Failed to start server channel");
        goto end;
    }

end:
	if (ue_stacktrace_is_filled()) {
		ue_logger_stacktrace("An error occurred with the following stacktrace :");
	}
    ue_channel_server_destroy();
    ue_uninit();
    return 0;
}
