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
#include <unknownecho/protocol/api/channel/channel_client.h>
#include <unknownecho/protocol/api/channel/channel_client_struct.h>
#include <unknownecho/protocol/factory/channel_client_factory.h>
#include <unknownecho/string/string_utility.h>
#include <unknownecho/alloc.h>
#include <unknownecho/input.h>
#include <unknownecho/bool.h>
#include <unknownecho/byte/byte_stream.h>
#include <unknownecho/byte/byte_writer.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <signal.h>

#define MAX_CHANNEL_CLIENTS_NUMBER 3

int fds[2];

static void handle_signal(int sig, void (*h)(int), int options) {
    struct sigaction s;

    s.sa_handler = h;
    sigemptyset(&s.sa_mask);
    s.sa_flags = options;
    if (sigaction(sig, &s, NULL) < 0) {
        ue_stacktrace_push_errno();
    }
}

bool write_callback(void *user_context, ue_byte_stream *printer) {
    if (!ue_byte_writer_append_bytes(printer, (unsigned char *)"\n\0", 2)) {
		ue_stacktrace_push_msg("Failed to write \n\0 to printer");
		return false;
	}

    return write(fds[1], ue_byte_stream_get_data(printer), ue_byte_stream_get_size(printer));
}

int main() {
    char *nickname, *password;
    ue_channel_client *channel_client;
    int child_pid;

    if (!ue_init()) {
		printf("[ERROR] Failed to init LibUnknownEcho\n");
		exit(1);
	}

    nickname = NULL;
    password = NULL;
    channel_client = NULL;
    fds[1] = -1;
    child_pid = -1;

	ue_logger_set_file_level(ue_logger_manager_get_logger(), LOG_TRACE);
	ue_logger_set_print_level(ue_logger_manager_get_logger(), LOG_INFO);

    if (!(nickname = ue_input_string("Nickname : "))) {
        ue_stacktrace_push_msg("Specified nickname isn't valid");
        goto end;
    }

    if (!(password = ue_input_string("Password : "))) {
        ue_stacktrace_push_msg("Specified password isn't valid");
        goto end;
    }

    if (pipe(fds) == -1) {
		ue_stacktrace_push_errno();
        goto end;
    }

    child_pid = fork();
    if (child_pid == -1) {
		ue_stacktrace_push_errno();
        goto end;
    }

    if (child_pid == 0) {
        close(fds[1]);
        char f[PATH_MAX + 1];
        sprintf(f, "/dev/fd/%d", fds[0]);
        execlp("xterm", "xterm", "-e", "cat", f, NULL);
		ue_stacktrace_push_errno();
        goto end;
    }

    if (child_pid != 0) {
        close(fds[0]);

        ue_channel_client_init(MAX_CHANNEL_CLIENTS_NUMBER);

        if (!(channel_client = ue_channel_client_create_default(nickname, password, write_callback))) {

            ue_stacktrace_push_msg("Failed to create channel client");
            goto end;
        }

        handle_signal(SIGINT, ue_channel_client_shutdown_signal_callback, 0);
        handle_signal(SIGPIPE, SIG_IGN, SA_RESTART);

        if (!ue_channel_client_start(channel_client)) {
            ue_stacktrace_push_msg("Failed to start channel client");
            goto end;
        }
    }

end:
    if (fds[1] != 1) {
        close(fds[1]);
    }
    ue_safe_free(nickname);
    ue_safe_free(password);
    if (ue_stacktrace_is_filled()) {
		ue_logger_stacktrace("An error occurred with the following stacktrace :");
	}
    if (child_pid != 0) {
        ue_channel_client_destroy(channel_client);
        ue_channel_client_uninit();
    }
    ue_uninit();
    return 0;
}
