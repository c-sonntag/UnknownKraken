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
  *  @file      channel_client_protocol_example.c
  *  @brief     Create and launch a channel client.
  *             For the example, the output of messages
  *             is a consola.
  *  @warn      Only work on Unix for now, because of use of
  *  @author    Charly Lamothe
  *  @copyright GNU Public License.
  */

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

/* Max channel number supported by this client */
#define MAX_CHANNEL_CLIENTS_NUMBER 3

/* The file descriptor of the output consola */
int fds[2];

/**
 * Set the specified callback h to the specified signal sig
 */
static void handle_signal(int sig, void (*h)(int), int options) {
    struct sigaction s;

    s.sa_handler = h;
    sigemptyset(&s.sa_mask);
    s.sa_flags = options;
    if (sigaction(sig, &s, NULL) < 0) {
        ue_stacktrace_push_errno();
    }
}

/**
 * The user callback to process the decipher received message.
 * It print the result on the second consola.
 */
bool write_callback(void *user_context, ue_byte_stream *printer) {
    /* Append \n and \0 to correctly print the message on the consola */
    if (!ue_byte_writer_append_bytes(printer, (unsigned char *)"\n\0", 2)) {
		ue_stacktrace_push_msg("Failed to write \n\0 to printer");
		return false;
	}

    /* Print the result */
    return write(fds[1], ue_byte_stream_get_data(printer), ue_byte_stream_get_size(printer));
}

void print_usage(char *name) {
    printf("%s [<host>]\n", name);
}

int main(int argc, char **argv) {
    char *nickname, *password;
    ue_channel_client *channel_client;
    int child_pid;

    if (argc > 2) {
        fprintf(stderr, "[FATAL] Only one optional argument is possible.\n");
        print_usage(argv[0]);
        exit(1);
    }

    /* Initialize LibUnknownEcho */
    if (!ue_init()) {
        fprintf(stderr, "[FATAL] Failed to initialize LibUnknownEcho\n");
        exit(EXIT_FAILURE);
	}

    nickname = NULL;
    password = NULL;
    channel_client = NULL;
    fds[1] = -1;
    child_pid = -1;

    /* Set log levels for the screen and the log file */
	ue_logger_set_file_level(ue_logger_manager_get_logger(), LOG_TRACE);
	ue_logger_set_print_level(ue_logger_manager_get_logger(), LOG_TRACE);

    /**
     * Get the user nickname.
     * The nickname is also used in certificate friendly names, so
     * for the moment it can leads to bugs if some user take the same
     * nickname.
     * If it's fail, it will add an error message to the stacktrace.
     */
    if (!(nickname = ue_input_string("Nickname : "))) {
        ue_stacktrace_push_msg("Specified nickname isn't valid");
        goto end;
    }

    /**
     * Get the user password.
     * The password is used to encrypt/decrypt the keystores.
     * If it's fail, it will add an error message to the stacktrace.
     */
    if (!(password = ue_input_string("Password : "))) {
        ue_stacktrace_push_msg("Specified password isn't valid");
        goto end;
    }

    /**
     * Create a pipe for interprocess communication,
     * in order to communicate deciphered messages to
     * second consola, to print them.
     * Only working on UNIX system.
     */
    if (pipe(fds) == -1) {
		ue_stacktrace_push_errno();
        goto end;
    }

    /**
     * Fork (duplicate) the process.
     * The second process is just a consola that print
     * deciphered messages.
     */
    child_pid = fork();
    /* Check if fork() failed. */
    if (child_pid == -1) {
		ue_stacktrace_push_errno();
        goto end;
    }

    /**
     * If child_pid is equal to 0, then
     * the current process is the child,
     * then the process is just an xtern consola
     * that will print messages.
     */
    if (child_pid == 0) {
        /* Close the unused parent process */
        close(fds[1]);
        char f[PATH_MAX + 1];
        sprintf(f, "/dev/fd/%d", fds[0]);
        execlp("xterm", "xterm", "-e", "cat", f, NULL);
		ue_stacktrace_push_errno();
        goto end;
    }

    /**
     * If child_pid is > to 0, then the current
     * process is the parent, so it close
     */
    if (child_pid != 0) {
        /* Close the unused child process */
        close(fds[0]);

        /* Init channel client list with this max channel number */
        ue_channel_client_init(MAX_CHANNEL_CLIENTS_NUMBER);

        /**
         * If an host is provided in parameter, then the client will try to
         * establish a connection with the remote host.
         */
        if (argc > 1) {
            ue_logger_info("Trying to create and connect remote channel client on host %s...", argv[1]);
            if (!(channel_client = ue_channel_client_create_default_remote(nickname, password, write_callback, argv[1]))) {
                ue_stacktrace_push_msg("Failed to create remote channel client");
                goto end;
            }
        }
        /**
         * Else if no host is provided in parameter, then the client will try
         * to establish a connection in localhost.
         */
        else {
            ue_logger_info("Trying to create and connect local channel client...");
            if (!(channel_client = ue_channel_client_create_default_local(nickname, password, write_callback))) {
                ue_stacktrace_push_msg("Failed to create local channel client");
                goto end;
            }
        }

        /* Shutdown all clients if ctrl+c is pressed. */
        handle_signal(SIGINT, ue_channel_client_shutdown_signal_callback, 0);
        handle_signal(SIGPIPE, SIG_IGN, SA_RESTART);

        /* Connect the client */
        if (!ue_channel_client_start(channel_client)) {
            ue_stacktrace_push_msg("Failed to start channel client");
            goto end;
        }
    }

end:
    /* Close the consola */
    if (fds[1] != 1) {
        close(fds[1]);
    }
    /* Clean-up nickname and password */
    ue_safe_free(nickname);
    ue_safe_free(password);
    /* Log the stacktrace if it exists */
    if (ue_stacktrace_is_filled()) {
		ue_logger_stacktrace("An error occurred with the following stacktrace :");
	}
    /* If it's the parent process */
    if (child_pid != 0) {
        /* Clean-up the channel client */
        ue_channel_client_destroy(channel_client);
        /* Uninit channel client protocol */
        ue_channel_client_uninit();
    }
    /* Clean-up UnknownEchoLib */
    ue_uninit();
    return 0;
}
