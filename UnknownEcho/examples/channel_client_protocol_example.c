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
  *  @file      channel_client_protocol_example.c
  *  @brief     Create and launch a channel client.
  *             For the example, the output of messages
  *             is a consola.
  *  @warn      Only work on Unix for now, because of use of fork/pipe
  *  @author    Charly Lamothe
  *  @copyright GNU Public License.
  */

#include <uk/unknownecho/init.h>
#include <uk/unknownecho/protocol/api/channel/channel_client.h>
#include <uk/unknownecho/protocol/api/channel/channel_client_struct.h>
#include <uk/unknownecho/protocol/factory/channel_client_factory.h>
#include <uk/utils/ueum.h>
#include <uk/utils/ei.h>

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
        uk_utils_stacktrace_push_errno();
    }
}

/**
 * The user callback to process the decipher received message.
 * It print the result on the second consola.
 */
bool write_callback(void *user_context, uk_utils_byte_stream *printer) {
    /* Append \n and \0 to correctly print the message on the consola */
    if (!uk_utils_byte_writer_append_bytes(printer, (unsigned char *)"\n\0", 2)) {
        uk_utils_stacktrace_push_msg("Failed to write \n\0 to printer");
        return false;
    }

    /* Print the result */
    return write(fds[1], uk_utils_byte_stream_get_data(printer), uk_utils_byte_stream_get_size(printer));
}

void print_usage(char *name) {
    printf("%s [<host>]\n", name);
}

int main(int argc, char **argv) {
    char *nickname, *password;
    uk_ue_channel_client *channel_client;
    int child_pid;

    if (argc > 2) {
        fprintf(stderr, "[FATAL] Only one optional argument is possible.\n");
        print_usage(argv[0]);
        exit(1);
    }

    /* Initialize LibUnknownEcho */
    if (!uk_ue_init()) {
        fprintf(stderr, "[FATAL] Failed to initialize LibUnknownEcho\n");
        exit(EXIT_FAILURE);
    }

    nickname = NULL;
    password = NULL;
    channel_client = NULL;
    fds[1] = -1;
    child_pid = -1;

    /* Set log levels for the screen and the log file */
    uk_utils_logger_set_file_level(uk_utils_logger_manager_get_logger(), UnknownKrakenUtils_LOG_TRACE);
    uk_utils_logger_set_print_level(uk_utils_logger_manager_get_logger(), UnknownKrakenUtils_LOG_TRACE);

    /**
     * Get the user nickname.
     * The nickname is also used in certificate friendly names, so
     * for the moment it can leads to bugs if some user take the same
     * nickname.
     * If it's fail, it will add an error message to the stacktrace.
     */
    if (!(nickname = uk_utils_input_string("Nickname : "))) {
        uk_utils_stacktrace_push_msg("Specified nickname isn't valid");
        goto end;
    }

    /**
     * Get the user password.
     * The password is used to encrypt/decrypt the keystores.
     * If it's fail, it will add an error message to the stacktrace.
     */
    if (!(password = uk_utils_input_string("Password : "))) {
        uk_utils_stacktrace_push_msg("Specified password isn't valid");
        goto end;
    }

    /**
     * Create a pipe for interprocess communication,
     * in order to communicate deciphered messages to
     * second consola, to print them.
     * Only working on UNIX system.
     */
    if (pipe(fds) == -1) {
        uk_utils_stacktrace_push_errno();
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
        uk_utils_stacktrace_push_errno();
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
        uk_utils_stacktrace_push_errno();
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
        uk_ue_channel_client_init(MAX_CHANNEL_CLIENTS_NUMBER);

        /**
         * If an host is provided in parameter, then the client will try to
         * establish a connection with the remote host.
         */
        if (argc > 1) {
            uk_utils_logger_info("Trying to create and connect remote channel client on host %s...", argv[1]);
            if (!(channel_client = uk_ue_channel_client_create_default_remote(nickname, password, write_callback, argv[1]))) {
                uk_utils_stacktrace_push_msg("Failed to create remote channel client");
                goto end;
            }
        }
        /**
         * Else if no host is provided in parameter, then the client will try
         * to establish a connection in localhost.
         */
        else {
            uk_utils_logger_info("Trying to create and connect local channel client...");
            if (!(channel_client = uk_ue_channel_client_create_default_local(nickname, password, write_callback))) {
                uk_utils_stacktrace_push_msg("Failed to create local channel client");
                goto end;
            }
        }

        /* Shutdown all clients if ctrl+c is pressed. */
        handle_signal(SIGINT, uk_ue_channel_client_shutdown_signal_callback, 0);
        handle_signal(SIGPIPE, SIG_IGN, SA_RESTART);

        /* Connect the client */
        if (!uk_ue_channel_client_start(channel_client)) {
            uk_utils_stacktrace_push_msg("Failed to start channel client");
            goto end;
        }
    }

end:
    /* Close the consola */
    if (fds[1] != 1) {
        close(fds[1]);
    }
    /* Clean-up nickname and password */
    uk_utils_safe_free(nickname);
    uk_utils_safe_free(password);
    /* Log the stacktrace if it exists */
    if (uk_utils_stacktrace_is_filled()) {
        uk_utils_logger_stacktrace("An error occurred with the following stacktrace :");
    }
    /* If it's the parent process */
    if (child_pid != 0) {
        /* Clean-up the channel client */
        uk_ue_channel_client_destroy(channel_client);
        /* Uninit channel client protocol */
        uk_ue_channel_client_uninit();
    }
    /* Clean-up LibUnknownEcho */
    uk_ue_uninit();
    return 0;
}
