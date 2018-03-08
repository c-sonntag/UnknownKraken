#include <unknownecho/init.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/errorHandling/logger_manager.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/protocol/api/channel/client_channel.h>
#include <unknownecho/protocol/api/channel/client_channel_struct.h>
#include <unknownecho/string/string_utility.h>
#include <unknownecho/alloc.h>
#include <unknownecho/input.h>
#include <unknownecho/bool.h>
#include <unknownecho/byte/byte_stream.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>

#define ROOT_PATH         "out"
#define CSR_SERVER_HOST   "127.0.0.1"
#define CSR_SERVER_PORT   5002
#define TLS_SERVER_HOST   "127.0.0.1"
#define TLS_SERVER_PORT   5001
#define KEYSTORE_PASSWORD "password"

int fds[2];

bool write_consumer(ue_byte_stream *printer) {
    return write(fds[1], ue_byte_stream_get_data(printer), ue_byte_stream_get_size(printer));
}

int main() {
    char *nickname;
    ue_client_channel *client_channel;
    int child_pid;

    if (!ue_init()) {
		printf("[ERROR] Failed to init LibUnknownEcho\n");
		exit(1);
	}

    nickname = NULL;
    client_channel = NULL;
    fds[1] = -1;

	ue_logger_set_file_level(ue_logger_manager_get_logger(), LOG_TRACE);
	ue_logger_set_print_level(ue_logger_manager_get_logger(), LOG_INFO);

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

        if (!(nickname = ue_input_string("Nickname : "))) {
            ue_stacktrace_push_msg("Specified nickname isn't valid");
            goto end;
        }

        ue_client_channel_init();

        if (!(client_channel = ue_client_channel_create(ROOT_PATH, nickname, CSR_SERVER_HOST, CSR_SERVER_PORT,
        	TLS_SERVER_HOST, TLS_SERVER_PORT, KEYSTORE_PASSWORD, write_consumer))) {
            ue_stacktrace_push_msg("Failed to create channel client");
            goto end;
        }

        if (!ue_client_channel_start(client_channel)) {
            ue_stacktrace_push_msg("Failed to start channel client");
            goto end;
        }
    }

end:
    if (fds[1] != 1) {
        close(fds[1]);
    }
    ue_safe_free(nickname);
	ue_client_channel_destroy(client_channel);
	ue_client_channel_uninit();
	if (ue_stacktrace_is_filled()) {
		ue_logger_stacktrace("An error occurred with the following stacktrace :");
	}
    ue_uninit();
    return 0;
}
