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
