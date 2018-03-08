#include <unknownecho/init.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/errorHandling/logger_manager.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/protocol/api/channel/server_channel.h>

#include <stdio.h>
#include <stdlib.h>

#define ROOT_PATH           "out/server"
#define CSR_SERVER_PORT     5002
#define TLS_SERVER_PORT     5001
#define KEYSTORE_PASSWORD   "password"
#define SERVER_KEY_PASSWORD "passphrase"

int main() {
    if (!ue_init()) {
		printf("[ERROR] Failed to init LibUnknownEcho\n");
		exit(1);
	}

	ue_logger_set_file_level(ue_logger_manager_get_logger(), LOG_TRACE);
	ue_logger_set_print_level(ue_logger_manager_get_logger(), LOG_INFO);

    if (!ue_server_channel_create(ROOT_PATH, CSR_SERVER_PORT, TLS_SERVER_PORT,
        KEYSTORE_PASSWORD, 3, SERVER_KEY_PASSWORD)) {
        ue_stacktrace_push_msg("Failed to create server channel");
        goto end;
    }

    if (!ue_server_channel_process()) {
        ue_stacktrace_push_msg("Failed to start server channel");
        goto end;
    }

end:
	if (ue_stacktrace_is_filled()) {
		ue_logger_stacktrace("An error occurred with the following stacktrace :");
	}
    ue_server_channel_destroy();
    ue_uninit();
    return 0;
}
