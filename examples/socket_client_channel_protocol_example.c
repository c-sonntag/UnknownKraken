#include <unknownecho/init.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/errorHandling/logger_manager.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/protocol/api/channel/socket_client_channel.h>
#include <unknownecho/string/string_utility.h>
#include <unknownecho/system/alloc.h>

#include <stdio.h>
#include <stdlib.h>

#define ROOT_PATH         "out"
#define CSR_SERVER_HOST   "127.0.0.1"
#define CSR_SERVER_PORT   5002
#define TLS_SERVER_HOST   "127.0.0.1"
#define TLS_SERVER_PORT   5001
#define KEYSTORE_PASSWORD "password"

static char *get_input(char *prefix) {
	char input[256], *result;
	int i;

	result = NULL;

	printf("%s", prefix);

  	if (fgets(input, 256, stdin)) {
  		if (input[0] == 10) {
  			return NULL;
  		}
  		for (i = 0; i < 256; i++) {
  			if (input[i] != ' ') {
  				result = ue_string_create_from(input);
  				ue_remove_last_char(result);
  				break;
  			}
  		}
  	}

  	return result;
}

int main() {
    char *nickname;

    if (!ue_init()) {
		printf("[ERROR] Failed to init LibUnknownEcho\n");
		exit(1);
	}

    nickname = NULL;

	ue_logger_set_file_level(ue_logger_manager_get_logger(), LOG_TRACE);
	ue_logger_set_print_level(ue_logger_manager_get_logger(), LOG_INFO);

    if (!(nickname = get_input("Nickname : "))) {
        ue_stacktrace_push_msg("Specified nickname isn't valid");
        goto end;
    }

    if (!ue_socket_client_channel_create(ROOT_PATH, nickname, CSR_SERVER_HOST, CSR_SERVER_PORT,
    	TLS_SERVER_HOST, TLS_SERVER_PORT, KEYSTORE_PASSWORD)) {
        ue_stacktrace_push_msg("Failed to create channel client");
        goto end;
    }

    if (!ue_socket_client_channel_start()) {
        ue_stacktrace_push_msg("Failed to start channel client");
        goto end;
    }

end:
    ue_safe_free(nickname);
	ue_socket_client_channel_destroy();
	if (ue_stacktrace_is_filled()) {
		ue_logger_stacktrace("An error occurred with the following stacktrace :");
	}
    ue_uninit();
    return 0;
}
