#include <unknownecho/init.h>
#include <unknownecho/protocol/api/relay/relay_client.h>
#include <unknownecho/protocol/api/relay/relay_step.h>
#include <unknownecho/network/api/communication/communication_metadata.h>
#include <unknownecho/network/factory/communication_metadata_factory.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/logger.h>

#include <stdio.h>
#include <stdlib.h>

int main() {
    ue_relay_client *client;

    client = NULL;

    if (!ue_init()) {
        fprintf(stderr, "[FATAL] Failed to initialize LibUnknownEcho\n");
        exit(EXIT_FAILURE);
    }

    if (!(client = ue_relay_client_create(ue_relay_step_create(ue_communication_metadata_create_socket_type("127.0.0.1", 5001),
        ue_communication_metadata_create_socket_type("127.0.0.1", 5001), NULL, NULL)))) {

        ue_stacktrace_push_msg("Failed to create new relay client");
        goto clean_up;
    }

    if (!ue_relay_client_is_valid(client)) {
        ue_stacktrace_push_msg("New relay client is invalid");
    } else {
        ue_logger_info("New relay client is valid");
    }

clean_up:
    if (ue_stacktrace_is_filled()) {
        ue_logger_error("An error occurred with the following stacktrace :");
        ue_stacktrace_print_all();
    }
    ue_relay_client_destroy(client);
    ue_uninit();
    return 0;
}
