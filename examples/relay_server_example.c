#include <unknownecho/init.h>
#include <unknownecho/bool.h>
#include <unknownecho/protocol/api/relay/relay_server.h>
#include <unknownecho/protocol/api/relay/relay_step.h>
#include <unknownecho/network/api/communication/communication_metadata.h>
#include <unknownecho/network/factory/communication_metadata_factory.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/logger.h>

#include <stdio.h>
#include <stdlib.h>

static bool read_consumer(void *connection) {
    return false;
}

static bool write_consumer(void *connection) {
    return false;
}

int main() {
    ue_relay_server *server;

    server = NULL;

    if (!ue_init()) {
        fprintf(stderr, "[FATAL] Failed to initialize LibUnknownEcho\n");
        exit(EXIT_FAILURE);
    }

    if (!(server = ue_relay_server_create(ue_communication_metadata_create_socket_type("127.0.0.1", 5001), read_consumer, write_consumer))) {
        ue_stacktrace_push_msg("Failed to create new relay server");
        goto clean_up;
    }

    if (!ue_relay_server_start(server)) {
        ue_stacktrace_push_msg("Failed to start server");
        goto clean_up;
    }

    /*if (!ue_relay_server_is_valid(server)) {
        ue_stacktrace_push_msg("New relay server is invalid");
        goto clean_up;
    } else {
        ue_logger_info("New relay server is valid");
    }*/

    if (!ue_relay_server_wait(server)) {
        ue_stacktrace_push_msg("Failed to process server");
    }

clean_up:
    if (ue_stacktrace_is_filled()) {
        ue_logger_error("An error occurred with the following stacktrace :");
        ue_stacktrace_print_all();
    }
    ue_relay_server_destroy(server);
    ue_uninit();
    return 0;
}
