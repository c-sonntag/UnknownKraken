#include <unknownecho/init.h>
#include <unknownecho/bool.h>
#include <unknownecho/protocol/api/relay/relay_server.h>
#include <unknownecho/protocol/api/relay/relay_step.h>
#include <unknownecho/network/api/communication/communication_metadata.h>
#include <unknownecho/network/factory/communication_metadata_factory.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/byte/byte_stream.h>
#include <unknownecho/crypto/api/crypto_metadata.h>
#include <unknownecho/crypto/api/certificate/x509_certificate.h>
#include <unknownecho/crypto/factory/crypto_metadata_factory.h>

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

bool received_message_callback(void *user_context, ue_byte_stream *received_message) {
    if (!received_message || ue_byte_stream_is_empty(received_message)) {
        ue_logger_error("Received message consumer called, but received message ptr is null or message is empty");
        return false;
    }

    ue_logger_info("Received the following message:");
    ue_byte_stream_print_string(received_message, stdout);

    return true;
}

/**
 * Set the specified callback h to the specified signal sig
 */
static void handle_signal(int sig, void (*h)(int), int options) {
    struct sigaction s;

    s.sa_handler = h;
    sigemptyset(&s.sa_mask);
    s.sa_flags = options;
    if (sigaction(sig, &s, NULL) < 0) {
        ue_stacktrace_push_errno()
    }
}

int main(int argc, char **argv) {
    ue_relay_server *server;
    ue_crypto_metadata *our_crypto_metadata;
    ue_communication_metadata *our_communication_metadata;

    server = NULL;
    our_crypto_metadata = NULL;
    our_communication_metadata = NULL;

    if (argc != 4) {
        fprintf(stdout, "Usage: %s <server_uid> <server_password> <server_port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    if (!ue_init()) {
        fprintf(stderr, "[FATAL] Failed to initialize LibUnknownEcho\n");
        exit(EXIT_FAILURE);
    }

    if (!(our_crypto_metadata = ue_crypto_metadata_create_default())) {
        ue_stacktrace_push_msg("Faield to create random crypto metadata");
        goto clean_up;
    }
    if (!ue_crypto_metadata_write(our_crypto_metadata, "out/private", argv[1], argv[2])) {
        ue_stacktrace_push_msg("Failed to write our crypto metadata in private files");
        goto clean_up;
    }
    if (!ue_crypto_metadata_write_certificates(our_crypto_metadata, "out/public", argv[1])) {
        ue_stacktrace_push_msg("Failed to write our certificates");
        goto clean_up;
    }
    if (!(our_communication_metadata = ue_communication_metadata_create_socket_type("127.0.0.1", atoi(argv[3])))) {
        ue_stacktrace_push_msg("Failed to create our communication metadata");
        goto clean_up;
    }

    if (!(server = ue_relay_server_create(our_communication_metadata, NULL,
        our_crypto_metadata, received_message_callback))) {

        ue_stacktrace_push_msg("Failed to create new relay server");
        goto clean_up;
    }

    if (!ue_relay_server_start(server)) {
        ue_stacktrace_push_msg("Failed to start server");
        goto clean_up;
    }

    /* Shutdown the server if ctrl+c if pressed. */
    handle_signal(SIGINT, ue_relay_server_shutdown_signal_callback, 0);
    handle_signal(SIGPIPE, SIG_IGN, SA_RESTART);

    ue_logger_info("Server is listening...");

    if (!ue_relay_server_wait(server)) {
        ue_stacktrace_push_msg("Failed to process server");
    }

clean_up:
    ue_relay_server_destroy(server);
    ue_crypto_metadata_destroy_all(our_crypto_metadata);
    ue_communication_metadata_destroy(our_communication_metadata);
    if (ue_stacktrace_is_filled()) {
        ue_logger_error("An error occurred with the following stacktrace :");
        ue_stacktrace_print_all();
    }
    ue_uninit();
    return 0;
}
