#include <unknownecho/init.h>
#include <unknownecho/alloc.h>
#include <unknownecho/protocol/api/relay/relay_client.h>
#include <unknownecho/protocol/api/relay/relay_step.h>
#include <unknownecho/protocol/api/relay/relay_route.h>
#include <unknownecho/network/api/communication/communication_metadata.h>
#include <unknownecho/network/factory/communication_metadata_factory.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/byte/byte_stream.h>
#include <unknownecho/byte/byte_writer.h>
#include <unknownecho/crypto/api/crypto_metadata.h>
#include <unknownecho/crypto/factory/crypto_metadata_factory.h>
#include <unknownecho/string/string_utility.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static ue_relay_step *create_step_from_uid(ue_crypto_metadata *our_crypto_metadata, char *target_uid, int target_port) {
    ue_relay_step *step;
    ue_crypto_metadata *target_crypto_metadata;

    if (!(target_crypto_metadata = ue_crypto_metadata_create_empty())) {
        ue_stacktrace_push_msg("Failed to create empty crypto metadata object for target");
        return NULL;
    }

    if (!ue_crypto_metadata_read_certificates(target_crypto_metadata, "out/public", target_uid)) {
        ue_crypto_metadata_destroy(target_crypto_metadata);
        ue_stacktrace_push_msg("Failed to read certificates of target");
        return NULL;
    }

    if (!(step = ue_relay_step_create(ue_communication_metadata_create_socket_type("127.0.0.1", target_port),
        our_crypto_metadata, target_crypto_metadata))) {

        ue_crypto_metadata_destroy(target_crypto_metadata);
        ue_stacktrace_push_msg("Failed to create step with uid '%s'", target_uid);
        return NULL;
    }

    return step;
}

ue_relay_route *create_route_from_args(ue_crypto_metadata *our_crypto_metadata, int argc, char **argv) {
    ue_relay_route *route;
    ue_relay_step **steps;
    int step_number;
    int i, j;

    route = NULL;
    steps = NULL;
    step_number = (argc - 3)/2;
    ue_safe_alloc(steps, ue_relay_step *, step_number);

    for (i = 3, j = 0; i < argc; i+=2, j++) {
        if (!(steps[j] = create_step_from_uid(our_crypto_metadata, argv[i], atoi(argv[i+1])))) {
            ue_stacktrace_push_msg("Failed to create step at iteration %d with uid '%s'", j, argv[i]);
            goto clean_up_fail;
        }
    }

    if (!(route = ue_relay_route_create(steps, step_number))) {
        ue_stacktrace_push_msg("Failed to create new relay route");
        goto clean_up_fail;
    }

    return route;

clean_up_fail:
    if (steps) {
        for (i = 0; i < step_number; i++) {
            ue_crypto_metadata_destroy_all(ue_relay_step_get_target_crypto_metadata(steps[i]));
            ue_relay_step_destroy(steps[i]);
        }
        ue_safe_free(steps);
    }
    return NULL;
}

ue_relay_route *generate_simple_route(ue_crypto_metadata *our_crypto_metadata) {
    ue_relay_route *route;
    ue_crypto_metadata *b_crypto_metadata, *c_crypto_metadata;

    if (!(b_crypto_metadata = ue_crypto_metadata_create_empty())) {
        ue_stacktrace_push_msg("Failed to create empty crypto metadata object for target b");
        return NULL;
    }

    if (!ue_crypto_metadata_read_certificates(b_crypto_metadata, "out/public", "server1_uid")) {
        ue_crypto_metadata_destroy(b_crypto_metadata);
        ue_stacktrace_push_msg("Failed to read certificates of target b");
        return NULL;
    }

    if (!(c_crypto_metadata = ue_crypto_metadata_create_empty())) {
        ue_stacktrace_push_msg("Failed to create empty crypto metadata object for target c");
        return NULL;
    }

    if (!ue_crypto_metadata_read_certificates(c_crypto_metadata, "out/public", "server2_uid")) {
        ue_crypto_metadata_destroy(c_crypto_metadata);
        ue_stacktrace_push_msg("Failed to read certificates of target c");
        return NULL;
    }

    if (!(route = ue_relay_route_create(
        ue_relay_steps_create(
            2,
            ue_relay_step_create(ue_communication_metadata_create_socket_type("127.0.0.1", 5001), our_crypto_metadata, b_crypto_metadata),
            ue_relay_step_create(ue_communication_metadata_create_socket_type("127.0.0.1", 5002), our_crypto_metadata, c_crypto_metadata)
        ),
        2))) {

        ue_stacktrace_push_msg("Failed to create route A -> B -> C");
        return NULL;
    }

    return route;
}

int main(int argc, char **argv) {
    ue_relay_client *client;
    ue_relay_route *route;
    ue_byte_stream *message;
    ue_crypto_metadata *our_crypto_metadata;

    client = NULL;
    route = NULL;
    message = NULL;
    our_crypto_metadata = NULL;

    if (argc < 4) {
        fprintf(stdout, "Usage: %s <client_uid> <client_password> <server_uid> <server_port> [server_uid server_port ...]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    if (!ue_init()) {
        fprintf(stderr, "[FATAL] Failed to initialize LibUnknownEcho\n");
        exit(EXIT_FAILURE);
    }
    ue_logger_info("UnknownEchoLib is correctly initialized.");

    if (!(message = ue_byte_stream_create())) {
        ue_stacktrace_push_msg("Failed to create empty byte stream");
        goto clean_up;
    }
    if (!(our_crypto_metadata = ue_crypto_metadata_create_default())) {
        ue_stacktrace_push_msg("Failed to create random crypto metadata");
        goto clean_up;
    }
    if (!ue_crypto_metadata_write(our_crypto_metadata, "out/private", argv[1], argv[2])) {
        ue_stacktrace_push_msg("Failed to write our crypto metadata in secure files");
        goto clean_up;
    }
    if (!ue_crypto_metadata_write_certificates(our_crypto_metadata, "out/public", argv[1])) {
        ue_stacktrace_push_msg("Failed to write our certificates in public folder");
        goto clean_up;
    }

    route = create_route_from_args(our_crypto_metadata, argc, argv);

    //route = generate_simple_route(our_crypto_metadata);

    if (!ue_relay_route_is_valid(route)) {
        ue_stacktrace_push_msg("New route is invalid");
        goto clean_up;
    }

    if (!(client = ue_relay_client_create_from_route(route))) {
        ue_stacktrace_push_msg("Failed to create new relay client");
        goto clean_up;
    }

    if (!ue_relay_client_is_valid(client)) {
        ue_stacktrace_push_msg("New relay client is invalid");
        goto clean_up;
    }
    ue_logger_info("New relay client is valid");

    ue_byte_writer_append_string(message, "Hello world !");

    if (!ue_relay_client_send_message(client, message)) {
        ue_stacktrace_push_msg("Failed to send message to server");
        goto clean_up;
    }

    ue_logger_info("Message sent.");

clean_up:
    ue_byte_stream_destroy(message);
    ue_relay_client_destroy(client);
    ue_crypto_metadata_destroy_all(our_crypto_metadata);
    ue_relay_route_destroy(route);
    if (ue_stacktrace_is_filled()) {
        ue_logger_error("An error occurred with the following stacktrace :");
        ue_stacktrace_print_all();
    }
    ue_uninit();
    return 0;
}
