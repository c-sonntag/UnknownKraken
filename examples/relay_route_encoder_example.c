#include <unknownecho/init.h>
#include <unknownecho/protocol/api/relay/relay_step.h>
#include <unknownecho/protocol/api/relay/relay_route.h>
#include <unknownecho/protocol/api/relay/relay_route_encoder.h>
#include <unknownecho/protocol/api/relay/relay_route_decoder.h>
#include <unknownecho/network/api/communication/communication_metadata.h>
#include <unknownecho/network/factory/communication_metadata_factory.h>
#include <unknownecho/crypto/factory/crypto_metadata_factory.h>
#include <unknownecho/byte/byte_stream.h>
#include <unknownecho/byte/byte_writer.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/errorHandling/stacktrace.h>

#include <stdio.h>
#include <stdlib.h>

/**
 * @brief main
 * @todo print route
 * @todo replace route creation by a factory
 */
int main() {
    int step_number;
    ue_relay_route *route;
    ue_byte_stream *encoded_route;
    ue_crypto_metadata *our_crypto_metadata, *b_crypto_metadata, *c_crypto_metadata;
    ue_relay_step *b_extracted_step, *c_extracted_step;

    step_number = 2;
    route = NULL;
    encoded_route = NULL;
    our_crypto_metadata = NULL;
    b_crypto_metadata = NULL;
    c_crypto_metadata = NULL;
    b_extracted_step = NULL;
    c_extracted_step = NULL;

    if (!ue_init()) {
        fprintf(stderr, "[FATAL] Failed to initialize LibUnknownEcho\n");
        exit(EXIT_FAILURE);
    }
    ue_logger_info("UnknownEchoLib is correctly initialized");

    ue_logger_info("Generating crypto metadata for point A...");
    if (!(our_crypto_metadata = ue_crypto_metadata_create_default())) {
        ue_stacktrace_push_msg("Failed to generate default crypto metadata for point A");
        goto clean_up;
    }

    ue_logger_info("Generating crypto metadata for point B...");
    if (!(b_crypto_metadata = ue_crypto_metadata_create_default())) {
        ue_stacktrace_push_msg("Failed to generate default crypto metadata for point B");
        goto clean_up;
    }

    ue_logger_info("Generating crypto metadata for point C...");
    if (!(c_crypto_metadata = ue_crypto_metadata_create_default())) {
        ue_stacktrace_push_msg("Failed to generate default crypto metadata for point C");
        goto clean_up;
    }

    ue_logger_info("Creating route...");

    /**
     * A: 192.168.0.1:5000
     * B: 192.168.0.2:5001
     * C: 192.168.0.3:5002
     * A -> B -> C
     * steps are represented by the arrows
     */
    if (!(route = ue_relay_route_create(
        ue_relay_steps_create(
            step_number,
            ue_relay_step_create(ue_communication_metadata_create_socket_type("192.168.0.1", 5000),
                ue_communication_metadata_create_socket_type("192.168.0.2", 5001), our_crypto_metadata, b_crypto_metadata),
            ue_relay_step_create(ue_communication_metadata_create_socket_type("192.168.0.2", 5001),
                ue_communication_metadata_create_socket_type("192.168.0.3", 5002), our_crypto_metadata, c_crypto_metadata)
        ),
        step_number))) {

        ue_stacktrace_push_msg("Failed to create route A -> B -> C");
        goto clean_up;
    }

    ue_logger_info("Encoding route...");
    if (!(encoded_route = ue_relay_route_encode(route))) {
        ue_stacktrace_push_msg("Failed to encode route A -> B -> C");
        goto clean_up;
    }

    ue_logger_info("Encoded route:");
    ue_byte_stream_print_hex(encoded_route, stdout);

    ue_logger_info("Extracting step for B...");
    if (!(b_extracted_step = ue_relay_route_decode_pop_step(encoded_route, b_crypto_metadata))) {
        ue_stacktrace_push_msg("Failed to pop step from encoded route with B crypto metadata");
        goto clean_up;
    }
    ue_logger_info("Step for B extracted: ");
    ue_relay_step_print(b_extracted_step, stdout);

    ue_logger_info("Lets say B send the remaining route to C [...]");

    ue_logger_info("Extracting step for C...");
    if (!(c_extracted_step = ue_relay_route_decode_pop_step(encoded_route, c_crypto_metadata))) {
        ue_stacktrace_push_msg("Failed to pop step from encoded route with C crypto metadata");
        goto clean_up;
    }
    ue_logger_info("Step for C extracted: ");
    ue_relay_step_print(c_extracted_step, stdout);

clean_up:
    ue_byte_stream_destroy(encoded_route);
    ue_relay_route_destroy(route);
    ue_crypto_metadata_destroy_all(our_crypto_metadata);
    ue_crypto_metadata_destroy_all(b_crypto_metadata);
    ue_crypto_metadata_destroy_all(c_crypto_metadata);
    ue_relay_step_destroy(b_extracted_step);
    ue_relay_step_destroy(c_extracted_step);
    if (ue_stacktrace_is_filled()) {
        ue_logger_error("An error occurred with the following stacktrace :");
        ue_stacktrace_print_all();
    }
    ue_uninit();
    return 0;
}
