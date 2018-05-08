#include <unknownecho/init.h>
#include <unknownecho/protocol/api/relay/relay_step.h>
#include <unknownecho/protocol/api/relay/relay_route.h>
#include <unknownecho/protocol/api/relay/relay_route_encoder.h>
#include <unknownecho/protocol/api/relay/relay_route_decoder.h>
#include <unknownecho/protocol/api/relay/relay_message_encoder.h>
#include <unknownecho/protocol/api/relay/relay_message_decoder.h>
#include <unknownecho/protocol/api/relay/relay_message_id.h>
#include <unknownecho/protocol/api/relay/relay_plain_message.h>
#include <unknownecho/protocol/api/relay/relay_plain_message_struct.h>
#include <unknownecho/network/api/communication/communication_metadata.h>
#include <unknownecho/network/factory/communication_metadata_factory.h>
#include <unknownecho/crypto/factory/crypto_metadata_factory.h>
#include <unknownecho/byte/byte_stream.h>
#include <unknownecho/byte/byte_writer.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/errorHandling/stacktrace.h>

#include <stdio.h>
#include <stdlib.h>

int main() {
    int step_number;
    ue_relay_route *route;
    ue_crypto_metadata *our_crypto_metadata, *b_crypto_metadata, *c_crypto_metadata;
    ue_byte_stream *encoded_message, *message_payload;
    ue_relay_plain_message *b_plain_message, *c_plain_message;

    step_number = 2;
    route = NULL;
    our_crypto_metadata = NULL;
    b_crypto_metadata = NULL;
    c_crypto_metadata = NULL;
    encoded_message = NULL;
    b_plain_message = NULL;
    c_plain_message = NULL;
    message_payload = ue_byte_stream_create();

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

    /* The payload is just an simple Hello world ! */
    ue_byte_writer_append_string(message_payload, "Hello world !");

    ue_logger_info("A -> B");

    ue_logger_info("Encoding route and message for B...");
    if (!(encoded_message = ue_relay_message_encode(route, UNKNOWNECHO_RELAY_MESSAGE_ID_SEND, message_payload))) {
        ue_stacktrace_push_msg("Failed to encode relay message for B");
        goto clean_up;
    }

    ue_logger_info("Lets say we send through network the encoded message to B [...]");

    ue_logger_info("Decoding message as B...");
    if (!(b_plain_message = ue_relay_message_decode(encoded_message, b_crypto_metadata))) {
        ue_stacktrace_push_msg("Failed to decode message with B crypto metadata");
        goto clean_up;
    }
    ue_logger_info("Part of B decoded.");

    ue_logger_info("B -> C");

    ue_byte_stream_destroy(encoded_message);

    ue_logger_info("Encoding route and message for C...");
    if (!(encoded_message = ue_relay_message_encode_relay(b_plain_message))) {
        ue_stacktrace_push_msg("Failed to encode relay message for B");
        goto clean_up;
    }

    ue_logger_info("Lets say B send through network the encoded message to C [...]");

    ue_logger_info("Decoding message as C...");
    if (!(c_plain_message = ue_relay_message_decode(encoded_message, c_crypto_metadata))) {
        ue_stacktrace_push_msg("Failed to decode message with C crypto metadata");
        goto clean_up;
    }

    if (!c_plain_message->unsealed_payload) {
        ue_stacktrace_push_msg("Message payload isn't unsealed");
        goto clean_up;
    }

    ue_logger_info("Part of C decoded.");
    ue_logger_info("Print message payload of C:");
    ue_byte_stream_print_string(c_plain_message->payload, stdout);

clean_up:
    ue_relay_route_destroy(route);
    ue_crypto_metadata_destroy_all(our_crypto_metadata);
    ue_crypto_metadata_destroy_all(b_crypto_metadata);
    ue_crypto_metadata_destroy_all(c_crypto_metadata);
    ue_byte_stream_destroy(encoded_message);
    ue_relay_plain_message_destroy(b_plain_message);
    ue_relay_plain_message_destroy(c_plain_message);
    ue_byte_stream_destroy(message_payload);
    if (ue_stacktrace_is_filled()) {
        ue_logger_error("An error occurred with the following stacktrace :");
        ue_stacktrace_print_all();
    }
    ue_uninit();
    return 0;
}
