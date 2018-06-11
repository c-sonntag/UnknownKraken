#include <unknownecho/init.h>
#include <unknownecho/protocol/api/relay/relay_step.h>
#include <unknownecho/protocol/api/relay/relay_route.h>
#include <unknownecho/protocol/api/relay/relay_route_encoder.h>
#include <unknownecho/protocol/api/relay/relay_route_decoder.h>
#include <unknownecho/protocol/api/relay/relay_message_encoder.h>
#include <unknownecho/protocol/api/relay/relay_message_decoder.h>
#include <unknownecho/protocol/api/relay/relay_message_id.h>
#include <unknownecho/protocol/api/relay/relay_received_message.h>
#include <unknownecho/protocol/api/relay/relay_received_message_struct.h>
#include <unknownecho/network/api/communication/communication_metadata.h>
#include <unknownecho/network/factory/communication_metadata_factory.h>
#include <unknownecho/crypto/factory/crypto_metadata_factory.h>
#include <unknownecho/byte/byte_stream.h>
#include <unknownecho/byte/byte_writer.h>
#include <unknownecho/string/string_utility.h>
#include <unknownecho/alloc.h>

#include <ei/ei.h>

#include <stdio.h>
#include <stdlib.h>

#define try_or_clean_up(exp, error_message, label) \
    if (!(exp)) { \
        ei_stacktrace_push_msg("%s", error_message); \
        goto label; \
    } \

static bool generate_crypto_metadatas(ue_crypto_metadata **a_crypto_metadata,
    ue_crypto_metadata **b_crypto_metadata, ue_crypto_metadata **c_crypto_metadata,
    ue_crypto_metadata **d_crypto_metadata) {

    ei_logger_info("Generating crypto metadata for point A...");
    if (!(*a_crypto_metadata = ue_crypto_metadata_create_default())) {
        ei_stacktrace_push_msg("Failed to generate default crypto metadata for point A");
        return false;
    }

    ei_logger_info("Generating crypto metadata for point B...");
    if (!(*b_crypto_metadata = ue_crypto_metadata_create_default())) {
        ei_stacktrace_push_msg("Failed to generate default crypto metadata for point B");
        return false;
    }

    ei_logger_info("Generating crypto metadata for point C...");
    if (!(*c_crypto_metadata = ue_crypto_metadata_create_default())) {
        ei_stacktrace_push_msg("Failed to generate default crypto metadata for point C");
        return false;
    }

    ei_logger_info("Generating crypto metadata for point D...");
    if (!(*d_crypto_metadata = ue_crypto_metadata_create_default())) {
        ei_stacktrace_push_msg("Failed to generate default crypto metadata for point D");
        return false;
    }

    return true;
}

static bool generate_routes(ue_relay_route **route, ue_relay_route **back_route, int step_number,
    ue_crypto_metadata *a_crypto_metadata, ue_crypto_metadata *b_crypto_metadata,
    ue_crypto_metadata *c_crypto_metadata, ue_crypto_metadata *d_crypto_metadata) {

    ei_logger_info("Creating route...");

    /**
     * A: 192.168.0.1
     * B: 192.168.0.2:5001
     * C: 192.168.0.3:5002
     * D: 0:192.168.0.4:5002:1
     * client1 (A) -> server1 (B) -> server2 (C) -> client2 (D)
     * steps are represented by the arrows
     */
    if (!(*route = ue_relay_route_create(
        ue_relay_steps_create(
            step_number,
            ue_relay_step_create(ue_communication_metadata_create_socket_type("server1", "192.168.0.2", 5001),
                a_crypto_metadata, b_crypto_metadata),
            ue_relay_step_create(ue_communication_metadata_create_socket_type("server2", "192.168.0.3", 5002),
                a_crypto_metadata, c_crypto_metadata),
            ue_relay_step_create(ue_communication_metadata_create_from_string("client2:0:192.168.0.4:5002:1"),
                a_crypto_metadata, d_crypto_metadata)
        ),
        step_number))) {

        ei_stacktrace_push_msg("Failed to create route A -> B -> C -> D");
        return false;
    }

    ei_logger_info("Creating back route...");

    /**
     * A: 192.168.0.1
     * B: 192.168.0.2:5001
     * C: 192.168.0.3:5002
     * D: 0:192.168.0.4:5002:1
     * client2 (D) -> server2 (C) -> server1 (B) -> client1 (D)
     * steps are represented by the arrows
     */
    if (!(*back_route = ue_relay_route_create(
        ue_relay_steps_create(
            step_number,
            ue_relay_step_create(ue_communication_metadata_create_socket_type("server2", "192.168.0.3", 5002),
                d_crypto_metadata, c_crypto_metadata),
            ue_relay_step_create(ue_communication_metadata_create_socket_type("server1", "192.168.0.2", 5001),
                d_crypto_metadata, b_crypto_metadata),
            ue_relay_step_create(ue_communication_metadata_create_from_string("client1:0:192.168.0.1:5001:1"),
                d_crypto_metadata, a_crypto_metadata)
        ),
        step_number))) {

        ei_stacktrace_push_msg("Failed to create back route D -> C -> B -> A");
        return false;
    }

    return true;
}

static bool send_request(ue_byte_stream *message_payload, ue_relay_route *route, ue_relay_route *back_route,
    ue_byte_stream **encoded_message, ue_relay_received_message **b_received_message,
    ue_relay_received_message **c_received_message, ue_relay_received_message **d_received_message,
    ue_crypto_metadata *b_crypto_metadata, ue_crypto_metadata *c_crypto_metadata, ue_crypto_metadata *d_crypto_metadata) {
    
    /* The payload is just an simple Hello world ! */
    ue_byte_writer_append_string(message_payload, "Hello world !");

    ei_logger_info("A -> B");

    ei_logger_info("Encoding route and message for B...");
    if (!(*encoded_message = ue_relay_message_encode(route, back_route, UNKNOWNECHO_RELAY_MESSAGE_ID_REQUEST, message_payload))) {
        ei_stacktrace_push_msg("Failed to encode relay message for B");
        return false;
    }

    ei_logger_info("Lets say we send through network the encoded message to B [...]");

    ei_logger_info("Decoding message as B...");
    if (!(*b_received_message = ue_relay_message_decode(*encoded_message, b_crypto_metadata))) {
        ei_stacktrace_push_msg("Failed to decode message with B crypto metadata");
        return false;
    }
    ei_logger_info("Part of B decoded.");

    ei_logger_info("B -> C");

    ue_byte_stream_destroy(*encoded_message);

    ei_logger_info("Encoding route and message for C...");
    if (!(*encoded_message = ue_relay_message_encode_relay(*b_received_message))) {
        ei_stacktrace_push_msg("Failed to encode relay message for B");
        return false;
    }

    ei_logger_info("Lets say B send through network the encoded message to C [...]");

    ei_logger_info("Decoding message as C...");
    if (!(*c_received_message = ue_relay_message_decode(*encoded_message, c_crypto_metadata))) {
        ei_stacktrace_push_msg("Failed to decode message with C crypto metadata");
        return false;
    }
    ei_logger_info("Part of C decoded.");

    ei_logger_info("C -> D");

    ue_byte_stream_destroy(*encoded_message);

    ei_logger_info("Encoding route and message for D...");
    if (!(*encoded_message = ue_relay_message_encode_relay(*c_received_message))) {
        ei_stacktrace_push_msg("Failed to encode relay message for C");
        return false;
    }

    ei_logger_info("Lets say C send through network the encoded message to D [...]");

    ei_logger_info("Decoding message as D...");
    if (!(*d_received_message = ue_relay_message_decode(*encoded_message, d_crypto_metadata))) {
        ei_stacktrace_push_msg("Failed to decode message with D crypto metadata");
        return false;
    }
    ei_logger_info("Part of D decoded.");

    if (!(*d_received_message)->unsealed_payload) {
        ei_stacktrace_push_msg("Message payload isn't unsealed");
        return false;
    }

    ei_logger_info("Print message payload of D:");
    ue_byte_stream_print_string((*d_received_message)->payload, stdout);

    ue_byte_stream_destroy(*encoded_message);

    return true;
}

static bool send_response(ue_byte_stream *message_payload, ue_relay_route *route, ue_relay_route *back_route,
    ue_byte_stream **encoded_message, ue_relay_received_message **c_received_message,
    ue_relay_received_message **b_received_message, ue_relay_received_message **a_received_message,
    ue_crypto_metadata *a_crypto_metadata, ue_crypto_metadata *b_crypto_metadata, ue_crypto_metadata *c_crypto_metadata) {
    
    char *uppercase;

    uppercase = ue_string_uppercase((const char *)ue_byte_stream_get_data(message_payload));

    ue_byte_stream_clean_up(message_payload);

    /* The payload is the uppercase of the received message */
    ue_byte_writer_append_string(message_payload, uppercase);

    ue_safe_free(uppercase);

    ei_logger_info("D -> C");

    ei_logger_info("Encoding route and message for C...");
    /* The back route became the main route, as we use it to respond */
    if (!(*encoded_message = ue_relay_message_encode(back_route, route, UNKNOWNECHO_RELAY_MESSAGE_ID_RESPONSE, message_payload))) {
        ei_stacktrace_push_msg("Failed to encode relay message for C");
        return false;
    }

    ei_logger_info("Lets say we send through network the encoded message to C [...]");

    ei_logger_info("Decoding message as C...");
    if (!(*c_received_message = ue_relay_message_decode(*encoded_message, c_crypto_metadata))) {
        ei_stacktrace_push_msg("Failed to decode message with C crypto metadata");
        return false;
    }
    ei_logger_info("Part of C decoded.");

    ei_logger_info("C -> B");

    ue_byte_stream_destroy(*encoded_message);

    ei_logger_info("Encoding route and message for B...");
    if (!(*encoded_message = ue_relay_message_encode_relay(*c_received_message))) {
        ei_stacktrace_push_msg("Failed to encode relay message for B");
        return false;
    }

    ei_logger_info("Lets say C send through network the encoded message to B [...]");

    ei_logger_info("Decoding message as B...");
    if (!(*b_received_message = ue_relay_message_decode(*encoded_message, b_crypto_metadata))) {
        ei_stacktrace_push_msg("Failed to decode message with B crypto metadata");
        return false;
    }
    ei_logger_info("Part of B decoded.");

    ei_logger_info("B -> A");

    ue_byte_stream_destroy(*encoded_message);

    ei_logger_info("Encoding route and message for A...");
    if (!(*encoded_message = ue_relay_message_encode_relay(*b_received_message))) {
        ei_stacktrace_push_msg("Failed to encode relay message for A");
        return false;
    }

    ei_logger_info("Lets say B send through network the encoded message to A [...]");

    ei_logger_info("Decoding message as A...");
    if (!(*a_received_message = ue_relay_message_decode(*encoded_message, a_crypto_metadata))) {
        ei_stacktrace_push_msg("Failed to decode message with A crypto metadata");
        return false;
    }
    ei_logger_info("Part of A decoded.");

    if (!(*a_received_message)->unsealed_payload) {
        ei_stacktrace_push_msg("Message payload isn't unsealed");
        return false;
    }

    ei_logger_info("Print message payload of A:");
    ue_byte_stream_print_string((*a_received_message)->payload, stdout);

    return true;
}

int main() {
    int step_number;
    ue_relay_route *route, *back_route;
    ue_crypto_metadata *a_crypto_metadata, *b_crypto_metadata, *c_crypto_metadata, *d_crypto_metadata;
    ue_byte_stream *encoded_message, *message_payload;
    ue_relay_received_message *a_received_message, *b_received_message, *c_received_message, *d_received_message;

    step_number = 3;
    route = NULL;
    back_route = NULL;
    a_crypto_metadata = NULL;
    b_crypto_metadata = NULL;
    c_crypto_metadata = NULL;
    d_crypto_metadata = NULL;
    encoded_message = NULL;
    a_received_message = NULL;
    b_received_message = NULL;
    c_received_message = NULL;
    d_received_message = NULL;
    message_payload = ue_byte_stream_create();

    if (!ue_init()) {
        fprintf(stderr, "[FATAL] Failed to initialize LibUnknownEcho\n");
        exit(EXIT_FAILURE);
    }
    ei_logger_info("UnknownEchoLib is correctly initialized");

    try_or_clean_up(generate_crypto_metadatas(&a_crypto_metadata, &b_crypto_metadata,
        &c_crypto_metadata, &d_crypto_metadata), "Failed to generate crypto metadatas", clean_up);

    try_or_clean_up(generate_routes(&route, &back_route, step_number, a_crypto_metadata,
        b_crypto_metadata, c_crypto_metadata, d_crypto_metadata), "Failed to generate routes", clean_up);

    try_or_clean_up(send_request(message_payload, route, back_route, &encoded_message, &b_received_message,
        &c_received_message, &d_received_message, b_crypto_metadata,
        c_crypto_metadata, d_crypto_metadata), "Failed to send message", clean_up);

    try_or_clean_up(send_response(message_payload, route, back_route, &encoded_message, &c_received_message,
        &b_received_message, &a_received_message, a_crypto_metadata,
        b_crypto_metadata, c_crypto_metadata), "Failed to receive message", clean_up);

clean_up:
    ue_relay_route_destroy(route);
    ue_crypto_metadata_destroy_all(a_crypto_metadata);
    ue_crypto_metadata_destroy_all(b_crypto_metadata);
    ue_crypto_metadata_destroy_all(c_crypto_metadata);
    ue_crypto_metadata_destroy_all(d_crypto_metadata);
    ue_byte_stream_destroy(encoded_message);
    ue_relay_received_message_destroy(a_received_message);
    ue_relay_received_message_destroy(b_received_message);
    ue_relay_received_message_destroy(c_received_message);
    ue_relay_received_message_destroy(d_received_message);
    ue_byte_stream_destroy(message_payload);
    if (ei_stacktrace_is_filled()) {
        ei_logger_error("An error occurred with the following stacktrace :");
        ei_stacktrace_print_all();
    }
    ue_uninit();
    return 0;
}
