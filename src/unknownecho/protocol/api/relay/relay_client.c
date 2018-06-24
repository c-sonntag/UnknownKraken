#include <unknownecho/protocol/api/relay/relay_client.h>
#include <unknownecho/protocol/api/relay/relay_step.h>
#include <unknownecho/protocol/api/relay/relay_route.h>
#include <unknownecho/protocol/api/relay/relay_message_encoder.h>
#include <unknownecho/protocol/api/relay/relay_message_decoder.h>
#include <unknownecho/protocol/api/relay/relay_message_id.h>
#include <unknownecho/protocol/api/relay/relay_route_encoder.h>
#include <unknownecho/protocol/api/relay/relay_received_message.h>
#include <unknownecho/network/api/communication/communication.h>
#include <unknownecho/network/factory/communication_factory.h>
#include <unknownecho/crypto/api/crypto_metadata.h>
#include <unknownecho/alloc.h>
#include <unknownecho/byte/byte_stream.h>
#include <unknownecho/byte/byte_writer.h>
#include <unknownecho/thread/thread.h>

#include <ei/ei.h>

#include <stddef.h>
#include <limits.h>
#include <string.h>

static ue_relay_client *ue_relay_client_create(ue_communication_metadata *our_communication_metadata,
    ue_communication_metadata *target_communication_metadata) {

    ue_relay_client *relay_client;
    void *client_connection_parameters;
    ue_byte_stream *message_to_send, *received_message;
    const char *uid;

    ei_check_parameter_or_return(target_communication_metadata);

    /* Alloc the client objet */
    ue_safe_alloc(relay_client, ue_relay_client, 1);
    relay_client->communication_context = NULL;
    relay_client->connection = NULL;
    relay_client->route = NULL;
    relay_client->back_route = NULL;
    relay_client->encoded_route = NULL;
    relay_client->encoded_back_route = NULL;
    relay_client->our_crypto_metadata = NULL;
    relay_client->our_communication_metadata = our_communication_metadata;

    message_to_send = NULL;
    received_message = NULL;
    uid = NULL;

    /* Create the communication context from the type of communication specified in the metadata of target */
    relay_client->communication_context = ue_communication_build_from_type(ue_communication_metadata_get_type(target_communication_metadata));

    /**
     * Build client connection parameters from communication builder, with host and port of target communication metadata
     * or record an error if it's failed.
     * @warning At this point of the POC, the optional third arg of secure layer isn't used, nor the crypto_metadata of the
     * step object.
     **/
    if (!(client_connection_parameters = ue_communication_build_client_connection_parameters(relay_client->communication_context, 2,
        ue_communication_metadata_get_host(target_communication_metadata), ue_communication_metadata_get_port(target_communication_metadata)))) {
        ue_safe_free(relay_client);
        ei_stacktrace_push_msg("Failed to create client connection parameters context");
        goto clean_up;
    }

    /* Finally connect the client or record an error if it's failed */
    if (!(relay_client->connection = ue_communication_connect(relay_client->communication_context,
        client_connection_parameters))) {
        ue_safe_free(relay_client);
        ei_stacktrace_push_msg("Failed to connect socket to server");
        goto clean_up;
    }

    if (!(message_to_send = ue_communication_client_connection_get_message_to_send(
        relay_client->communication_context, relay_client->connection))) {

        ei_stacktrace_push_msg("Failed to get message to send of the previous connection. Closing the connection");
        ue_relay_client_destroy(relay_client);
        goto clean_up;
    }

    if (!(received_message = ue_communication_client_connection_get_received_message(
        relay_client->communication_context, relay_client->connection))) {

        ei_stacktrace_push_msg("Failed to get received message of the previous connection. Closing the connection");
        ue_relay_client_destroy(relay_client);
        goto clean_up;
    }

    if (!(uid = ue_communication_metadata_get_uid(our_communication_metadata))) {
        ei_stacktrace_push_msg("Failed to get our communication metadata uid");
        ue_relay_client_destroy(relay_client);
        goto clean_up;
    }

    if (!ue_byte_writer_append_int(message_to_send, UNKNOWNECHO_PROTOCOL_ID_RELAY)) {
        ei_stacktrace_push_msg("Failed to write protocol id to message to send");
        ue_relay_client_destroy(relay_client);
        goto clean_up;
    }

    if (!ue_byte_writer_append_int(message_to_send, UNKNOWNECHO_RELAY_MESSAGE_ID_ESTABLISH)) {
        ei_stacktrace_push_msg("Failed to write message id to message to send");
        ue_relay_client_destroy(relay_client);
        goto clean_up;
    }

    if (!ue_byte_writer_append_int(message_to_send, strlen(uid))) {
        ei_stacktrace_push_msg("Failed to write uid length");
        ue_relay_client_destroy(relay_client);
        goto clean_up;
    }

    if (!ue_byte_writer_append_string(message_to_send, uid)) {
        ei_stacktrace_push_msg("Failed to write our uid to message to send. Closing the connection");
        ue_relay_client_destroy(relay_client);
        goto clean_up;
    }

    if (!ue_communication_send_sync(relay_client->communication_context, relay_client->connection, message_to_send)) {
        ei_stacktrace_push_msg("Failed to send our uid to server. Closing the connection");
        ue_relay_client_destroy(relay_client);
        goto clean_up;
    }

    if (!ue_communication_receive_sync(relay_client->communication_context, relay_client->connection, received_message)) {
        ei_stacktrace_push_msg("Failed to received ack message. Closing the connection");
        ue_relay_client_destroy(relay_client);
        goto clean_up;
    }

    if (memcmp(ue_byte_stream_get_data(received_message), "ACK", 3) != 0) {
        ei_stacktrace_push_msg("Received message isn't a correct ACK. Closing the connection");
        ue_relay_client_destroy(relay_client);
        goto clean_up;
    }

clean_up:
    ue_safe_free(client_connection_parameters);
    return relay_client;
}

static ue_relay_client *ue_relay_client_create_from_connection(ue_communication_metadata *our_communication_metadata,
    ue_communication_metadata *target_communication_metadata, void *connection) {

    ue_relay_client *relay_client;
    void *client_connection_parameters;

    ei_check_parameter_or_return(target_communication_metadata);

    /* Alloc the client objet */
    ue_safe_alloc(relay_client, ue_relay_client, 1);
    relay_client->communication_context = NULL;
    relay_client->connection = NULL;
    relay_client->route = NULL;
    relay_client->back_route = NULL;
    relay_client->encoded_route = NULL;
    relay_client->encoded_back_route = NULL;
    relay_client->our_crypto_metadata = NULL;
    relay_client->our_communication_metadata = our_communication_metadata;

    /* Create the communication context from the type of communication specified in the metadata of target */
    relay_client->communication_context = ue_communication_build_from_type(ue_communication_metadata_get_type(target_communication_metadata));

    /**
     * Build client connection parameters from communication builder, with host and port of target communication metadata
     * or record an error if it's failed.
     * @warning At this point of the POC, the optional third arg of secure layer isn't used, nor the crypto_metadata of the
     * step object.
     * @todo fix this warning this setting the use of the secure layer mandatory
     **/
    if (!(client_connection_parameters = ue_communication_build_client_connection_parameters(relay_client->communication_context, 2,
        ue_communication_metadata_get_host(target_communication_metadata), ue_communication_metadata_get_port(target_communication_metadata)))) {
        ue_safe_free(relay_client);
        ei_stacktrace_push_msg("Failed to create client connection parameters context");
        goto clean_up;
    }

    relay_client->connection = connection;

clean_up:
    ue_safe_free(client_connection_parameters);
    return relay_client;
}

ue_relay_client *ue_relay_client_create_from_route(ue_communication_metadata *our_communication_metadata, ue_relay_route *route) {
    ue_relay_client *client;
    ue_relay_step *step;
    ue_communication_metadata *target_communication_metadata;

    client = NULL;
    step = NULL;
    target_communication_metadata = NULL;

    if (!ue_relay_route_is_valid(route)) {
        ei_stacktrace_push_msg("Specified route isn't valid");
        return NULL;
    }

    if (!(step = ue_relay_route_get_sender(route))) {
        ei_stacktrace_push_msg("Specified route seems valid but it returns a null sender step");
        return NULL;
    }

    /* Check if relay objet is valid */
    if (!ue_relay_step_is_valid(step)) {
        ei_stacktrace_push_msg("Specified route seems valid but it returns an invalid sender step");
        return NULL;
    }

    /* Get the communication metadata of the target */
    if (!(target_communication_metadata = ue_relay_step_get_target_communication_metadata(step))) {
        ei_stacktrace_push_msg("Failed to get target communication metadata from sender step");
        return NULL;
    }

    if (!(client = ue_relay_client_create(our_communication_metadata, target_communication_metadata))) {
        ei_stacktrace_push_msg("Failed to create new relay client from target communication metadata");
        return NULL;
    }

    if (!(client->back_route = ue_relay_route_create_back_route(route))) {
        ei_stacktrace_push_msg("Failed to create back relay route from normal route");
        return NULL;
    }

    client->route = route;
    client->our_crypto_metadata = ue_relay_step_get_our_crypto_metadata(step);

    if (!(client->encoded_route = ue_relay_route_encode(route))) {
        ue_relay_client_destroy(client);
        ei_stacktrace_push_msg("Failed to create encoded route from specified route");
        return NULL;
    }

    if (!(client->encoded_back_route = ue_relay_route_encode(client->back_route))) {
        ue_relay_client_destroy(client);
        ei_stacktrace_push_msg("Failed to create encoded back route from specified route");
        return NULL;
    }

    return client;
}

ue_relay_client *ue_relay_client_create_as_relay(ue_communication_metadata *our_communication_metadata,
    ue_communication_metadata *target_communication_metadata, ue_crypto_metadata *our_crypto_metadata) {

    ue_relay_client *relay_client;

    if (!(relay_client = ue_relay_client_create(our_communication_metadata, target_communication_metadata))) {
        ei_stacktrace_push_msg("Failed to create relay client with next step");
        return NULL;
    }
    relay_client->our_crypto_metadata = our_crypto_metadata;

    return relay_client;
}

ue_relay_client *ue_relay_client_create_as_relay_from_connection(ue_communication_metadata *our_communication_metadata,
    ue_communication_metadata *target_communication_metadata, ue_crypto_metadata *our_crypto_metadata, void *connection) {

    ue_relay_client *relay_client;

    if (!(relay_client = ue_relay_client_create_from_connection(our_communication_metadata, target_communication_metadata, connection))) {
        ei_stacktrace_push_msg("Failed to create relay client with next step");
        return NULL;
    }
    relay_client->our_crypto_metadata = our_crypto_metadata;

    return relay_client;
}

void ue_relay_client_destroy(ue_relay_client *client) {
    if (client) {
        ue_communication_client_connection_destroy(client->communication_context, client->connection);
        ue_communication_destroy(client->communication_context);
        ue_byte_stream_destroy(client->encoded_route);
        ue_safe_free(client);
    }
}

bool ue_relay_client_is_valid(ue_relay_client *client) {
    return client && ue_communication_context_is_valid(client->communication_context) &&
        client->connection && (client->communication_context->communication_client_connection_is_established_impl ?
        client->communication_context->communication_client_connection_is_established_impl(client->connection) : true);
}

ue_communication_context *ue_relay_client_get_communication_context(ue_relay_client *client) {
    /* Check first if the specified client is valid */
    if (!ue_relay_client_is_valid(client)) {
        ei_stacktrace_push_msg("Specified client isn't valid. The connection is maybe isn't established");
        return NULL;
    }

    return client->communication_context;
}

void *ue_relay_client_get_connection(ue_relay_client *client) {
    /* Check first if the specified client is valid */
    if (!ue_relay_client_is_valid(client)) {
        ei_stacktrace_push_msg("Specified client isn't valid. The connection is maybe isn't established");
        return NULL;
    }

    return client->connection;
}

bool ue_relay_client_send_message(ue_relay_client *client, ue_byte_stream *message) {
    bool result;
    ue_byte_stream *encoded_message;
    ue_relay_step *receiver_step;

    result = false;
    encoded_message = NULL;

    if (!ue_relay_client_is_valid(client)) {
        ei_stacktrace_push_msg("Specified client is invalid");
        goto clean_up;
    }

    if (!client->route) {
        ei_stacktrace_push_msg("Specified client has no route specified");
        goto clean_up;
    }

    if (!client->encoded_route) {
        ei_stacktrace_push_msg("Specified client has no encoded route specified");
        goto clean_up;
    }

    if (!client->back_route) {
        ei_stacktrace_push_msg("Specified client has no back route specified");
        goto clean_up;
    }

    if (!client->encoded_back_route) {
        ei_stacktrace_push_msg("Specified client has no encoded back route specified");
        goto clean_up;
    }

    if (!message || ue_byte_stream_is_empty(message)) {
        ei_stacktrace_push_msg("Specified message ptr is null or the message is empty");
        goto clean_up;
    }

    if (!(receiver_step = ue_relay_route_get_receiver(client->route))) {
        ei_stacktrace_push_msg("Failed to get receiver step from client relay route");
        goto clean_up;
    }

    if (!(encoded_message = ue_relay_message_encode_from_encoded_route(client->encoded_route,
        client->encoded_back_route, UNKNOWNECHO_RELAY_MESSAGE_ID_REQUEST, message, receiver_step))) {

        ei_stacktrace_push_msg("Failed to encoded specified message");
        goto clean_up;
    }

    if (!ue_communication_send_sync(client->communication_context, client->connection, encoded_message)) {
        ei_stacktrace_push_msg("Failed to send encoded message in synchronous mode");
        goto clean_up;
    }

    result = true;

clean_up:
    ue_byte_stream_destroy(encoded_message);
    return result;
}

bool ue_relay_client_relay_message(ue_relay_client *client, ue_relay_received_message *received_message) {
    bool result;
    ue_byte_stream *encoded_message;

    result = false;
    encoded_message = NULL;

    if (!ue_relay_client_is_valid(client)) {
        ei_stacktrace_push_msg("Specified client is invalid");
        goto clean_up;
    }

    if (!(encoded_message = ue_relay_message_encode_relay(received_message))) {
        ei_stacktrace_push_msg("Failed to encode message as relay from received message");
        goto clean_up;
    }

    if (!ue_communication_send_sync(client->communication_context, client->connection, encoded_message)) {
        ei_stacktrace_push_msg("Failed to send encoded message in synchronous mode");
        goto clean_up;
    }

    result = true;

clean_up:
    ue_byte_stream_destroy(encoded_message);
    return result;
}

bool ue_relay_client_receive_message(ue_relay_client *client, ue_byte_stream *message) {
    bool result;
    size_t received;
    ue_byte_stream *received_message;
    ue_relay_received_message *decoded_message;

    result = false;
    received_message = NULL;
    decoded_message = NULL;

    if (!ue_relay_client_is_valid(client)) {
        ei_stacktrace_push_msg("Specified client is invalid");
        goto clean_up;
    }

    ei_check_parameter_or_return(message);

    received_message = ue_byte_stream_create();

    received = ue_communication_receive_sync(client->communication_context, client->connection, received_message);
    if (received == 0) {
        ei_stacktrace_push_msg("Failed to received bytes");
        goto clean_up;
    } else if (received == ULLONG_MAX) {
        ei_stacktrace_push_msg("Failed to received bytes: connection was interrupted");
        goto clean_up;
    }

    if (!(decoded_message = ue_relay_message_decode(received_message, client->our_crypto_metadata))) {
        ei_stacktrace_push_msg("Failed to decode message");
        goto clean_up;
    }

    if (!decoded_message->unsealed_payload) {
        ei_stacktrace_push_msg("Decoded message doesn't contains the unsealed payload. Maybe the message wasn't meant for us");
        goto clean_up;
    }

    ue_byte_stream_clean_up(message);
    ue_byte_writer_append_bytes(message, ue_byte_stream_get_data(decoded_message->payload),
        ue_byte_stream_get_size(decoded_message->payload));

    result = true;

clean_up:
    ue_byte_stream_destroy(received_message);
    ue_relay_received_message_destroy(decoded_message);
    return result;
}
