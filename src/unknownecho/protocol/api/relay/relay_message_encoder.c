#include <unknownecho/protocol/api/relay/relay_message_encoder.h>
#include <unknownecho/protocol/api/relay/relay_route_encoder.h>
#include <unknownecho/protocol/api/relay/relay_route.h>
#include <unknownecho/protocol/api/relay/relay_step_struct.h>
#include <unknownecho/protocol/api/relay/relay_step.h>
#include <unknownecho/protocol/api/protocol_id.h>
#include <unknownecho/crypto/api/crypto_metadata.h>
#include <unknownecho/crypto/api/cipher/data_cipher.h>
#include <unknownecho/byte/byte_stream.h>
#include <unknownecho/byte/byte_writer.h>
#include <ei/ei.h>
#include <unknownecho/alloc.h>
#include <unknownecho/bool.h>

#include <stddef.h>

static bool write_sealed_payload(ue_relay_step *first_step, ue_byte_stream *payload, ue_byte_stream *encoded_message) {
    bool result;
    ue_crypto_metadata *our_crypto_metadata, *target_crypto_metadata;
    unsigned char *cipher_data;
    size_t cipher_data_size;

    result = false;
    if (!(our_crypto_metadata = ue_relay_step_get_our_crypto_metadata(first_step))) {
        ei_stacktrace_push_msg("The first step doesn't contain our crypto metadata");
        return false;
    }
    if (!(target_crypto_metadata = ue_relay_step_get_target_crypto_metadata(first_step))) {
        ei_stacktrace_push_msg("The first step doesn't contain target crypto metadata");
        return false;
    }
    cipher_data = NULL;

    /**
     * @todo sign the message with our private key in place of NULL
     */
    if (!ue_cipher_plain_data(ue_byte_stream_get_data(payload), ue_byte_stream_get_size(payload),
        ue_crypto_metadata_get_cipher_public_key(target_crypto_metadata), NULL, &cipher_data, &cipher_data_size,
        ue_crypto_metadata_get_cipher_name(our_crypto_metadata), ue_crypto_metadata_get_digest_name(our_crypto_metadata))) {

        ei_stacktrace_push_msg("Failed to cipher content of payload");
        goto clean_up;
    }

    if (!ue_byte_writer_append_int(encoded_message, (int)cipher_data_size)) {
        ei_stacktrace_push_msg("Failed to write cipher payload size to encoded message stream");
        goto clean_up;
    }

    if (!ue_byte_writer_append_bytes(encoded_message, cipher_data, cipher_data_size)) {
        ei_stacktrace_push_msg("Failed to write cipher payload to encoded message stream");
        goto clean_up;
    }

    result = true;

clean_up:
    ue_safe_free(cipher_data);
    return result;
}

ue_byte_stream *ue_relay_message_encode(ue_relay_route *route, ue_relay_message_id message_id, ue_byte_stream *payload) {
    ue_byte_stream *encoded_message, *encoded_route;
    ue_relay_step *first_step;

    if (!ue_relay_route_is_valid(route)) {
        ei_stacktrace_push_msg("Specified route ptr is invalid");
        return NULL;
    }

    if ((message_id == UNKNOWNECHO_RELAY_MESSAGE_ID_SEND ||
        message_id == UNKNOWNECHO_RELAY_MESSAGE_ID_RECEIVE) &&
        (!payload || ue_byte_stream_is_empty(payload))) {

        ei_stacktrace_push_msg("Specified payload is null or empty, but message_id type specify it needs to be filled");
        return NULL;
    }
    else if (message_id != UNKNOWNECHO_RELAY_MESSAGE_ID_SEND &&
        message_id != UNKNOWNECHO_RELAY_MESSAGE_ID_RECEIVE &&
        payload && !ue_byte_stream_is_empty(payload)) {

        ei_logger_warn("A message payload is specified, but the message id is: %d", message_id);
    }

    if (!(encoded_route = ue_relay_route_encode(route))) {
        ei_stacktrace_push_msg("Failed to encode specified route (route seems valid)");
        return NULL;
    }

    encoded_message = ue_byte_stream_create();

    ue_byte_writer_append_int(encoded_message, (int)UNKNOWNECHO_PROTOCOL_ID_RELAY);
    ue_byte_writer_append_int(encoded_message, (int)message_id);
    if (!ue_byte_writer_append_stream(encoded_message, encoded_route)) {
        ei_stacktrace_push_msg("Failed to write encoded route to encoded message stream");
        ue_byte_stream_destroy(encoded_message);
        return NULL;
    }

    if (payload && !ue_byte_stream_is_empty(payload)) {
        first_step = ue_relay_route_get_receiver(route);
        if (!write_sealed_payload(first_step, payload, encoded_message)) {
            ei_stacktrace_push_msg("Failed to write sealed payload to encoded message");
            ue_byte_stream_destroy(encoded_message);
            ue_byte_stream_destroy(encoded_route);
            return NULL;
        }
    }

    ue_byte_stream_destroy(encoded_route);

    return encoded_message;
}

ue_byte_stream *ue_relay_message_encode_from_encoded_route(ue_byte_stream *encoded_route,
    ue_relay_message_id message_id, ue_byte_stream *payload, ue_relay_step *payload_receiver) {

    ue_byte_stream *encoded_message;

    if (!encoded_route || ue_byte_stream_is_empty(encoded_route)) {
        ei_stacktrace_push_msg("Specified encoded route ptr is null or empty");
        return NULL;
    }

    if ((message_id == UNKNOWNECHO_RELAY_MESSAGE_ID_SEND ||
        message_id == UNKNOWNECHO_RELAY_MESSAGE_ID_RECEIVE) &&
        (!payload || ue_byte_stream_is_empty(payload))) {

        ei_stacktrace_push_msg("Specified payload is null or empty, but message_id type specify it needs to be filled");
        return NULL;
    }
    else if (message_id != UNKNOWNECHO_RELAY_MESSAGE_ID_SEND &&
        message_id != UNKNOWNECHO_RELAY_MESSAGE_ID_RECEIVE &&
        payload && !ue_byte_stream_is_empty(payload)) {

        ei_logger_warn("A message payload is specified, but the message id is: %d", message_id);
    }

    encoded_message = ue_byte_stream_create();

    ue_byte_writer_append_int(encoded_message, (int)UNKNOWNECHO_PROTOCOL_ID_RELAY);
    ue_byte_writer_append_int(encoded_message, (int)message_id);
    if (!ue_byte_writer_append_stream(encoded_message, encoded_route)) {
        ei_stacktrace_push_msg("Failed to write encoded route to encoded message stream");
        ue_byte_stream_destroy(encoded_message);
        return NULL;
    }

    if (payload && !ue_byte_stream_is_empty(payload)) {
        if (!write_sealed_payload(payload_receiver, payload, encoded_message)) {
            ei_stacktrace_push_msg("Failed to write sealed payload to encoded message");
            ue_byte_stream_destroy(encoded_message);
            ue_byte_stream_destroy(encoded_route);
            return NULL;
        }
    }

    return encoded_message;
}

ue_byte_stream *ue_relay_message_encode_relay(ue_relay_received_message *received_message) {
    ue_byte_stream *encoded_message;

    ei_check_parameter_or_return(received_message);

    if (received_message->unsealed_payload) {
        ei_stacktrace_push_msg("Cannot relay a message which is meant for us");
        return NULL;
    }

    if (!received_message->remaining_encoded_route ||
        ue_byte_stream_is_empty(received_message->remaining_encoded_route)) {
        ei_stacktrace_push_msg("Cannot encode a message as relay without a route");
        return NULL;
    }

    encoded_message = ue_byte_stream_create();

    ue_byte_writer_append_int(encoded_message, (int)received_message->protocol_id);
    ue_byte_writer_append_int(encoded_message, (int)received_message->message_id);

    if (!ue_byte_writer_append_stream(encoded_message, received_message->remaining_encoded_route)) {
        ei_stacktrace_push_msg("Failed to write remaining encoded route to encoded message stream");
        ue_byte_stream_destroy(encoded_message);
        return NULL;
    }

    if (!ue_byte_writer_append_stream(encoded_message, received_message->payload)) {
        ei_stacktrace_push_msg("Failed to write sealed payload to message stream");
        ue_byte_stream_destroy(encoded_message);
        return NULL;
    }

    return encoded_message;
}
