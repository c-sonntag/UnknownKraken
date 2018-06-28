#include <unknownecho/protocol/api/relay/relay_message_encoder.h>
#include <unknownecho/protocol/api/relay/relay_route_encoder.h>
#include <unknownecho/protocol/api/relay/relay_route.h>
#include <unknownecho/protocol/api/relay/relay_step_struct.h>
#include <unknownecho/protocol/api/relay/relay_step.h>
#include <unknownecho/protocol/api/protocol_id.h>
#include <ueum/ueum.h>
#include <uecm/uecm.h>
#include <ei/ei.h>

#include <stddef.h>

static bool write_sealed_payload(ue_relay_step *first_step, ueum_byte_stream *payload, ueum_byte_stream *encoded_message) {
    bool result;
    uecm_crypto_metadata *our_crypto_metadata, *target_crypto_metadata;
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
    if (!uecm_cipher_plain_data(ueum_byte_stream_get_data(payload), ueum_byte_stream_get_size(payload),
        uecm_crypto_metadata_get_cipher_public_key(target_crypto_metadata), NULL, &cipher_data, &cipher_data_size,
        uecm_crypto_metadata_get_cipher_name(our_crypto_metadata), uecm_crypto_metadata_get_digest_name(our_crypto_metadata))) {

        ei_stacktrace_push_msg("Failed to cipher content of payload");
        goto clean_up;
    }

    if (!ueum_byte_writer_append_int(encoded_message, (int)cipher_data_size)) {
        ei_stacktrace_push_msg("Failed to write cipher payload size to encoded message stream");
        goto clean_up;
    }

    if (!ueum_byte_writer_append_bytes(encoded_message, cipher_data, cipher_data_size)) {
        ei_stacktrace_push_msg("Failed to write cipher payload to encoded message stream");
        goto clean_up;
    }

    result = true;

clean_up:
    ueum_safe_free(cipher_data);
    return result;
}

ueum_byte_stream *ue_relay_message_encode(ue_relay_route *route, ue_relay_route *back_route,
    ue_relay_message_id message_id, ueum_byte_stream *payload) {

    ueum_byte_stream *encoded_message, *encoded_route, *encoded_back_route;
    ue_relay_step *first_step;

    encoded_message = NULL;
    encoded_route = NULL;
    encoded_back_route = NULL;
    first_step = NULL;

    if (!ue_relay_route_is_valid(route)) {
        ei_stacktrace_push_msg("Specified route ptr is invalid");
        return NULL;
    }

    if ((message_id == UNKNOWNECHO_RELAY_MESSAGE_ID_REQUEST ||
        message_id == UNKNOWNECHO_RELAY_MESSAGE_ID_RESPONSE) &&
        (!payload || ueum_byte_stream_is_empty(payload))) {

        ei_stacktrace_push_msg("Specified payload is null or empty, but message_id type specify it needs to be filled");
        return NULL;
    }
    else if (message_id != UNKNOWNECHO_RELAY_MESSAGE_ID_REQUEST &&
        message_id != UNKNOWNECHO_RELAY_MESSAGE_ID_RESPONSE &&
        payload && !ueum_byte_stream_is_empty(payload)) {

        ei_logger_warn("A message payload is specified, but the message id is: %d", message_id);
    }

    if (!(encoded_route = ue_relay_route_encode(route))) {
        ei_stacktrace_push_msg("Failed to encode specified route (route seems valid)");
        return NULL;
    }

    if (!(encoded_back_route = ue_relay_route_encode(back_route))) {
        ueum_byte_stream_destroy(encoded_route);
        ei_stacktrace_push_msg("Failed to encode specified back route (route seems valid)");
        return NULL;
    }

    encoded_message = ueum_byte_stream_create();

    ueum_byte_writer_append_int(encoded_message, (int)UNKNOWNECHO_PROTOCOL_ID_RELAY);
    ueum_byte_writer_append_int(encoded_message, (int)message_id);

    if (!ueum_byte_writer_append_stream(encoded_message, encoded_route)) {
        ei_stacktrace_push_msg("Failed to write encoded route to encoded message stream");
        ueum_byte_stream_destroy(encoded_message);
        goto clean_up;
    }

    if (!ueum_byte_writer_append_stream(encoded_message, encoded_back_route)) {
        ei_stacktrace_push_msg("Failed to write encoded back route to encoded message stream");
        ueum_byte_stream_destroy(encoded_message);
        goto clean_up;
    }

    if (payload && !ueum_byte_stream_is_empty(payload)) {
        first_step = ue_relay_route_get_receiver(route);
        if (!write_sealed_payload(first_step, payload, encoded_message)) {
            ei_stacktrace_push_msg("Failed to write sealed payload to encoded message");
            ueum_byte_stream_destroy(encoded_message);
            goto clean_up;
        }
    }

clean_up:
    ueum_byte_stream_destroy(encoded_route);
    ueum_byte_stream_destroy(encoded_back_route);
    return encoded_message;
}

ueum_byte_stream *ue_relay_message_encode_from_encoded_route(ueum_byte_stream *encoded_route,
    ueum_byte_stream *encoded_back_route, ue_relay_message_id message_id, ueum_byte_stream *payload,
    ue_relay_step *payload_receiver) {

    ueum_byte_stream *encoded_message;

    if (!encoded_route || ueum_byte_stream_is_empty(encoded_route)) {
        ei_stacktrace_push_msg("Specified encoded route ptr is null or empty");
        return NULL;
    }

    if ((message_id == UNKNOWNECHO_RELAY_MESSAGE_ID_REQUEST ||
        message_id == UNKNOWNECHO_RELAY_MESSAGE_ID_RESPONSE) &&
        (!payload || ueum_byte_stream_is_empty(payload))) {

        ei_stacktrace_push_msg("Specified payload is null or empty, but message_id type specify it needs to be filled");
        return NULL;
    }
    else if (message_id != UNKNOWNECHO_RELAY_MESSAGE_ID_REQUEST &&
        message_id != UNKNOWNECHO_RELAY_MESSAGE_ID_RESPONSE &&
        payload && !ueum_byte_stream_is_empty(payload)) {

        ei_logger_warn("A message payload is specified, but the message id is: %d", message_id);
    }

    encoded_message = ueum_byte_stream_create();

    ueum_byte_writer_append_int(encoded_message, (int)UNKNOWNECHO_PROTOCOL_ID_RELAY);
    ueum_byte_writer_append_int(encoded_message, (int)message_id);

    if (!ueum_byte_writer_append_stream(encoded_message, encoded_route)) {
        ei_stacktrace_push_msg("Failed to write encoded route to encoded message stream");
        ueum_byte_stream_destroy(encoded_message);
        return NULL;
    }

    if (!ueum_byte_writer_append_stream(encoded_message, encoded_back_route)) {
        ei_stacktrace_push_msg("Failed to write encoded back route to encoded message stream");
        ueum_byte_stream_destroy(encoded_message);
        return NULL;
    }

    if (payload && !ueum_byte_stream_is_empty(payload)) {
        if (!write_sealed_payload(payload_receiver, payload, encoded_message)) {
            ei_stacktrace_push_msg("Failed to write sealed payload to encoded message");
            ueum_byte_stream_destroy(encoded_message);
            return NULL;
        }
    }

    return encoded_message;
}

ueum_byte_stream *ue_relay_message_encode_relay(ue_relay_received_message *received_message) {
    ueum_byte_stream *encoded_message;

    ei_check_parameter_or_return(received_message);

    if (received_message->unsealed_payload) {
        ei_stacktrace_push_msg("Cannot relay a message which is meant for us");
        return NULL;
    }

    if (!received_message->remaining_encoded_route ||
        ueum_byte_stream_is_empty(received_message->remaining_encoded_route)) {
        ei_stacktrace_push_msg("Cannot encode a message as relay without a route");
        return NULL;
    }

    encoded_message = ueum_byte_stream_create();

    ueum_byte_writer_append_int(encoded_message, (int)received_message->protocol_id);
    ueum_byte_writer_append_int(encoded_message, (int)received_message->message_id);

    if (!ueum_byte_writer_append_stream(encoded_message, received_message->remaining_encoded_route)) {
        ei_stacktrace_push_msg("Failed to write remaining encoded route to encoded message stream");
        ueum_byte_stream_destroy(encoded_message);
        return NULL;
    }

    if (!ueum_byte_writer_append_stream(encoded_message, received_message->remaining_encoded_back_route)) {
        ei_stacktrace_push_msg("Failed to write remaining encoded back route to encoded message stream");
        ueum_byte_stream_destroy(encoded_message);
        return NULL;
    }

    if (!ueum_byte_writer_append_stream(encoded_message, received_message->payload)) {
        ei_stacktrace_push_msg("Failed to write sealed payload to message stream");
        ueum_byte_stream_destroy(encoded_message);
        return NULL;
    }

    return encoded_message;
}
