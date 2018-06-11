#include <unknownecho/protocol/api/relay/relay_message_decoder.h>
#include <unknownecho/protocol/api/relay/relay_received_message.h>
#include <unknownecho/protocol/api/relay/relay_message_id.h>
#include <unknownecho/protocol/api/relay/relay_route_decoder.h>
#include <unknownecho/protocol/api/protocol_id.h>
#include <unknownecho/crypto/api/cipher/data_cipher.h>
#include <unknownecho/byte/byte_stream.h>
#include <unknownecho/byte/byte_reader.h>
#include <unknownecho/byte/byte_writer.h>
#include <ei/ei.h>
#include <unknownecho/bool.h>
#include <unknownecho/alloc.h>

#include <stddef.h>

static bool read_seal_payload(ue_byte_stream *encoded_message, ue_crypto_metadata *our_crypto_metadata,
    ue_byte_stream *payload) {
    
    bool result;
    int cipher_data_size;
    unsigned char *cipher_data, *plain_data;
    size_t plain_data_size;

    result = false;
    cipher_data = NULL;
    plain_data = NULL;

    if (!ue_byte_read_next_int(encoded_message, &cipher_data_size)) {
        ei_stacktrace_push_msg("Failed to read cipher payload size");
        return false;
    }

    if (cipher_data_size == 0) {
        ei_stacktrace_push_msg("Cipher data size of the payload is equal to 0");
        return false;
    }

    ue_byte_read_next_bytes(encoded_message, &cipher_data, (size_t)cipher_data_size);

    if (!ue_decipher_cipher_data(cipher_data, (size_t)cipher_data_size,
        ue_crypto_metadata_get_cipher_private_key(our_crypto_metadata), NULL, &plain_data, &plain_data_size,
        ue_crypto_metadata_get_cipher_name(our_crypto_metadata), ue_crypto_metadata_get_digest_name(our_crypto_metadata))) {

        ei_stacktrace_push_msg("Failed to decipher data");
        goto clean_up;
    }

    if (!ue_byte_writer_append_bytes(payload, plain_data, plain_data_size)) {
        ei_stacktrace_push_msg("Failed to write plain data to payload");
        goto clean_up;
    }

    result = true;

clean_up:
    ue_safe_free(cipher_data);
    ue_safe_free(plain_data);
    return result;
}

ue_relay_received_message *ue_relay_message_decode(ue_byte_stream *encoded_message,
    ue_crypto_metadata *our_crypto_metadata) {
    
    ue_relay_received_message *received_message;
    int read_int;

    ei_check_parameter_or_return(encoded_message);
    ei_check_parameter_or_return(our_crypto_metadata);

    /* Check if encoded message is empty */
    if (ue_byte_stream_is_empty(encoded_message)) {
        ei_stacktrace_push_msg("Specified encoded message is empty");
        return NULL;
    }

    received_message = ue_relay_received_message_create_empty();

    /* Set the virtual cursor of the encoded message stream to the begining */
    ue_byte_stream_set_position(encoded_message, 0);

    /* Check protocol id */
    ue_byte_read_next_int(encoded_message, &read_int);
    if (ue_protocol_id_is_valid(read_int)) {
        received_message->protocol_id = (ue_protocol_id)read_int;
    } else {
        ue_relay_received_message_destroy(received_message);
        ei_stacktrace_push_msg("Specified protocol id '%d' is invalid", read_int);
        return NULL;
    }
    ei_logger_trace("Protocol id: %d", read_int);

    /* Check message id */
    ue_byte_read_next_int(encoded_message, &read_int);
    if (ue_relay_message_id_is_valid(read_int)) {
        received_message->message_id = (ue_relay_message_id)read_int;
    } else {
        ue_relay_received_message_destroy(received_message);
        ei_stacktrace_push_msg("Specified relay message id '%d' is invalid", read_int);
        return NULL;
    }
    ei_logger_trace("Message id: %d", read_int);

    received_message->remaining_encoded_route = ue_byte_stream_create();
    received_message->remaining_encoded_back_route = ue_byte_stream_create();

    /* Read the encoded route */
    if (!ue_byte_read_next_stream(encoded_message, received_message->remaining_encoded_route)) {
        ue_relay_received_message_destroy(received_message);
        ei_stacktrace_push_msg("Failed to read encoded route from encoded message");
        return NULL;
    }

    /* Read the encoded back route */
    if (!ue_byte_read_next_stream(encoded_message, received_message->remaining_encoded_back_route)) {
        ue_relay_received_message_destroy(received_message);
        ei_stacktrace_push_msg("Failed to read encoded back route from encoded message");
        return NULL;
    }

    /* Decode the first step of the encoded route and get the remaining route */
    if (!(received_message->next_step = ue_relay_route_decode_pop_step(received_message->remaining_encoded_route,
        our_crypto_metadata))) {

        if (ei_stacktrace_is_filled()) {
            ei_stacktrace_push_msg("Failed to pop next step");
            ue_relay_received_message_destroy(received_message);
            return NULL;
        }

        ei_logger_trace("Cannot pop next step - maybe we're the end user of the route");
    }

    /* Check if there's a payload in the message */
    if (received_message->message_id == UNKNOWNECHO_RELAY_MESSAGE_ID_REQUEST ||
        received_message->message_id == UNKNOWNECHO_RELAY_MESSAGE_ID_RESPONSE) {

        if (!ue_byte_stream_is_empty(received_message->remaining_encoded_route)) {
            ei_logger_trace("Remaining route isn't empty, so the message wasn't meant for us. We cannot unseal it, anyway.");
            received_message->payload = ue_byte_stream_create();
            if (!ue_byte_read_next_stream(encoded_message, received_message->payload)) {
                ue_relay_received_message_destroy(received_message);
                ei_stacktrace_push_msg("Failed to copy seal payload to received message");
                return NULL;
            }
        } else {
            ei_logger_trace("Remaining route is empty, so the message is meant for us. Trying to unseal it...");
            /* Read and unseal the payload */
            received_message->payload = ue_byte_stream_create();
            if (!read_seal_payload(encoded_message, our_crypto_metadata, received_message->payload)) {
                ue_relay_received_message_destroy(received_message);
                ei_stacktrace_push_msg("Failed to read seal payload from encoded message");
                return NULL;
            }
            received_message->unsealed_payload = true;
        }
    }

    if (!received_message->unsealed_payload && !received_message->next_step) {
        ue_relay_received_message_destroy(received_message);
        ei_stacktrace_push_msg("The payload isn't unsealed and we doesn't know the next step");
        return NULL;
    }

    return received_message;
}
