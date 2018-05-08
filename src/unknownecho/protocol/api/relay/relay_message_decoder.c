#include <unknownecho/protocol/api/relay/relay_message_decoder.h>
#include <unknownecho/protocol/api/relay/relay_plain_message.h>
#include <unknownecho/protocol/api/relay/relay_message_id.h>
#include <unknownecho/protocol/api/relay/relay_route_decoder.h>
#include <unknownecho/protocol/api/protocol_id.h>
#include <unknownecho/crypto/api/cipher/data_cipher.h>
#include <unknownecho/byte/byte_stream.h>
#include <unknownecho/byte/byte_reader.h>
#include <unknownecho/byte/byte_writer.h>
#include <unknownecho/errorHandling/check_parameter.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/bool.h>
#include <unknownecho/alloc.h>

#include <stddef.h>

bool read_seal_payload(ue_byte_stream *encoded_message, ue_crypto_metadata *our_crypto_metadata, ue_byte_stream *payload) {
    bool result;
    int cipher_data_size;
    unsigned char *cipher_data, *plain_data;
    size_t plain_data_size;

    result = false;
    cipher_data = NULL;
    plain_data = NULL;

    if (!ue_byte_read_next_int(encoded_message, &cipher_data_size)) {
        ue_stacktrace_push_msg("Failed to read cipher payload size");
        return false;
    }

    if (cipher_data_size == 0) {
        ue_stacktrace_push_msg("Cipher data size of the payload is equal to 0");
        return false;
    }

    ue_byte_read_next_bytes(encoded_message, &cipher_data, (size_t)cipher_data_size);

    if (!ue_decipher_cipher_data(cipher_data, (size_t)cipher_data_size,
        ue_crypto_metadata_get_cipher_private_key(our_crypto_metadata), NULL, &plain_data, &plain_data_size,
        ue_crypto_metadata_get_cipher_name(our_crypto_metadata), ue_crypto_metadata_get_digest_name(our_crypto_metadata))) {

        ue_stacktrace_push_msg("Failed to decipher data");
        goto clean_up;
    }

    if (!ue_byte_writer_append_bytes(payload, plain_data, plain_data_size)) {
        ue_stacktrace_push_msg("Failed to write plain data to payload");
        goto clean_up;
    }

    result = true;

clean_up:
    ue_safe_free(cipher_data);
    ue_safe_free(plain_data);
    return result;
}

ue_relay_plain_message *ue_relay_message_decode(ue_byte_stream *encoded_message, ue_crypto_metadata *our_crypto_metadata) {
    ue_relay_plain_message *plain_message;
    int read_int;

    ue_check_parameter_or_return(encoded_message);
    ue_check_parameter_or_return(our_crypto_metadata);

    /* Check if encoded message is empty */
    if (ue_byte_stream_is_empty(encoded_message)) {
        ue_stacktrace_push_msg("Specified encoded message is empty");
        return NULL;
    }

    plain_message = ue_relay_plain_message_create_empty();

    /* Set the virtual cursor of the encoded message stream to the begining */
    ue_byte_stream_set_position(encoded_message, 0);

    /* Check protocol id */
    ue_byte_read_next_int(encoded_message, &read_int);
    if (ue_protocol_id_is_valid(read_int)) {
        plain_message->protocol_id = (ue_protocol_id)read_int;
    } else {
        ue_relay_plain_message_destroy(plain_message);
        ue_stacktrace_push_msg("Specified protocol id '%d' is invalid", read_int);
        return NULL;
    }
    ue_logger_trace("Protocol id: %d", read_int);

    /* Check message id */
    ue_byte_read_next_int(encoded_message, &read_int);
    if (ue_relay_message_id_is_valid(read_int)) {
        plain_message->message_id = (ue_relay_message_id)read_int;
    } else {
        ue_relay_plain_message_destroy(plain_message);
        ue_stacktrace_push_msg("Specified relay message id '%d' is invalid", read_int);
        return NULL;
    }
    ue_logger_trace("Message id: %d", read_int);

    plain_message->remaining_encoded_route = ue_byte_stream_create();

    /* Read the encoded route */
    if (!ue_byte_read_next_stream(encoded_message, plain_message->remaining_encoded_route)) {
        ue_relay_plain_message_destroy(plain_message);
        ue_stacktrace_push_msg("Failed to read encoded route from encoded message");
        return NULL;
    }

    /* Decode the first step of the encoded route and get the remaining route */
    if (!(plain_message->next_step = ue_relay_route_decode_pop_step(plain_message->remaining_encoded_route,
        our_crypto_metadata))) {

        ue_relay_plain_message_destroy(plain_message);
        ue_stacktrace_push_msg("Failed to read encoded route from encoded message");
        return NULL;
    }

    /* Check if there's a payload in the message */
    if (plain_message->message_id == UNKNOWNECHO_RELAY_MESSAGE_ID_SEND ||
        plain_message->message_id == UNKNOWNECHO_RELAY_MESSAGE_ID_RECEIVE) {

        if (!ue_byte_stream_is_empty(plain_message->remaining_encoded_route)) {
            ue_logger_trace("Remaining route isn't empty, so the message wasn't meant for us. We cannot unseal it, anyway.");
            plain_message->payload = ue_byte_stream_create();
            if (!ue_byte_read_next_stream(encoded_message, plain_message->payload)) {
                ue_relay_plain_message_destroy(plain_message);
                ue_stacktrace_push_msg("Failed to copy seal payload to plain message state");
                return NULL;
            }
        } else {
            ue_logger_trace("Remaining route is empty, so the message is meant for us. Trying to unseal it...");
            /* Read and unseal the payload */
            plain_message->payload = ue_byte_stream_create();
            if (!read_seal_payload(encoded_message, our_crypto_metadata, plain_message->payload)) {
                ue_relay_plain_message_destroy(plain_message);
                ue_stacktrace_push_msg("Failed to read seal payload from encoded message");
                return NULL;
            }
            plain_message->unsealed_payload = true;
        }
    }

    return plain_message;
}
