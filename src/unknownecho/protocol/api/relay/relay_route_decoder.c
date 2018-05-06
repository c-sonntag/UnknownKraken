#include <unknownecho/protocol/api/relay/relay_route_decoder.h>
#include <unknownecho/protocol/api/relay/relay_step.h>
#include <unknownecho/crypto/api/cipher/data_cipher.h>
#include <unknownecho/byte/byte_stream.h>
#include <unknownecho/byte/byte_reader.h>
#include <unknownecho/byte/byte_writer.h>
#include <unknownecho/string/string_utility.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/alloc.h>

#include <stddef.h>

ue_relay_step *ue_relay_route_decode_pop_step(ue_byte_stream *encoded_route, ue_crypto_metadata *our_crypto_metadata) {
    ue_relay_step *step;
    ue_communication_metadata *our_communication_metadata, *target_communication_metadata;
    unsigned char *plain_data, *read_bytes, *remaining_bytes;
    size_t plain_data_size;
    ue_byte_stream *payload;
    const char *our_communication_metadata_string, *target_communication_metadata_string;
    int our_communication_metadata_size, target_communication_metadata_size, remaining_bytes_size;

    step = NULL;
    plain_data = NULL;
    read_bytes = NULL;
    remaining_bytes = NULL;
    payload = ue_byte_stream_create();
    our_communication_metadata_string = NULL;
    target_communication_metadata_string = NULL;

    if (!ue_decipher_cipher_data(ue_byte_stream_get_data(encoded_route), ue_byte_stream_get_size(encoded_route),
        ue_crypto_metadata_get_cipher_private_key(our_crypto_metadata), NULL, &plain_data, &plain_data_size,
        ue_crypto_metadata_get_cipher_name(our_crypto_metadata), ue_crypto_metadata_get_digest_name(our_crypto_metadata))) {

        ue_stacktrace_push_msg("Failed to decipher data");
        return NULL;
    }

    if (!ue_byte_writer_append_bytes(payload, plain_data, plain_data_size)) {
        ue_stacktrace_push_msg("Failed to append plain data to payload");
        goto clean_up;
    }
    if (!ue_byte_stream_set_position(payload, 0)) {
        ue_stacktrace_push_msg("Failed to set position of payload to 0");
        goto clean_up;
    }

    if (!ue_byte_read_next_int(payload, &our_communication_metadata_size)) {
        ue_stacktrace_push_msg("Failed to read our communication metadata size");
        goto clean_up;
    }
    if (!ue_byte_read_next_int(payload, &target_communication_metadata_size)) {
        ue_stacktrace_push_msg("Failed to read target communication metadata size");
        goto clean_up;
    }

    if (!ue_byte_read_next_bytes(payload, &read_bytes, our_communication_metadata_size)) {
        ue_stacktrace_push_msg("Failed to read our communication metadata");
        goto clean_up;
    }
    if (!(our_communication_metadata_string = ue_string_create_from_bytes(read_bytes, (size_t)our_communication_metadata_size))) {
        ue_stacktrace_push_msg("Failed to convert our communication metadata from bytes to string");
        goto clean_up;
    }
    ue_safe_free(read_bytes);

    if (!ue_byte_read_next_bytes(payload, &read_bytes, target_communication_metadata_size)) {
        ue_stacktrace_push_msg("Failed to read target communication metadata");
        goto clean_up;
    }
    if (!(target_communication_metadata_string = ue_string_create_from_bytes(read_bytes, (size_t)target_communication_metadata_size))) {
        ue_stacktrace_push_msg("Failed to convert target communication metadata from bytes to string");
        goto clean_up;
    }

    if (!(our_communication_metadata = ue_communication_metadata_create_from_string(our_communication_metadata_string))) {
        ue_stacktrace_push_msg("Failed to create our communication metadata from string");
        goto clean_up;
    }
    if (!(target_communication_metadata = ue_communication_metadata_create_from_string(target_communication_metadata_string))) {
        ue_stacktrace_push_msg("Failed to create target communication metadata from string");
        goto clean_up;
    }

    if (!(step = ue_relay_step_create(our_communication_metadata, target_communication_metadata, our_crypto_metadata, NULL))) {
        ue_stacktrace_push_msg("Failed to build relay step from communication metadatas");
        goto clean_up;
    }

    /* Clean-up the encoded route */
    ue_byte_stream_clean_up(encoded_route);
    ue_byte_stream_set_position(encoded_route, 0);

    /* Check if there's another step(s) in the route. If not, the encoded route will be empty */
    if (ue_byte_read_next_int(payload, &remaining_bytes_size) && remaining_bytes_size > 0) {
        /* Pushing remaining encoded steps */
        ue_byte_read_next_bytes(payload, &remaining_bytes, (size_t)remaining_bytes_size);
        ue_byte_writer_append_bytes(encoded_route, remaining_bytes, remaining_bytes_size);
    }

clean_up:
    ue_safe_free(plain_data);
    ue_safe_free(read_bytes);
    ue_safe_free(remaining_bytes);
    ue_byte_stream_destroy(payload);
    ue_safe_free(our_communication_metadata_string);
    ue_safe_free(target_communication_metadata_string);
    return step;
}
