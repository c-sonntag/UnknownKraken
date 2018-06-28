#include <unknownecho/protocol/api/relay/relay_route_decoder.h>
#include <unknownecho/protocol/api/relay/relay_step.h>
#include <ueum/ueum.h>
#include <uecm/uecm.h>
#include <ei/ei.h>

#include <stddef.h>

ue_relay_step *ue_relay_route_decode_pop_step(ueum_byte_stream *encoded_route, uecm_crypto_metadata *our_crypto_metadata) {
    ue_relay_step *step;
    ue_communication_metadata *target_communication_metadata;
    unsigned char *plain_data, *read_bytes, *remaining_bytes;
    size_t plain_data_size;
    ueum_byte_stream *payload;
    const char *target_communication_metadata_string;
    int target_communication_metadata_size, remaining_bytes_size, has_next_step;

    step = NULL;
    plain_data = NULL;
    read_bytes = NULL;
    remaining_bytes = NULL;
    payload = ueum_byte_stream_create();
    target_communication_metadata_string = NULL;

    if (!uecm_decipher_cipher_data(ueum_byte_stream_get_data(encoded_route), ueum_byte_stream_get_size(encoded_route),
        uecm_crypto_metadata_get_cipher_private_key(our_crypto_metadata), NULL, &plain_data, &plain_data_size,
        uecm_crypto_metadata_get_cipher_name(our_crypto_metadata), uecm_crypto_metadata_get_digest_name(our_crypto_metadata))) {

        ei_stacktrace_push_msg("Failed to decipher data");
        return NULL;
    }

    if (!ueum_byte_writer_append_bytes(payload, plain_data, plain_data_size)) {
        ei_stacktrace_push_msg("Failed to append plain data to payload");
        goto clean_up;
    }
    if (!ueum_byte_stream_set_position(payload, 0)) {
        ei_stacktrace_push_msg("Failed to set position of payload to 0");
        goto clean_up;
    }

    ueum_byte_read_next_int(payload, &has_next_step);

    if (has_next_step) {
        if (!ueum_byte_read_next_int(payload, &target_communication_metadata_size)) {
            ei_stacktrace_push_msg("Failed to read target communication metadata size");
            goto clean_up;
        }

        ueum_safe_free(read_bytes);

        if (!ueum_byte_read_next_bytes(payload, &read_bytes, target_communication_metadata_size)) {
            ei_stacktrace_push_msg("Failed to read target communication metadata");
            goto clean_up;
        }
        if (!(target_communication_metadata_string = ueum_string_create_from_bytes(read_bytes, (size_t)target_communication_metadata_size))) {
            ei_stacktrace_push_msg("Failed to convert target communication metadata from bytes to string");
            goto clean_up;
        }

        if (!(target_communication_metadata = ue_communication_metadata_create_from_string(target_communication_metadata_string))) {
            ei_stacktrace_push_msg("Failed to create target communication metadata from string");
            goto clean_up;
        }

        if (!(step = ue_relay_step_create(target_communication_metadata, our_crypto_metadata, NULL))) {
            ei_stacktrace_push_msg("Failed to build relay step from communication metadatas");
            goto clean_up;
        }
    }

    /* Clean-up the encoded route */
    ueum_byte_stream_clean_up(encoded_route);
    ueum_byte_stream_set_position(encoded_route, 0);

    /* Check if there's another step(s) in the route. If not, the encoded route will be empty */
    if (ueum_byte_read_next_int(payload, &remaining_bytes_size) && remaining_bytes_size > 0) {
        /* Pushing remaining encoded steps */
        ueum_byte_read_next_bytes(payload, &remaining_bytes, (size_t)remaining_bytes_size);
        ueum_byte_writer_append_bytes(encoded_route, remaining_bytes, remaining_bytes_size);
    }

clean_up:
    ueum_safe_free(plain_data);
    ueum_safe_free(read_bytes);
    ueum_safe_free(remaining_bytes);
    ueum_byte_stream_destroy(payload);
    ueum_safe_free(target_communication_metadata_string);
    return step;
}
