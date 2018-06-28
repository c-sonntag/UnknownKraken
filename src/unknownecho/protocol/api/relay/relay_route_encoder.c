#include <unknownecho/protocol/api/relay/relay_route_encoder.h>
#include <unknownecho/protocol/api/relay/relay_route.h>
#include <unknownecho/protocol/api/relay/relay_step.h>
#include <unknownecho/defines.h>
#include <ueum/ueum.h>
#include <uecm/uecm.h>
#include <ei/ei.h>

#include <stddef.h>
#include <string.h>

static bool encode_step(ueum_byte_stream *encoded_route, ue_relay_step *step, ue_relay_step *next_step,
    ueum_byte_stream *payload, uecm_crypto_metadata *crypto_metadata) {

    bool result;
    uecm_crypto_metadata *target_crypto_metadata;
    const char *target_communication_metadata_string;
    unsigned char *cipher_data;
    size_t cipher_data_size;

    result = false;
    target_communication_metadata_string = NULL;
    cipher_data = NULL;

    if (!(target_crypto_metadata = ue_relay_step_get_target_crypto_metadata(step))) {
        ei_stacktrace_push_msg("Specified step doesn't contain target crypto metadata");
        return false;
    }

    if (next_step && !(target_communication_metadata_string = ue_communication_metadata_to_string(ue_relay_step_get_target_communication_metadata(next_step)))) {
        ei_stacktrace_push_msg("Failed to convert target communication metadata to string");
        goto clean_up;
    }

    if (next_step) {
        ueum_byte_writer_append_int(payload, 1);
        ueum_byte_writer_append_int(payload, (int)strlen(target_communication_metadata_string));
        ueum_byte_writer_append_string(payload, (char *)target_communication_metadata_string);
    } else {
        ueum_byte_writer_append_int(payload, 0);
    }

    if (!ueum_byte_stream_is_empty(encoded_route)) {
        ueum_byte_writer_append_int(payload, ueum_byte_stream_get_size(encoded_route));
        if (!ueum_byte_writer_append_bytes(payload, ueum_byte_stream_get_data(encoded_route), ueum_byte_stream_get_size(encoded_route))) {
            ei_stacktrace_push_msg("Failed to append previous encoded route to payload");
            goto clean_up;
        }
    }
    /**
     * @todo use the private key of our_crypto_metadata (from the sender step)
     * to sign each encoded step
     */
    if (!uecm_cipher_plain_data(ueum_byte_stream_get_data(payload), ueum_byte_stream_get_size(payload),
        uecm_crypto_metadata_get_cipher_public_key(target_crypto_metadata), NULL, &cipher_data, &cipher_data_size,
        uecm_crypto_metadata_get_cipher_name(crypto_metadata), uecm_crypto_metadata_get_digest_name(crypto_metadata))) {

        ei_stacktrace_push_msg("Failed to cipher current step with target crypto metadata");
        goto clean_up;
    }
    ueum_byte_stream_clean_up(encoded_route);
    if (!ueum_byte_writer_append_bytes(encoded_route, cipher_data, cipher_data_size)) {
        ei_stacktrace_push_msg("Failed to write cipher data of the current step into the encoded route");
        goto clean_up;
    }

    result = true;

clean_up:
    ueum_safe_free(target_communication_metadata_string);
    ueum_safe_free(cipher_data);
    ueum_byte_stream_clean_up(payload);
    return result;
}

ueum_byte_stream *ue_relay_route_encode(ue_relay_route *route) {
    ueum_byte_stream *encoded_route;
    int i, j;
    ue_relay_step *current_step, *next_step;
    ueum_byte_stream *payload;
    uecm_crypto_metadata *our_crypto_metadata;

    if (!ue_relay_route_is_valid(route)) {
        ei_stacktrace_push_msg("Specified route ptr is invalid");
        return NULL;
    }

    encoded_route = ueum_byte_stream_create();
    payload = ueum_byte_stream_create();
    our_crypto_metadata = ue_relay_step_get_our_crypto_metadata(ue_relay_route_get_sender(route));

    for (i = route->steps_number - 1, j = 1; i >= 0; i--, j++) {
        ei_logger_trace("Relay route encoding iteration: %d", i);
        current_step = route->steps[i];
        if (i == route->steps_number - 1) {
            next_step = NULL;
        } else {
            next_step = route->steps[i+1];
        }
        ei_logger_debug("current_step: %s", ue_communication_metadata_to_string(
            ue_relay_step_get_target_communication_metadata(current_step)));
        ei_logger_debug("next_step: %s", ue_communication_metadata_to_string(
            ue_relay_step_get_target_communication_metadata(next_step)));
        printf("\n");
        if (!encode_step(encoded_route, current_step, next_step, payload, our_crypto_metadata)) {
            ueum_byte_stream_destroy(encoded_route);
            ueum_byte_stream_destroy(payload);
            ei_stacktrace_push_msg("Failed to encode a step at iteration #%d", j);
            return NULL;
        }
    }

    ueum_byte_stream_destroy(payload);
    return encoded_route;
}
