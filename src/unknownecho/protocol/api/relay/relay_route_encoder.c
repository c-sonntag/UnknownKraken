#include <unknownecho/protocol/api/relay/relay_route_encoder.h>
#include <unknownecho/protocol/api/relay/relay_route.h>
#include <unknownecho/protocol/api/relay/relay_step.h>
#include <unknownecho/crypto/api/crypto_metadata.h>
#include <unknownecho/crypto/api/cipher/data_cipher.h>
#include <unknownecho/byte/byte_stream.h>
#include <unknownecho/byte/byte_writer.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/defines.h>
#include <unknownecho/alloc.h>

#include <stddef.h>
#include <string.h>

bool encode_step(ue_byte_stream *encoded_route, ue_relay_step *step, ue_byte_stream *payload) {
    bool result;
    ue_crypto_metadata *our_crypto_metadata, *target_crypto_metadata;
    const char *our_communication_metadata_string, *target_communication_metadata_string;
    unsigned char *cipher_data;
    size_t cipher_data_size;

    result = false;
    cipher_data = NULL;

    our_crypto_metadata = ue_relay_step_get_our_crypto_metadata(step);
    target_crypto_metadata = ue_relay_step_get_target_crypto_metadata(step);
    our_communication_metadata_string = ue_communication_metadata_to_string(ue_relay_step_get_our_communication_metadata(step));
    target_communication_metadata_string = ue_communication_metadata_to_string(ue_relay_step_get_target_communication_metadata(step));
    ue_byte_writer_append_int(payload, (int)strlen(our_communication_metadata_string));
    ue_byte_writer_append_int(payload, (int)strlen(target_communication_metadata_string));
    ue_byte_writer_append_string(payload, (char *)our_communication_metadata_string);
    ue_byte_writer_append_string(payload, (char *)target_communication_metadata_string);
    if (!ue_byte_stream_is_empty(encoded_route)) {
        ue_byte_writer_append_int(payload, ue_byte_stream_get_size(encoded_route));
        if (!ue_byte_writer_append_bytes(payload, ue_byte_stream_get_data(encoded_route), ue_byte_stream_get_size(encoded_route))) {
            ue_stacktrace_push_msg("Failed to append previous encoded route to payload");
            goto clean_up;
        }
    }
    ue_cipher_plain_data(ue_byte_stream_get_data(payload), ue_byte_stream_get_size(payload),
        ue_crypto_metadata_get_cipher_public_key(target_crypto_metadata), NULL, &cipher_data, &cipher_data_size,
        ue_crypto_metadata_get_cipher_name(our_crypto_metadata), ue_crypto_metadata_get_digest_name(our_crypto_metadata));
    ue_byte_stream_clean_up(encoded_route);
    ue_byte_writer_append_bytes(encoded_route, cipher_data, cipher_data_size);

    result = true;

clean_up:
    ue_safe_free(cipher_data);
    ue_byte_stream_clean_up(payload);
    return result;
}

ue_byte_stream *ue_relay_route_encode(ue_relay_route *route) {
    ue_byte_stream *encoded_route;
    int i, j;
    ue_relay_step *current_step;
    ue_byte_stream *payload;

    encoded_route = ue_byte_stream_create();
    payload = ue_byte_stream_create();

    for (i = route->steps_number - 1, j = 1; i >= 0; i--, j++) {
        ue_logger_trace("i:%d", i);
        current_step = route->steps[i];
        if (!encode_step(encoded_route, current_step, payload)) {
            ue_byte_stream_destroy(encoded_route);
            ue_byte_stream_destroy(payload);
            ue_stacktrace_push_msg("Failed to encode a step at iteration #%d", j);
            return NULL;
        }
    }

    ue_byte_stream_destroy(payload);
    return encoded_route;
}
