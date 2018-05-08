#include <unknownecho/protocol/api/relay/relay_plain_message.h>
#include <unknownecho/protocol/api/relay/relay_step.h>
#include <unknownecho/byte/byte_stream.h>
#include <unknownecho/alloc.h>

ue_relay_plain_message *ue_relay_plain_message_create_empty() {
    ue_relay_plain_message *plain_message;

    ue_safe_alloc(plain_message, ue_relay_plain_message, 1);
    plain_message->next_step = NULL;
    plain_message->payload = NULL;
    plain_message->remaining_encoded_route = NULL;
    plain_message->unsealed_payload = false;

    return plain_message;
}

void ue_relay_plain_message_destroy(ue_relay_plain_message *plain_message) {
    if (plain_message) {
        ue_relay_step_destroy(plain_message->next_step);
        ue_byte_stream_destroy(plain_message->payload);
        ue_byte_stream_destroy(plain_message->remaining_encoded_route);
        ue_safe_free(plain_message);
    }
}
