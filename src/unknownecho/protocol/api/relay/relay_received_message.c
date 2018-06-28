#include <unknownecho/protocol/api/relay/relay_received_message.h>
#include <unknownecho/protocol/api/relay/relay_step.h>
#include <ueum/ueum.h>

ue_relay_received_message *ue_relay_received_message_create_empty() {
    ue_relay_received_message *received_message;

    ueum_safe_alloc(received_message, ue_relay_received_message, 1);
    received_message->next_step = NULL;
    received_message->payload = NULL;
    received_message->remaining_encoded_route = NULL;
    received_message->remaining_encoded_back_route = NULL;
    received_message->unsealed_payload = false;

    return received_message;
}

void ue_relay_received_message_destroy(ue_relay_received_message *received_message) {
    if (received_message) {
        ue_relay_step_destroy(received_message->next_step);
        ueum_byte_stream_destroy(received_message->payload);
        ueum_byte_stream_destroy(received_message->remaining_encoded_route);
        ueum_byte_stream_destroy(received_message->remaining_encoded_back_route);
        ueum_safe_free(received_message);
    }
}
