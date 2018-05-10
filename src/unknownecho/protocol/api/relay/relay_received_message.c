#include <unknownecho/protocol/api/relay/relay_received_message.h>
#include <unknownecho/protocol/api/relay/relay_step.h>
#include <unknownecho/byte/byte_stream.h>
#include <unknownecho/alloc.h>

ue_relay_received_message *ue_relay_received_message_create_empty() {
    ue_relay_received_message *received_message;

    ue_safe_alloc(received_message, ue_relay_received_message, 1);
    received_message->next_step = NULL;
    received_message->payload = NULL;
    received_message->remaining_encoded_route = NULL;
    received_message->unsealed_payload = false;

    return received_message;
}

void ue_relay_received_message_destroy(ue_relay_received_message *received_message) {
    if (received_message) {
        ue_relay_step_destroy(received_message->next_step);
        ue_byte_stream_destroy(received_message->payload);
        ue_byte_stream_destroy(received_message->remaining_encoded_route);
        ue_safe_free(received_message);
    }
}
