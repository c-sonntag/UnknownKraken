#ifndef UNKNOWNECHO_RELAY_RECEIVED_MESSAGE_STRUCT_H
#define UNKNOWNECHO_RELAY_RECEIVED_MESSAGE_STRUCT_H

#include <unknownecho/protocol/api/relay/relay_step_struct.h>
#include <unknownecho/protocol/api/relay/relay_message_id.h>
#include <unknownecho/protocol/api/protocol_id.h>
#include <unknownecho/byte/byte_stream_struct.h>
#include <unknownecho/bool.h>

typedef struct {
    ue_byte_stream *payload;
    ue_relay_step *next_step;
    ue_protocol_id protocol_id;
    ue_relay_message_id message_id;
    ue_byte_stream *remaining_encoded_route, *remaining_encoded_back_route;
    bool unsealed_payload;
} ue_relay_received_message;

#endif
