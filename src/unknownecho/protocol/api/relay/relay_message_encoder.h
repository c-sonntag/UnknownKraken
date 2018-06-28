#ifndef UNKNOWNECHO_RELAY_MESSAGE_ENCODER_H
#define UNKNOWNECHO_RELAY_MESSAGE_ENCODER_H

#include <unknownecho/protocol/api/relay/relay_route_struct.h>
#include <unknownecho/protocol/api/relay/relay_message_id.h>
#include <unknownecho/protocol/api/relay/relay_received_message_struct.h>
#include <ueum/ueum.h>

ueum_byte_stream *ue_relay_message_encode(ue_relay_route *route, ue_relay_route *back_route,
    ue_relay_message_id message_id, ueum_byte_stream *payload);

ueum_byte_stream *ue_relay_message_encode_from_encoded_route(ueum_byte_stream *encoded_route,
    ueum_byte_stream *encoded_back_route, ue_relay_message_id message_id, ueum_byte_stream *payload,
    ue_relay_step *payload_receiver);

ueum_byte_stream *ue_relay_message_encode_relay(ue_relay_received_message *received_message);

#endif
