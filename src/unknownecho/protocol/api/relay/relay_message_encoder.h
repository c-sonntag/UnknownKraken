#ifndef UNKNOWNECHO_RELAY_MESSAGE_ENCODER_H
#define UNKNOWNECHO_RELAY_MESSAGE_ENCODER_H

#include <unknownecho/protocol/api/relay/relay_route_struct.h>
#include <unknownecho/protocol/api/relay/relay_message_id.h>
#include <unknownecho/protocol/api/relay/relay_plain_message_struct.h>
#include <unknownecho/byte/byte_stream_struct.h>

/**
 * @brief ue_relay_message_encode
 * @param route  the list of step to use that build the route. The route will be seal in the message
 * @param message_id
 * @param payload  optional message content
 * @return  encoded message
 */
ue_byte_stream *ue_relay_message_encode(ue_relay_route *route, ue_relay_message_id message_id, ue_byte_stream *payload);

ue_byte_stream *ue_relay_message_encode_relay(ue_relay_plain_message *plain_message);

#endif
