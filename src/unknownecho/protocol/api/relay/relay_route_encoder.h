#ifndef UNKNOWNECHO_RELAY_ROUTE_ENCODER_H
#define UNKNOWNECHO_RELAY_ROUTE_ENCODER_H

#include <unknownecho/protocol/api/relay/relay_route_struct.h>
#include <unknownecho/byte/byte_stream_struct.h>

ue_byte_stream *ue_relay_route_encode(ue_relay_route *route);

#endif
