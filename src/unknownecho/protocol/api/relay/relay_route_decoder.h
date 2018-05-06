#ifndef UNKNOWNECHO_RELAY_ROUTE_DECODER_H
#define UNKNOWNECHO_RELAY_ROUTE_DECODER_H

#include <unknownecho/protocol/api/relay/relay_step_struct.h>
#include <unknownecho/crypto/api/crypto_metadata.h>
#include <unknownecho/byte/byte_stream_struct.h>

ue_relay_step *ue_relay_route_decode_pop_step(ue_byte_stream *encoded_route, ue_crypto_metadata *our_crypto_metadata);

#endif
