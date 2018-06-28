#ifndef UNKNOWNECHO_RELAY_ROUTE_DECODER_H
#define UNKNOWNECHO_RELAY_ROUTE_DECODER_H

#include <unknownecho/protocol/api/relay/relay_step_struct.h>
#include <ueum/ueum.h>
#include <uecm/uecm.h>

ue_relay_step *ue_relay_route_decode_pop_step(ueum_byte_stream *encoded_route, uecm_crypto_metadata *our_crypto_metadata);

#endif
