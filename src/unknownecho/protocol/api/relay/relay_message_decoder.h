#ifndef UNKNOWNECHO_RELAY_MESSAGE_DECODER_H
#define UNKNOWNECHO_RELAY_MESSAGE_DECODER_H

#include <unknownecho/protocol/api/relay/relay_received_message_struct.h>
#include <ueum/ueum.h>
#include <uecm/uecm.h>

ue_relay_received_message *ue_relay_message_decode(ueum_byte_stream *encoded_message,
    uecm_crypto_metadata *our_crypto_metadata);

#endif
