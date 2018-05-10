#ifndef UNKNOWNECHO_RELAY_MESSAGE_DECODER_H
#define UNKNOWNECHO_RELAY_MESSAGE_DECODER_H

#include <unknownecho/protocol/api/relay/relay_received_message_struct.h>
#include <unknownecho/byte/byte_stream_struct.h>
#include <unknownecho/crypto/api/crypto_metadata.h>

ue_relay_received_message *ue_relay_message_decode(ue_byte_stream *encoded_message, ue_crypto_metadata *our_crypto_metadata);

#endif
