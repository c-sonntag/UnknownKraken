#ifndef UNKNOWNECHO_RELAY_CLIENT_STRUCT_H
#define UNKNOWNECHO_RELAY_CLIENT_STRUCT_H

#include <unknownecho/protocol/api/relay/relay_route_struct.h>
#include <unknownecho/network/api/communication/communication_context.h>
#include <unknownecho/network/api/communication/communication_metadata.h>
#include <ueum/ueum.h>
#include <uecm/uecm.h>

typedef struct {
    ue_communication_metadata *our_communication_metadata;
    ue_communication_context *communication_context;
    void *read_connection, *write_connection;
    ue_relay_route *route, *back_route;
    ueum_byte_stream *encoded_route, *encoded_back_route;
    uecm_crypto_metadata *our_crypto_metadata;
} ue_relay_client;

#endif
