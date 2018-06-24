#ifndef UNKNOWNECHO_RELAY_SERVER_STRUCT_H
#define UNKNOWNECHO_RELAY_SERVER_STRUCT_H

#include <unknownecho/network/api/communication/communication_context.h>
#include <unknownecho/network/api/communication/communication_metadata.h>
#include <unknownecho/crypto/api/crypto_metadata.h>
#include <unknownecho/protocol/api/relay/relay_client_struct.h>
#include <unknownecho/bool.h>

#include <uv.h>

typedef struct {
    ue_communication_metadata *our_communication_metadata;
    ue_communication_context *communication_context;
    void *communication_server;
    uv_thread_t server_thread;
    ue_crypto_metadata *our_crypto_metadata;
    void *user_context;
    bool (*user_received_callback)(void *user_context, ue_byte_stream *received_message);
    bool signal_caught;
    ue_relay_client **relay_clients;
    int relay_clients_number;
} ue_relay_server;

#endif
