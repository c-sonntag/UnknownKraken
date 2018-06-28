#ifndef UNKNOWNECHO_RELAY_SERVER_H
#define UNKNOWNECHO_RELAY_SERVER_H

#include <unknownecho/protocol/api/relay/relay_server_struct.h>
#include <unknownecho/network/api/communication/communication_metadata.h>
#include <ueum/ueum.h>
#include <uecm/uecm.h>

ue_relay_server *ue_relay_server_create(ue_communication_metadata *communication_metadata, void *user_context,
    uecm_crypto_metadata *our_crypto_metadata, bool (*user_received_callback)(void *user_context, ueum_byte_stream *received_message));

void ue_relay_server_destroy(ue_relay_server *relay_server);

bool ue_relay_server_is_valid(ue_relay_server *relay_server);

bool ue_relay_server_start(ue_relay_server *relay_server);

bool ue_relay_server_stop(ue_relay_server *relay_server);

bool ue_relay_server_wait(ue_relay_server *relay_server);

ue_communication_context *ue_relay_server_get_communication_context(ue_relay_server *relay_server);

void *ue_relay_server_get_communication_server(ue_relay_server *relay_server);

void ue_relay_server_shutdown_signal_callback(int sig);

#endif
