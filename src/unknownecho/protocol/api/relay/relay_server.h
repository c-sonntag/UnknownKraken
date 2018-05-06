#ifndef UNKNOWNECHO_RELAY_SERVER_H
#define UNKNOWNECHO_RELAY_SERVER_H

#include <unknownecho/protocol/api/relay/relay_server_struct.h>
#include <unknownecho/network/api/communication/communication_metadata.h>
#include <unknownecho/bool.h>

ue_relay_server *ue_relay_server_create(ue_communication_metadata *communication_metadata,
    bool (*read_consumer)(void *connection),
    bool (*write_consumer)(void *connection));

void ue_relay_server_destroy(ue_relay_server *relay_server);

bool ue_relay_server_is_valid(ue_relay_server *relay_server);

bool ue_relay_server_start(ue_relay_server *relay_server);

bool ue_relay_server_stop(ue_relay_server *relay_server);

bool ue_relay_server_wait(ue_relay_server *relay_server);

ue_communication_context *ue_relay_server_get_communication_context(ue_relay_server *relay_server);

void *ue_relay_server_get_communication_server(ue_relay_server *relay_server);

#endif
