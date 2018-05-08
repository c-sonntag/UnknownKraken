#ifndef UNKNOWNECHO_RELAY_CLIENT_H
#define UNKNOWNECHO_RELAY_CLIENT_H

#include <unknownecho/protocol/api/relay/relay_client_struct.h>
#include <unknownecho/protocol/api/relay/relay_route_struct.h>
#include <unknownecho/network/api/communication/communication_context.h>
#include <unknownecho/byte/byte_stream_struct.h>
#include <unknownecho/bool.h>

ue_relay_client *ue_relay_client_create(ue_relay_route *route);

void ue_relay_client_destroy(ue_relay_client *client);

bool ue_relay_client_is_valid(ue_relay_client *client);

ue_communication_context *ue_relay_client_get_communication_context(ue_relay_client *client);

void *ue_relay_client_get_connection(ue_relay_client *client);

bool ue_relay_client_send_message(ue_relay_client *client, ue_byte_stream *message);

#endif
