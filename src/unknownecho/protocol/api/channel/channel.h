#ifndef UNKNOWNECHO_CHANNEL_H
#define UNKNOWNECHO_CHANNEL_H

#include <unknownecho/bool.h>
#include <unknownecho/network/api/socket/socket_client_connection.h>

typedef struct {
    ue_socket_client_connection **connections;
    int connections_number, max_connections_number;
} ue_channel;

ue_channel *ue_channel_create();

void ue_channel_destroy(ue_channel *channel);

bool ue_channel_add_connection(ue_channel *channel, ue_socket_client_connection *connection);

bool ue_channel_remove_connection_by_nickname(ue_channel *channel, char *nickname);

bool ue_channels_remove_connection_by_nickname(ue_channel **channels, int channels_number, char *nickname);

ue_socket_client_connection *ue_channel_get_availabe_connection_for_channel_key(ue_channel *channel, ue_socket_client_connection *unused_connection);

#endif
