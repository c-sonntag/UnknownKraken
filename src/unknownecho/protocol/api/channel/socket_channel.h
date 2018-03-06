#ifndef UNKNOWNECHO_SOCKET_CHANNEL_H
#define UNKNOWNECHO_SOCKET_CHANNEL_H

#include <unknownecho/bool.h>
#include <unknownecho/network/api/socket/socket_client_connection.h>

typedef struct {
    ue_socket_client_connection **connections;
    int connections_number, max_connections_number;
} ue_socket_channel;

ue_socket_channel *ue_socket_channel_create();

void ue_socket_channel_destroy(ue_socket_channel *channel);

bool ue_socket_channel_add_connection(ue_socket_channel *channel, ue_socket_client_connection *connection);

bool ue_socket_channel_remove_connection_by_nickname(ue_socket_channel *channel, char *nickname);

bool ue_socket_channels_remove_connection_by_nickname(ue_socket_channel **channels, int channels_number, char *nickname);

ue_socket_client_connection *ue_socket_channel_get_availabe_connection_for_channel_key(ue_socket_channel *channel, ue_socket_client_connection *unused_connection);

#endif
