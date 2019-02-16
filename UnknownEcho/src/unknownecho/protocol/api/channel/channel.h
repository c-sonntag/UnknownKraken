/*******************************************************************************
 * Copyright (C) 2018 Charly Lamothe                                           *
 *                                                                             *
 * This file is part of LibUnknownEcho.                                        *
 *                                                                             *
 *   Licensed under the Apache License, Version 2.0 (the "License");           *
 *   you may not use this file except in compliance with the License.          *
 *   You may obtain a copy of the License at                                   *
 *                                                                             *
 *   http://www.apache.org/licenses/LICENSE-2.0                                *
 *                                                                             *
 *   Unless required by applicable law or agreed to in writing, software       *
 *   distributed under the License is distributed on an "AS IS" BASIS,         *
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  *
 *   See the License for the specific language governing permissions and       *
 *   limitations under the License.                                            *
 *******************************************************************************/

#ifndef UNKNOWNECHO_CHANNEL_H
#define UNKNOWNECHO_CHANNEL_H

#include <unknownecho/network/api/socket/socket_client_connection.h>
#include <ueum/ueum.h>

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
