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

#ifndef UnknownKrakenUnknownEcho_CHANNEL_H
#define UnknownKrakenUnknownEcho_CHANNEL_H

#include <uk/unknownecho/network/api/socket/socket_client_connection.h>
#include <uk/utils/ueum.h>

typedef struct {
    uk_ue_socket_client_connection **connections;
    int connections_number, max_connections_number;
} uk_ue_channel;

uk_ue_channel *uk_ue_channel_create();

void uk_ue_channel_destroy(uk_ue_channel *channel);

bool uk_ue_channel_add_connection(uk_ue_channel *channel, uk_ue_socket_client_connection *connection);

bool uk_ue_channel_remove_connection_by_nickname(uk_ue_channel *channel, char *nickname);

bool uk_ue_channels_remove_connection_by_nickname(uk_ue_channel **channels, int channels_number, char *nickname);

uk_ue_socket_client_connection *uk_ue_channel_get_availabe_connection_for_channel_key(uk_ue_channel *channel, uk_ue_socket_client_connection *unused_connection);

#endif
