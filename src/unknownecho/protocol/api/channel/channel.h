/*******************************************************************************
 * Copyright (C) 2018 by Charly Lamothe                                        *
 *                                                                             *
 * This file is part of UnknownEchoLib.                                        *
 *                                                                             *
 *   UnknownEchoLib is free software: you can redistribute it and/or modify    *
 *   it under the terms of the GNU General Public License as published by      *
 *   the Free Software Foundation, either version 3 of the License, or         *
 *   (at your option) any later version.                                       *
 *                                                                             *
 *   UnknownEchoLib is distributed in the hope that it will be useful,         *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of            *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the             *
 *   GNU General Public License for more details.                              *
 *                                                                             *
 *   You should have received a copy of the GNU General Public License         *
 *   along with UnknownEchoLib.  If not, see <http://www.gnu.org/licenses/>.   *
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
