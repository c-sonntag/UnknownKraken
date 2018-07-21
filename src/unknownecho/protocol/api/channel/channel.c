/*******************************************************************************
 * Copyright (C) 2018 by Charly Lamothe                                        *
 *                                                                             *
 * This file is part of LibUnknownEcho.                                        *
 *                                                                             *
 *   LibUnknownEcho is free software: you can redistribute it and/or modify    *
 *   it under the terms of the GNU General Public License as published by      *
 *   the Free Software Foundation, either version 3 of the License, or         *
 *   (at your option) any later version.                                       *
 *                                                                             *
 *   LibUnknownEcho is distributed in the hope that it will be useful,         *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of            *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the             *
 *   GNU General Public License for more details.                              *
 *                                                                             *
 *   You should have received a copy of the GNU General Public License         *
 *   along with LibUnknownEcho.  If not, see <http://www.gnu.org/licenses/>.   *
 *******************************************************************************/

#include <unknownecho/protocol/api/channel/channel.h>
#include <ueum/ueum.h>
#include <ei/ei.h>

ue_channel *ue_channel_create() {
    ue_channel *channel;
    int i;

    ueum_safe_alloc(channel, ue_channel, 1);
    channel->max_connections_number = 10;
    ueum_safe_alloc(channel->connections, ue_socket_client_connection *, channel->max_connections_number);
    for (i = 0; i < channel->max_connections_number; i++) {
        channel->connections[i] = NULL;
    }
    channel->connections_number = 0;

    return channel;
}

void ue_channel_destroy(ue_channel *channel) {
    if (channel) {
        ueum_safe_free(channel->connections);
        ueum_safe_free(channel);
    }
}

bool ue_channel_add_connection(ue_channel *channel, ue_socket_client_connection *connection) {
    int i;

    if (!channel) {
        ei_stacktrace_push_msg("Specified channel is null");
        return false;
    }

    if (!connection) {
        ei_stacktrace_push_msg("Specified connection is null");
        return false;
    }

    if (!ue_socket_client_connection_is_established(connection)) {
        ei_stacktrace_push_msg("Specified connection isn't establish");
        return false;
    }

    if (channel->connections_number == channel->max_connections_number) {
        ei_stacktrace_push_msg("No such slot available");
        return false;
    }

    for (i = 0; i < channel->max_connections_number; i++) {
        if (channel->connections[i] == NULL) {
            channel->connections[i] = connection;
            channel->connections_number++;
            return true;
        }
    }

    return false;
}

bool ue_channel_remove_connection_by_nickname(ue_channel *channel, char *nickname) {
    int i;

    if (!channel) {
        ei_stacktrace_push_msg("Specified channel is null");
        return false;
    }

    if (!nickname) {
        ei_stacktrace_push_msg("Specified nickname is null");
        return false;
    }

    if (!channel->connections) {
        return true;
    }

    if (channel->connections_number == 0) {
        return true;
    }

    for (i = 0; i < channel->max_connections_number; i++) {
        if (channel->connections[i] && strcmp(channel->connections[i]->nickname, nickname) == 0) {
            ueum_safe_free(channel->connections[i]->optional_data);
            channel->connections[i]->optional_data = NULL;
            channel->connections[i] = NULL;
            channel->connections_number--;
            return true;
        }
    }

    ei_logger_trace("There's no client connection with this nickname in this channel");

    return true;
}

bool ue_channels_remove_connection_by_nickname(ue_channel **channels, int channels_number, char *nickname) {
    int i;

    if (!channels) {
        ei_stacktrace_push_msg("Specified channels is null");
        return false;
    }

    if (!nickname) {
        ei_stacktrace_push_msg("Specified nickname is null");
        return false;
    }

    for (i = 0; i < channels_number; i++) {
        if (!ue_channel_remove_connection_by_nickname(channels[i], nickname)) {
            ei_logger_warn("Failed to remove connection by nickname in channel id %d", i);
        }
    }

    return true;
}

ue_socket_client_connection *ue_channel_get_availabe_connection_for_channel_key(ue_channel *channel, ue_socket_client_connection *unused_connection) {
    int i;

    for (i = 0; i < channel->max_connections_number; i++) {
        if (channel->connections[i] && channel->connections[i] != unused_connection) {
            return channel->connections[i];
        }
    }

    return NULL;
}
