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

#include <unknownecho/protocol/api/channel/channel.h>
#include <ueum/ueum.h>
#include <ei/ei.h>

ue_channel *ue_channel_create() {
    ue_channel *channel;
    int i;

    channel = NULL;

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