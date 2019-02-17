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

#include <uk/unknownecho/protocol/api/channel/channel.h>
#include <uk/utils/ueum.h>
#include <uk/utils/ei.h>

uk_ue_channel *uk_ue_channel_create() {
    uk_ue_channel *channel;
    int i;

    channel = NULL;

    uk_utils_safe_alloc(channel, uk_ue_channel, 1);
    channel->max_connections_number = 10;
    uk_utils_safe_alloc(channel->connections, uk_ue_socket_client_connection *, channel->max_connections_number);
    for (i = 0; i < channel->max_connections_number; i++) {
        channel->connections[i] = NULL;
    }
    channel->connections_number = 0;

    return channel;
}

void uk_ue_channel_destroy(uk_ue_channel *channel) {
    if (channel) {
        uk_utils_safe_free(channel->connections);
        uk_utils_safe_free(channel);
    }
}

bool uk_ue_channel_add_connection(uk_ue_channel *channel, uk_ue_socket_client_connection *connection) {
    int i;

    if (!channel) {
        uk_utils_stacktrace_push_msg("Specified channel is null");
        return false;
    }

    if (!connection) {
        uk_utils_stacktrace_push_msg("Specified connection is null");
        return false;
    }

    if (!uk_ue_socket_client_connection_is_established(connection)) {
        uk_utils_stacktrace_push_msg("Specified connection isn't establish");
        return false;
    }

    if (channel->connections_number == channel->max_connections_number) {
        uk_utils_stacktrace_push_msg("No such slot available");
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

bool uk_ue_channel_remove_connection_by_nickname(uk_ue_channel *channel, char *nickname) {
    int i;

    if (!channel) {
        uk_utils_stacktrace_push_msg("Specified channel is null");
        return false;
    }

    if (!nickname) {
        uk_utils_stacktrace_push_msg("Specified nickname is null");
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
            uk_utils_safe_free(channel->connections[i]->optional_data);
            channel->connections[i]->optional_data = NULL;
            channel->connections[i] = NULL;
            channel->connections_number--;
            return true;
        }
    }

    uk_utils_logger_trace("There's no client connection with this nickname in this channel");

    return true;
}

bool uk_ue_channels_remove_connection_by_nickname(uk_ue_channel **channels, int channels_number, char *nickname) {
    int i;

    if (!channels) {
        uk_utils_stacktrace_push_msg("Specified channels is null");
        return false;
    }

    if (!nickname) {
        uk_utils_stacktrace_push_msg("Specified nickname is null");
        return false;
    }

    for (i = 0; i < channels_number; i++) {
        if (!uk_ue_channel_remove_connection_by_nickname(channels[i], nickname)) {
            uk_utils_logger_warn("Failed to remove connection by nickname in channel id %d", i);
        }
    }

    return true;
}

uk_ue_socket_client_connection *uk_ue_channel_get_availabe_connection_for_channel_key(uk_ue_channel *channel, uk_ue_socket_client_connection *unused_connection) {
    int i;

    for (i = 0; i < channel->max_connections_number; i++) {
        if (channel->connections[i] && channel->connections[i] != unused_connection) {
            return channel->connections[i];
        }
    }

    return NULL;
}
