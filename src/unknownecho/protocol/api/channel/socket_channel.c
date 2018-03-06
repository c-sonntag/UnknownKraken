#include <unknownecho/protocol/api/channel/socket_channel.h>
#include <unknownecho/system/alloc.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/logger.h>

ue_socket_channel *ue_socket_channel_create() {
    ue_socket_channel *channel;
    int i;

    ue_safe_alloc(channel, ue_socket_channel, 1);
    channel->max_connections_number = 10;
    ue_safe_alloc(channel->connections, ue_socket_client_connection *, channel->max_connections_number);
    for (i = 0; i < channel->max_connections_number; i++) {
        channel->connections[i] = NULL;
    }
    channel->connections_number = 0;;

    return channel;
}

void ue_socket_channel_destroy(ue_socket_channel *channel) {
    if (channel) {
        ue_safe_free(channel->connections);
        ue_safe_free(channel);
    }
}

bool ue_socket_channel_add_connection(ue_socket_channel *channel, ue_socket_client_connection *connection) {
    int i;

    if (!channel) {
        ue_stacktrace_push_msg("Specified channel is null");
        return false;
    }

    if (!connection) {
        ue_stacktrace_push_msg("Specified connection is null");
        return false;
    }

    if (!ue_socket_client_connection_is_established(connection)) {
        ue_stacktrace_push_msg("Specified connection isn't establish");
        return false;
    }

    if (channel->connections_number == channel->max_connections_number) {
        ue_stacktrace_push_msg("No such slot available");
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

bool ue_socket_channel_remove_connection_by_nickname(ue_socket_channel *channel, char *nickname) {
    int i;

    if (!channel) {
        ue_stacktrace_push_msg("Specified channel is null");
        return false;
    }

    if (!nickname) {
        ue_stacktrace_push_msg("Specified nickname is null");
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
            ue_safe_free(channel->connections[i]->optional_data);
            channel->connections[i]->optional_data = NULL;
            channel->connections[i] = NULL;
            channel->connections_number--;
            return true;
        }
    }

    ue_logger_trace("There's no client connection with this nickname in this channel");

    return true;
}

bool ue_socket_channels_remove_connection_by_nickname(ue_socket_channel **channels, int channels_number, char *nickname) {
    int i;

    if (!channels) {
        ue_stacktrace_push_msg("Specified channels is null");
        return false;
    }

    if (!nickname) {
        ue_stacktrace_push_msg("Specified nickname is null");
        return false;
    }

    for (i = 0; i < channels_number; i++) {
        if (!ue_socket_channel_remove_connection_by_nickname(channels[i], nickname)) {
            ue_logger_warn("Failed to remove connection by nickname in channel id %d", i);
        }
    }

    return true;
}

ue_socket_client_connection *ue_socket_channel_get_availabe_connection_for_channel_key(ue_socket_channel *channel, ue_socket_client_connection *unused_connection) {
    int i;

    for (i = 0; i < channel->max_connections_number; i++) {
        if (channel->connections[i] && channel->connections[i] != unused_connection) {
            return channel->connections[i];
        }
    }

    return NULL;
}
