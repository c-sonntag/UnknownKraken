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

#include <uk/unknownecho/network/api/socket/socket_client_connection.h>
#include <uk/unknownecho/network/api/socket/socket.h>
#include <uk/unknownecho/network/api/communication/communication_connection_state.h>
#include <uk/utils/ueum.h>
#include <uk/utils/ei.h>

#include <string.h>

#if defined(__unix__)
    #include <arpa/inet.h>
#endif


static void *byte_stream_alloc_func(void *data) {
    return uk_utils_byte_stream_copy((uk_utils_byte_stream *)data);
}

static void byte_stream_free_func(void *data) {
    uk_utils_byte_stream_destroy((uk_utils_byte_stream *)data);
}

uk_ue_socket_client_connection *uk_ue_socket_client_connection_init() {
    uk_ue_socket_client_connection *connection;

    connection = NULL;

    uk_utils_safe_alloc(connection, uk_ue_socket_client_connection, 1);
    connection->state = UnknownKrakenUnknownEcho_COMMUNICATION_CONNECTION_FREE_STATE;
    connection->fd = -1;
    connection->nickname = NULL;
    connection->split_message = uk_utils_byte_vector_create_empty();
    connection->all_messages = uk_utils_byte_vector_create_empty();
    connection->tmp_message = uk_utils_byte_vector_create_empty();
    connection->current_message = uk_utils_byte_vector_create_empty();
    if ((connection->received_message = uk_utils_byte_stream_create()) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to init received message");
        goto clean_up;
    }
    if ((connection->message_to_send = uk_utils_byte_stream_create()) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to init message to send");
        goto clean_up;
    }
    connection->received_message_stream = uk_utils_byte_stream_create();
    connection->tmp_stream = uk_utils_byte_stream_create();
    connection->tls = NULL;
    connection->peer_certificate = NULL;
    connection->established = false;
    connection->optional_data = NULL;
    connection->received_messages = uk_utils_queuk_ue_create_mem(byte_stream_alloc_func, byte_stream_free_func);
    connection->messages_to_send = uk_utils_queuk_ue_create(byte_stream_alloc_func, byte_stream_free_func);
    connection->communication_metadata = uk_ue_communication_metadata_create_empty();
    connection->connection_direction = UnknownKrakenUnknownEcho_COMMUNICATION_CONNECTION_UNIDIRECTIONAL_BIDIRECTIONAL;

    return connection;

clean_up:
    uk_utils_safe_free(connection);
    return NULL;
}

void uk_ue_socket_client_connection_destroy(uk_ue_socket_client_connection *connection) {
    if (connection) {
        uk_ue_socket_close(connection->fd);
        uk_utils_safe_free(connection->nickname);
        uk_utils_byte_vector_destroy(connection->all_messages);
        uk_utils_byte_vector_destroy(connection->current_message);
        uk_utils_byte_vector_destroy(connection->tmp_message);
        uk_utils_byte_vector_destroy(connection->split_message);
        uk_utils_byte_stream_destroy(connection->received_message);
        uk_utils_byte_stream_destroy(connection->message_to_send);
        if (connection->peer_certificate) {
            uk_crypto_x509_certificate_destroy(connection->peer_certificate);
            connection->peer_certificate = NULL;
        }
        uk_utils_byte_stream_destroy(connection->received_message_stream);
        uk_utils_byte_stream_destroy(connection->tmp_stream);
        uk_utils_queuk_ue_destroy(connection->received_messages);
        uk_utils_queuk_ue_destroy(connection->messages_to_send);
        uk_ue_communication_metadata_destroy(connection->communication_metadata);
        uk_utils_safe_free(connection);
    }
}

void uk_ue_socket_client_connection_clean_up(uk_ue_socket_client_connection *connection) {
    if (!connection) {
        uk_utils_logger_warn("Specified connection ptr is null");
        return;
    }

    uk_ue_socket_close(connection->fd);
    connection->fd = -1;
    uk_utils_safe_free(connection->nickname);
    uk_utils_byte_vector_clean_up(connection->all_messages);
    uk_utils_byte_vector_clean_up(connection->current_message);
    uk_utils_byte_vector_clean_up(connection->tmp_message);
    uk_utils_byte_stream_clean_up(connection->received_message);
    uk_utils_byte_stream_clean_up(connection->message_to_send);
    uk_utils_byte_vector_clean_up(connection->split_message);
    connection->state = UnknownKrakenUnknownEcho_COMMUNICATION_CONNECTION_FREE_STATE;
    if (connection->peer_certificate) {
        uk_crypto_x509_certificate_destroy(connection->peer_certificate);
        connection->peer_certificate = NULL;
    }
    uk_utils_byte_stream_clean_up(connection->received_message_stream);
    uk_utils_byte_stream_clean_up(connection->tmp_stream);
    connection->tls = NULL;
    connection->peer_certificate = NULL;
    connection->established = false;
    connection->optional_data = NULL;
    uk_utils_queuk_ue_clean_up(connection->received_messages);
    uk_utils_queuk_ue_clean_up(connection->messages_to_send);
    //uk_ue_communication_metadata_clean_up(connection->communication_metadata);
}

bool uk_ue_socket_client_connection_is_available(uk_ue_socket_client_connection *connection) {
    return connection && connection->state == UnknownKrakenUnknownEcho_COMMUNICATION_CONNECTION_FREE_STATE;
}

bool uk_ue_socket_client_connection_establish(uk_ue_socket_client_connection *connection, int uk_ue_socket_fd) {
    uk_utils_check_parameter_or_return(connection);

    connection->fd = uk_ue_socket_fd;
    connection->state = UnknownKrakenUnknownEcho_COMMUNICATION_CONNECTION_READ_STATE;
    connection->established = true;

    return true;
}

bool uk_ue_socket_client_connection_is_established(uk_ue_socket_client_connection *connection) {
    uk_utils_check_parameter_or_return(connection);

    return connection->established;
}

void *uk_ue_socket_client_connection_get_user_data(uk_ue_socket_client_connection *connection) {
    uk_utils_check_parameter_or_return(connection);

    return connection->optional_data;
}

bool uk_ue_socket_client_connection_set_user_data(uk_ue_socket_client_connection *connection, void *user_data) {
    uk_utils_check_parameter_or_return(connection);

    connection->optional_data = user_data;
    return true;
}

char *uk_ue_socket_client_connection_get_nickname(uk_ue_socket_client_connection *connection) {
    uk_utils_check_parameter_or_return(connection);

    return connection->nickname;
}

bool uk_ue_socket_client_connection_set_nickname(uk_ue_socket_client_connection *connection, char *nickname) {
    uk_utils_check_parameter_or_return(connection);

    connection->nickname = nickname;

    return true;
}

uk_utils_byte_stream *uk_ue_socket_client_connection_get_received_message(uk_ue_socket_client_connection *connection) {
    uk_utils_check_parameter_or_return(connection);

    return connection->received_message;
}

uk_utils_byte_stream *uk_ue_socket_client_connection_get_message_to_send(uk_ue_socket_client_connection *connection) {
    uk_utils_check_parameter_or_return(connection);

    return connection->message_to_send;
}

uk_utils_queue *uk_ue_socket_client_connection_get_received_messages(uk_ue_socket_client_connection *connection) {
    uk_utils_check_parameter_or_return(connection);

    return connection->received_messages;
}

uk_utils_queue *uk_ue_socket_client_connection_get_messages_to_send(uk_ue_socket_client_connection *connection) {
    uk_utils_check_parameter_or_return(connection);

    return connection->messages_to_send;
}

uk_ue_communication_connection_state uk_ue_socket_client_connection_get_state(uk_ue_socket_client_connection *connection) {
    uk_utils_check_parameter_or_return(connection);

    return connection->state;
}

bool uk_ue_socket_client_connection_set_state(uk_ue_socket_client_connection *connection, uk_ue_communication_connection_state state) {
    uk_utils_check_parameter_or_return(connection);

    if (!connection->established) {
        uk_utils_logger_warn("Cannot update the state of an unestablished connection");
        return false;
    }
    connection->state = state;
    return true;
}

bool uk_ue_socket_client_connection_build_communication_metadata(uk_ue_socket_client_connection *connection, struct sockaddr *sa) {
    void *sock_addr_in;
    int inet_addr_len, family, port;
    char *host;

    uk_utils_check_parameter_or_return(connection);
    uk_utils_check_parameter_or_return(sa);

    host = NULL;

    if (sa->sa_family == AF_INET) {
        sock_addr_in = &(((struct sockaddr_in *)sa)->sin_addr);
        inet_addr_len = INET_ADDRSTRLEN;
        family = AF_INET;
        port = ((struct sockaddr_in *)sa)->sin_port;
    } else {
        sock_addr_in = &(((struct sockaddr_in6 *)sa)->sin6_addr);
        inet_addr_len = INET6_ADDRSTRLEN;
        family = AF_INET6;
        port = ((struct sockaddr_in6 *)sa)->sin6_port;
    }

    uk_utils_safe_alloc(host, char, inet_addr_len);

    if (!inet_ntop(family, sock_addr_in, host, inet_addr_len)) {
        uk_utils_stacktrace_push_errno();
        uk_utils_safe_free(host);
        return false;
    }

    uk_ue_communication_metadata_clean_up(connection->communication_metadata);
    uk_ue_communication_metadata_set_type(connection->communication_metadata, UnknownKrakenUnknownEcho_COMMUNICATION_TYPE_SOCKET);
    uk_ue_communication_metadata_set_host(connection->communication_metadata, host);
    uk_utils_safe_free(host);
    uk_ue_communication_metadata_set_port(connection->communication_metadata, port);
    uk_ue_communication_metadata_set_destination_type(connection->communication_metadata, UnknownKrakenUnknownEcho_RELAY_CLIENT);

    return true;
}

uk_ue_communication_metadata *uk_ue_socket_client_connection_get_communication_metadata(uk_ue_socket_client_connection *connection) {
    uk_utils_check_parameter_or_return(connection);

    return connection->communication_metadata;
}

uk_ue_communication_connection_direction uk_ue_socket_client_connection_get_direction(uk_ue_socket_client_connection *connection) {
    return connection->connection_direction;
}

bool uk_ue_socket_client_connection_set_direction(uk_ue_socket_client_connection *connection, uk_ue_communication_connection_direction
    connection_direction) {

    connection->connection_direction = connection_direction;
    return true;
}
