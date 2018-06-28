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

#include <unknownecho/network/api/socket/socket_client_connection.h>
#include <unknownecho/network/api/socket/socket.h>
#include <unknownecho/network/api/communication/communication_connection_state.h>
#include <ueum/ueum.h>
#include <ei/ei.h>

#include <string.h>

#if defined(__unix__)
    #include <arpa/inet.h>
#endif

static void *byte_stream_alloc_func(void *data) {
	return ueum_byte_stream_copy((ueum_byte_stream *)data);
}

static void byte_stream_free_func(void *data) {
	ueum_byte_stream_destroy((ueum_byte_stream *)data);
}

ue_socket_client_connection *ue_socket_client_connection_init() {
	ue_socket_client_connection *connection;

	ueum_safe_alloc(connection, ue_socket_client_connection, 1);
    connection->state = UNKNOWNECHO_COMMUNICATION_CONNECTION_FREE_STATE;
	connection->fd = -1;
	connection->nickname = NULL;
	connection->split_message = ueum_byte_vector_create_empty();
	connection->all_messages = ueum_byte_vector_create_empty();
	connection->tmp_message = ueum_byte_vector_create_empty();
	connection->current_message = ueum_byte_vector_create_empty();
	if ((connection->received_message = ueum_byte_stream_create()) == NULL) {
		ei_stacktrace_push_msg("Failed to init received message");
		goto clean_up;
	}
	if ((connection->message_to_send = ueum_byte_stream_create()) == NULL) {
		ei_stacktrace_push_msg("Failed to init message to send");
		goto clean_up;
	}
	connection->received_message_stream = ueum_byte_stream_create();
	connection->tmp_stream = ueum_byte_stream_create();
	connection->tls = NULL;
	connection->peer_certificate = NULL;
	connection->established = false;
	connection->optional_data = NULL;
	connection->received_messages = ueum_queue_create_mem(byte_stream_alloc_func, byte_stream_free_func);
	connection->messages_to_send = ueum_queue_create(byte_stream_alloc_func, byte_stream_free_func);
    connection->communication_metadata = ue_communication_metadata_create_empty();
    connection->connection_direction = UNKNOWNECHO_COMMUNICATION_CONNECTION_UNIDIRECTIONAL_BIDIRECTIONAL;

	return connection;

clean_up:
	ueum_safe_free(connection);
	return NULL;
}

void ue_socket_client_connection_destroy(ue_socket_client_connection *connection) {
	if (connection) {
		ue_socket_close(connection->fd);
		ueum_safe_free(connection->nickname);
		ueum_byte_vector_destroy(connection->all_messages);
		ueum_byte_vector_destroy(connection->current_message);
		ueum_byte_vector_destroy(connection->tmp_message);
		ueum_byte_vector_destroy(connection->split_message);
		ueum_byte_stream_destroy(connection->received_message);
		ueum_byte_stream_destroy(connection->message_to_send);
		if (connection->peer_certificate) {
			uecm_x509_certificate_destroy(connection->peer_certificate);
			connection->peer_certificate = NULL;
		}
		ueum_byte_stream_destroy(connection->received_message_stream);
		ueum_byte_stream_destroy(connection->tmp_stream);
		ueum_queue_destroy(connection->received_messages);
		ueum_queue_destroy(connection->messages_to_send);
        ue_communication_metadata_destroy(connection->communication_metadata);
		ueum_safe_free(connection);
	}
}

void ue_socket_client_connection_clean_up(ue_socket_client_connection *connection) {
    if (!connection) {
        ei_logger_warn("Specified connection ptr is null");
        return;
    }

    ue_socket_close(connection->fd);
    connection->fd = -1;
    ueum_safe_free(connection->nickname);
    ueum_byte_vector_clean_up(connection->all_messages);
    ueum_byte_vector_clean_up(connection->current_message);
    ueum_byte_vector_clean_up(connection->tmp_message);
    ueum_byte_stream_clean_up(connection->received_message);
    ueum_byte_stream_clean_up(connection->message_to_send);
    ueum_byte_vector_clean_up(connection->split_message);
    connection->state = UNKNOWNECHO_COMMUNICATION_CONNECTION_FREE_STATE;
    if (connection->peer_certificate) {
        uecm_x509_certificate_destroy(connection->peer_certificate);
        connection->peer_certificate = NULL;
    }
    ueum_byte_stream_clean_up(connection->received_message_stream);
    ueum_byte_stream_clean_up(connection->tmp_stream);
    connection->tls = NULL;
    connection->peer_certificate = NULL;
    connection->established = false;
    connection->optional_data = NULL;
    ueum_queue_clean_up(connection->received_messages);
    ueum_queue_clean_up(connection->messages_to_send);
    //ue_communication_metadata_clean_up(connection->communication_metadata);
}

bool ue_socket_client_connection_is_available(ue_socket_client_connection *connection) {
    return connection && connection->state == UNKNOWNECHO_COMMUNICATION_CONNECTION_FREE_STATE;
}

bool ue_socket_client_connection_establish(ue_socket_client_connection *connection, int ue_socket_fd) {
	ei_check_parameter_or_return(connection);

	connection->fd = ue_socket_fd;
    connection->state = UNKNOWNECHO_COMMUNICATION_CONNECTION_READ_STATE;
	connection->established = true;

	return true;
}

bool ue_socket_client_connection_is_established(ue_socket_client_connection *connection) {
    ei_check_parameter_or_return(connection);

	return connection->established;
}

void *ue_socket_client_connection_get_user_data(ue_socket_client_connection *connection) {
    ei_check_parameter_or_return(connection);

    return connection->optional_data;
}

bool ue_socket_client_connection_set_user_data(ue_socket_client_connection *connection, void *user_data) {
    ei_check_parameter_or_return(connection);

    connection->optional_data = user_data;
    return true;
}

char *ue_socket_client_connection_get_nickname(ue_socket_client_connection *connection) {
    ei_check_parameter_or_return(connection);

    return connection->nickname;
}

bool ue_socket_client_connection_set_nickname(ue_socket_client_connection *connection, char *nickname) {
    ei_check_parameter_or_return(connection);

    connection->nickname = nickname;

    return true;
}

ueum_byte_stream *ue_socket_client_connection_get_received_message(ue_socket_client_connection *connection) {
    ei_check_parameter_or_return(connection);

    return connection->received_message;
}

ueum_byte_stream *ue_socket_client_connection_get_message_to_send(ue_socket_client_connection *connection) {
    ei_check_parameter_or_return(connection);

    return connection->message_to_send;
}

ueum_queue *ue_socket_client_connection_get_received_messages(ue_socket_client_connection *connection) {
    ei_check_parameter_or_return(connection);

    return connection->received_messages;
}

ueum_queue *ue_socket_client_connection_get_messages_to_send(ue_socket_client_connection *connection) {
    ei_check_parameter_or_return(connection);

    return connection->messages_to_send;
}

ue_communication_connection_state ue_socket_client_connection_get_state(ue_socket_client_connection *connection) {
    ei_check_parameter_or_return(connection);

    return connection->state;
}

bool ue_socket_client_connection_set_state(ue_socket_client_connection *connection, ue_communication_connection_state state) {
    ei_check_parameter_or_return(connection);

    if (!connection->established) {
        ei_logger_warn("Cannot update the state of an unestablished connection");
        return false;
    }
    connection->state = state;
    return true;
}

bool ue_socket_client_connection_build_communication_metadata(ue_socket_client_connection *connection, struct sockaddr *sa) {
    void *sock_addr_in;
    int inet_addr_len, family, port;
    char *host;

    ei_check_parameter_or_return(connection);
    ei_check_parameter_or_return(sa);

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

    ueum_safe_alloc(host, char, inet_addr_len);

    if (!inet_ntop(family, sock_addr_in, host, inet_addr_len)) {
        ei_stacktrace_push_errno();
        ueum_safe_free(host);
        return false;
    }

    ue_communication_metadata_clean_up(connection->communication_metadata);
    ue_communication_metadata_set_type(connection->communication_metadata, UNKNOWNECHO_COMMUNICATION_TYPE_SOCKET);
    ue_communication_metadata_set_host(connection->communication_metadata, host);
    ueum_safe_free(host);
    ue_communication_metadata_set_port(connection->communication_metadata, port);
    ue_communication_metadata_set_destination_type(connection->communication_metadata, UNKNOWNECHO_RELAY_CLIENT);

    return true;
}

ue_communication_metadata *ue_socket_client_connection_get_communication_metadata(ue_socket_client_connection *connection) {
    ei_check_parameter_or_return(connection);

    return connection->communication_metadata;
}

ue_communication_connection_direction ue_socket_client_connection_get_direction(ue_socket_client_connection *connection) {
    return connection->connection_direction;
}

bool ue_socket_client_connection_set_direction(ue_socket_client_connection *connection, ue_communication_connection_direction
	connection_direction) {

    connection->connection_direction = connection_direction;
    return true;
}
