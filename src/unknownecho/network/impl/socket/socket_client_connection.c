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
#include <unknownecho/system/alloc.h>
#include <unknownecho/errorHandling/check_parameter.h>
#include <unknownecho/string/string_utility.h>

ue_socket_client_connection *ue_socket_client_connection_init() {
	ue_socket_client_connection *connection;

	ue_safe_alloc(connection, ue_socket_client_connection, 1);
	connection->state = UNKNOWNECHO_CONNECTION_FREE_STATE;
	connection->fd = -1;
	connection->nickname = NULL;
	connection->split_message = ue_byte_vector_create_empty();
	connection->all_messages = ue_byte_vector_create_empty();
	connection->tmp_message = ue_byte_vector_create_empty();
	connection->current_message = ue_byte_vector_create_empty();
	if ((connection->received_message = ue_byte_stream_create()) == NULL) {
		ue_stacktrace_push_msg("Failed to init received message");
		goto clean_up;
	}
	if ((connection->message_to_send = ue_byte_stream_create()) == NULL) {
		ue_stacktrace_push_msg("Failed to init message to send");
		goto clean_up;
	}
	connection->received_message_stream = ue_byte_stream_create();
	connection->tmp_stream = ue_byte_stream_create();
	connection->tls = NULL;
	connection->peer_certificate = NULL;
	connection->established = false;
	connection->optional_data = NULL;
	ue_safe_alloc(connection->message_header, ue_byte_vector_element, 1);
	connection->message_header->data = NULL;
	connection->message_header->size = 0;
	ue_safe_alloc(connection->message_content, ue_byte_vector_element, 1);
	connection->message_content->data = NULL;
	connection->message_content->size = 0;

	return connection;

clean_up:
	ue_safe_free(connection);
	return NULL;
}

void ue_socket_client_connection_destroy(ue_socket_client_connection *connection) {
	if (connection) {
		ue_socket_close(connection->fd);
		ue_safe_free(connection->nickname);
		ue_byte_vector_destroy(connection->all_messages);
		ue_byte_vector_destroy(connection->current_message);
		ue_byte_vector_destroy(connection->tmp_message);
		ue_byte_vector_destroy(connection->split_message);
		ue_byte_stream_destroy(connection->received_message);
		ue_byte_stream_destroy(connection->message_to_send);
		if (connection->peer_certificate) {
			ue_x509_certificate_destroy(connection->peer_certificate);
			connection->peer_certificate = NULL;
		}
		ue_byte_stream_destroy(connection->received_message_stream);
		ue_byte_stream_destroy(connection->tmp_stream);
		if (connection->message_header) {
			ue_safe_free(connection->message_header->data);
			ue_safe_free(connection->message_header);
		}
		if (connection->message_content) {
			ue_safe_free(connection->message_content->data);
			ue_safe_free(connection->message_content);
		}
		ue_safe_free(connection);
	}
}

void ue_socket_client_connection_clean_up(ue_socket_client_connection *connection) {
	if (connection) {
		ue_socket_close(connection->fd);
		connection->fd = -1;
		ue_safe_free(connection->nickname);
		ue_byte_vector_clean_up(connection->all_messages);
		ue_byte_vector_clean_up(connection->current_message);
		ue_byte_vector_clean_up(connection->tmp_message);
		ue_byte_stream_clean_up(connection->received_message);
		ue_byte_stream_clean_up(connection->message_to_send);
		ue_byte_vector_clean_up(connection->split_message);
		connection->state = UNKNOWNECHO_CONNECTION_FREE_STATE;
		if (connection->peer_certificate) {
			ue_x509_certificate_destroy(connection->peer_certificate);
			connection->peer_certificate = NULL;
		}
		ue_byte_stream_clean_up(connection->received_message_stream);
		ue_byte_stream_clean_up(connection->tmp_stream);
		if (connection->message_header) {
			ue_safe_free(connection->message_header->data);
			connection->message_header->size = 0;
		}
		if (connection->message_content) {
			ue_safe_free(connection->message_content->data);
			connection->message_content->size = 0;
		}
		connection->tls = NULL;
		connection->peer_certificate = NULL;
		connection->established = false;
		connection->optional_data = NULL;
	}
}

bool ue_socket_client_connection_is_available(ue_socket_client_connection *connection) {
	return connection && connection->state == UNKNOWNECHO_CONNECTION_FREE_STATE;
}

bool ue_socket_client_connection_establish(ue_socket_client_connection *connection, int ue_socket_fd) {
	ue_check_parameter_or_return(connection);

	connection->fd = ue_socket_fd;
	connection->state = UNKNOWNECHO_CONNECTION_READ_STATE;
	connection->established = true;

	return true;
}

bool ue_socket_client_connection_is_established(ue_socket_client_connection *connection) {
	return connection->established;
}
