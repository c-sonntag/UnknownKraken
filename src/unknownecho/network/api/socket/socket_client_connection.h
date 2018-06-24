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

/**
 *  @file      socket_client_connection.h
 *  @brief     Represent the socket connection of the client.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UNKNOWNECHO_SOCKET_CLIENT_UNKNOWNECHO_CONNECTION_H
#define UNKNOWNECHO_SOCKET_CLIENT_UNKNOWNECHO_CONNECTION_H

#include <unknownecho/bool.h>
#include <unknownecho/string/string_builder.h>
#include <unknownecho/string/string_utility.h>
#include <unknownecho/container/string_vector.h>
#include <unknownecho/container/byte_vector.h>
#include <unknownecho/container/queue.h>
#include <unknownecho/byte/byte_stream.h>
#include <unknownecho/crypto/api/certificate/x509_certificate.h>
#include <unknownecho/network/api/tls/tls_connection.h>
#include <unknownecho/network/api/communication/communication_connection_state.h>
#include <unknownecho/network/api/communication/communication_metadata.h>
#include <unknownecho/thread/thread_id_struct.h>

#if defined(__unix__)
    #include <netinet/in.h>
#else
    #include <windows.h>
#endif

typedef struct {
	int fd;
	ue_byte_stream *received_message, *message_to_send, *tmp_stream;
	ue_queue *received_messages, *messages_to_send;
    ue_thread_id *read_messages_consumer_thread, *write_messages_consumer_thread;
    ue_communication_connection_state state;
	char *nickname;
	ue_byte_vector *split_message, *all_messages, *tmp_message, *current_message;
	ue_tls_connection *tls;
	ue_x509_certificate *peer_certificate;
	ue_byte_stream *received_message_stream;
	bool established;
	void *optional_data;
    ue_communication_metadata *communication_metadata;
} ue_socket_client_connection;

ue_socket_client_connection *ue_socket_client_connection_init();

void ue_socket_client_connection_destroy(ue_socket_client_connection *connection);

void ue_socket_client_connection_clean_up(ue_socket_client_connection *connection);

bool ue_socket_client_connection_is_available(ue_socket_client_connection *connection);

bool ue_socket_client_connection_establish(ue_socket_client_connection *connection, int ue_socket_fd);

bool ue_socket_client_connection_is_established(ue_socket_client_connection *connection);

void *ue_socket_client_connection_get_user_data(ue_socket_client_connection *connection);

bool ue_socket_client_connection_set_user_data(ue_socket_client_connection *connection, void *user_data);

char *ue_socket_client_connection_get_nickname(ue_socket_client_connection *connection);

bool ue_socket_client_connection_set_nickname(ue_socket_client_connection *connection, char *nickname);

ue_byte_stream *ue_socket_client_connection_get_received_message(ue_socket_client_connection *connection);

ue_byte_stream *ue_socket_client_connection_get_message_to_send(ue_socket_client_connection *connection);

ue_queue *ue_socket_client_connection_get_received_messages(ue_socket_client_connection *connection);

ue_queue *ue_socket_client_connection_get_messages_to_send(ue_socket_client_connection *connection);

ue_communication_connection_state ue_socket_client_connection_get_state(ue_socket_client_connection *connection);

bool ue_socket_client_connection_set_state(ue_socket_client_connection *connection, ue_communication_connection_state state);

bool ue_socket_client_connection_build_communication_metadata(ue_socket_client_connection *connection, struct sockaddr *sa);

ue_communication_metadata *ue_socket_client_connection_get_communication_metadata(ue_socket_client_connection *connection);

#endif
