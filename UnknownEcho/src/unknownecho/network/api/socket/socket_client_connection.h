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

/**
 *  @file      socket_client_connection.h
 *  @brief     Represent the socket connection of the client.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UNKNOWNECHO_SOCKET_CLIENT_UNKNOWNECHO_CONNECTION_H
#define UNKNOWNECHO_SOCKET_CLIENT_UNKNOWNECHO_CONNECTION_H

#include <unknownecho/network/api/tls/tls_connection.h>
#include <unknownecho/network/api/communication/communication_connection_state.h>
#include <unknownecho/network/api/communication/communication_metadata.h>
#include <unknownecho/network/api/communication/communication_connection_direction.h>
#include <ueum/ueum.h>
#include <uecm/uecm.h>

#if defined(__unix__)
    #include <netinet/in.h>
#else
    #include <windows.h>
#endif

typedef struct {
    int fd;
    ueum_byte_stream *received_message, *message_to_send, *tmp_stream;
    ueum_queue *received_messages, *messages_to_send;
    ueum_thread_id *read_messages_consumer_thread, *write_messages_consumer_thread;
    ue_communication_connection_state state;
    char *nickname;
    ueum_byte_vector *split_message, *all_messages, *tmp_message, *current_message;
    uecm_tls_connection *tls;
    uecm_x509_certificate *peer_certificate;
    ueum_byte_stream *received_message_stream;
    bool established;
    void *optional_data;
    ue_communication_metadata *communication_metadata;
    ue_communication_connection_direction connection_direction;
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

ueum_byte_stream *ue_socket_client_connection_get_received_message(ue_socket_client_connection *connection);

ueum_byte_stream *ue_socket_client_connection_get_message_to_send(ue_socket_client_connection *connection);

ueum_queue *ue_socket_client_connection_get_received_messages(ue_socket_client_connection *connection);

ueum_queue *ue_socket_client_connection_get_messages_to_send(ue_socket_client_connection *connection);

ue_communication_connection_state ue_socket_client_connection_get_state(ue_socket_client_connection *connection);

bool ue_socket_client_connection_set_state(ue_socket_client_connection *connection, ue_communication_connection_state state);

bool ue_socket_client_connection_build_communication_metadata(ue_socket_client_connection *connection, struct sockaddr *sa);

ue_communication_metadata *ue_socket_client_connection_get_communication_metadata(ue_socket_client_connection *connection);

ue_communication_connection_direction ue_socket_client_connection_get_direction(ue_socket_client_connection *connection);

bool ue_socket_client_connection_set_direction(ue_socket_client_connection *connection, ue_communication_connection_direction
    connection_direction);

#endif