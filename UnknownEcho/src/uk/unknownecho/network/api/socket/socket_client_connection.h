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

#ifndef UnknownKrakenUnknownEcho_SOCKET_CLIENT_CONNECTION_H
#define UnknownKrakenUnknownEcho_SOCKET_CLIENT_CONNECTION_H

#include <uk/unknownecho/network/api/tls/tls_connection.h>
#include <uk/unknownecho/network/api/communication/communication_connection_state.h>
#include <uk/unknownecho/network/api/communication/communication_metadata.h>
#include <uk/unknownecho/network/api/communication/communication_connection_direction.h>
#include <uk/utils/ueum.h>
#include <uk/crypto/uecm.h>

#if defined(__unix__)
    #include <netinet/in.h>
#else
    #include <windows.h>
    //#include <ws2ipdef.h>
    //#include <ws2def.h>
#endif

typedef struct {
    int fd;
    uk_utils_byte_stream *received_message, *message_to_send, *tuk_mp_stream;
    uk_utils_queue *received_messages, *messages_to_send;
    uk_utils_thread_id *read_messages_consumer_thread, *write_messages_consumer_thread;
    uk_ue_communication_connection_state state;
    char *nickname;
    uk_utils_byte_vector *split_message, *all_messages, *tuk_mp_message, *current_message;
    uk_crypto_tls_connection *tls;
    uk_crypto_x509_certificate *peer_certificate;
    uk_utils_byte_stream *received_message_stream;
    bool established;
    void *optional_data;
    uk_ue_communication_metadata *communication_metadata;
    uk_ue_communication_connection_direction connection_direction;
} uk_ue_socket_client_connection;

uk_ue_socket_client_connection *uk_ue_socket_client_connection_init();

void uk_ue_socket_client_connection_destroy(uk_ue_socket_client_connection *connection);

void uk_ue_socket_client_connection_clean_up(uk_ue_socket_client_connection *connection);

bool uk_ue_socket_client_connection_is_available(uk_ue_socket_client_connection *connection);

bool uk_ue_socket_client_connection_establish(uk_ue_socket_client_connection *connection, int uk_ue_socket_fd);

bool uk_ue_socket_client_connection_is_established(uk_ue_socket_client_connection *connection);

void *uk_ue_socket_client_connection_get_user_data(uk_ue_socket_client_connection *connection);

bool uk_ue_socket_client_connection_set_user_data(uk_ue_socket_client_connection *connection, void *user_data);

char *uk_ue_socket_client_connection_get_nickname(uk_ue_socket_client_connection *connection);

bool uk_ue_socket_client_connection_set_nickname(uk_ue_socket_client_connection *connection, char *nickname);

uk_utils_byte_stream *uk_ue_socket_client_connection_get_received_message(uk_ue_socket_client_connection *connection);

uk_utils_byte_stream *uk_ue_socket_client_connection_get_message_to_send(uk_ue_socket_client_connection *connection);

uk_utils_queue *uk_ue_socket_client_connection_get_received_messages(uk_ue_socket_client_connection *connection);

uk_utils_queue *uk_ue_socket_client_connection_get_messages_to_send(uk_ue_socket_client_connection *connection);

uk_ue_communication_connection_state uk_ue_socket_client_connection_get_state(uk_ue_socket_client_connection *connection);

bool uk_ue_socket_client_connection_set_state(uk_ue_socket_client_connection *connection, uk_ue_communication_connection_state state);

bool uk_ue_socket_client_connection_build_communication_metadata(uk_ue_socket_client_connection *connection, struct sockaddr *sa);

uk_ue_communication_metadata *uk_ue_socket_client_connection_get_communication_metadata(uk_ue_socket_client_connection *connection);

uk_ue_communication_connection_direction uk_ue_socket_client_connection_get_direction(uk_ue_socket_client_connection *connection);

bool uk_ue_socket_client_connection_set_direction(uk_ue_socket_client_connection *connection, uk_ue_communication_connection_direction
    connection_direction);

#endif
