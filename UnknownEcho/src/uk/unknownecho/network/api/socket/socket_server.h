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
 *  @file      socket_server.h
 *  @brief     Module to build socket server based on polling algorithm.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UnknownKrakenUnknownEcho_SOCKET_SERVER_H
#define UnknownKrakenUnknownEcho_SOCKET_SERVER_H

#include <uk/unknownecho/network/api/socket/socket_client_connection.h>
#include <uk/unknownecho/network/api/socket/socket_server_parameters.h>
#include <uk/unknownecho/network/api/tls/tls_session.h>
#include <uk/utils/ueum.h>

typedef struct {
    int uk_ue_socket_fd;
    uk_ue_socket_client_connection **connections;
    int connections_number, simultaneous_connections_number;
    bool (*read_consumer)(uk_ue_socket_client_connection *connection);
    bool (*write_consumer)(uk_ue_socket_client_connection *connection);
    bool running;
    uk_crypto_tls_session *tls_session;
} uk_ue_socket_server;

uk_ue_socket_server *uk_ue_socket_server_create(uk_ue_socket_server_parameters *parameters);

bool uk_ue_socket_server_is_valid(uk_ue_socket_server *server);

bool uk_ue_socket_server_is_running(uk_ue_socket_server *server);

void uk_ue_socket_server_destroy(uk_ue_socket_server *server);

bool uk_ue_socket_server_process_polling(uk_ue_socket_server *server);

bool uk_ue_socket_server_disconnect(uk_ue_socket_server *server, uk_ue_socket_client_connection *connection);

bool uk_ue_socket_server_stop(uk_ue_socket_server *server);

int uk_ue_socket_server_get_connections_number(uk_ue_socket_server *server);

uk_ue_socket_client_connection *uk_ue_socket_server_get_connection(uk_ue_socket_server *server, int index);

#endif
