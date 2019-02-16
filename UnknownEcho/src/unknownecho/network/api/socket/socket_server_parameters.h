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

#ifndef UNKNOWNECHO_SOCKET_SERVER_PARAMETERS_H
#define UNKNOWNECHO_SOCKET_SERVER_PARAMETERS_H

#include <unknownecho/network/api/socket/socket_client.h>
#include <unknownecho/network/api/tls/tls_session.h>
#include <ueum/ueum.h>

typedef struct {
    unsigned short int port;
    bool (*read_consumer)(ue_socket_client_connection *connection);
    bool (*write_consumer)(ue_socket_client_connection *connection);
    uecm_tls_session *tls_session;
} ue_socket_server_parameters;

ue_socket_server_parameters *ue_socket_server_parameters_build(unsigned short int port,
    bool (*read_consumer)(ue_socket_client_connection *connection),
    bool (*write_consumer)(ue_socket_client_connection *connection),
    uecm_tls_session *tls_session);

#endif
