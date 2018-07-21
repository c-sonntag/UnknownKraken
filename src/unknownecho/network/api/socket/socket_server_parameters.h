/*******************************************************************************
 * Copyright (C) 2018 by Charly Lamothe                                        *
 *                                                                             *
 * This file is part of LibUnknownEcho.                                        *
 *                                                                             *
 *   LibUnknownEcho is free software: you can redistribute it and/or modify    *
 *   it under the terms of the GNU General Public License as published by      *
 *   the Free Software Foundation, either version 3 of the License, or         *
 *   (at your option) any later version.                                       *
 *                                                                             *
 *   LibUnknownEcho is distributed in the hope that it will be useful,         *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of            *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the             *
 *   GNU General Public License for more details.                              *
 *                                                                             *
 *   You should have received a copy of the GNU General Public License         *
 *   along with LibUnknownEcho.  If not, see <http://www.gnu.org/licenses/>.   *
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
