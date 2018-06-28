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

#include <unknownecho/network/api/socket/socket_server_parameters.h>
#include <ueum/ueum.h>

ue_socket_server_parameters *ue_socket_server_parameters_build(unsigned short int port,
    bool (*read_consumer)(ue_socket_client_connection *connection),
    bool (*write_consumer)(ue_socket_client_connection *connection),
    uecm_tls_session *tls_session) {

    ue_socket_server_parameters *parameters;

    ueum_safe_alloc(parameters, ue_socket_server_parameters, 1);
    parameters->port = port;
    parameters->read_consumer = read_consumer;
    parameters->write_consumer = write_consumer;
    parameters->tls_session = tls_session;

    return parameters;
}
