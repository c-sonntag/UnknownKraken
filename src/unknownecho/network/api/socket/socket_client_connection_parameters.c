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

#include <unknownecho/network/api/socket/socket_client_connection_parameters.h>
#include <unknownecho/alloc.h>

ue_socket_client_connection_parameters *ue_socket_client_connection_parameters_build(int fd, int domain,
    const char *host, unsigned short int port, ue_tls_session *tls_session) {

    ue_socket_client_connection_parameters *parameters;

    ue_safe_alloc(parameters, ue_socket_client_connection_parameters, 1);
    parameters->fd = fd;
    parameters->domain = domain;
    parameters->domain_s = NULL;
    parameters->host = host;
    parameters->port = port;
    parameters->port_s = NULL;
    parameters->tls_session = tls_session;

    return parameters;
}

ue_socket_client_connection_parameters *ue_socket_client_connection_parameters_build_s(int fd, const char *domain,
    const char *host, const char *port, ue_tls_session *tls_session) {

    ue_socket_client_connection_parameters *parameters;

    ue_safe_alloc(parameters, ue_socket_client_connection_parameters, 1);
    parameters->fd = fd;
    parameters->domain_s = domain;
    parameters->domain = -1;
    parameters->host = host;
    parameters->port_s = port;
    parameters->port = -1;
    parameters->tls_session = tls_session;

    return parameters;
}
