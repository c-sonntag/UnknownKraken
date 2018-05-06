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

#ifndef UNKNOWNECHO_SOCKET_CLIENT_CONNECTION_PARAMETERS_H
#define UNKNOWNECHO_SOCKET_CLIENT_CONNECTION_PARAMETERS_H

#include <unknownecho/network/api/tls/tls_session.h>

typedef struct {
    int fd;
    int domain;
    const char *host, *domain_s, *port_s;
    unsigned short int port;
    ue_tls_session *tls_session;
} ue_socket_client_connection_parameters;

ue_socket_client_connection_parameters *ue_socket_client_connection_parameters_build(int fd, int domain,
    const char *host, unsigned short int port, ue_tls_session *tls_session);

ue_socket_client_connection_parameters *ue_socket_client_connection_parameters_build_s(int fd, const char *domain,
    const char *host, const char *port, ue_tls_session *tls_session);

#endif
