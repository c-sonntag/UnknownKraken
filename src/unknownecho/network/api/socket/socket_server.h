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
 *  @file      socket_server.h
 *  @brief     Module to build socket server based on polling algorithm.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UNKNOWNECHO_SOCKET_SERVER_H
#define UNKNOWNECHO_SOCKET_SERVER_H

#include <unknownecho/network/api/socket/socket_client_connection.h>
#include <unknownecho/network/api/tls/tls_session.h>
#include <unknownecho/bool.h>

typedef struct {
	int ue_socket_fd;
	ue_socket_client_connection **connections;
	int connections_number, simultaneous_connections_number;
	bool (*read_consumer)(ue_socket_client_connection *connection);
	bool (*write_consumer)(ue_socket_client_connection *connection);
	bool running;
	ue_tls_session *tls_session;
} ue_socket_server;

ue_socket_server *ue_socket_server_create(unsigned short int port,
	bool (*read_consumer)(ue_socket_client_connection *connection),
	bool (*write_consumer)(ue_socket_client_connection *connection),
	ue_tls_session *tls_session);

bool ue_socket_server_is_valid(ue_socket_server *server);

void ue_socket_server_destroy(ue_socket_server *server);

void ue_socket_server_process_polling(ue_socket_server *server);

bool ue_socket_server_disconnect(ue_socket_server *server, ue_socket_client_connection *connection);

#endif
