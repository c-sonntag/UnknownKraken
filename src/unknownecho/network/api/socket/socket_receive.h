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

#ifndef UNKNOWNECHO_SOCKET_RECEIVE_H
#define UNKNOWNECHO_SOCKET_RECEIVE_H

#include <unknownecho/network/api/tls/tls_connection.h>
#include <unknownecho/network/api/socket/socket_client_connection.h>
#include <unknownecho/bool.h>

#include <stddef.h>

size_t ue_socket_receive_sync(ue_socket_client_connection *connection);

size_t ue_socket_receive_all_sync(int fd, unsigned char **bytes, size_t size, ue_tls_connection *tls);

size_t ue_socket_receive_async(int fd, bool (*flow_consumer)(void *flow, size_t flow_size), ue_tls_connection *tls);

#endif
