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
 *  @file      socket.h
 *  @brief     Utility and IO functions of socket file descriptor.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UNKNOWNECHO_SOCKET_H
#define UNKNOWNECHO_SOCKET_H

#include <unknownecho/bool.h>
#include <unknownecho/string/string_builder.h>
#include <unknownecho/byte/byte_stream.h>
#include <unknownecho/network/api/tls/tls_connection.h>

#include <stddef.h>

bool ue_socket_is_valid_domain(int domain);

int ue_socket_str_to_domain(const char *domain);

int ue_socket_open(int domain, int type);

int ue_socket_open_s(const char *domain, const char *type);

int ue_socket_open_tcp();

bool ue_socket_close(int fd);

bool ue_socket_destroy(int fd);

bool ue_socket_is_valid(int fd);

int ue_socket_send_string(int fd, const char *string, ue_tls_connection *tls);

int ue_socket_send_data(int fd, unsigned char *data, size_t size, ue_tls_connection *tls);

size_t ue_socket_receive_string_sync(int fd, ue_string_builder *sb, bool blocking, ue_tls_connection *tls);

size_t ue_socket_receive_bytes_sync(int fd, ue_byte_stream *stream, bool blocking, ue_tls_connection *tls);

size_t ue_socket_receive_all_bytes_sync(int fd, unsigned char **bytes, size_t size, ue_tls_connection *tls);

size_t ue_socket_receive_data_async(int fd, bool (*flow_consumer)(void *flow, size_t flow_size), ue_tls_connection *tls);

#endif
