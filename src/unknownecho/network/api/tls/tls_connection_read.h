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

#ifndef UNKNOWNECHO_TLS_CONNECTION_READ_H
#define UNKNOWNECHO_TLS_CONNECTION_READ_H

#include <unknownecho/network/api/tls/tls_connection.h>
#include <ueum/ueum.h>

#include <stddef.h>

size_t uecm_tls_connection_read_sync(uecm_tls_connection *connection, ueum_byte_stream *stream);

size_t uecm_tls_connection_read_async(uecm_tls_connection *connection, bool (*flow_consumer)(void *flow, size_t flow_size));

#endif
