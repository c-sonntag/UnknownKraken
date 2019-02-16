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

#ifndef UNKNOWNECHO_SOCKET_RECEIVE_H
#define UNKNOWNECHO_SOCKET_RECEIVE_H

#include <unknownecho/network/api/tls/tls_connection.h>
#include <unknownecho/network/api/socket/socket_client_connection.h>
#include <ueum/ueum.h>

#include <stddef.h>

size_t ue_socket_receive_sync(ue_socket_client_connection *connection, ueum_byte_stream *received_message);

size_t ue_socket_receive_all_sync(int fd, unsigned char **bytes, size_t size, uecm_tls_connection *tls);

size_t ue_socket_receive_async(int fd, bool (*flow_consumer)(void *flow, size_t flow_size), uecm_tls_connection *tls);

#endif
