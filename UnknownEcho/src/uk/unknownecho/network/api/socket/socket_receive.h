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

#ifndef UnknownKrakenUnknownEcho_SOCKET_RECEIVE_H
#define UnknownKrakenUnknownEcho_SOCKET_RECEIVE_H

#include <uk/unknownecho/network/api/tls/tls_connection.h>
#include <uk/unknownecho/network/api/socket/socket_client_connection.h>
#include <uk/utils/ueum.h>

#include <stddef.h>

size_t uk_ue_socket_receive_sync(uk_ue_socket_client_connection *connection, uk_utils_byte_stream *received_message);

size_t uk_ue_socket_receive_all_sync(int fd, unsigned char **bytes, size_t size, uk_crypto_tls_connection *tls);

size_t uk_ue_socket_receive_async(int fd, bool (*flow_consumer)(void *flow, size_t flow_size), uk_crypto_tls_connection *tls);

#endif
