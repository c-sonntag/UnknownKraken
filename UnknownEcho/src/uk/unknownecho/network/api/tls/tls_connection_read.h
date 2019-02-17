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

#ifndef UnknownKrakenUnknownEcho_TLS_CONNECTION_READ_H
#define UnknownKrakenUnknownEcho_TLS_CONNECTION_READ_H

#include <uk/unknownecho/network/api/tls/tls_connection.h>
#include <uk/utils/ueum.h>

#include <stddef.h>

size_t uk_crypto_tls_connection_read_sync(uk_crypto_tls_connection *connection, uk_utils_byte_stream *stream);

size_t uk_crypto_tls_connection_read_async(uk_crypto_tls_connection *connection, bool (*flow_consumer)(void *flow, size_t flow_size));

#endif
