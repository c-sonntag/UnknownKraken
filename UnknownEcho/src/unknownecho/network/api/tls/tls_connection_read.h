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

#ifndef UNKNOWNECHO_TLS_CONNECTION_READ_H
#define UNKNOWNECHO_TLS_CONNECTION_READ_H

#include <unknownecho/network/api/tls/tls_connection.h>
#include <ueum/ueum.h>

#include <stddef.h>

size_t uecm_tls_connection_read_sync(uecm_tls_connection *connection, ueum_byte_stream *stream);

size_t uecm_tls_connection_read_async(uecm_tls_connection *connection, bool (*flow_consumer)(void *flow, size_t flow_size));

#endif