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

/**
 *  @file      tls_connection.h
 *  @brief     Represent a TLS connection.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UnknownKrakenUnknownEcho_TLS_UnknownKrakenUnknownEcho_CONNECTION_H
#define UnknownKrakenUnknownEcho_TLS_UnknownKrakenUnknownEcho_CONNECTION_H

#include <uk/unknownecho/network/api/tls/tls_context.h>
#include <uk/crypto/uecm.h>
#include <uk/utils/ueum.h>

#include <stddef.h>

typedef struct uk_crypto_tls_connection uk_crypto_tls_connection;

uk_crypto_tls_connection *uk_crypto_tls_connection_create(uk_crypto_tls_context *context);

void uk_crypto_tls_connection_destroy(uk_crypto_tls_connection *connection);

bool uk_crypto_tls_connection_set_fd(uk_crypto_tls_connection *connection, int fd);

void *uk_crypto_tls_connection_get_impl(uk_crypto_tls_connection *connection);

bool uk_crypto_tls_connection_connect(uk_crypto_tls_connection *connection);

bool uk_crypto_tls_connection_accept(uk_crypto_tls_connection *connection);

uk_crypto_x509_certificate *uk_crypto_tls_connection_get_peer_certificate(uk_crypto_tls_connection *connection);

bool uk_crypto_tls_connection_verify_peer_certificate(uk_crypto_tls_connection *connection);

#endif
