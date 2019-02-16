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

#ifndef UNKNOWNECHO_TLS_UNKNOWNECHO_CONNECTION_H
#define UNKNOWNECHO_TLS_UNKNOWNECHO_CONNECTION_H

#include <unknownecho/network/api/tls/tls_context.h>
#include <uecm/uecm.h>
#include <ueum/ueum.h>

#include <stddef.h>

typedef struct uecm_tls_connection uecm_tls_connection;

uecm_tls_connection *uecm_tls_connection_create(uecm_tls_context *context);

void uecm_tls_connection_destroy(uecm_tls_connection *connection);

bool uecm_tls_connection_set_fd(uecm_tls_connection *connection, int fd);

void *uecm_tls_connection_get_impl(uecm_tls_connection *connection);

bool uecm_tls_connection_connect(uecm_tls_connection *connection);

bool uecm_tls_connection_accept(uecm_tls_connection *connection);

uecm_x509_certificate *uecm_tls_connection_get_peer_certificate(uecm_tls_connection *connection);

bool uecm_tls_connection_verify_peer_certificate(uecm_tls_connection *connection);

#endif
