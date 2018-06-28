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
