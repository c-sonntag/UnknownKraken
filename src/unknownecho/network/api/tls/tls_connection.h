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
#include <unknownecho/crypto/api/certificate/x509_certificate.h>
#include <unknownecho/bool.h>
#include <unknownecho/byte/byte_stream.h>

#include <stddef.h>

typedef struct ue_tls_connection ue_tls_connection;

ue_tls_connection *ue_tls_connection_create(ue_tls_context *context);

void ue_tls_connection_destroy(ue_tls_connection *connection);

bool ue_tls_connection_set_fd(ue_tls_connection *connection, int fd);

void *ue_tls_connection_get_impl(ue_tls_connection *connection);

bool ue_tls_connection_connect(ue_tls_connection *connection);

bool ue_tls_connection_accept(ue_tls_connection *connection);

ue_x509_certificate *ue_tls_connection_get_peer_certificate(ue_tls_connection *connection);

bool ue_tls_connection_verify_peer_certificate(ue_tls_connection *connection);

#endif
