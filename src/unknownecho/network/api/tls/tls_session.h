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
 *  @file      tls_session.h
 *  @brief     The tls_session object is global context for a TLS session, that
 *             contains the connection, the context, the method and the hard
 *             drive PKCS12 keystore.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UNKNOWNECHO_TLS_SESSION_H
#define UNKNOWNECHO_TLS_SESSION_H

#include <unknownecho/bool.h>
#include <unknownecho/network/api/tls/tls_connection.h>
#include <unknownecho/network/api/tls/tls_context.h>
#include <unknownecho/network/api/tls/tls_method.h>
#include <unknownecho/crypto/api/keystore/pkcs12_keystore.h>
#include <unknownecho/crypto/api/certificate/x509_certificate.h>

typedef struct {
	ue_tls_connection *tls;
	ue_tls_context *ctx;
	bool verify_peer;
	ue_tls_method *method;
	ue_pkcs12_keystore *keystore;
} ue_tls_session;

ue_tls_session *ue_tls_session_create(char *keystore_path, char *passphrase, ue_tls_method *method, ue_x509_certificate **ca_certificates, int ca_certificate_count);

ue_tls_session *ue_tls_session_create_server(char *keystore_path, char *passphrase, ue_x509_certificate **ca_certificates, int ca_certificate_count);

ue_tls_session *ue_tls_session_create_client(char *keystore_path, char *passphrase, ue_x509_certificate **ca_certificates, int ca_certificate_count);

void ue_tls_session_destroy(ue_tls_session *tls_session);

bool ue_tls_session_verify_peer(ue_tls_session *tls_session);

#endif
