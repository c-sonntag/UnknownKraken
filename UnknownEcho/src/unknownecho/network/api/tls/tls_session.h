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
 *  @file      tls_session.h
 *  @brief     The tls_session object is global context for a TLS session, that
 *             contains the connection, the context, the method and the hard
 *             drive PKCS12 keystore.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UNKNOWNECHO_TLS_SESSION_H
#define UNKNOWNECHO_TLS_SESSION_H

#include <unknownecho/network/api/tls/tls_connection.h>
#include <unknownecho/network/api/tls/tls_context.h>
#include <unknownecho/network/api/tls/tls_method.h>
#include <ueum/ueum.h>
#include <uecm/uecm.h>

typedef struct {
    uecm_tls_connection *tls;
    uecm_tls_context *ctx;
    bool verify_peer;
    uecm_tls_method *method;
    uecm_pkcs12_keystore *keystore;
} uecm_tls_session;

uecm_tls_session *uecm_tls_session_create(char *keystore_path, char *passphrase, uecm_tls_method *method, uecm_x509_certificate **ca_certificates, int ca_certificate_count);

uecm_tls_session *uecm_tls_session_create_server(char *keystore_path, char *passphrase, uecm_x509_certificate **ca_certificates, int ca_certificate_count);

uecm_tls_session *uecm_tls_session_create_client(char *keystore_path, char *passphrase, uecm_x509_certificate **ca_certificates, int ca_certificate_count);

void uecm_tls_session_destroy(uecm_tls_session *tls_session);

bool uecm_tls_session_verify_peer(uecm_tls_session *tls_session);

#endif
