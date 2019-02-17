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

#ifndef UnknownKrakenUnknownEcho_TLS_SESSION_H
#define UnknownKrakenUnknownEcho_TLS_SESSION_H

#include <uk/unknownecho/network/api/tls/tls_connection.h>
#include <uk/unknownecho/network/api/tls/tls_context.h>
#include <uk/unknownecho/network/api/tls/tls_method.h>
#include <uk/utils/ueum.h>
#include <uk/crypto/uecm.h>

typedef struct {
    uk_crypto_tls_connection *tls;
    uk_crypto_tls_context *ctx;
    bool verify_peer;
    uk_crypto_tls_method *method;
    uk_crypto_pkcs12_keystore *keystore;
} uk_crypto_tls_session;

uk_crypto_tls_session *uk_crypto_tls_session_create(char *keystore_path, char *passphrase, uk_crypto_tls_method *method, uk_crypto_x509_certificate **ca_certificates, int ca_certificate_count);

uk_crypto_tls_session *uk_crypto_tls_session_create_server(char *keystore_path, char *passphrase, uk_crypto_x509_certificate **ca_certificates, int ca_certificate_count);

uk_crypto_tls_session *uk_crypto_tls_session_create_client(char *keystore_path, char *passphrase, uk_crypto_x509_certificate **ca_certificates, int ca_certificate_count);

void uk_crypto_tls_session_destroy(uk_crypto_tls_session *tls_session);

bool uk_crypto_tls_session_verify_peer(uk_crypto_tls_session *tls_session);

#endif
