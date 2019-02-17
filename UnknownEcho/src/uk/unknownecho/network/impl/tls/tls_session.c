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

#include <uk/unknownecho/network/api/tls/tls_session.h>
#include <uk/utils/ueum.h>
#include <uk/utils/ei.h>

uk_crypto_tls_session *uk_crypto_tls_session_create(char *keystore_path, char *passphrase, uk_crypto_tls_method *method, uk_crypto_x509_certificate **ca_certificates, int ca_certificate_count) {
    uk_crypto_tls_session *tls_session;

    tls_session = NULL;

    uk_utils_safe_alloc(tls_session, uk_crypto_tls_session, 1);

    if (!(tls_session->keystore = uk_crypto_pkcs12_keystore_load(keystore_path, passphrase))) {
        uk_utils_stacktrace_push_msg("Failed to loas pkcs12 keystore from file '%s'", keystore_path);
        uk_utils_safe_free(tls_session);
        return NULL;
    }

    tls_session->method = method;

    if (!(tls_session->ctx = uk_crypto_tls_context_create(tls_session->method))) {
        uk_utils_stacktrace_push_msg("Failed to create TLS context");
        uk_crypto_tls_session_destroy(tls_session);
        return NULL;
    }

    if (!(uk_crypto_tls_context_load_certificates(tls_session->ctx, tls_session->keystore, ca_certificates, ca_certificate_count))) {
        uk_utils_stacktrace_push_msg("Failed to load keystore certificates into TLS context");
        uk_crypto_tls_session_destroy(tls_session);
        return NULL;
    }

    tls_session->verify_peer = ca_certificates ? true : false;
    tls_session->tls = NULL;

    return tls_session;
}

uk_crypto_tls_session *uk_crypto_tls_session_create_server(char *keystore_path, char *passphrase, uk_crypto_x509_certificate **ca_certificates, int ca_certificate_count) {
    uk_crypto_tls_session *tls_session;

    if (!(tls_session = uk_crypto_tls_session_create(keystore_path, passphrase, uk_crypto_tls_method_create_server(), ca_certificates, ca_certificate_count))) {
        uk_utils_stacktrace_push_msg("Failed to create TLS session as server");
        return NULL;
    }

    return tls_session;
}

uk_crypto_tls_session *uk_crypto_tls_session_create_client(char *keystore_path, char *passphrase, uk_crypto_x509_certificate **ca_certificates, int ca_certificate_count) {
    uk_crypto_tls_session *tls_session;

    if (!(tls_session = uk_crypto_tls_session_create(keystore_path, passphrase, uk_crypto_tls_method_create_client(), ca_certificates, ca_certificate_count))) {
        uk_utils_stacktrace_push_msg("Failed to create TLS session as client");
        return NULL;
    }

    return tls_session;
}

void uk_crypto_tls_session_destroy(uk_crypto_tls_session *tls_session) {
    if (tls_session) {
        uk_crypto_tls_context_destroy(tls_session->ctx);
        uk_crypto_tls_connection_destroy(tls_session->tls);
        uk_crypto_tls_method_destroy(tls_session->method);
        uk_crypto_pkcs12_keystore_destroy(tls_session->keystore);
        uk_utils_safe_free(tls_session);
    }
}

bool uk_crypto_tls_session_verify_peer(uk_crypto_tls_session *tls_session) {
    return uk_crypto_tls_connection_verify_peer_certificate(tls_session->tls);
}
