/*******************************************************************************
 * Copyright (C) 2018 by Charly Lamothe                                        *
 *                                                                             *
 * This file is part of LibUnknownEcho.                                        *
 *                                                                             *
 *   LibUnknownEcho is free software: you can redistribute it and/or modify    *
 *   it under the terms of the GNU General Public License as published by      *
 *   the Free Software Foundation, either version 3 of the License, or         *
 *   (at your option) any later version.                                       *
 *                                                                             *
 *   LibUnknownEcho is distributed in the hope that it will be useful,         *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of            *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the             *
 *   GNU General Public License for more details.                              *
 *                                                                             *
 *   You should have received a copy of the GNU General Public License         *
 *   along with LibUnknownEcho.  If not, see <http://www.gnu.org/licenses/>.   *
 *******************************************************************************/

#include <unknownecho/network/api/tls/tls_session.h>
#include <ueum/ueum.h>
#include <ei/ei.h>

uecm_tls_session *uecm_tls_session_create(char *keystore_path, char *passphrase, uecm_tls_method *method, uecm_x509_certificate **ca_certificates, int ca_certificate_count) {
    uecm_tls_session *tls_session;

    tls_session = NULL;

    ueum_safe_alloc(tls_session, uecm_tls_session, 1);

    if (!(tls_session->keystore = uecm_pkcs12_keystore_load(keystore_path, passphrase))) {
        ei_stacktrace_push_msg("Failed to loas pkcs12 keystore from file '%s'", keystore_path);
        ueum_safe_free(tls_session);
        return NULL;
    }

    tls_session->method = method;

    if (!(tls_session->ctx = uecm_tls_context_create(tls_session->method))) {
        ei_stacktrace_push_msg("Failed to create TLS context");
        uecm_tls_session_destroy(tls_session);
        return NULL;
    }

    if (!(uecm_tls_context_load_certificates(tls_session->ctx, tls_session->keystore, ca_certificates, ca_certificate_count))) {
        ei_stacktrace_push_msg("Failed to load keystore certificates into TLS context");
        uecm_tls_session_destroy(tls_session);
        return NULL;
    }

    tls_session->verify_peer = ca_certificates ? true : false;
    tls_session->tls = NULL;

    return tls_session;
}

uecm_tls_session *uecm_tls_session_create_server(char *keystore_path, char *passphrase, uecm_x509_certificate **ca_certificates, int ca_certificate_count) {
    uecm_tls_session *tls_session;

    if (!(tls_session = uecm_tls_session_create(keystore_path, passphrase, uecm_tls_method_create_server(), ca_certificates, ca_certificate_count))) {
        ei_stacktrace_push_msg("Failed to create TLS session as server");
        return NULL;
    }

    return tls_session;
}

uecm_tls_session *uecm_tls_session_create_client(char *keystore_path, char *passphrase, uecm_x509_certificate **ca_certificates, int ca_certificate_count) {
    uecm_tls_session *tls_session;

    if (!(tls_session = uecm_tls_session_create(keystore_path, passphrase, uecm_tls_method_create_client(), ca_certificates, ca_certificate_count))) {
        ei_stacktrace_push_msg("Failed to create TLS session as client");
        return NULL;
    }

    return tls_session;
}

void uecm_tls_session_destroy(uecm_tls_session *tls_session) {
    if (tls_session) {
        uecm_tls_context_destroy(tls_session->ctx);
        uecm_tls_connection_destroy(tls_session->tls);
        uecm_tls_method_destroy(tls_session->method);
        uecm_pkcs12_keystore_destroy(tls_session->keystore);
        ueum_safe_free(tls_session);
    }
}

bool uecm_tls_session_verify_peer(uecm_tls_session *tls_session) {
    return uecm_tls_connection_verify_peer_certificate(tls_session->tls);
}
