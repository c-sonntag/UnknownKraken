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

#include <unknownecho/network/api/tls/tls_session.h>
#include <unknownecho/system/alloc.h>
#include <unknownecho/errorHandling/stacktrace.h>

ue_tls_session *ue_tls_session_create(char *keystore_path, char *passphrase, ue_tls_method *method, ue_x509_certificate *ca_certificate) {
    ue_tls_session *tls_session;

    ue_safe_alloc(tls_session, ue_tls_session, 1);

    if (!(tls_session->keystore = ue_pkcs12_keystore_load(keystore_path, passphrase))) {
        ue_stacktrace_push_msg("Failed to loas pkcs12 keystore from file '%s'", keystore_path);
        ue_safe_free(tls_session);
        return NULL;
    }

    tls_session->method = method;

    if (!(tls_session->ctx = ue_tls_context_create(tls_session->method))) {
        ue_stacktrace_push_msg("Failed to create TLS context");
        ue_tls_session_destroy(tls_session);
        return NULL;
    }

	if (!(ue_tls_context_load_certificates(tls_session->ctx, tls_session->keystore, ca_certificate))) {
        ue_stacktrace_push_msg("Failed to load keystore certificates into TLS context");
        ue_tls_session_destroy(tls_session);
        return NULL;
    }

	tls_session->verify_peer = ca_certificate ? true : false;
    tls_session->tls = NULL;

    return tls_session;
}

void ue_tls_session_destroy(ue_tls_session *tls_session) {
    if (tls_session) {
        ue_tls_context_destroy(tls_session->ctx);
        ue_tls_connection_destroy(tls_session->tls);
        ue_tls_method_destroy(tls_session->method);
        ue_pkcs12_keystore_destroy(tls_session->keystore);
        ue_safe_free(tls_session);
    }
}

bool ue_tls_session_verify_peer(ue_tls_session *tls_session) {
    return ue_tls_connection_verify_peer_certificate(tls_session->tls);
}
