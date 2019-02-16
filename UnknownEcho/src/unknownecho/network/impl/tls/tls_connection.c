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

#include <unknownecho/network/api/tls/tls_connection.h>
#include <ueum/ueum.h>
#include <uecm/uecm.h>
#include <ei/ei.h>

#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <string.h>

struct uecm_tls_connection {
    SSL *impl;
};

uecm_tls_connection *uecm_tls_connection_create(uecm_tls_context *context) {
    uecm_tls_connection *connection;
    char *error_buffer;

    connection = NULL;

    ueum_safe_alloc(connection, uecm_tls_connection, 1);

    connection->impl = SSL_new((SSL_CTX *)uecm_tls_context_get_impl(context));
    if (!connection->impl) {
        uecm_openssl_error_handling(error_buffer, "Error SSL_new");
        ueum_safe_free(connection);
        return NULL;
    }

    return connection;
}

void uecm_tls_connection_destroy(uecm_tls_connection *connection) {
    if (connection) {
        if (connection->impl) {
            SSL_shutdown(connection->impl);
            SSL_free(connection->impl);
        }
        ueum_safe_free(connection);
    }
}

bool uecm_tls_connection_set_fd(uecm_tls_connection *connection, int fd) {
    char *error_buffer;

    error_buffer = NULL;

    if (SSL_set_fd(connection->impl, fd) == 0) {
        uecm_crypto_error_handling(error_buffer, "Failed to set file descriptor to TLS connection");
        return false;
    }

    return true;
}

void *uecm_tls_connection_get_impl(uecm_tls_connection *connection) {
    return connection->impl;
}

bool uecm_tls_connection_connect(uecm_tls_connection *connection) {
    char *error_buffer;

    if (SSL_connect(connection->impl) != 1) {
        uecm_openssl_error_handling(error_buffer, "Handshake connection");
        return false;
    }

    return true;
}

bool uecm_tls_connection_accept(uecm_tls_connection *connection) {
    char *error_buffer;

    if (SSL_accept(connection->impl) != 1) {
        uecm_openssl_error_handling(error_buffer, "Handshake accept");
        return false;
    }

    return true;
}

uecm_x509_certificate *uecm_tls_connection_get_peer_certificate(uecm_tls_connection *connection) {
    uecm_x509_certificate *peer_certificate;
    X509 *peer_tls_certificate;
    long verify_result;

    peer_certificate = NULL;
    peer_tls_certificate = NULL;

    peer_tls_certificate = SSL_get_peer_certificate(connection->impl);
    if (!peer_tls_certificate) {
        ei_logger_warn("There is no peer certificate in this TLS connection, in order to verify user certificate");
        return NULL;
    }

    verify_result = SSL_get_verify_result(connection->impl);
    if (verify_result != X509_V_OK) {
        ei_logger_warn("Peer certificate verification failed with result %ld", verify_result);
        X509_free(peer_tls_certificate);
        return NULL;
    }

    peer_certificate = uecm_x509_certificate_create_empty();
    if (!uecm_x509_certificate_set_impl(peer_certificate, peer_tls_certificate)) {
        ei_logger_warn("This implementation of x509 isn't valid");
        return NULL;
    }

    return peer_certificate;
}

bool uecm_tls_connection_verify_peer_certificate(uecm_tls_connection *connection) {
    uecm_x509_certificate *certificate;

    if ((certificate = uecm_tls_connection_get_peer_certificate(connection))) {
        uecm_x509_certificate_destroy(certificate);
        return true;
    }

    return false;
}
