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

#include <uk/unknownecho/network/api/tls/tls_connection.h>
#include <uk/utils/ueum.h>
#include <uk/crypto/uecm.h>
#include <uk/utils/ei.h>

#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <string.h>

struct uk_crypto_tls_connection {
    SSL *impl;
};

uk_crypto_tls_connection *uk_crypto_tls_connection_create(uk_crypto_tls_context *context) {
    uk_crypto_tls_connection *connection;
    char *error_buffer;

    connection = NULL;

    uk_utils_safe_alloc(connection, uk_crypto_tls_connection, 1);

    connection->impl = SSL_new((SSL_CTX *)uk_crypto_tls_context_get_impl(context));
    if (!connection->impl) {
        uk_crypto_openssl_error_handling(error_buffer, "Error SSL_new");
        uk_utils_safe_free(connection);
        return NULL;
    }

    return connection;
}

void uk_crypto_tls_connection_destroy(uk_crypto_tls_connection *connection) {
    if (connection) {
        if (connection->impl) {
            SSL_shutdown(connection->impl);
            SSL_free(connection->impl);
        }
        uk_utils_safe_free(connection);
    }
}

bool uk_crypto_tls_connection_set_fd(uk_crypto_tls_connection *connection, int fd) {
    char *error_buffer;

    error_buffer = NULL;

    if (SSL_set_fd(connection->impl, fd) == 0) {
        uk_crypto_crypto_error_handling(error_buffer, "Failed to set file descriptor to TLS connection");
        return false;
    }

    return true;
}

void *uk_crypto_tls_connection_get_impl(uk_crypto_tls_connection *connection) {
    return connection->impl;
}

bool uk_crypto_tls_connection_connect(uk_crypto_tls_connection *connection) {
    char *error_buffer;

    if (SSL_connect(connection->impl) != 1) {
        uk_crypto_openssl_error_handling(error_buffer, "Handshake connection");
        return false;
    }

    return true;
}

bool uk_crypto_tls_connection_accept(uk_crypto_tls_connection *connection) {
    char *error_buffer;

    if (SSL_accept(connection->impl) != 1) {
        uk_crypto_openssl_error_handling(error_buffer, "Handshake accept");
        return false;
    }

    return true;
}

uk_crypto_x509_certificate *uk_crypto_tls_connection_get_peer_certificate(uk_crypto_tls_connection *connection) {
    uk_crypto_x509_certificate *peer_certificate;
    X509 *peer_tls_certificate;
    long verify_result;

    peer_certificate = NULL;
    peer_tls_certificate = NULL;

    peer_tls_certificate = SSL_get_peer_certificate(connection->impl);
    if (!peer_tls_certificate) {
        uk_utils_logger_warn("There is no peer certificate in this TLS connection, in order to verify user certificate");
        return NULL;
    }

    verify_result = SSL_get_verify_result(connection->impl);
    if (verify_result != X509_V_OK) {
        uk_utils_logger_warn("Peer certificate verification failed with result %ld", verify_result);
        X509_free(peer_tls_certificate);
        return NULL;
    }

    peer_certificate = uk_crypto_x509_certificate_create_empty();
    if (!uk_crypto_x509_certificate_set_impl(peer_certificate, peer_tls_certificate)) {
        uk_utils_logger_warn("This implementation of x509 isn't valid");
        return NULL;
    }

    return peer_certificate;
}

bool uk_crypto_tls_connection_verify_peer_certificate(uk_crypto_tls_connection *connection) {
    uk_crypto_x509_certificate *certificate;

    if ((certificate = uk_crypto_tls_connection_get_peer_certificate(connection))) {
        uk_crypto_x509_certificate_destroy(certificate);
        return true;
    }

    return false;
}
