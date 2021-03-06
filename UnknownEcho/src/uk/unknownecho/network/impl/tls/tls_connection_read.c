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

#include <uk/unknownecho/network/api/tls/tls_connection_read.h>
#include <uk/utils/ueum.h>
#include <uk/utils/ei.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <string.h>

size_t uk_crypto_tls_connection_read_sync(uk_crypto_tls_connection *connection, uk_utils_byte_stream *stream) {
    int32_t ssl_error;
    size_t received, total, bytes;
    unsigned char response[4096];
    SSL *ssl;

    memset(response, 0, sizeof(response));
    total = sizeof(response) - 1;
    received = 0;
    ssl_error = SSL_ERROR_NONE;
    ssl = uk_crypto_tls_connection_get_impl(connection);

    do {
        memset(response, 0, sizeof(response));
        bytes = SSL_read(ssl, response, 4096);
        if (bytes < 0) {
            ERR_clear_error();
            ssl_error = SSL_get_error(ssl, bytes);
            switch (ssl_error) {
                case SSL_ERROR_NONE:
                    uk_utils_logger_trace("SSL_ERROR_NONE");
                break;

                case SSL_ERROR_WANT_READ:
                    uk_utils_logger_trace("SSL_ERROR_WANT_READ");
                break;

                case SSL_ERROR_WANT_WRITE:
                    uk_utils_logger_trace("SSL_ERROR_WANT_WRITE");
                break;

                case SSL_ERROR_ZERO_RETURN:
                    uk_utils_logger_trace("SSL_ERROR_ZERO_RETURN");
                break;

                default:
                break;
            }
        }

        if ((bytes > 0) && (ssl_error == SSL_ERROR_NONE)) {
            received += bytes;
            if (!uk_utils_byte_writer_append_bytes(stream, response, bytes)) {
                uk_utils_stacktrace_push_msg("Failed to append in bytes stream socket response");
                return -1;
            }

            return received;
        }
        else if ((bytes < 0) && (ssl_error == SSL_ERROR_WANT_READ)) {
            if (errno != EAGAIN) {
                continue;
            }
            uk_utils_stacktrace_push_errno();
            return -1;
        }
        else if (bytes == 0) {
            break;
        }

    } while (1);

    if (received == total) {
        uk_utils_stacktrace_push_msg("Failed storing complete response from socket");
        return -1;
    }

    return received;
}

size_t uk_crypto_tls_connection_read_async(uk_crypto_tls_connection *connection, bool (*flow_consumer)(void *flow, size_t flow_size)) {
    int32_t ssl_error;
    size_t received, total, bytes;
    char response[4096];
    SSL *ssl;

    memset(response, 0, sizeof(response));
    total = sizeof(response) - 1;
    received = 0;
    ssl_error = SSL_ERROR_NONE;
    ssl = uk_crypto_tls_connection_get_impl(connection);

    do {
        memset(response, 0, sizeof(response));
        bytes = SSL_read(ssl, response, 4096);
        if (bytes < 0) {
            ERR_clear_error();
            ssl_error = SSL_get_error(ssl, bytes);
            switch (ssl_error) {
                case SSL_ERROR_NONE:
                    uk_utils_logger_trace("SSL_ERROR_NONE");
                break;

                case SSL_ERROR_WANT_READ:
                    uk_utils_logger_trace("SSL_ERROR_WANT_READ");
                break;

                case SSL_ERROR_WANT_WRITE:
                    uk_utils_logger_trace("SSL_ERROR_WANT_WRITE");
                break;

                case SSL_ERROR_ZERO_RETURN:
                    uk_utils_logger_trace("SSL_ERROR_ZERO_RETURN");
                break;

                default:
                break;
            }
        }

        if ((bytes > 0) && (ssl_error == SSL_ERROR_NONE)) {
            if (!flow_consumer(response, bytes)) {
                uk_utils_stacktrace_push_msg("Flow consumer failed");
                return -1;
            }
        }
        else if ((bytes < 0) && (ssl_error == SSL_ERROR_WANT_READ)) {
            if (errno != EAGAIN) {
                continue;
            }
            uk_utils_stacktrace_push_errno();
            return -1;
        }
        else if (bytes == 0) {
            ERR_print_errors_fp(stderr);
            uk_utils_logger_warn("Client disconnected ?");
            break;
        }

    } while (1);

    if (received == total) {
        uk_utils_stacktrace_push_msg("Failed storing complete response from socket");
        return -1;
    }

    return received;
}
