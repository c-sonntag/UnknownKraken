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

#include <unknownecho/network/api/tls/tls_connection_write.h>
#include <ei/ei.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

size_t uecm_tls_connection_write_sync(uecm_tls_connection *connection, const void *data, int size) {
    size_t sent, bytes;
    int32_t ssl_error;
    SSL *ssl;

    sent = 0;
    ssl_error = SSL_ERROR_NONE;
    ssl = uecm_tls_connection_get_impl(connection);

    do {
        _Pragma("GCC diagnostic push");
        _Pragma("GCC diagnostic ignored \"-Wpedantic\"");
            bytes = SSL_write(ssl, (unsigned char *)data + sent, size - sent);
        _Pragma("GCC diagnostic pop");
        if (bytes < 0) {
            ERR_clear_error();
            ssl_error = SSL_get_error(ssl, bytes);
            switch (ssl_error) {
                case SSL_ERROR_NONE:
                    ei_logger_trace("SSL_ERROR_NONE");
                break;

                case SSL_ERROR_WANT_READ:
                    ei_logger_trace("SSL_ERROR_WANT_READ");
                break;

                case SSL_ERROR_WANT_WRITE:
                    ei_logger_trace("SSL_ERROR_WANT_WRITE");
                break;

                case SSL_ERROR_ZERO_RETURN:
                    ei_logger_trace("SSL_ERROR_ZERO_RETURN");
                break;

                default:
                break;
            }
        }

        if ((bytes > 0) && (ssl_error == SSL_ERROR_NONE)) {
            sent += bytes;
        }
        else if ((bytes < 0)  && (ssl_error == SSL_ERROR_WANT_READ)) {
            if (errno != EAGAIN) {
                continue;
            }

            ei_stacktrace_push_errno();
            return -1;
        }
        else if (bytes == 0) {
            ERR_print_errors_fp(stderr);
            ei_logger_warn("Client disconnected ?");
            break;
        }
    } while (sent < size);

    return sent;
}
