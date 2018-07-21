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
