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

#include <unknownecho/network/api/tls/tls_connection.h>
#include <unknownecho/system/alloc.h>
#include <unknownecho/crypto/api/certificate/x509_certificate.h>
#include <unknownecho/crypto/api/errorHandling/crypto_error_handling.h>
#include <unknownecho/string/string_utility.h>
#include <unknownecho/byte/byte_writer.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/logger.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <string.h>

struct ue_tls_connection {
	SSL *impl;
};

ue_tls_connection *ue_tls_connection_create(ue_tls_context *context) {
	ue_tls_connection *connection;
	char *error_buffer;

	ue_safe_alloc(connection, ue_tls_connection, 1);

	connection->impl = SSL_new((SSL_CTX *)ue_tls_context_get_impl(context));
	if (!connection->impl) {
		ue_openssl_error_handling(error_buffer, "Error SSL_new");
		ue_safe_free(connection);
		return NULL;
	}

	return connection;
}

void ue_tls_connection_destroy(ue_tls_connection *connection) {
	if (connection) {
		SSL_shutdown(connection->impl);
		SSL_free(connection->impl);
		ue_safe_free(connection);
	}
}

bool ue_tls_connection_set_fd(ue_tls_connection *connection, int fd) {
	char *error_buffer;

	error_buffer = NULL;

	if (SSL_set_fd(connection->impl, fd) == 0) {
		ue_crypto_error_handling(error_buffer, "Failed to set file descriptor to TLS connection");
		return false;
	}

	return true;
}

void *ue_tls_connection_get_impl(ue_tls_connection *connection) {
	return connection->impl;
}

bool ue_tls_connection_connect(ue_tls_connection *connection) {
	char *error_buffer;

	if (SSL_connect(connection->impl) != 1) {
		ue_openssl_error_handling(error_buffer, "Handshake connection");
		return false;
	}

	return true;
}

bool ue_tls_connection_accept(ue_tls_connection *connection) {
	char *error_buffer;

	if (SSL_accept(connection->impl) != 1) {
		ue_openssl_error_handling(error_buffer, "Handshake accept");
		return false;
	}

	return true;
}

ue_x509_certificate *ue_tls_connection_get_peer_certificate(ue_tls_connection *connection) {
	ue_x509_certificate *peer_certificate;
	X509 *peer_tls_certificate;
    long verify_result;

	peer_certificate = NULL;
	peer_tls_certificate = NULL;

    peer_tls_certificate = SSL_get_peer_certificate(connection->impl);
    if (!peer_tls_certificate) {
		ue_logger_warn("There is no peer certificate in this TLS connection, in order to verify user certificate");
        return NULL;
    }

    verify_result = SSL_get_verify_result(connection->impl);
    if (verify_result != X509_V_OK) {
		ue_logger_warn("Peer certificate verification failed with result %ld", verify_result);
        X509_free(peer_tls_certificate);
        return NULL;
    }

	peer_certificate = ue_x509_certificate_create_empty();
	if (!ue_x509_certificate_set_impl(peer_certificate, peer_tls_certificate)) {
		ue_logger_warn("This implementation of x509 isn't valid");
		return NULL;
	}

    return peer_certificate;
}

bool ue_tls_connection_verify_peer_certificate(ue_tls_connection *connection) {
	ue_x509_certificate *certificate;

	if ((certificate = ue_tls_connection_get_peer_certificate(connection))) {
		ue_x509_certificate_destroy(certificate);
		return true;
	}

	return false;
}

size_t ue_tls_connection_write_sync(ue_tls_connection *connection, const void *data, int size) {
	size_t sent, bytes;
    int32_t ssl_error;

	sent = 0;
	ssl_error = SSL_ERROR_NONE;

	do {
		_Pragma("GCC diagnostic push");
    	_Pragma("GCC diagnostic ignored \"-Wpedantic\"");
			bytes = SSL_write(connection->impl, data + sent, size - sent);
		_Pragma("GCC diagnostic pop");
		if (bytes < 0) {
			ERR_clear_error();
			ssl_error = SSL_get_error(connection->impl, bytes);
			switch (ssl_error) {
				case SSL_ERROR_NONE:
					ue_logger_trace("SSL_ERROR_NONE");
				break;

				case SSL_ERROR_WANT_READ:
					ue_logger_trace("SSL_ERROR_WANT_READ");
				break;

				case SSL_ERROR_WANT_WRITE:
					ue_logger_trace("SSL_ERROR_WANT_WRITE");
				break;

				case SSL_ERROR_ZERO_RETURN:
					ue_logger_trace("SSL_ERROR_ZERO_RETURN");
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

			ue_stacktrace_push_errno();
			return -1;
		}
		else if (bytes == 0) {
			ERR_print_errors_fp(stderr);
			ue_logger_warn("Client disconnected ?");
			break;
		}
	} while (sent < size);

	return sent;
}

size_t ue_tls_connection_read_string_sync(ue_tls_connection *connection, ue_string_builder *sb, bool blocking) {
	int32_t ssl_error;
    size_t received, total, bytes;
    char response[4096];

	memset(response, 0, sizeof(response));
	total = sizeof(response) - 1;
	received = 0;
	ssl_error = SSL_ERROR_NONE;

	do {
		memset(response, 0, sizeof(response));
		bytes = SSL_read(connection->impl, response, 1024);
		if (bytes < 0) {
			ERR_clear_error();
			ssl_error = SSL_get_error(connection->impl, bytes);
			switch (ssl_error) {
				case SSL_ERROR_NONE:
					ue_logger_trace("SSL_ERROR_NONE");
				break;

				case SSL_ERROR_WANT_READ:
					ue_logger_trace("SSL_ERROR_WANT_READ");
				break;

				case SSL_ERROR_WANT_WRITE:
					ue_logger_trace("SSL_ERROR_WANT_WRITE");
				break;

				case SSL_ERROR_ZERO_RETURN:
					ue_logger_trace("SSL_ERROR_ZERO_RETURN");
				break;

				default:
				break;
			}
		}

		if ((bytes > 0) && (ssl_error == SSL_ERROR_NONE)) {
			received += bytes;
			if (!ue_string_builder_append(sb, response, bytes)) {
				ue_stacktrace_push_msg("Failed to append in string builder socket response");
				return -1;
			}
			if (!blocking) {
				return received;
			}
		}
		else if ((bytes < 0) && (ssl_error == SSL_ERROR_WANT_READ)) {
			if (errno != EAGAIN) {
				continue;
			}
			ue_stacktrace_push_errno();
			return -1;
		}
		else if (bytes == 0) {
			break;
		}

	} while (1);

	if (received == total) {
		ue_stacktrace_push_msg("Failed storing complete response from socket");
		return -1;
	}

	return received;
}

size_t ue_tls_connection_read_bytes_sync(ue_tls_connection *connection, ue_byte_stream *stream, bool blocking) {
	int32_t ssl_error;
    size_t received, total, bytes;
    unsigned char response[4096];

	memset(response, 0, sizeof(response));
	total = sizeof(response) - 1;
	received = 0;
	ssl_error = SSL_ERROR_NONE;

	do {
		memset(response, 0, sizeof(response));
		bytes = SSL_read(connection->impl, response, 1024);
		if (bytes < 0) {
			ERR_clear_error();
			ssl_error = SSL_get_error(connection->impl, bytes);
			switch (ssl_error) {
				case SSL_ERROR_NONE:
					ue_logger_trace("SSL_ERROR_NONE");
				break;

				case SSL_ERROR_WANT_READ:
					ue_logger_trace("SSL_ERROR_WANT_READ");
				break;

				case SSL_ERROR_WANT_WRITE:
					ue_logger_trace("SSL_ERROR_WANT_WRITE");
				break;

				case SSL_ERROR_ZERO_RETURN:
					ue_logger_trace("SSL_ERROR_ZERO_RETURN");
				break;

				default:
				break;
			}
		}

		if ((bytes > 0) && (ssl_error == SSL_ERROR_NONE)) {
			received += bytes;
			if (!ue_byte_writer_append_bytes(stream, response, bytes)) {
				ue_stacktrace_push_msg("Failed to append in bytes stream socket response");
				return -1;
			}
			if (!blocking) {
				return received;
			}
		}
		else if ((bytes < 0) && (ssl_error == SSL_ERROR_WANT_READ)) {
			if (errno != EAGAIN) {
				continue;
			}
			ue_stacktrace_push_errno();
			return -1;
		}
		else if (bytes == 0) {
			break;
		}

	} while (1);

	if (received == total) {
		ue_stacktrace_push_msg("Failed storing complete response from socket");
		return -1;
	}

	return received;
}

size_t ue_tls_connection_read_async(ue_tls_connection *connection, bool (*flow_consumer)(void *flow, size_t flow_size)) {
	int32_t ssl_error;
    size_t received, total, bytes;
    char response[4096];

	memset(response, 0, sizeof(response));
	total = sizeof(response) - 1;
	received = 0;
	ssl_error = SSL_ERROR_NONE;

	do {
		memset(response, 0, sizeof(response));
		bytes = SSL_read(connection->impl, response, 1024);
		if (bytes < 0) {
			ERR_clear_error();
			ssl_error = SSL_get_error(connection->impl, bytes);
			switch (ssl_error) {
				case SSL_ERROR_NONE:
					ue_logger_trace("SSL_ERROR_NONE");
				break;

				case SSL_ERROR_WANT_READ:
					ue_logger_trace("SSL_ERROR_WANT_READ");
				break;

				case SSL_ERROR_WANT_WRITE:
					ue_logger_trace("SSL_ERROR_WANT_WRITE");
				break;

				case SSL_ERROR_ZERO_RETURN:
					ue_logger_trace("SSL_ERROR_ZERO_RETURN");
				break;

				default:
				break;
			}
		}

		if ((bytes > 0) && (ssl_error == SSL_ERROR_NONE)) {
			if (!flow_consumer(response, bytes)) {
				ue_stacktrace_push_msg("Flow consumer failed");
				return -1;
			}
		}
		else if ((bytes < 0) && (ssl_error == SSL_ERROR_WANT_READ)) {
			if (errno != EAGAIN) {
				continue;
			}
			ue_stacktrace_push_errno();
			return -1;
		}
		else if (bytes == 0) {
			ERR_print_errors_fp(stderr);
			ue_logger_warn("Client disconnected ?");
			break;
		}

	} while (1);

	if (received == total) {
		ue_stacktrace_push_msg("Failed storing complete response from socket");
		return -1;
	}

	return received;
}
