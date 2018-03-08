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

#include <unknownecho/crypto/api/csr/csr_request.h>
#include <unknownecho/crypto/api/certificate/x509_csr.h>
#include <unknownecho/crypto/api/certificate/x509_certificate_sign.h>
#include <unknownecho/crypto/api/cipher/data_cipher.h>
#include <unknownecho/crypto/api/encryption/sym_encrypter.h>
#include <unknownecho/crypto/factory/sym_encrypter_factory.h>
#include <unknownecho/errorHandling/check_parameter.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/byte/byte_stream.h>
#include <unknownecho/byte/byte_writer.h>
#include <unknownecho/byte/byte_reader.h>
#include <unknownecho/alloc.h>

static char *generate_csr_string(ue_x509_certificate *certificate, ue_private_key *private_key) {
    ue_x509_csr *csr;
    char *csr_string;

	ue_check_parameter_or_return(certificate);
	ue_check_parameter_or_return(private_key);

    csr_string = NULL;
    csr = NULL;

    if (!(csr = ue_x509_csr_create(certificate, private_key))) {
        ue_stacktrace_push_msg("Failed to create x509 CRS from certificate and private key");
        return NULL;
    }

    ue_logger_info("Convert x509 CRS to string...");
    if (!(csr_string = ue_x509_csr_to_string(csr))) {
        ue_stacktrace_push_msg("Failed to convert x509 CRS to string");
        ue_x509_csr_destroy(csr);
        return NULL;
    }

    ue_x509_csr_destroy(csr);

    return csr_string;
}

unsigned char *ue_csr_build_client_request(ue_x509_certificate *certificate, ue_private_key *private_key,
    ue_public_key *ca_public_key, size_t *cipher_data_size, ue_sym_key *future_key, unsigned char *iv, size_t iv_size) {

    char *csr_string;
    ue_public_key *public_key;
    ue_byte_stream *stream;
    unsigned char *cipher_data;

	ue_check_parameter_or_return(certificate);
	ue_check_parameter_or_return(private_key);
	ue_check_parameter_or_return(ca_public_key);
	ue_check_parameter_or_return(future_key);
	ue_check_parameter_or_return(iv);
	ue_check_parameter_or_return(iv_size > 0);

    csr_string = NULL;
    public_key = NULL;
    stream = ue_byte_stream_create();
    cipher_data = NULL;

    if (!(csr_string = generate_csr_string(certificate, private_key))) {
		ue_stacktrace_push_msg("Failed to generate CSR string from certificate and private key");
		goto clean_up;
	}

    if (!ue_byte_writer_append_int(stream, (int)strlen(csr_string))) {
		ue_stacktrace_push_msg("Failed to write CSR string size to stream");
		goto clean_up;
	}
    if (!ue_byte_writer_append_int(stream, (int)future_key->size)) {
		ue_stacktrace_push_msg("Failed to write future key size to stream");
		goto clean_up;
	}
    if (!ue_byte_writer_append_int(stream, (int)iv_size)) {
		ue_stacktrace_push_msg("Failed to write IV size to stream");
		goto clean_up;
	}
    if (!ue_byte_writer_append_string(stream, csr_string)) {
		ue_stacktrace_push_msg("Failed to write CSR string to stream");
		goto clean_up;
	}
    if (!ue_byte_writer_append_bytes(stream, future_key->data, future_key->size)) {
		ue_stacktrace_push_msg("Failed to write future to stream");
		goto clean_up;
	}
    if (!ue_byte_writer_append_bytes(stream, iv, iv_size)) {
		ue_stacktrace_push_msg("Failed to write IV to stream");
		goto clean_up;
	}

    if (!ue_cipher_plain_data(ue_byte_stream_get_data(stream), ue_byte_stream_get_size(stream), ca_public_key, NULL, &cipher_data, cipher_data_size, "aes-256-cbc")) {
        ue_stacktrace_push_msg("Failed to cipher plain data");
        goto clean_up;
    }

clean_up:
    ue_public_key_destroy(public_key);
    ue_byte_stream_destroy(stream);
    ue_safe_free(csr_string);
    return cipher_data;
}

ue_x509_certificate *ue_csr_process_server_response(unsigned char *server_response, size_t server_response_size, ue_sym_key *key,
    unsigned char *iv, size_t iv_size) {

    ue_sym_encrypter *sym_encrypter;
    ue_x509_certificate *signed_certificate;
    unsigned char *signed_certificate_buffer;
    size_t signed_certificate_buffer_size;

	ue_check_parameter_or_return(server_response);
	ue_check_parameter_or_return(server_response_size > 0);
	ue_check_parameter_or_return(key);
	ue_check_parameter_or_return(iv);
	ue_check_parameter_or_return(iv_size > 0);

    signed_certificate = NULL;

    sym_encrypter = ue_sym_encrypter_default_create(key);
	if (!ue_sym_encrypter_decrypt(sym_encrypter, server_response, server_response_size, iv, &signed_certificate_buffer, &signed_certificate_buffer_size)) {
		ue_stacktrace_push_msg("Failed to decrypt signed certificate");
		goto clean_up;
	}

    if (!(signed_certificate = ue_x509_certificate_load_from_bytes(signed_certificate_buffer, signed_certificate_buffer_size))) {
        ue_stacktrace_push_msg("Failed to convert bytes to x509 certificate");
    }

clean_up:
    ue_sym_encrypter_destroy(sym_encrypter);
    ue_safe_free(signed_certificate_buffer);
    return signed_certificate;
}

unsigned char *ue_csr_build_server_response(ue_private_key *csr_private_key, ue_x509_certificate *ca_certificate, ue_private_key *ca_private_key,
    unsigned char *client_request, size_t client_request_size, size_t *server_response_size, ue_x509_certificate **signed_certificate) {

    unsigned char *decipher_data, *server_response, *decipher_client_request, *key_data, *iv;
    size_t decipher_data_size, decipher_client_request_size, key_size, iv_size;
    ue_byte_stream *stream;
    int read_int;
    ue_sym_key *key;
    ue_sym_encrypter *sym_encrypter;
    ue_x509_csr *csr;
    char *string_pem_certificate;

    decipher_data = NULL;
    server_response = NULL;
    decipher_client_request = NULL;
    stream = ue_byte_stream_create();
    key = NULL;
    sym_encrypter = NULL;
    csr = NULL;
    string_pem_certificate = NULL;
    key_data = NULL;
    iv = NULL;

    ue_check_parameter_or_return(csr_private_key);
    ue_check_parameter_or_return(ca_certificate);
    ue_check_parameter_or_return(ca_private_key);
    ue_check_parameter_or_return(client_request);
    ue_check_parameter_or_return(client_request_size > 0);

    if (!ue_decipher_cipher_data(client_request, client_request_size, csr_private_key, NULL, &decipher_data, &decipher_data_size, "aes-256-cbc")) {
        ue_stacktrace_push_msg("Failed to decipher cipher data");
        goto clean_up;
    }

    if (!ue_byte_writer_append_bytes(stream, decipher_data, decipher_data_size)) {
		ue_stacktrace_push_msg("Failed to write deciphered client CSR");
		goto clean_up;
	}
	ue_byte_stream_set_position(stream, 0);

    ue_byte_read_next_int(stream, &read_int);
    if (read_int == 0) {
        ue_stacktrace_push_msg("Failed to read decipher client request size");
        goto clean_up;
    }
    decipher_client_request_size = read_int;

    ue_byte_read_next_int(stream, &read_int);
    if (read_int == 0) {
        ue_stacktrace_push_msg("Failed to read future key size");
        goto clean_up;
    }
    key_size = read_int;

    ue_byte_read_next_int(stream, &read_int);
    if (read_int == 0) {
        ue_stacktrace_push_msg("Failed to read future IV size");
        goto clean_up;
    }
    iv_size = read_int;

    if (!(ue_byte_read_next_bytes(stream, &decipher_client_request, decipher_client_request_size))) {
        ue_stacktrace_push_msg("Failed to read decipher client request");
        goto clean_up;
    }

    if (!(ue_byte_read_next_bytes(stream, &key_data, key_size))) {
        ue_stacktrace_push_msg("Failed to read asym key to use");
        goto clean_up;
    }

    if (!(ue_byte_read_next_bytes(stream, &iv, iv_size))) {
        ue_stacktrace_push_msg("Failed to read IV to use");
        goto clean_up;
    }

    if (!(key = ue_sym_key_create(key_data, key_size))) {
        ue_stacktrace_push_msg("Failed to create sym key");
        goto clean_up;
    }

    if (!(csr = ue_x509_bytes_to_csr(decipher_client_request, decipher_client_request_size))) {
        ue_stacktrace_push_msg("Failed to convert decipher bytes to x509 CSR");
        goto clean_up;
    }

    if (!(*signed_certificate = ue_x509_certificate_sign_from_csr(csr, ca_certificate, ca_private_key))) {
        ue_stacktrace_push_msg("Failed to gen certificate from client certificate");
        goto clean_up;
    }

    if (!(string_pem_certificate = ue_x509_certificate_to_pem_string(*signed_certificate))) {
        ue_stacktrace_push_msg("Failed to convert certificate to PEM string");
        goto clean_up;
    }

    sym_encrypter = ue_sym_encrypter_default_create(key);
	if (!ue_sym_encrypter_encrypt(sym_encrypter, (unsigned char *)string_pem_certificate, strlen(string_pem_certificate), iv, &server_response, server_response_size)) {
		ue_stacktrace_push_msg("Failed to encrypt csr content");
		goto clean_up;
	}

clean_up:
    ue_safe_free(decipher_data);
    ue_safe_free(decipher_client_request);
    ue_safe_free(iv);
    ue_byte_stream_destroy(stream);
    ue_sym_key_destroy(key);
    ue_safe_free(key_data);
    ue_sym_encrypter_destroy(sym_encrypter);
    ue_x509_csr_destroy(csr);
    ue_safe_free(string_pem_certificate);
    return server_response;
}
