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

#include <unknownecho/init.h>
#include <unknownecho/bool.h>
#include <unknownecho/time/timer.h>
#include <unknownecho/crypto/api/key/public_key.h>
#include <unknownecho/crypto/api/key/private_key.h>
#include <unknownecho/crypto/api/key/asym_key.h>
#include <unknownecho/crypto/api/certificate/x509_certificate.h>
#include <unknownecho/crypto/api/certificate/x509_certificate_sign.h>
#include <unknownecho/crypto/api/certificate/x509_csr.h>
#include <unknownecho/crypto/api/certificate/x509_certificate_parameters.h>
#include <unknownecho/crypto/api/certificate/x509_certificate_generation.h>
#include <unknownecho/crypto/api/cipher/data_cipher.h>
#include <unknownecho/crypto/api/encryption/sym_encrypter.h>
#include <unknownecho/crypto/utils/crypto_random.h>
#include <unknownecho/crypto/factory/rsa_asym_key_factory.h>
#include <unknownecho/crypto/factory/sym_key_factory.h>
#include <unknownecho/crypto/factory/sym_encrypter_factory.h>
#include <unknownecho/alloc.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/byte/byte_utility.h>
#include <unknownecho/byte/byte_writer.h>
#include <unknownecho/byte/byte_reader.h>
#include <unknownecho/byte/byte_stream.h>

#include <string.h>
#include <stddef.h>
#include <stdio.h>

bool generate_certificate(ue_x509_certificate **certificate, ue_private_key **private_key) {
    bool result;
    ue_x509_certificate_parameters *parameters;

	result = false;
	parameters = NULL;

	if (!(parameters = ue_x509_certificate_parameters_create())) {
		ue_stacktrace_push_msg("Failed to create x509 parameters structure");
		return false;
	}

    if (!ue_x509_certificate_parameters_set_country(parameters, "FR")) {
		ue_stacktrace_push_msg("Failed to set C to x509 parameters");
		goto clean_up;
	}

    if (!ue_x509_certificate_parameters_set_common_name(parameters, "CLIENT")) {
		ue_stacktrace_push_msg("Failed to set CN to x509 parameters");
		goto clean_up;
	}

    if (!ue_x509_certificate_parameters_set_ca_type(parameters)) {
		ue_stacktrace_push_msg("Failed to set certificate as ca type");
		goto clean_up;
	}

    if (!ue_x509_certificate_parameters_set_subject_key_identifier_as_hash(parameters)) {
		ue_stacktrace_push_msg("Failed to set certificate subject key identifier as hash");
		goto clean_up;
	}

    if (!ue_x509_certificate_parameters_set_self_signed(parameters)) {
		ue_stacktrace_push_msg("Failed to set certificate as self signed");
		goto clean_up;
	}

    if (!ue_x509_certificate_generate(parameters, certificate, private_key)) {
		ue_stacktrace_push_msg("Failed to generate certificate and relative private key");
		goto clean_up;
	}

    result = true;

clean_up:
    ue_x509_certificate_parameters_destroy(parameters);
    return result;
}

char *generate_csr_string(ue_x509_certificate *certificate, ue_private_key *private_key) {
    ue_x509_csr *csr;
    char *csr_string;

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

unsigned char *client_build_request(ue_public_key *ca_public_key, size_t *cipher_data_size, ue_sym_key *future_key, unsigned char *iv, size_t iv_size) {
    ue_x509_certificate *certificate;
    ue_private_key *private_key;
    char *csr_string;
    ue_public_key *public_key;
    ue_byte_stream *stream;
    unsigned char *cipher_data;

    certificate = NULL;
    private_key = NULL;
    csr_string = NULL;
    public_key = NULL;
    stream = ue_byte_stream_create();
    cipher_data = NULL;

    if (!generate_certificate(&certificate, &private_key)) {
        ue_stacktrace_push_msg("Failed to generate x509 certificate and private key");
        goto clean_up;
    }

    csr_string = generate_csr_string(certificate, private_key);

    ue_byte_writer_append_int(stream, (int)strlen(csr_string));
    ue_byte_writer_append_int(stream, (int)future_key->size);
    ue_byte_writer_append_int(stream, (int)iv_size);
    ue_byte_writer_append_string(stream, csr_string);
    ue_byte_writer_append_bytes(stream, future_key->data, future_key->size);
    ue_byte_writer_append_bytes(stream, iv, iv_size);

    if (!ue_cipher_plain_data(ue_byte_stream_get_data(stream), ue_byte_stream_get_size(stream), ca_public_key, NULL, &cipher_data, cipher_data_size, "aes-256-cbc")) {
        ue_stacktrace_push_msg("Failed to cipher plain data");
        goto clean_up;
    }

clean_up:
    ue_x509_certificate_destroy(certificate);
    ue_private_key_destroy(private_key);
    ue_public_key_destroy(public_key);
    ue_byte_stream_destroy(stream);
    ue_safe_free(csr_string);
    return cipher_data;
}

unsigned char *server_process_response(ue_x509_certificate *ca_certificate, ue_public_key *ca_public_key, ue_private_key *ca_private_key, unsigned char *client_request, size_t client_request_size, size_t *server_response_size) {
    unsigned char *decipher_data, *server_response, *decipher_client_request, *key_data, *iv;
    size_t decipher_data_size, decipher_client_request_size, key_size, iv_size;
    ue_byte_stream *stream;
    int read_int;
    ue_sym_key *key;
    ue_sym_encrypter *sym_encrypter;
    ue_x509_csr *csr;
    ue_x509_certificate *signed_certificate;
    char *string_pem_certificate;

    decipher_data = NULL;
    server_response = NULL;
    decipher_client_request = NULL;
    stream = ue_byte_stream_create();
    key = NULL;
    sym_encrypter = NULL;
    csr = NULL;
    signed_certificate = NULL;
    string_pem_certificate = NULL;
    key_data = NULL;
    iv = NULL;

    if (!ue_decipher_cipher_data(client_request, client_request_size, ca_private_key, NULL, &decipher_data, &decipher_data_size, "aes-256-cbc")) {
        ue_stacktrace_push_msg("Failed to decipher cipher data");
        goto clean_up;
    }

    if (!ue_byte_writer_append_bytes(stream, decipher_data, decipher_data_size)) {
		ue_stacktrace_push_msg("Failed to write deciphered client CRS");
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

    key = ue_sym_key_create(key_data, key_size);

    if (!(csr = ue_x509_bytes_to_csr(decipher_client_request, decipher_client_request_size))) {
        ue_stacktrace_push_msg("Failed to convert decipher bytes to x509 CSR");
        goto clean_up;
    }

    if (!(signed_certificate = ue_x509_certificate_sign_from_csr(csr, ca_certificate, ca_private_key))) {
        ue_stacktrace_push_msg("Failed to gen certificate from client certificate");
        goto clean_up;
    }

    if (!(string_pem_certificate = ue_x509_certificate_to_pem_string(signed_certificate))) {
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
    ue_x509_certificate_destroy(signed_certificate);
    ue_safe_free(string_pem_certificate);
    return server_response;
}

ue_x509_certificate *client_process_server_response(unsigned char *server_response, size_t server_response_size, ue_sym_key *key, unsigned char *iv, size_t iv_size) {
    ue_sym_encrypter *sym_encrypter;
    ue_x509_certificate *signed_certificate;
    unsigned char *signed_certificate_buffer;
    size_t signed_certificate_buffer_size;

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

int main(int argc, char **argv) {
    unsigned char *cipher_data, *server_response, *iv;
    size_t cipher_data_size, server_response_size, iv_size;
    ue_x509_certificate *signed_certificate, *ca_certificate;
    ue_sym_key *future_key;
    ue_public_key *ca_public_key;
    ue_private_key *ca_private_key;

    ue_init();

    cipher_data = NULL;
    server_response = NULL;
    iv = NULL;
    signed_certificate = NULL;
    future_key = NULL;

    ue_safe_alloc(iv, unsigned char, 16);
	if (!(ue_crypto_random_bytes(iv, 16))) {
		ue_stacktrace_push_msg("Failed to get crypto random bytes for IV");
		goto clean_up;
	}
	iv_size = 16;

    if (!(future_key = ue_sym_key_create_random())) {
        ue_stacktrace_push_msg("Failed to gen random sym key");
        goto clean_up;
    }

    ue_x509_certificate_load_from_file(argv[1], &ca_certificate);
    ca_public_key = ue_rsa_public_key_from_x509_certificate(ca_certificate);

    if (!(ca_private_key = ue_rsa_private_key_from_key_certificate(argv[2]))) {
        ue_stacktrace_push_msg("Failed to load RSA key certificate from file '%s'", argv[2]);
        goto clean_up;
    }

    if (!(cipher_data = client_build_request(ca_public_key, &cipher_data_size, future_key, iv, iv_size))) {
        ue_stacktrace_push_msg("Failed to cipher client request");
        goto clean_up;
    }

    if (!(server_response = server_process_response(ca_certificate, ca_public_key, ca_private_key, cipher_data, cipher_data_size, &server_response_size))) {
        ue_stacktrace_push_msg("Failed to process client request as server");
        goto clean_up;
    }

    if (!(signed_certificate = client_process_server_response(server_response, server_response_size, future_key, iv, iv_size))) {
        ue_stacktrace_push_msg("Failed to process server response as client");
        goto clean_up;
    }

    if (ue_x509_certificate_verify(signed_certificate, ca_certificate)) {
        ue_logger_info("Certificate is correctly signed by the CA");
    } else {
        ue_logger_error("Certificate isn't correctly signed by the CA");
    }

clean_up:
    ue_safe_free(cipher_data);
    ue_sym_key_destroy(future_key);
    ue_safe_free(iv);
    ue_x509_certificate_destroy(signed_certificate);
    ue_safe_free(server_response);
    ue_x509_certificate_destroy(ca_certificate);
    ue_public_key_destroy(ca_public_key);
    ue_private_key_destroy(ca_private_key);
    if (ue_stacktrace_is_filled()) {
        ue_logger_error("Error(s) occurred with the following stacktrace(s) :");
        ue_stacktrace_print_all();
    }
    ue_uninit();
    return 0;
}
