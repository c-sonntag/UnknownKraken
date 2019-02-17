/*******************************************************************************
 * Copyright (C) 2018 Charly Lamothe                                           *
 *                                                                             *
 * This file is part of LibUnknownEchoCryptoModule.                            *
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

#include <uk/crypto/api/csr/csr_request.h>
#include <uk/crypto/api/certificate/x509_csr.h>
#include <uk/crypto/api/certificate/x509_certificate_sign.h>
#include <uk/crypto/api/cipher/data_cipher.h>
#include <uk/crypto/api/encryption/sym_encrypter.h>
#include <uk/crypto/factory/sym_encrypter_factory.h>
#include <uk/utils/ei.h>
#include <uk/utils/ueum.h>

static char *generate_csr_string(uk_crypto_x509_certificate *certificate, uk_crypto_private_key *private_key) {
    uk_crypto_x509_csr *csr;
    char *csr_string;

    uk_utils_check_parameter_or_return(certificate);
    uk_utils_check_parameter_or_return(private_key);

    csr_string = NULL;
    csr = NULL;

    if ((csr = uk_crypto_x509_csr_create(certificate, private_key)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to create x509 CRS from certificate and private key");
        return NULL;
    }

    uk_utils_logger_info("Convert x509 CRS to string...");
    if ((csr_string = uk_crypto_x509_csr_to_string(csr)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to convert x509 CRS to string");
        uk_crypto_x509_csr_destroy(csr);
        return NULL;
    }

    uk_crypto_x509_csr_destroy(csr);

    return csr_string;
}

unsigned char *uk_crypto_csr_build_client_request(uk_crypto_x509_certificate *certificate, uk_crypto_private_key *private_key,
    uk_crypto_public_key *ca_public_key, size_t *cipher_data_size, uk_crypto_sym_key *future_key, unsigned char *iv, size_t iv_size,
    const char *cipher_name, const char *digest_name) {

    char *csr_string;
    uk_crypto_public_key *public_key;
    uk_utils_byte_stream *stream;
    unsigned char *cipher_data;

    uk_utils_check_parameter_or_return(certificate);
    uk_utils_check_parameter_or_return(private_key);
    uk_utils_check_parameter_or_return(ca_public_key);
    uk_utils_check_parameter_or_return(future_key);
    uk_utils_check_parameter_or_return(iv);
    uk_utils_check_parameter_or_return(iv_size > 0);

    csr_string = NULL;
    public_key = NULL;
    stream = uk_utils_byte_stream_create();
    cipher_data = NULL;

    if ((csr_string = generate_csr_string(certificate, private_key)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to generate CSR string from certificate and private key");
        goto clean_up;
    }

    if (!uk_utils_byte_writer_append_int(stream, (int)strlen(csr_string))) {
        uk_utils_stacktrace_push_msg("Failed to write CSR string size to stream");
        goto clean_up;
    }
    if (!uk_utils_byte_writer_append_int(stream, (int)future_key->size)) {
        uk_utils_stacktrace_push_msg("Failed to write future key size to stream");
        goto clean_up;
    }
    if (!uk_utils_byte_writer_append_int(stream, (int)iv_size)) {
        uk_utils_stacktrace_push_msg("Failed to write IV size to stream");
        goto clean_up;
    }
    if (!uk_utils_byte_writer_append_string(stream, csr_string)) {
        uk_utils_stacktrace_push_msg("Failed to write CSR string to stream");
        goto clean_up;
    }
    if (!uk_utils_byte_writer_append_bytes(stream, future_key->data, future_key->size)) {
        uk_utils_stacktrace_push_msg("Failed to write future to stream");
        goto clean_up;
    }
    if (!uk_utils_byte_writer_append_bytes(stream, iv, iv_size)) {
        uk_utils_stacktrace_push_msg("Failed to write IV to stream");
        goto clean_up;
    }

    if (!uk_crypto_cipher_plain_data(uk_utils_byte_stream_get_data(stream), uk_utils_byte_stream_get_size(stream), ca_public_key, NULL, &cipher_data,
        cipher_data_size, cipher_name, digest_name)) {

        uk_utils_stacktrace_push_msg("Failed to cipher plain data");
        goto clean_up;
    }

clean_up:
    uk_crypto_public_key_destroy(public_key);
    uk_utils_byte_stream_destroy(stream);
    uk_utils_safe_free(csr_string);
    return cipher_data;
}

uk_crypto_x509_certificate *uk_crypto_csr_process_server_response(unsigned char *server_response, size_t server_response_size, uk_crypto_sym_key *key,
    unsigned char *iv, size_t iv_size) {

    uk_crypto_sym_encrypter *sym_encrypter;
    uk_crypto_x509_certificate *signed_certificate;
    unsigned char *signed_certificate_buffer;
    size_t signed_certificate_buffer_size;

    uk_utils_check_parameter_or_return(server_response);
    uk_utils_check_parameter_or_return(server_response_size > 0);
    uk_utils_check_parameter_or_return(key);
    uk_utils_check_parameter_or_return(iv);
    uk_utils_check_parameter_or_return(iv_size > 0);

    signed_certificate = NULL;

    sym_encrypter = uk_crypto_sym_encrypter_default_create(key);
    if (!uk_crypto_sym_encrypter_decrypt(sym_encrypter, server_response, server_response_size, iv, &signed_certificate_buffer, &signed_certificate_buffer_size)) {
        uk_utils_stacktrace_push_msg("Failed to decrypt signed certificate");
        goto clean_up;
    }

    if ((signed_certificate = uk_crypto_x509_certificate_load_from_bytes(signed_certificate_buffer, signed_certificate_buffer_size)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to convert bytes to x509 certificate");
    }

clean_up:
    uk_crypto_sym_encrypter_destroy(sym_encrypter);
    uk_utils_safe_free(signed_certificate_buffer);
    return signed_certificate;
}

unsigned char *uk_crypto_csr_build_server_response(uk_crypto_private_key *csr_private_key, uk_crypto_x509_certificate *ca_certificate, uk_crypto_private_key *ca_private_key,
    unsigned char *client_request, size_t client_request_size, size_t *server_response_size, uk_crypto_x509_certificate **signed_certificate,
    const char *cipher_name, const char *digest_name) {

    unsigned char *decipher_data, *server_response, *decipher_client_request, *key_data, *iv;
    size_t decipher_data_size, decipher_client_request_size, key_size, iv_size;
    uk_utils_byte_stream *stream;
    int read_int;
    uk_crypto_sym_key *key;
    uk_crypto_sym_encrypter *sym_encrypter;
    uk_crypto_x509_csr *csr;
    char *string_pem_certificate;
    size_t string_pem_certificate_size;

    decipher_data = NULL;
    server_response = NULL;
    decipher_client_request = NULL;
    stream = uk_utils_byte_stream_create();
    key = NULL;
    sym_encrypter = NULL;
    csr = NULL;
    string_pem_certificate = NULL;
    key_data = NULL;
    iv = NULL;
    string_pem_certificate_size = 0;

    uk_utils_check_parameter_or_return(csr_private_key);
    uk_utils_check_parameter_or_return(ca_certificate);
    uk_utils_check_parameter_or_return(ca_private_key);
    uk_utils_check_parameter_or_return(client_request);
    uk_utils_check_parameter_or_return(client_request_size > 0);

    if (!uk_crypto_decipher_cipher_data(client_request, client_request_size, csr_private_key, NULL, &decipher_data, &decipher_data_size,
        cipher_name, digest_name)) {

        uk_utils_stacktrace_push_msg("Failed to decipher cipher data");
        goto clean_up;
    }

    if (!uk_utils_byte_writer_append_bytes(stream, decipher_data, decipher_data_size)) {
        uk_utils_stacktrace_push_msg("Failed to write deciphered client CSR");
        goto clean_up;
    }
    uk_utils_byte_stream_set_position(stream, 0);

    uk_utils_byte_read_next_int(stream, &read_int);
    if (read_int == 0) {
        uk_utils_stacktrace_push_msg("Failed to read decipher client request size");
        goto clean_up;
    }
    decipher_client_request_size = read_int;

    uk_utils_byte_read_next_int(stream, &read_int);
    if (read_int == 0) {
        uk_utils_stacktrace_push_msg("Failed to read future key size");
        goto clean_up;
    }
    key_size = read_int;

    uk_utils_byte_read_next_int(stream, &read_int);
    if (read_int == 0) {
        uk_utils_stacktrace_push_msg("Failed to read future IV size");
        goto clean_up;
    }
    iv_size = read_int;

    if (!(uk_utils_byte_read_next_bytes(stream, &decipher_client_request, decipher_client_request_size))) {
        uk_utils_stacktrace_push_msg("Failed to read decipher client request");
        goto clean_up;
    }

    if (!(uk_utils_byte_read_next_bytes(stream, &key_data, key_size))) {
        uk_utils_stacktrace_push_msg("Failed to read asym key to use");
        goto clean_up;
    }

    if (!(uk_utils_byte_read_next_bytes(stream, &iv, iv_size))) {
        uk_utils_stacktrace_push_msg("Failed to read IV to use");
        goto clean_up;
    }

    if ((key = uk_crypto_sym_key_create(key_data, key_size)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to create sym key");
        goto clean_up;
    }

    if ((csr = uk_crypto_x509_bytes_to_csr(decipher_client_request, decipher_client_request_size)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to convert decipher bytes to x509 CSR");
        goto clean_up;
    }

    if ((*signed_certificate = uk_crypto_x509_certificate_sign_from_csr(csr, ca_certificate, ca_private_key)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to gen certificate from client certificate");
        goto clean_up;
    }

    if ((string_pem_certificate = uk_crypto_x509_certificate_to_pem_string(*signed_certificate, &string_pem_certificate_size)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to convert certificate to PEM string");
        goto clean_up;
    }

    sym_encrypter = uk_crypto_sym_encrypter_default_create(key);
    if (!uk_crypto_sym_encrypter_encrypt(sym_encrypter, (unsigned char *)string_pem_certificate, string_pem_certificate_size, iv, &server_response, server_response_size)) {
        uk_utils_stacktrace_push_msg("Failed to encrypt csr content");
        goto clean_up;
    }

clean_up:
    uk_utils_safe_free(decipher_data);
    uk_utils_safe_free(decipher_client_request);
    uk_utils_safe_free(iv);
    uk_utils_byte_stream_destroy(stream);
    uk_crypto_sym_key_destroy(key);
    uk_utils_safe_free(key_data);
    uk_crypto_sym_encrypter_destroy(sym_encrypter);
    uk_crypto_x509_csr_destroy(csr);
    uk_utils_safe_free(string_pem_certificate);
    return server_response;
}
