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
#include <unknownecho/network/api/socket/socket_server.h>
#include <unknownecho/network/api/socket/socket_client_connection.h>
#include <unknownecho/network/api/socket/socket.h>
#include <unknownecho/network/api/tls/tls_context.h>
#include <unknownecho/network/api/tls/tls_session.h>
#include <unknownecho/string/string_utility.h>
#include <unknownecho/thread/thread_id_struct.h>
#include <unknownecho/thread/thread.h>
#include <unknownecho/thread/thread_mutex.h>
#include <unknownecho/thread/thread_cond.h>
#include <unknownecho/alloc.h>
#include <unknownecho/bool.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/errorHandling/check_parameter.h>
#include <unknownecho/crypto/api/key/public_key.h>
#include <unknownecho/crypto/api/key/private_key.h>
#include <unknownecho/crypto/api/certificate/x509_certificate.h>
#include <unknownecho/crypto/api/certificate/x509_certificate_sign.h>
#include <unknownecho/crypto/api/certificate/x509_csr.h>
#include <unknownecho/crypto/api/cipher/data_cipher.h>
#include <unknownecho/crypto/api/keystore/pkcs12_keystore.h>
#include <unknownecho/crypto/api/encryption/sym_encrypter.h>
#include <unknownecho/crypto/factory/x509_certificate_factory.h>
#include <unknownecho/crypto/factory/sym_key_factory.h>
#include <unknownecho/crypto/factory/sym_encrypter_factory.h>
#include <unknownecho/crypto/factory/pkcs12_keystore_factory.h>
#include <unknownecho/crypto/factory/rsa_asym_key_factory.h>
#include <unknownecho/crypto/utils/crypto_random.h>
#include <unknownecho/crypto/utils/friendly_name.h>
#include <unknownecho/byte/byte_utility.h>
#include <unknownecho/byte/byte_writer.h>
#include <unknownecho/byte/byte_reader.h>
#include <unknownecho/byte/byte_stream.h>
#include <unknownecho/byte/byte_split.h>
#include <unknownecho/container/byte_vector.h>
#include <unknownecho/fileSystem/file_utility.h>
#include <unknownecho/input.h>

#include <stdlib.h>
#include <signal.h>
#include <stddef.h>
#include <string.h>
#include <limits.h>
#include <stdio.h>

#define CSR_SERVER_CERTIFICATE_PATH    "out/server/certificate/csr_server.pem"
#define CSR_SERVER_KEY_PATH            "out/server/certificate/csr_server_key.pem"
#define TLS_SERVER_CERTIFICATE_PATH    "out/server/certificate/tls_server.pem"
#define TLS_SERVER_KEY_PATH            "out/server/certificate/tls_server_key.pem"
#define CIPHER_SERVER_CERTIFICATE_PATH "out/server/certificate/cipher_server.pem"
#define CIPHER_SERVER_KEY_PATH         "out/server/certificate/cipher_server_key.pem"
#define SIGNER_SERVER_CERTIFICATE_PATH "out/server/certificate/signer_server.pem"
#define SIGNER_SERVER_KEY_PATH         "out/server/certificate/signer_server_key.pem"
#define SERVER_KEY_PASSWORD            "passphrase"
#define CSR_KEYSTORE_PATH              "out/server/keystore/csr_server_keystore.p12"
#define TLS_KEYSTORE_PATH              "out/server/keystore/tls_server_keystore.p12"
#define CIPHER_KEYSTORE_PATH           "out/server/keystore/cipher_server_keystore.p12"
#define SIGNER_KEYSTORE_PATH           "out/server/keystore/signer_server_keystore.p12"
#define CSR_SERVER_PORT                5002
#define TLS_SERVER_PORT                5001
#define LOGGER_FILE_PATH               "out/server/logs.txt"

#define CHANNELS_NUMBER 3

#define CHANNEL_KEY_REQUEST         1
#define DISCONNECTION_NOW_REQUEST   2
#define SHUTDOWN_NOW_REQUEST        3
#define CHANNEL_CONNECTION_REQUEST  4
#define GET_CERTIFICATE_REQUEST     5
#define NICKNAME_REQUEST            6
#define CHANNEL_KEY_REQUEST_ANSWER  7
#define CHANNEL_CONNECTION_RESPONSE 8
#define CHANNEL_KEY_RESPONSE        9
#define CHANNEL_KEY_CREATOR_STATE   10
#define WAIT_CHANNEL_KEY_STATE      11
#define MESSAGE                     12
#define CSR_TLS_REQUEST             13
#define CSR_CIPHER_REQUEST          14
#define CSR_SIGNER_REQUEST          15
#define CERTIFICATE_RESPONSE        16
#define NICKNAME_RESPONSE           17
#define CSR_TLS_RESPONSE            18
#define CSR_CIPHER_RESPONSE         19
#define CSR_SIGNER_RESPONSE         20
#define ALREADY_CONNECTED_RESPONSE  21

typedef struct {
    ue_socket_client_connection **connections;
    int connections_number, max_connections_number;
    bool (*read_consumer)(ue_socket_client_connection *connection);
    bool (*write_consumer)(ue_socket_client_connection *connection);
} channel;

channel *channel_create(bool (*read_consumer)(ue_socket_client_connection *connection), bool (*write_consumer)(ue_socket_client_connection *connection));

void channel_destroy(channel *chan);

bool channel_add_connection(channel *chan, ue_socket_client_connection *connection);

bool channel_remove_connection_by_nickname(channel *chan, char *nickname);

bool channels_remove_connection_by_nickname(channel **channels, int channels_number, char *nickname);

channel *channel_create(bool (*read_consumer)(ue_socket_client_connection *connection), bool (*write_consumer)(ue_socket_client_connection *connection)) {
    channel *chan;
    int i;

    ue_safe_alloc(chan, channel, 1);
    chan->max_connections_number = 10;
    ue_safe_alloc(chan->connections, ue_socket_client_connection *, chan->max_connections_number);
    for (i = 0; i < chan->max_connections_number; i++) {
        chan->connections[i] = NULL;
    }
    chan->connections_number = 0;
    chan->read_consumer = read_consumer;
    chan->write_consumer = write_consumer;

    return chan;
}

void channel_destroy(channel *chan) {
    if (chan) {
        ue_safe_free(chan->connections);
        ue_safe_free(chan);
    }
}

bool channel_add_connection(channel *chan, ue_socket_client_connection *connection) {
    int i;

    if (!chan) {
        ue_stacktrace_push_msg("Specified chan is null");
        return false;
    }

    if (!connection) {
        ue_stacktrace_push_msg("Specified connection is null");
        return false;
    }

    if (!ue_socket_client_connection_is_established(connection)) {
        ue_stacktrace_push_msg("Specified connection isn't establish");
        return false;
    }

    if (chan->connections_number == chan->max_connections_number) {
        ue_stacktrace_push_msg("No such slot available");
        return false;
    }

    for (i = 0; i < chan->max_connections_number; i++) {
        if (chan->connections[i] == NULL) {
            chan->connections[i] = connection;
            chan->connections_number++;
            return true;
        }
    }

    return false;
}

bool channel_remove_connection_by_nickname(channel *chan, char *nickname) {
    int i;

    if (!chan) {
        ue_stacktrace_push_msg("Specified chan is null");
        return false;
    }

    if (!nickname) {
        ue_stacktrace_push_msg("Specified nickname is null");
        return false;
    }

    if (!chan->connections) {
        return true;
    }

    if (chan->connections_number == 0) {
        return true;
    }

    for (i = 0; i < chan->max_connections_number; i++) {
        if (chan->connections[i] && strcmp(chan->connections[i]->nickname, nickname) == 0) {
            ue_safe_free(chan->connections[i]->optional_data);
            chan->connections[i]->optional_data = NULL;
            chan->connections[i] = NULL;
            chan->connections_number--;
            return true;
        }
    }

    ue_logger_trace("There's no client connection with this nickname in this channel");

    return true;
}

bool channels_remove_connection_by_nickname(channel **channels, int channels_number, char *nickname) {
    int i;

    if (!channels) {
        ue_stacktrace_push_msg("Specified channels is null");
        return false;
    }

    if (!nickname) {
        ue_stacktrace_push_msg("Specified nickname is null");
        return false;
    }

    for (i = 0; i < channels_number; i++) {
        if (!channel_remove_connection_by_nickname(channels[i], nickname)) {
            ue_logger_warn("Failed to remove connection by nickname in channel id %d", i);
        }
    }

    return true;
}

ue_socket_client_connection *channel_get_availabe_connection_for_channel_key(channel *channel, ue_socket_client_connection *unused_connection) {
    int i;

    for (i = 0; i < channel->max_connections_number; i++) {
        if (channel->connections[i] && channel->connections[i] != unused_connection) {
            return channel->connections[i];
        }
    }

    return NULL;
}

typedef enum {
    WORKING_STATE,
    FREE_STATE
} request_processing_state;

typedef struct {
    ue_socket_server *csr_server, *tls_server;
	ue_thread_mutex *csr_server_mutex, *tls_server_mutex;
	ue_thread_cond *csr_server_cond, *tls_server_cond;
	request_processing_state csr_server_processing_state, tls_server_processing_state;
	ue_tls_session *tls_session;
    channel **channels;
    int channels_number;
    ue_thread_id *csr_server_thread, *tls_server_thread;
    bool signal_caught;
    char *keystore_password;
    ue_pkcs12_keystore *csr_keystore, *tls_keystore, *cipher_keystore, *signer_keystore;
    FILE *logs_file;
} socket_server_manager;

socket_server_manager *instance = NULL;

void handle_signal(int sig, void (*h)(int), int options) {
    struct sigaction s;

    s.sa_handler = h;
    sigemptyset(&s.sa_mask);
    s.sa_flags = options;
    if (sigaction(sig, &s, NULL) < 0) {
        ue_stacktrace_push_errno()
    }
}

void shutdown_server(int sig) {
    ue_logger_trace("Signal received %d", sig);
    ue_logger_info("Shuting down server...");
    instance->signal_caught = true;
    if (instance->tls_server) {
        instance->tls_server->running = false;
    }
    if (instance->csr_server) {
        instance->csr_server->running = false;
    }

    ue_thread_cancel(instance->csr_server_thread);
    ue_thread_cancel(instance->tls_server_thread);
}

unsigned char *csr_server_process_response(ue_private_key *csr_private_key, ue_x509_certificate *ca_certificate, ue_private_key *ca_private_key,
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

bool record_client_certificate(ue_x509_certificate *signed_certificate, int csr_sub_type, unsigned char *friendly_name, size_t friendly_name_size) {
    bool result;
    ue_pkcs12_keystore *keystore;
    const char *keystore_path;

    ue_check_parameter_or_return(signed_certificate);
    ue_check_parameter_or_return(friendly_name);
    ue_check_parameter_or_return(friendly_name_size > 0);

    result = false;
    keystore = NULL;

    if (csr_sub_type == CSR_TLS_REQUEST) {
        keystore = instance->tls_session->keystore;
        keystore_path = TLS_KEYSTORE_PATH;
    }
    else if (csr_sub_type == CSR_CIPHER_REQUEST) {
        keystore = instance->cipher_keystore;
        keystore_path = CIPHER_KEYSTORE_PATH;
    }
    else if (csr_sub_type == CSR_SIGNER_REQUEST) {
        keystore = instance->signer_keystore;
        keystore_path = SIGNER_KEYSTORE_PATH;
    }
    else {
        ue_stacktrace_push_msg("Unknown CSR sub type '%d'", csr_sub_type);
        goto clean_up;
    }

    if (!ue_pkcs12_keystore_add_certificate(keystore, signed_certificate, (const unsigned char *)friendly_name, friendly_name_size)) {
        ue_stacktrace_push_msg("Failed to add signed certificate to keystore");
        goto clean_up;
    }

    /* @todo update keystore periodically with a mutex, and not each time */
    if (!ue_pkcs12_keystore_write(keystore, keystore_path, instance->keystore_password)) {
        ue_stacktrace_push_msg("Failed to write new keystore to '%s'", keystore_path);
        goto clean_up;
    }

    result = true;

clean_up:
    return result;
}

bool distribute_client_certificate(ue_x509_certificate *signed_certificate, unsigned char *friendly_name, size_t friendly_name_size) {
    int i;
    char *certificate_data;

    ue_check_parameter_or_return(signed_certificate);
    ue_check_parameter_or_return(friendly_name);
    ue_check_parameter_or_return(friendly_name_size > 0);

    if (!(certificate_data = ue_x509_certificate_to_pem_string(signed_certificate))) {
        ue_stacktrace_push_msg("Failed to convert signed certificate from PEM to string");
        return false;
    }

    for (i = 0; i < instance->tls_server->connections_number; i++) {
        if (!instance->tls_server->connections[i]) {
            continue;
        }
        if (ue_socket_client_connection_is_available(instance->tls_server->connections[i])) {
            continue;
        }

        ue_byte_stream_clean_up(instance->tls_server->connections[i]->message_to_send);

        if (!ue_byte_writer_append_int(instance->tls_server->connections[i]->message_to_send, CERTIFICATE_RESPONSE)) {
            ue_logger_warn("Failed to write CERTIFICATE_RESPONSE type to connection %d", i);
            continue;
        }

        if (!ue_byte_writer_append_int(instance->tls_server->connections[i]->message_to_send, (int)friendly_name_size)) {
            ue_logger_warn("Failed to write friendly name size to connection %d", i);
            continue;
        }

        if (!ue_byte_writer_append_bytes(instance->tls_server->connections[i]->message_to_send, friendly_name, friendly_name_size)) {
            ue_logger_warn("Failed to write friendly name to connection %d", i);
            continue;
        }

        if (!ue_byte_writer_append_int(instance->tls_server->connections[i]->message_to_send, (int)strlen(certificate_data))) {
            ue_logger_warn("Failed to write certificate data size to connection %d", i);
            continue;
        }

        if (!ue_byte_writer_append_string(instance->tls_server->connections[i]->message_to_send, certificate_data)) {
            ue_logger_warn("Failed to write certificate data to connection %d", i);
            continue;
        }
    }

    ue_safe_free(certificate_data);

    return true;
}

bool csr_server_process_request(void *parameter) {
    bool result;
    ue_socket_client_connection *connection;
    int i, csr_sub_type, nickname_size, csr_request_size, response_type;
    ue_x509_certificate *ca_certificate, *signed_certificate;
    ue_private_key *ca_private_key;
    unsigned char *signed_certificate_data, *nickname, *csr_request, *friendly_name;
    size_t signed_certificate_data_size, friendly_name_size;

    connection = (ue_socket_client_connection *)parameter;
    result = false;
    ca_certificate = NULL;
    ca_private_key = NULL;
    signed_certificate = NULL;
    signed_certificate_data = NULL;
    signed_certificate_data_size = 0;
    nickname = NULL;
    csr_request = NULL;
    friendly_name = NULL;

    ue_thread_mutex_lock(instance->csr_server_mutex);
    while (instance->csr_server_processing_state == WORKING_STATE) {
        if (!ue_thread_cond_wait(instance->csr_server_cond, instance->csr_server_mutex)) {
            ue_logger_warn("Wait failed. Possible deadlock detected.");
            instance->tls_server_processing_state = FREE_STATE;
            return false;
        }
    }
    ue_thread_mutex_unlock(instance->csr_server_mutex);
    instance->csr_server_processing_state = WORKING_STATE;

    for (i = 0; i < ue_byte_vector_size(connection->all_messages); i++) {
        if (!ue_byte_vector_get(connection->all_messages, i) || !ue_byte_vector_get(connection->all_messages, i)->data) {
            continue;
        }

        ue_byte_stream_clean_up(connection->tmp_stream);
        if (!ue_byte_writer_append_bytes(connection->tmp_stream, ue_byte_vector_get(connection->all_messages, i)->data, ue_byte_vector_get(connection->all_messages, i)->size)) {
            ue_stacktrace_push_msg("Failed to split current message");
            goto clean_up;
        }

        ue_byte_stream_set_position(connection->tmp_stream, 0);

        if (!ue_byte_read_next_int(connection->tmp_stream, &csr_sub_type)) {
            ue_stacktrace_push_msg("Failed to append CSR sub type in connection temp stream");
            goto clean_up;
        }

        if (csr_sub_type == CSR_TLS_REQUEST ||
            csr_sub_type == CSR_CIPHER_REQUEST ||
            csr_sub_type == CSR_SIGNER_REQUEST) {

            if (!ue_byte_read_next_int(connection->tmp_stream, &nickname_size)) {
                ue_stacktrace_push_msg("Failed to read nickname size");
                goto clean_up;
            }
            if (!ue_byte_read_next_bytes(connection->tmp_stream, &nickname, (size_t)nickname_size)) {
                ue_stacktrace_push_msg("Failed to read nickname");
                goto clean_up;
            }
            if (!ue_byte_read_next_int(connection->tmp_stream, &csr_request_size)) {
                ue_stacktrace_push_msg("Failed to read CSR request size");
                goto clean_up;
            }
            if (!ue_byte_read_next_bytes(connection->tmp_stream, &csr_request, (size_t)csr_request_size)) {
                ue_stacktrace_push_msg("Failed to read CSR request");
                goto clean_up;
            }

            ue_logger_trace("CSR server has receive a request");

            if (csr_sub_type == CSR_TLS_REQUEST) {
                ca_certificate = instance->tls_keystore->certificate;
                ca_private_key = instance->tls_keystore->private_key;
                if (!(friendly_name = ue_friendly_name_build(nickname, (size_t)nickname_size, "TLS", &friendly_name_size))) {
                    ue_stacktrace_push_msg("Failed to build friendly name for TLS keystore");
                    goto clean_up;
                }
                response_type = CSR_TLS_RESPONSE;
            }
            else if (csr_sub_type == CSR_CIPHER_REQUEST) {
                ca_certificate = instance->cipher_keystore->certificate;
                ca_private_key = instance->cipher_keystore->private_key;
                if (!(friendly_name = ue_friendly_name_build(nickname, (size_t)nickname_size, "CIPHER", &friendly_name_size))) {
                    ue_stacktrace_push_msg("Failed to build friendly name for CIPHER keystore");
                    goto clean_up;
                }
                response_type = CSR_CIPHER_RESPONSE;
            }
            else if (csr_sub_type == CSR_SIGNER_REQUEST) {
                ca_certificate = instance->signer_keystore->certificate;
                ca_private_key = instance->signer_keystore->private_key;
                if (!(friendly_name = ue_friendly_name_build(nickname, (size_t)nickname_size, "SIGNER", &friendly_name_size))) {
                    ue_stacktrace_push_msg("Failed to build friendly name for SIGNER keystore");
                    goto clean_up;
                }
                response_type = CSR_SIGNER_RESPONSE;
            }
            else {
                ue_stacktrace_push_msg("Unknown CSR sub type '%d'", csr_sub_type);
                goto clean_up;
            }

            if (!(signed_certificate_data = csr_server_process_response(instance->csr_keystore->private_key, ca_certificate, ca_private_key,
                csr_request, (size_t)csr_request_size, &signed_certificate_data_size, &signed_certificate))) {

                ue_stacktrace_push_msg("Failed to process CSR response");
                goto clean_up;
            }

            if (!record_client_certificate(signed_certificate, csr_sub_type, friendly_name, friendly_name_size)) {
                ue_stacktrace_push_msg("Failed to record signed certificate");
                ue_x509_certificate_destroy(signed_certificate);
                goto clean_up;
            }

            if (!distribute_client_certificate(signed_certificate, friendly_name, friendly_name_size)) {
                ue_stacktrace_push_msg("Failed to distribute client certificate");
                goto clean_up;
            }

            ue_byte_stream_clean_up(connection->message_to_send);
            if (!ue_byte_writer_append_int(connection->message_to_send, response_type)) {
                ue_stacktrace_push_msg("Failed to write response type to message to send");
                goto clean_up;
            }
            if (!ue_byte_writer_append_int(connection->message_to_send, (size_t)signed_certificate_data_size)) {
                ue_stacktrace_push_msg("Failed to write signed certificate data size to message to send");
                goto clean_up;
            }
            if (!ue_byte_writer_append_bytes(connection->message_to_send, signed_certificate_data, signed_certificate_data_size)) {
                ue_stacktrace_push_msg("Failed to write signed certificate data to message to send");
                goto clean_up;
            }
            connection->state = UNKNOWNECHO_CONNECTION_WRITE_STATE;
            result = true;
clean_up:
            if (ue_stacktrace_is_filled()) {
                /* @todo send a response to the client in case of error */
                ue_logger_stacktrace("An error occured with the following stacktrace :");
                ue_stacktrace_clean_up();
            }
            ue_byte_vector_remove(connection->all_messages, i);
            ue_safe_free(nickname);
            //break;
        } else {
            ue_logger_warn("Received invalid data from client.");
        }
        ue_byte_vector_remove(connection->all_messages, i);
    }

    instance->csr_server_processing_state = FREE_STATE;

    return result;
}

bool csr_server_read_consumer(ue_socket_client_connection *connection) {
    size_t received;
    ue_thread_id *request_processor_thread;

    if (!instance->csr_server->running) {
        return false;
    }

    request_processor_thread = NULL;

    ue_byte_stream_clean_up(connection->received_message);
    received = ue_socket_receive_bytes_sync(connection->fd, connection->received_message, false, NULL);

    if (received == 0) {
        ue_logger_info("Client has disconnected.");
        ue_socket_client_connection_clean_up(connection);
    }
    else if (received < 0 || received == ULLONG_MAX) {
        ue_stacktrace_push_msg("Error while receiving message")
        ue_socket_client_connection_clean_up(connection);
        return false;
    }
    else {
        ue_byte_vector_clean_up(connection->tmp_message);
        ue_byte_vector_append_bytes(connection->all_messages, ue_byte_stream_get_data(connection->received_message), ue_byte_stream_get_size(connection->received_message));
        _Pragma("GCC diagnostic push")
        _Pragma("GCC diagnostic ignored \"-Wpedantic\"")
            request_processor_thread = ue_thread_create((void *)csr_server_process_request, (void *)connection);
        _Pragma("GCC diagnostic pop")
        ue_thread_join(request_processor_thread, NULL);
    }

    ue_safe_free(request_processor_thread)

    return true;
}

bool csr_server_write_consumer(ue_socket_client_connection *connection) {
    size_t sent;

    if (!instance->csr_server->running) {
        return false;
    }

    if (connection->message_to_send->position > 0) {
        ue_logger_trace("Request received from CSR server starts with 'CSR'");
        if (ue_socket_client_connection_is_available(connection)) {
            ue_logger_info("Client connection isn't available");
            return false;
        }
        if (connection->message_to_send->position == 0) {
            ue_logger_info("Message to send is empty");
            connection->state = UNKNOWNECHO_CONNECTION_READ_STATE;
            return false;
        }
        sent = ue_socket_send_data(connection->fd, ue_byte_stream_get_data(connection->message_to_send),
            ue_byte_stream_get_size(connection->message_to_send), NULL);
        if (sent == 0) {
            ue_logger_info("Client has disconnected.");
            return true;
        }
        else if (sent < 0 || sent == ULLONG_MAX) {
            ue_stacktrace_push_msg("Error while sending message")
            ue_socket_client_connection_clean_up(connection);
            return false;
        }
        else {
            connection->state = UNKNOWNECHO_CONNECTION_READ_STATE;
        }
    }

    connection->state = UNKNOWNECHO_CONNECTION_READ_STATE;

    return true;
}

static bool check_suggest_nickname(const char *nickname) {
    int i;

    if (!nickname) {
        return false;
    }

    ue_logger_trace("Check if nickname is already in use.");

    for (i = 0; i < instance->tls_server->connections_number; i++) {
        if (ue_socket_client_connection_is_available(instance->tls_server->connections[i])) {
            continue;
        }

        if (instance->tls_server->connections[i]->nickname && strcmp(instance->tls_server->connections[i]->nickname, nickname) == 0) {
            return false;
        }
    }

    return true;
}

size_t send_cipher_message(ue_socket_client_connection *connection, ue_byte_stream *message_to_send) {
	unsigned char *cipher_data, *friendly_name;
	size_t cipher_data_size, sent, friendly_name_size;
    ue_x509_certificate *client_certificate;
    ue_public_key *client_public_key;
    ue_byte_stream *message_stream;

	cipher_data = NULL;
    client_public_key = NULL;
    sent = -1;
    friendly_name = NULL;

    ue_check_parameter_or_return(connection);
    ue_check_parameter_or_return(connection->nickname);

    message_stream = ue_byte_stream_create();

    if (!ue_byte_writer_append_bytes(message_stream, ue_byte_stream_get_data(message_to_send), ue_byte_stream_get_size(message_to_send))) {
        ue_stacktrace_push_msg("Failed to write message to send to the stream");
        goto clean_up;
    }

    if (!(friendly_name = ue_friendly_name_build((unsigned char *)connection->nickname, strlen(connection->nickname), "CIPHER", &friendly_name_size))) {
        ue_stacktrace_push_msg("Failed to build friendly name for CIPHER keystore with connection->nickname : %s", connection->nickname);
        goto clean_up;
    }

    if (!(client_certificate = ue_pkcs12_keystore_find_certificate_by_friendly_name(instance->cipher_keystore, (const unsigned char *)friendly_name, friendly_name_size))) {
        ue_stacktrace_push_msg("Failed to get cipher client certificate");
        goto clean_up;
    }

    if (!(client_public_key = ue_rsa_public_key_from_x509_certificate(client_certificate))) {
        ue_stacktrace_push_msg("Failed to get client public key from client certificate");
        goto clean_up;
    }

	if (!ue_cipher_plain_data(ue_byte_stream_get_data(message_stream), ue_byte_stream_get_size(message_stream),
	       client_public_key, instance->signer_keystore->private_key, &cipher_data, &cipher_data_size, "aes-256-cbc")) {

        ue_stacktrace_push_msg("Failed to cipher plain data");
        goto clean_up;
    }

	ue_byte_stream_clean_up(message_stream);

	if (!ue_byte_writer_append_bytes(message_stream, cipher_data, cipher_data_size)) {
        ue_stacktrace_push_msg("Failed to write cipher data to message stream");
        goto clean_up;
    }

    sent = ue_socket_send_data(connection->fd, ue_byte_stream_get_data(message_stream),
        ue_byte_stream_get_size(message_stream), connection->tls);

clean_up:
    ue_safe_free(friendly_name);
    ue_public_key_destroy(client_public_key);
	ue_safe_free(cipher_data);
    ue_byte_stream_destroy(message_stream);
	return sent;
}

size_t receive_cipher_message(ue_socket_client_connection *connection) {
	unsigned char *plain_data, *friendly_name;
    size_t received, plain_data_size, friendly_name_size;
    ue_x509_certificate *client_certificate;
	ue_public_key *client_public_key;

	plain_data = NULL;
    client_public_key = NULL;
    friendly_name = NULL;

    ue_check_parameter_or_return(connection);
    ue_check_parameter_or_return(connection->nickname);

    if (!(friendly_name = ue_friendly_name_build((unsigned char *)connection->nickname, strlen(connection->nickname), "SIGNER", &friendly_name_size))) {
        ue_stacktrace_push_msg("Failed to build friendly name for SIGNER keystore with connection->nickname : %s", connection->nickname);
        goto clean_up;
    }

    received = ue_socket_receive_bytes_sync(connection->fd, connection->received_message, false, connection->tls);
	if (received <= 0 || received == ULLONG_MAX) {
		ue_logger_warn("Connection with client is interrupted.");
        goto clean_up;
	}

    if (!(client_certificate = ue_pkcs12_keystore_find_certificate_by_friendly_name(instance->signer_keystore, (const unsigned char *)friendly_name, friendly_name_size))) {
		ue_stacktrace_push_msg("Failed to find client signer certificate");
		received = -1;
		goto clean_up;
	}

    if (!(client_public_key = ue_rsa_public_key_from_x509_certificate(client_certificate))) {
        ue_stacktrace_push_msg("Failed to get client public key from client certificate");
        goto clean_up;
    }

	if (!ue_decipher_cipher_data(ue_byte_stream_get_data(connection->received_message), ue_byte_stream_get_size(connection->received_message),
		instance->cipher_keystore->private_key, client_public_key, &plain_data, &plain_data_size, "aes-256-cbc")) {

		received = -1;
		ue_stacktrace_push_msg("Failed decipher message data");
        goto clean_up;
	}

	ue_byte_stream_clean_up(connection->received_message);

	if (!ue_byte_writer_append_bytes(connection->received_message, plain_data, plain_data_size)) {
        ue_stacktrace_push_msg("Failed to write plain data to received message");
        goto clean_up;
    }

clean_up:
    ue_safe_free(friendly_name);
    ue_public_key_destroy(client_public_key);
	ue_safe_free(plain_data);
	return received;
}

bool process_nickname_request(ue_socket_client_connection *connection, ue_byte_stream *request) {
    bool result;
    int nickname_size;
    unsigned char *nickname;
    char *nickname_string;

    result = false;
    nickname = NULL;
    nickname_string = NULL;

    ue_check_parameter_or_return(connection);
    ue_check_parameter_or_return(request);

    if (!ue_byte_read_next_int(request, &nickname_size)) {
        ue_stacktrace_push_msg("Failed to read nickname size in request");
        goto clean_up;
    }

    if (!ue_byte_read_next_bytes(request, &nickname, (size_t)nickname_size)) {
        ue_stacktrace_push_msg("Failed to read nickname in request");
        goto clean_up;
    }

    if (!(nickname_string = ue_string_create_from_bytes(nickname, nickname_size))) {
        ue_stacktrace_push_msg("Failed to convert nickname from bytes to string");
        goto clean_up;
    }

    ue_byte_stream_clean_up(connection->message_to_send);

    if (!ue_byte_writer_append_int(connection->message_to_send, NICKNAME_RESPONSE)) {
        ue_stacktrace_push_msg("Failed to write NICKNAME_RESPONSE type to message to send");
        goto clean_up;
    }

    if (check_suggest_nickname(nickname_string)) {
        connection->nickname = nickname_string;
        if (!ue_byte_writer_append_int(connection->message_to_send, 1)) {
            ue_stacktrace_push_msg("Failed to write TRUE answer to message to send");
            goto clean_up;
        }
    }
    else {
        ue_safe_free(nickname_string);
        if (!ue_byte_writer_append_int(connection->message_to_send, 0)) {
            ue_stacktrace_push_msg("Failed to write FALSE answer to message to send");
            goto clean_up;
        }
    }

    connection->state = UNKNOWNECHO_CONNECTION_WRITE_STATE;
    result = true;

clean_up:
    ue_safe_free(nickname);
    return result;
}

bool process_channel_connection_request(ue_socket_client_connection *connection, ue_byte_stream *request, int current_channel_id) {
    bool result;
    int channel_id;
    ue_socket_client_connection *channel_key_owner_connection;

    result = false;
    channel_key_owner_connection = NULL;

    ue_check_parameter_or_return(connection);
    ue_check_parameter_or_return(connection->nickname);
    ue_check_parameter_or_return(request);

    ue_byte_stream_clean_up(connection->message_to_send);

    if (!ue_byte_writer_append_int(connection->message_to_send, CHANNEL_CONNECTION_RESPONSE)) {
        ue_stacktrace_push_msg("Failed to write CHANNEL_CONNECTION_RESPONSE to message to send");
        goto clean_up;
    }

    if (!ue_byte_read_next_int(request, &channel_id)) {
        ue_stacktrace_push_msg("Failed to read channel id in request");
        goto clean_up;
    }

    /* @todo override connection ? */
    if (current_channel_id != -1) {
        ue_logger_info("Connection with nickname %s and channel_id %d is already connected but ask for a channel connection", connection->nickname, current_channel_id);
        goto clean_up;
    }
    else if (channel_id < 0 || channel_id > instance->channels_number - 1) {
        ue_logger_warn("Channel id %d is out of range. Channels number of this instance : %d", channel_id, instance->channels_number);
        if (!ue_byte_writer_append_int(connection->message_to_send, 0)) {
            ue_stacktrace_push_msg("Failed to write FALSE answer to message to send");
            goto clean_up;
        }
    } else if (!channel_add_connection(instance->channels[channel_id], connection)) {
        ue_logger_warn("Failed to add connection of nickname '%s' to channel id %d", connection->nickname, channel_id);
        if (!ue_byte_writer_append_int(connection->message_to_send, 0)) {
            ue_stacktrace_push_msg("Failed to write FALSE answer to message to send");
            goto clean_up;
        }
    } else {
        ue_logger_info("Successfully added connection of nickname %s to channel id %d", connection->nickname, channel_id);
        ue_logger_info("Building response...");
        if (!ue_byte_writer_append_int(connection->message_to_send, 1)) {
            ue_stacktrace_push_msg("Failed to write TRUE answer to message to send");
            goto clean_up;
        }
        if (!ue_byte_writer_append_int(connection->message_to_send, channel_id)) {
            ue_stacktrace_push_msg("Failed to write channel id to message to send");
            goto clean_up;
        }

        ue_safe_alloc(connection->optional_data, int, 1);
        memcpy(connection->optional_data, &channel_id, sizeof(int));

        /* If this connection is the only one in this channel, he's the channel key creator */
        if (instance->channels[channel_id]->connections_number == 1) {
            if (!ue_byte_writer_append_int(connection->message_to_send, CHANNEL_KEY_CREATOR_STATE)) {
                ue_stacktrace_push_msg("Failed to write CHANNEL_KEY_CREATOR_STATE to message to send");
                goto clean_up;
            }
        }
        /* Else we have to the key from another client */
        else {
            if (!(channel_key_owner_connection = channel_get_availabe_connection_for_channel_key(instance->channels[channel_id], connection))) {
                ue_stacktrace_push_msg("Failed to found channel key owner connection but connections_number of channel id %d is > 1 (%d)",
                    channel_id, instance->channels[channel_id]->connections_number);
                goto clean_up;
            }
            channel_key_owner_connection->state = UNKNOWNECHO_CONNECTION_WRITE_STATE;
            ue_byte_stream_clean_up(channel_key_owner_connection->message_to_send);
            if (!ue_byte_writer_append_int(channel_key_owner_connection->message_to_send, CHANNEL_KEY_REQUEST)) {
                ue_stacktrace_push_msg("Failed to write CHANNEL_KEY_REQUEST type to message to send");
                goto clean_up;
            }
            if (!ue_byte_writer_append_int(channel_key_owner_connection->message_to_send, (int)strlen(connection->nickname))) {
                ue_stacktrace_push_msg("Failed to write nickname size to message to send");
                goto clean_up;
            }
            if (!ue_byte_writer_append_bytes(channel_key_owner_connection->message_to_send, (unsigned char *)connection->nickname, strlen(connection->nickname))) {
                ue_stacktrace_push_msg("Failed to write nickname to message to send");
                goto clean_up;
            }
            if (!ue_byte_writer_append_int(connection->message_to_send, WAIT_CHANNEL_KEY_STATE)) {
                ue_stacktrace_push_msg("Failed to write WAIT_CHANNEL_KEY_STATE to message to send");
                goto clean_up;
            }
        }
    }

    connection->state = UNKNOWNECHO_CONNECTION_WRITE_STATE;
    result = true;

clean_up:
    return result;
}

bool process_message_request(ue_socket_client_connection *connection, ue_byte_stream *request, int channel_id) {
    bool result;
    unsigned char *nickname, *message;
    int current_channel_id, nickname_size, message_size;

    result = false;
    nickname = NULL;
    current_channel_id = channel_id;

    ue_check_parameter_or_return(connection);
    ue_check_parameter_or_return(request);

    if (!ue_byte_read_next_int(request, &nickname_size)) {
        ue_stacktrace_push_msg("Failed to read nickname size in request");
        goto clean_up;
    }
    if (!ue_byte_read_next_bytes(request, &nickname, (size_t)nickname_size)) {
        ue_stacktrace_push_msg("Failed to read nickname in request");
        goto clean_up;
    }

    if (!ue_byte_read_next_int(request, &message_size)) {
        ue_stacktrace_push_msg("Failed to read message size in request");
        goto clean_up;
    }
    if (!ue_byte_read_next_bytes(request, &message, (size_t)message_size)) {
        ue_stacktrace_push_msg("Failed to read message in request");
        goto clean_up;
    }

    ue_byte_stream_clean_up(connection->message_to_send);
    if (!ue_byte_writer_append_int(connection->message_to_send, MESSAGE)) {
        ue_stacktrace_push_msg("Failed to write MESSAGE type to message to send");
        goto clean_up;
    }
    if (!ue_byte_writer_append_int(connection->message_to_send, nickname_size)) {
        ue_stacktrace_push_msg("Failed to write nickname size to message to send");
        goto clean_up;
    }
    if (!ue_byte_writer_append_bytes(connection->message_to_send, nickname, (size_t)nickname_size)) {
        ue_stacktrace_push_msg("Failed to write nickname to message to send");
        goto clean_up;
    }
    if (!ue_byte_writer_append_int(connection->message_to_send, message_size)) {
        ue_stacktrace_push_msg("Failed to write message size to message to send");
        goto clean_up;
    }
    if (!ue_byte_writer_append_bytes(connection->message_to_send, message, (size_t)message_size)) {
        ue_stacktrace_push_msg("Failed to write message to message to send");
        goto clean_up;
    }

    if (!connection->optional_data) {
        ue_safe_alloc(connection->optional_data, int, 1);
    }
    memcpy(connection->optional_data, &current_channel_id, sizeof(int));
    connection->state = UNKNOWNECHO_CONNECTION_WRITE_STATE;
    result = true;

clean_up:
    ue_safe_free(nickname);
    ue_safe_free(message);
    return result;
}

bool process_channel_key_request_answer(ue_socket_client_connection *connection, ue_byte_stream *request) {
    bool result;
    int i, cipher_data_size, nickname_size;
    ue_socket_client_connection *new_connection;
    unsigned char *cipher_data, *nickname;

    new_connection = NULL;
    cipher_data = NULL;
    nickname = NULL;

    ue_check_parameter_or_return(connection);
    ue_check_parameter_or_return(connection->nickname);
    ue_check_parameter_or_return(request);

    if (!ue_byte_read_next_int(request, &nickname_size)) {
        ue_stacktrace_push_msg("Failed to read nickname size in request");
        goto clean_up;
    }
    if (!ue_byte_read_next_bytes(request, &nickname, (size_t)nickname_size)) {
        ue_stacktrace_push_msg("Failed to read nickname in request");
        goto clean_up;
    }

    if (!ue_byte_read_next_int(request, &cipher_data_size)) {
        ue_stacktrace_push_msg("Failed to read cipher data size in request");
        goto clean_up;
    }
    if (!ue_byte_read_next_bytes(request, &cipher_data, (size_t)cipher_data_size)) {
        ue_stacktrace_push_msg("Failed to read cipher data in request");
        goto clean_up;
    }

    for (i = 0; i < instance->tls_server->connections_number; i++) {
        if (instance->tls_server->connections[i] && memcmp(instance->tls_server->connections[i]->nickname, nickname, (size_t)nickname_size) == 0) {
            new_connection = instance->tls_server->connections[i];
            break;
        }
    }

    if (!new_connection) {
        ue_logger_warn("The client that ask the channel key was not found. He disconnected in the meantime.");
    } else {
        ue_byte_stream_clean_up(new_connection->message_to_send);
        if (!ue_byte_writer_append_int(new_connection->message_to_send, CHANNEL_KEY_RESPONSE)) {
            ue_stacktrace_push_msg("Failed to write CHANNEL_KEY_RESPONSE type to message to send");
            goto clean_up;
        }
        if (!ue_byte_writer_append_int(new_connection->message_to_send, (int)strlen(connection->nickname))) {
            ue_stacktrace_push_msg("Failed to write nickname size to message to send");
            goto clean_up;
        }
        if (!ue_byte_writer_append_bytes(new_connection->message_to_send, (unsigned char *)connection->nickname, strlen(connection->nickname))) {
            ue_stacktrace_push_msg("Failed to write nickname to message to send");
            goto clean_up;
        }
        if (!ue_byte_writer_append_int(new_connection->message_to_send, cipher_data_size)) {
            ue_stacktrace_push_msg("Failed to writer cipher data size to message to send");
            goto clean_up;
        }
        if (!ue_byte_writer_append_bytes(new_connection->message_to_send, cipher_data, (size_t)cipher_data_size)) {
            ue_stacktrace_push_msg("Failed to write cipher data to message to send");
            goto clean_up;
        }

        new_connection->state = UNKNOWNECHO_CONNECTION_WRITE_STATE;
    }

    result = true;

clean_up:
    ue_safe_free(cipher_data);
    ue_safe_free(nickname);
    return result;
}

bool process_get_certificate_request(ue_socket_client_connection *connection, ue_byte_stream *request) {
    bool result;
    ue_x509_certificate *certificate;
    ue_pkcs12_keystore *keystore;
    char *certificate_data;
    unsigned char *friendly_name;
    int friendly_name_size;

    result = false;
    certificate = NULL;
    keystore = NULL;
    certificate_data = NULL;
    friendly_name = NULL;

    ue_check_parameter_or_return(connection);
    ue_check_parameter_or_return(request);

    if (!ue_byte_read_next_int(request, &friendly_name_size)) {
        ue_stacktrace_push_msg("Failed to read friendly name size in request");
        goto clean_up;
    }
    if (!ue_byte_read_next_bytes(request, &friendly_name, (size_t)friendly_name_size)) {
        ue_stacktrace_push_msg("Failed to read friendly name in request");
        goto clean_up;
    }

    if (bytes_contains(friendly_name, (size_t)friendly_name_size, (unsigned char *)"_CIPHER", strlen("_CIPHER"))) {
        keystore = instance->cipher_keystore;
    } else if (bytes_contains(friendly_name, (size_t)friendly_name_size, (unsigned char *)"_SIGNER", strlen("_SIGNER"))) {
        keystore = instance->signer_keystore;
    } else {
        ue_logger_warn("Invalid friendly name in GET_CERTIFICATE_REQUEST");
        goto clean_up;
    }

    if (!(certificate = ue_pkcs12_keystore_find_certificate_by_friendly_name(keystore, (const unsigned char *)friendly_name, (size_t)friendly_name_size))) {
        ue_stacktrace_push_msg("Failed to get cipher client certificate");
        goto clean_up;
    } else if (!(certificate_data = ue_x509_certificate_to_pem_string(certificate))) {
        ue_stacktrace_push_msg("Failed to convert certificate to PEM format in bytes buffer");
        goto clean_up;
    } else {
        ue_byte_stream_clean_up(connection->message_to_send);
        if (!ue_byte_writer_append_int(connection->message_to_send, CERTIFICATE_RESPONSE)) {
            ue_stacktrace_push_msg("Failed to write CERTIFICATE_RESPONSE type to message to send");
            goto clean_up;
        }
        if (!ue_byte_writer_append_int(connection->message_to_send, (int)strlen(certificate_data))) {
            ue_stacktrace_push_msg("Failed to write certificate data size to message to send");
            goto clean_up;
        }
        if (!ue_byte_writer_append_bytes(connection->message_to_send, (unsigned char *)certificate_data, strlen(certificate_data))) {
            ue_stacktrace_push_msg("Failed to write certificate data to message to send");
            goto clean_up;
        }
        connection->state = UNKNOWNECHO_CONNECTION_WRITE_STATE;
        ue_logger_trace("GET_CERTIFICATE_REQUEST request successfully proceed");
    }

    result = true;

clean_up:
    ue_safe_free(certificate_data);
    ue_safe_free(friendly_name);
    return result;
}

static bool tls_server_process_request(void *parameter) {
    bool result;
    ue_socket_client_connection *connection;
    int i, channel_id, type;
    ue_byte_stream *request;

    connection = (ue_socket_client_connection *)parameter;
    result = false;
    request = ue_byte_stream_create();

    ue_thread_mutex_lock(instance->tls_server_mutex);
    while (instance->tls_server_processing_state == WORKING_STATE) {
        if (!ue_thread_cond_wait(instance->tls_server_cond, instance->tls_server_mutex)) {
            ue_logger_warn("Wait failed. Possible deadlock detected. Exit process_request().");
            instance->tls_server_processing_state = FREE_STATE;
            return false;
        }
    }
    ue_thread_mutex_unlock(instance->tls_server_mutex);
    instance->tls_server_processing_state = WORKING_STATE;

    for (i = 0; i < ue_byte_vector_size(connection->all_messages); i++) {

        if (!ue_byte_vector_get(connection->all_messages, i) || !ue_byte_vector_get(connection->all_messages, i)->data) {
            continue;
        }

        ue_byte_stream_clean_up(request);
        if (!ue_byte_writer_append_bytes(request, ue_byte_vector_get(connection->all_messages, i)->data, ue_byte_vector_get(connection->all_messages, i)->size)) {
            ue_stacktrace_push_msg("Failed to build request from current message at iteration %d", i);
            goto clean_up;
        }
        ue_byte_stream_set_position(request, 0);

        if (!ue_byte_read_next_int(request, &channel_id)) {
            ue_stacktrace_push_msg("Failed to read channel id in request");
            goto clean_up;
        }
        if (!ue_byte_read_next_int(request, &type)) {
            ue_stacktrace_push_msg("Failed to read request type in request stream");
            goto clean_up;
        }

        if (type == DISCONNECTION_NOW_REQUEST) {
            ue_logger_info("Client disconnection.");
            channels_remove_connection_by_nickname(instance->channels, instance->channels_number, connection->nickname);
            ue_socket_client_connection_clean_up(connection);
            result = true;
        }
        else if (type == SHUTDOWN_NOW_REQUEST) {
            ue_logger_info("Shutdown detected");
            instance->signal_caught = true;
            instance->tls_server->running = false;
            instance->csr_server->running = false;
            result = true;
        }
        else if (type == NICKNAME_REQUEST) {
            ue_logger_trace("Received nickname request");
            result = process_nickname_request(connection, request);
        }
        else if (type == CHANNEL_CONNECTION_REQUEST) {
            ue_logger_trace("CHANNEL_CONNECTION request received");
            result = process_channel_connection_request(connection, request, channel_id);
        }
        else if (type == MESSAGE) {
            if (channel_id == -1) {
                ue_logger_warn("Cannot send message without a channel id");
                result = false;
            } else {
                ue_logger_trace("Received MESSAGE from client");
                result = process_message_request(connection, request, channel_id);
            }
        }
        else if (type == CHANNEL_KEY_REQUEST_ANSWER) {
            ue_logger_trace("CHANNEL_KEY_REQUEST_ANSWER");
            result = process_channel_key_request_answer(connection, request);
        }
        else if (type == GET_CERTIFICATE_REQUEST) {
            ue_logger_trace("GET_CERTIFICATE_REQUEST");
            result = process_get_certificate_request(connection, request);
        }
        else {
            ue_logger_warn("Received invalid data from client");
        }

clean_up:
        if (!result && ue_stacktrace_is_filled()) {
            ue_stacktrace_push_msg("The processing of a client request failed");
            /* @todo send a response to the client in case of error */
            ue_logger_stacktrace("An error occured with the following stacktrace :");
            ue_stacktrace_clean_up();
        }
        ue_byte_vector_remove(connection->all_messages, i);
    }

    instance->tls_server_processing_state = FREE_STATE;

    return result;
}

bool tls_server_read_consumer(ue_socket_client_connection *connection) {
    size_t received;
    ue_thread_id *request_processor_thread;

    if (!instance->tls_server->running) {
        return false;
    }

    request_processor_thread = NULL;

    ue_check_parameter_or_return(connection);

    ue_byte_stream_clean_up(connection->received_message);

    if (connection->nickname) {
        received = receive_cipher_message(connection);
    } else {
        received = ue_socket_receive_bytes_sync(connection->fd, connection->received_message, false, connection->tls);
    }

    if (received == 0) {
        ue_logger_info("Client has disconnected.");
        ue_socket_client_connection_clean_up(connection);
    }
    else if (received < 0 || received == ULLONG_MAX) {
        ue_stacktrace_push_msg("Error while receiving message")
        ue_socket_client_connection_clean_up(connection);
        return false;
    }
    else {
        ue_byte_vector_clean_up(connection->tmp_message);
        if (!ue_byte_split_append(connection->tmp_message, ue_byte_stream_get_data(connection->received_message), ue_byte_stream_get_size(connection->received_message),
            (unsigned char *)"|||EOFEOFEOF", strlen("|||EOFEOFEOF"))) {
            ue_stacktrace_push_msg("Failed to split received message");
            return false;
        }

        ue_byte_vector_append_vector(connection->tmp_message, connection->all_messages);
        ue_byte_vector_clean_up(connection->tmp_message);
        _Pragma("GCC diagnostic push")
        _Pragma("GCC diagnostic ignored \"-Wpedantic\"")
            request_processor_thread = ue_thread_create((void *)tls_server_process_request, (void *)connection);
        _Pragma("GCC diagnostic pop")
        ue_thread_join(request_processor_thread, NULL);
    }

    ue_safe_free(request_processor_thread)

    if (instance->signal_caught) {
        ue_thread_cancel(instance->tls_server_thread);
        ue_thread_cancel(instance->csr_server_thread);
    }

    return true;
}

bool tls_server_write_consumer(ue_socket_client_connection *connection) {
    size_t sent;
    int i;

    /* @todo detect possible deadlock */
    if (!instance->tls_server->running) {
        ue_logger_warn("Server isn't running");
        return false;
    }

    if (connection->message_to_send->position > 0) {
        if (ue_byte_read_is_int(connection->message_to_send, 0, MESSAGE)) {
            for (i = 0; i < instance->tls_server->connections_number; i++) {
                /* Check that server and connection are initialized */
                if (!instance->tls_server || !instance->tls_server->connections || !instance->tls_server->connections[i]) {
                    continue;
                }
                /* Check that optional_data (the channel id) is filled in current connection and specified connection, and equals  */
                if (!instance->tls_server->connections[i]->optional_data || !connection->optional_data ||
                    (*(int *)instance->tls_server->connections[i]->optional_data != *(int *)connection->optional_data)) {
                    continue;
                }
                /* Check that current connection is still established */
                if (ue_socket_client_connection_is_available(instance->tls_server->connections[i])) {
                    continue;
                }
                /* Check that current connection have a message to send, otherwise set it to read state */
                if (instance->tls_server->connections[i]->message_to_send->position == 0) {
                    instance->tls_server->connections[i]->state = UNKNOWNECHO_CONNECTION_READ_STATE;
                    continue;
                }
                /**
                 * If nickname is known, we can use it to retreive the public key of the client in the cipher keystore.
                 * Else we cannot proceed a cipher connection, and the message isn't send to him.
                 */
                if (instance->tls_server->connections[i]) {
                    sent = send_cipher_message(instance->tls_server->connections[i], connection->message_to_send);
                } else {
                    ue_logger_warn("Connection %d have a handshake issue because his nickname field isn't filled.");
                    continue;
                }
                if (sent <= 0) {
                    if (ue_stacktrace_is_filled()) {
                        ue_logger_stacktrace("An error occured while sending cipher message with the following stacktrace :");
                        ue_stacktrace_clean_up();
                    }
                }
                if (sent == 0) {
                    ue_logger_info("Client has disconnected.");
                    ue_socket_client_connection_clean_up(instance->tls_server->connections[i]);
                    continue;
                }
                else if (sent < 0 || sent == ULLONG_MAX) {
                    ue_logger_warn("Error while sending message to client %d", i);
                    ue_socket_client_connection_clean_up(instance->tls_server->connections[i]);
                    continue;
                }
                else {
                    instance->tls_server->connections[i]->state = UNKNOWNECHO_CONNECTION_READ_STATE;
                }
            }
        }
        /* The message to send isn't a MESSAGE, but a request response */
        else {
            /**
             * If the nickname of the connection is known, we can retreive the client public client and then
             * perform a ciphered message.
             * Else, the message isn't ciphered but it's still encrypted in the TLS connection.
             */
            if (connection->nickname) {
                sent = send_cipher_message(connection, connection->message_to_send);
            } else {
                sent = ue_socket_send_data(connection->fd, ue_byte_stream_get_data(connection->message_to_send),
                    ue_byte_stream_get_size(connection->message_to_send), connection->tls);
            }
            if (sent == 0) {
                ue_logger_info("Client has disconnected.");
                ue_socket_client_connection_clean_up(connection);
                return true;
            }
            else if (sent < 0 || sent == ULLONG_MAX) {
                if (ue_stacktrace_is_filled()) {
                    ue_stacktrace_push_msg("Error while sending message")
                    ue_logger_stacktrace("An error occured while sending cipher message with the following stacktrace :");
                    ue_stacktrace_clean_up();
                }
                ue_socket_client_connection_clean_up(connection);
                return false;
            }
            else {
                connection->state = UNKNOWNECHO_CONNECTION_READ_STATE;
            }
        }
    }

    connection->state = UNKNOWNECHO_CONNECTION_READ_STATE;

    return true;
}

bool create_keystores() {
    bool result;
    ue_x509_certificate *csr_certificate, *tls_certificate, *cipher_certificate, *signer_certificate;
    ue_private_key *csr_private_key, *tls_private_key, *cipher_private_key, *signer_private_key;

    result = false;
    csr_certificate = NULL;
    tls_certificate = NULL;
    cipher_certificate = NULL;
    signer_certificate = NULL;
    csr_private_key = NULL;
    tls_private_key = NULL;
    cipher_private_key = NULL;
    signer_private_key = NULL;

    if (!ue_is_file_exists(CSR_KEYSTORE_PATH)) {
        if (!ue_x509_certificate_load_from_files(CSR_SERVER_CERTIFICATE_PATH, CSR_SERVER_KEY_PATH, SERVER_KEY_PASSWORD, &csr_certificate, &csr_private_key)) {
            ue_stacktrace_push_msg("Failed to load certificate and key from files '%s' and '%s'", CSR_SERVER_CERTIFICATE_PATH, CSR_SERVER_KEY_PATH);
            goto end;
        }

        if (!(instance->csr_keystore = ue_pkcs12_keystore_create(csr_certificate, csr_private_key, "SERVER"))) {
            ue_stacktrace_push_msg("Failed to create PKCS12 keystore from specified certificate and private key");
            goto end;
        }

        if (!ue_pkcs12_keystore_write(instance->csr_keystore, CSR_KEYSTORE_PATH, instance->keystore_password)) {
            ue_stacktrace_push_msg("Failed to write keystore to '%s'", CSR_KEYSTORE_PATH);
            goto end;
        }
    } else {
        if (!(instance->csr_keystore = ue_pkcs12_keystore_load(CSR_KEYSTORE_PATH, instance->keystore_password))) {
            ue_stacktrace_push_msg("Failed to load specified pkcs12 keystore");
            goto end;
        }
    }

    if (!ue_is_file_exists(TLS_KEYSTORE_PATH)) {
        if (!ue_x509_certificate_load_from_files(TLS_SERVER_CERTIFICATE_PATH, TLS_SERVER_KEY_PATH, SERVER_KEY_PASSWORD, &tls_certificate, &tls_private_key)) {
            ue_stacktrace_push_msg("Failed to load certificate and key from files '%s' and '%s'", TLS_SERVER_CERTIFICATE_PATH, TLS_SERVER_KEY_PATH);
            goto end;
        }

        if (!(instance->tls_keystore = ue_pkcs12_keystore_create(tls_certificate, tls_private_key, "SERVER"))) {
            ue_stacktrace_push_msg("Failed to create PKCS12 keystore from specified certificate and private key");
            goto end;
        }

        if (!ue_pkcs12_keystore_write(instance->tls_keystore, TLS_KEYSTORE_PATH, instance->keystore_password)) {
            ue_stacktrace_push_msg("Failed to write keystore to '%s'", TLS_KEYSTORE_PATH);
            goto end;
        }
    } else {
        if (!(instance->tls_keystore = ue_pkcs12_keystore_load(TLS_KEYSTORE_PATH, instance->keystore_password))) {
            ue_stacktrace_push_msg("Failed to load specified pkcs12 keystore");
            goto end;
        }
    }

    if (!ue_is_file_exists(CIPHER_KEYSTORE_PATH)) {
        if (!ue_x509_certificate_load_from_files(CIPHER_SERVER_CERTIFICATE_PATH, CIPHER_SERVER_KEY_PATH, SERVER_KEY_PASSWORD, &cipher_certificate, &cipher_private_key)) {
            ue_stacktrace_push_msg("Failed to load certificate and key from files '%s' and '%s'", CIPHER_SERVER_CERTIFICATE_PATH, CIPHER_SERVER_KEY_PATH);
            goto end;
        }

        if (!(instance->cipher_keystore = ue_pkcs12_keystore_create(cipher_certificate, cipher_private_key, "SERVER"))) {
            ue_stacktrace_push_msg("Failed to create PKCS12 keystore from specified certificate and private key");
            goto end;
        }

        if (!ue_pkcs12_keystore_write(instance->cipher_keystore, CIPHER_KEYSTORE_PATH, instance->keystore_password)) {
            ue_stacktrace_push_msg("Failed to write keystore to '%s'", CIPHER_KEYSTORE_PATH);
            goto end;
        }
    } else {
        if (!(instance->cipher_keystore = ue_pkcs12_keystore_load(CIPHER_KEYSTORE_PATH, instance->keystore_password))) {
            ue_stacktrace_push_msg("Failed to load specified pkcs12 keystore");
            goto end;
        }
    }

    if (!ue_is_file_exists(SIGNER_KEYSTORE_PATH)) {
        if (!ue_x509_certificate_load_from_files(SIGNER_SERVER_CERTIFICATE_PATH, SIGNER_SERVER_KEY_PATH, SERVER_KEY_PASSWORD, &signer_certificate, &signer_private_key)) {
            ue_stacktrace_push_msg("Failed to load certificate and key from files '%s' and '%s'", SIGNER_SERVER_CERTIFICATE_PATH, SIGNER_SERVER_KEY_PATH);
            goto end;
        }

        if (!(instance->signer_keystore = ue_pkcs12_keystore_create(signer_certificate, signer_private_key, "SERVER"))) {
            ue_stacktrace_push_msg("Failed to create PKCS12 keystore from specified certificate and private key");
            goto end;
        }

        if (!ue_pkcs12_keystore_write(instance->signer_keystore, SIGNER_KEYSTORE_PATH, instance->keystore_password)) {
            ue_stacktrace_push_msg("Failed to write keystore to '%s'", SIGNER_KEYSTORE_PATH);
            goto end;
        }
    } else {
        if (!(instance->signer_keystore = ue_pkcs12_keystore_load(SIGNER_KEYSTORE_PATH, instance->keystore_password))) {
            ue_stacktrace_push_msg("Failed to load specified pkcs12 keystore");
            goto end;
        }
    }

    result = true;

end:
    return result;
}

bool socket_server_manager_create(unsigned short int csr_server_port, unsigned short int tls_server_port) {
    int i;

    ue_safe_alloc(instance, socket_server_manager, 1)
    instance->csr_server = NULL;
    instance->tls_server = NULL;
    instance->tls_session = NULL;
    instance->csr_keystore = NULL;
    instance->tls_keystore = NULL;
    instance->cipher_keystore = NULL;
    instance->signer_keystore = NULL;

    instance->logs_file = NULL;
    if (!(instance->logs_file = fopen(LOGGER_FILE_PATH, "a"))) {
        ue_stacktrace_push_msg("Failed to open logs file at path '%s'", LOGGER_FILE_PATH)
    }

    ue_logger_set_fp(ue_logger_manager_get_logger(), instance->logs_file);

    ue_logger_set_details(ue_logger_manager_get_logger(), true);

    ue_safe_alloc(instance->channels, channel *, CHANNELS_NUMBER);
    instance->channels_number = CHANNELS_NUMBER;
    for (i = 0; i < instance->channels_number; i++) {
        instance->channels[i] = channel_create(NULL, NULL);
    }

    /*if (!(instance->keystore_password = ue_input_string("Keystore password : "))) {
        ue_stacktrace_push_msg("Specified password isn't valid");
        return false;
    }*/

    instance->keystore_password = ue_string_create_from("password");

    if (!create_keystores()) {
        ue_stacktrace_push_msg("Failed to create keystore");
        return false;
    }

    if (!(instance->csr_server = ue_socket_server_create(csr_server_port, csr_server_read_consumer, csr_server_write_consumer, NULL))) {
        ue_stacktrace_push_msg("Failed to start establisher server on port %d", csr_server_port);
        return false;
    }

    ue_logger_info("CSR server waiting on port %d", csr_server_port);

    ue_x509_certificate **ca_certificates = NULL;
    ue_safe_alloc(ca_certificates, ue_x509_certificate *, 1);
    ca_certificates[0] = instance->tls_keystore->certificate;

    if (!(instance->tls_session = ue_tls_session_create_server(TLS_KEYSTORE_PATH, instance->keystore_password, ca_certificates, 1))) {
        ue_stacktrace_push_msg("Failed to create TLS session");
        return false;
    }

    ue_safe_free(ca_certificates);

    if (!(instance->tls_server = ue_socket_server_create(tls_server_port, tls_server_read_consumer, tls_server_write_consumer, instance->tls_session))) {
        ue_stacktrace_push_msg("Failed to tls start server on port %d", tls_server_port);
        return false;
    }

    ue_logger_info("TLS server waiting on port %d", tls_server_port);

    handle_signal(SIGINT, shutdown_server, 0);
    handle_signal(SIGPIPE, SIG_IGN, SA_RESTART);

    instance->tls_server_mutex = ue_thread_mutex_create();
    instance->tls_server_cond = ue_thread_cond_create();
    instance->tls_server_processing_state = FREE_STATE;
    instance->csr_server_mutex = ue_thread_mutex_create();
    instance->csr_server_cond = ue_thread_cond_create();
    instance->csr_server_processing_state = FREE_STATE;
    instance->signal_caught = false;

    return true;
}

void socket_server_manager_destroy() {
    int i;

	if (instance) {
		ue_thread_mutex_destroy(instance->tls_server_mutex);
        ue_thread_mutex_destroy(instance->csr_server_mutex);
	    ue_thread_cond_destroy(instance->tls_server_cond);
        ue_thread_cond_destroy(instance->csr_server_cond);
	    ue_socket_server_destroy(instance->tls_server);
        ue_socket_server_destroy(instance->csr_server);
	    ue_tls_session_destroy(instance->tls_session);
        for (i = 0; i < instance->channels_number; i++) {
            channel_destroy(instance->channels[i]);
        }
        ue_safe_free(instance->channels);
        if (instance->signal_caught) {
            ue_safe_free(instance->csr_server_thread);
            ue_safe_free(instance->tls_server_thread);
        }
        ue_safe_free(instance->keystore_password);
        ue_pkcs12_keystore_destroy(instance->csr_keystore);
        ue_pkcs12_keystore_destroy(instance->tls_keystore);
        ue_pkcs12_keystore_destroy(instance->cipher_keystore);
    	ue_pkcs12_keystore_destroy(instance->signer_keystore);
        ue_safe_fclose(instance->logs_file);
	    ue_safe_free(instance)
	}
}

int main() {
    if (!ue_init()) {
		printf("[ERROR] Failed to init LibUnknownEcho\n");
		exit(1);
	}

    ue_logger_set_file_level(ue_logger_manager_get_logger(), LOG_TRACE);
	ue_logger_set_print_level(ue_logger_manager_get_logger(), LOG_INFO);

    if (!socket_server_manager_create(CSR_SERVER_PORT, TLS_SERVER_PORT)) {
        ue_stacktrace_push_msg("Failed to create socket server manager");
        goto end;
    }

    _Pragma("GCC diagnostic push")
    _Pragma("GCC diagnostic ignored \"-Wpedantic\"")
        instance->csr_server_thread = ue_thread_create((void *)ue_socket_server_process_polling, (void *)instance->csr_server);
        instance->tls_server_thread = ue_thread_create((void *)ue_socket_server_process_polling, (void *)instance->tls_server);
    _Pragma("GCC diagnostic pop")

    ue_thread_join(instance->csr_server_thread, NULL);
    ue_thread_join(instance->tls_server_thread, NULL);

end:
    if (ue_stacktrace_is_filled()) {
        ue_logger_stacktrace("An error occured with the following stacktrace");
    }
    socket_server_manager_destroy();
    ue_uninit();
    return 0;
}
