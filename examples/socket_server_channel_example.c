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
#include <unknownecho/system/alloc.h>
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
#include <unknownecho/byte/byte_utility.h>
#include <unknownecho/byte/byte_writer.h>
#include <unknownecho/byte/byte_reader.h>
#include <unknownecho/byte/byte_stream.h>
#include <unknownecho/byte/byte_split.h>
#include <unknownecho/container/byte_vector.h>
#include <unknownecho/fileSystem/file_utility.h>

#include <stdlib.h>
#include <signal.h>
#include <stddef.h>
#include <string.h>
#include <limits.h>
#include <stdio.h>

#define CA_CERTIFICATE_PATH "res/ah/ca.crt"
#define CA_KEY_PATH         "res/ah/ca.key"
#define KEYSTORE_PATH       "res/server_keystore.p12"

#define CHANNELS_NUMBER 3

typedef struct {
    ue_socket_client_connection **connections;
    int connections_number;
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

    ue_safe_alloc(chan, channel, 1);
    chan->connections = NULL;
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

    if (chan->connections) {
        ue_safe_alloc(chan->connections, ue_socket_client_connection *, 1);
    } else {
        ue_safe_realloc(chan->connections, ue_socket_client_connection *, chan->connections_number, 1);
    }

    chan->connections[chan->connections_number] = connection;
    chan->connections_number++;

    return true;
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

    for (i = 0; i < chan->connections_number; i++) {
        if (strcmp(chan->connections[i]->nickname, nickname) == 0) {
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
    ue_x509_certificate *ca_certificate;
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

unsigned char *csr_server_process_response(ue_x509_certificate *ca_certificate, ue_public_key *ca_public_key, ue_private_key *ca_private_key, unsigned char *client_request, size_t client_request_size, size_t *server_response_size) {
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

    if (!decipher_cipher_data(client_request, client_request_size, ca_private_key, NULL, &decipher_data, &decipher_data_size)) {
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
	if (!(server_response = ue_sym_encrypter_encrypt(sym_encrypter, (unsigned char *)string_pem_certificate, strlen(string_pem_certificate), iv, iv_size, server_response_size))) {
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

/*static */bool csr_server_process_request(void *parameter) {
    ue_socket_client_connection *connection;
    ue_byte_vector_element *type, *content;
    bool result;
    int i;

    connection = (ue_socket_client_connection *)parameter;
    result = false;

    ue_thread_mutex_lock(instance->csr_server_mutex);
    while (instance->csr_server_processing_state == WORKING_STATE) {
        if (!ue_thread_cond_wait(instance->csr_server_cond, instance->csr_server_mutex)) {
            ue_logger_warn("Wait failed. Possible deadlock detected.");
            return false;
        }
    }
    ue_thread_mutex_unlock(instance->csr_server_mutex);
    instance->csr_server_processing_state = WORKING_STATE;

    for (i = 0; i < ue_byte_vector_size(connection->all_messages); i++) {
        ue_byte_vector_clean_up(connection->current_message);
        if (!ue_byte_split_append(connection->current_message, ue_byte_vector_get(connection->all_messages, i)->data, ue_byte_vector_get(connection->all_messages, i)->size,
            (unsigned char *)"|", 1)) {
            ue_stacktrace_push_msg("Failed to split received message");
            continue;
        }

        if (ue_byte_vector_is_empty(connection->current_message)) {
            ue_logger_warn("Failed to split current message");
            continue;
        }

        if (ue_byte_vector_size(connection->current_message) < 2) {
            ue_logger_warn("Specified message isn't formatted correctly");
            continue;
        }

        type = ue_byte_vector_get(connection->current_message, 0);
        content = ue_byte_vector_get(connection->current_message, 1);

        if (memcmp(type->data, "DISCONNECTION", type->size) == 0) {
            ue_logger_info("Client disconnection.");
            channels_remove_connection_by_nickname(instance->channels, instance->channels_number, connection->nickname);
            ue_socket_client_connection_clean_up(connection);
            result = true;
        } else if (memcmp(type->data, "SHUTDOWN", type->size) == 0) {
            ue_logger_info("Shutdown detected");
            instance->signal_caught = true;
            instance->tls_server->running = false;
            instance->csr_server->running = false;
            result = true;
        } else if (memcmp(type->data, "CSR", type->size) == 0) {
            ue_logger_trace("CSR server has receive a request");
            ue_x509_certificate *ca_certificate;
            ue_private_key *ca_private_key;
            ue_x509_certificate_load_from_files("res/ah/ca.crt", "res/ah/ca.key", "passphrase", &ca_certificate, &ca_private_key);
            unsigned char *signed_certificate_data;
            size_t signed_certificate_data_size;
            ue_public_key *ca_public_key = ue_rsa_public_key_from_x509_certificate(ca_certificate);
            signed_certificate_data = csr_server_process_response(ca_certificate, ca_public_key, ca_private_key, content->data, content->size, &signed_certificate_data_size);
            ue_public_key_destroy(ca_public_key);
            ue_x509_certificate_destroy(ca_certificate);
            ue_private_key_destroy(ca_private_key);
            ue_byte_stream_clean_up(connection->message_to_send);
            ue_byte_writer_append_string(connection->message_to_send, "CSR|");
            ue_byte_writer_append_bytes(connection->message_to_send, signed_certificate_data, signed_certificate_data_size);
            result = true;
        } else {
            ue_logger_warn("Received invalid data from client '%s'.", (char *)content->data);
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
    ue_byte_stream *stream = ue_byte_stream_create();

    ue_byte_stream_clean_up(connection->received_message);
    received = ue_socket_receive_bytes_sync(connection->fd, stream, false, NULL);

    if (received == 0) {
        ue_logger_info("Client has disconnected.");
        if (instance->csr_server->running) {
            ue_socket_client_connection_clean_up(connection);
        }
    }
    else if (received < 0 || received == ULLONG_MAX) {
        ue_stacktrace_push_msg("Error while receiving message")
        return false;
    }
    else {
        //ue_byte_writer_append_bytes(connection->received_message, ue_byte_stream_get_data(stream), ue_byte_stream_get_size(stream));
        /*ue_byte_stream_destroy(stream);

        ue_logger_info("Print received message :");
        ue_byte_stream_print(connection->received_message, stdout);

        ue_logger_trace("CSR server received a message of size %ld", received);

        ue_byte_vector_clean_up(connection->tmp_message);
        if (!ue_byte_split_append(connection->tmp_message, ue_byte_stream_get_data(connection->received_message), ue_byte_stream_get_size(connection->received_message),
            (unsigned char *)"|EOFEOFEOF", strlen("|EOFEOFEOF"))) {
            ue_stacktrace_push_msg("Failed to split received message");
            return false;
        }*/
        /*ue_byte_vector_append_bytes(connection->all_messages, ue_byte_stream_get_data(stream), ue_byte_stream_get_size(stream));
        ue_byte_stream_destroy(stream);
        //ue_byte_vector_append_vector(connection->tmp_message, connection->all_messages);
        _Pragma("GCC diagnostic push")
        _Pragma("GCC diagnostic ignored \"-Wpedantic\"")
            request_processor_thread = ue_thread_create((void *)csr_server_process_request, (void *)connection);
        _Pragma("GCC diagnostic pop")
        ue_thread_join(request_processor_thread, NULL);*/
        //ue_logger_warn("Join failed. Possible deadlock detected. Exit process_request().");

        ue_logger_trace("CSR server has receive a request");
        ue_x509_certificate *ca_certificate = NULL;
        ue_private_key *ca_private_key = NULL;
        ue_x509_certificate_load_from_files("res/ah/ca.crt", "res/ah/ca.key", "passphrase", &ca_certificate, &ca_private_key);
        unsigned char *signed_certificate_data;
        size_t signed_certificate_data_size;
        ue_public_key *ca_public_key = ue_rsa_public_key_from_x509_certificate(ca_certificate);
        signed_certificate_data = csr_server_process_response(ca_certificate, ca_public_key, ca_private_key, ue_byte_stream_get_data(stream),
            ue_byte_stream_get_size(stream), &signed_certificate_data_size);
        ue_public_key_destroy(ca_public_key);
        ue_x509_certificate_destroy(ca_certificate);
        ue_private_key_destroy(ca_private_key);
        ue_byte_stream_clean_up(connection->message_to_send);
        ue_byte_writer_append_bytes(connection->message_to_send, signed_certificate_data, signed_certificate_data_size);
        connection->state = UNKNOWNECHO_CONNECTION_WRITE_STATE;
        instance->csr_server_processing_state = FREE_STATE;
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
        if (ue_starts_with("CSR", (char *)ue_byte_stream_get_data(connection->message_to_send))) {
            ue_logger_trace("Request receve by CSR server starts with 'CSR'");
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
                ue_byte_stream_get_size(connection->message_to_send), connection->tls);
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
        else {
            sent = ue_socket_send_data(connection->fd, ue_byte_stream_get_data(connection->message_to_send),
                ue_byte_stream_get_size(connection->message_to_send), connection->tls);
            if (sent == 0) {
                ue_logger_info("Client has disconnected.");
                ue_socket_client_connection_clean_up(connection);
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
    }

    connection->state = UNKNOWNECHO_CONNECTION_READ_STATE;

    return true;
}

static bool check_suggest_nickname(const char *nickname) {
    int i;

    if (!nickname) {
        return false;
    }

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

static bool tls_server_process_request(void *parameter) {
    ue_socket_client_connection *connection;
    ue_byte_vector_element *channel_id_field, *type, *content, *content2;
    bool result;
    int i, channel_id;
    char *buffer;

    //ue_logger_set_level(ue_logger_manager_get_logger(), LOG_DEBUG);

    connection = (ue_socket_client_connection *)parameter;
    result = false;

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

        ue_byte_vector_clean_up(connection->current_message);
        if (!ue_byte_split_append(connection->current_message, ue_byte_vector_get(connection->all_messages, i)->data, ue_byte_vector_get(connection->all_messages, i)->size,
            (unsigned char *)"|", 1)) {
            ue_stacktrace_push_msg("Failed to split received message");
            continue;
        }

        if (ue_byte_vector_is_empty(connection->current_message)) {
            ue_logger_warn("Failed to split current message");
            continue;
        }

        if (ue_byte_vector_size(connection->current_message) < 2) {
            ue_logger_warn("Specified message isn't formatted correctly");
            continue;
        }

        channel_id_field = ue_byte_vector_get(connection->current_message, 0);
        buffer = ue_string_create_from_bytes(channel_id_field->data, channel_id_field->size);
        sscanf(buffer, "CHANNEL_ID:%d", &channel_id);
        ue_safe_free(buffer);
        type = ue_byte_vector_get(connection->current_message, 1);
        content = ue_byte_vector_get(connection->current_message, 2);

        if (memcmp(type->data, "DISCONNECTION", type->size) == 0) {
            ue_logger_info("Client disconnection.");
            channels_remove_connection_by_nickname(instance->channels, instance->channels_number, connection->nickname);
            ue_socket_client_connection_clean_up(connection);
            result = true;
        } else if (memcmp(type->data, "SHUTDOWN", type->size) == 0) {
            ue_logger_info("Shutdown detected");
            instance->signal_caught = true;
            instance->tls_server->running = false;
            instance->csr_server->running = false;
            result = true;
        } else if (memcmp(type->data, "NICKNAME", type->size) == 0) {
            if (check_suggest_nickname((char *)content->data)) {
                connection->nickname = ue_string_create_from_bytes(content->data, content->size);
                ue_byte_stream_clean_up(connection->message_to_send);
                if (!ue_byte_writer_append_string(connection->message_to_send, "NICKNAME|TRUE")) {
                    ue_logger_warn("Failed to create response of nickname-request (true)");;
                    result = false;
                    break;
                } else {
                    result = true;
                }
            }
            else {
                ue_byte_stream_clean_up(connection->message_to_send);
                if (ue_byte_writer_append_string(connection->message_to_send, "NICKNAME|FALSE")) {
                    ue_logger_warn("Failed to create response of nickname-request (false)");
                    result = false;
                    break;
                } else {
                    result = true;
                }
            }
        } else if (memcmp(type->data, "CHANNEL_CONNECTION", type->size) == 0) {

            ue_logger_info("CHANNEL_CONNECTION request received");

            ue_byte_stream_clean_up(connection->message_to_send);

            buffer = ue_string_create_from_bytes(content->data, content->size);

            if (channel_id != -1) {
                ue_logger_info("Connection with nickname %s and channel_id %d is already connected but ask for a channel connection", connection->nickname, channel_id);
            } else if (!ue_string_to_int(buffer, &channel_id, 10)) {
                ue_logger_warn("Failed to convert received channel id from string to int");
                if (!ue_byte_writer_append_string(connection->message_to_send, "CHANNEL_CONNECTION|FALSE|")) {
                    ue_logger_warn("Failed to send channel connection FALSE response");
                }
                result = false;
            } else if (channel_id < 0 || channel_id > instance->channels_number - 1) {
                ue_logger_warn("Channel id %d is out of range. Channels number of this instance : %d", channel_id, instance->channels_number);
                if (!ue_byte_writer_append_string(connection->message_to_send, "CHANNEL_CONNECTION|FALSE|")) {
                    ue_logger_warn("Failed to send channel connection FALSE response");
                }
                result = false;
            } else if (!channel_add_connection(instance->channels[channel_id], connection)) {
                ue_logger_warn("Failed to add connection of nickname %s to channel id %d", connection->nickname, channel_id);
                if (!ue_byte_writer_append_string(connection->message_to_send, "CHANNEL_CONNECTION|FALSE|")) {
                    ue_logger_warn("Failed to send channel connection FALSE response");
                }
                result = false;
            } else {
                ue_logger_info("Successfully added connection of nickname %s to channel id %d", connection->nickname, channel_id);
                ue_logger_info("Building response...");
                if (!ue_byte_writer_append_string(connection->message_to_send, "CHANNEL_CONNECTION|TRUE|")) {
                    ue_logger_warn("Failed to send channel connection TRUE response");
                    result = false;
                } else if (!ue_byte_writer_append_bytes(connection->message_to_send, content->data, content->size)) {
                    ue_logger_warn("Failed to send channel connection TRUE response");
                    result = false;
                } else if (!ue_byte_writer_append_string(connection->message_to_send, "|")) {
                    ue_logger_warn("Failed to send channel connection TRUE response");
                    result = false;
                } else {
                    connection->state = UNKNOWNECHO_CONNECTION_WRITE_STATE;
                    result = true;
                }

                ue_safe_free(buffer);
            }
        } else if (memcmp(type->data, "MESSAGE", type->size) == 0) {
            if (channel_id == -1) {
                ue_logger_warn("Cannot send message without a channel id");
                result = false;
            } else {
                /* Here data is the nickname of the sender and data2 the real message */
                content2 = ue_byte_vector_get(connection->current_message, 3);
                ue_byte_stream_clean_up(connection->message_to_send);

                ue_byte_writer_append_bytes(connection->message_to_send, type->data, type->size);
                ue_byte_writer_append_string(connection->message_to_send, "|");
                ue_byte_writer_append_bytes(connection->message_to_send, content->data, content->size);
                ue_byte_writer_append_string(connection->message_to_send, "|");
                ue_byte_writer_append_bytes(connection->message_to_send, content2->data, content2->size);

                connection->optional_data = &channel_id;
                connection->state = UNKNOWNECHO_CONNECTION_WRITE_STATE;
                result = true;
            }
        } else {
            ue_logger_warn("Received invalid data from client '%s'.", (char *)content->data);
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

    //ue_logger_set_level(ue_logger_manager_get_logger(), LOG_DEBUG);

    request_processor_thread = NULL;

    ue_check_parameter_or_return(connection);
    ue_check_parameter_or_return(connection->received_message);

    ue_byte_stream_clean_up(connection->received_message);
    received = ue_socket_receive_bytes_sync(connection->fd, connection->received_message, false, connection->tls);

    if (received == 0) {
        ue_logger_info("Client has disconnected.");
        //if (instance->tls_server->running) {
            ue_socket_client_connection_clean_up(connection);
        //}
    }
    else if (received < 0 || received == ULLONG_MAX) {
        ue_stacktrace_push_msg("Error while receiving message")
        return false;
    }
    else {
        ue_logger_info("Received message of size %ld : %s", received, (char *)ue_byte_stream_get_data(connection->received_message));
        ue_byte_vector_clean_up(connection->tmp_message);
        if (!ue_byte_split_append(connection->tmp_message, ue_byte_stream_get_data(connection->received_message), ue_byte_stream_get_size(connection->received_message),
            (unsigned char *)"|EOFEOFEOF", strlen("|EOFEOFEOF"))) {
            ue_stacktrace_push_msg("Failed to split received message");
            return false;
        }
        /* @todo fix memory leak */
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

    if (!instance->tls_server->running) {
        return false;
    }

    //ue_logger_set_level(ue_logger_manager_get_logger(), LOG_DEBUG);

    if (connection->message_to_send->position > 0) {
        if (ue_starts_with("MESSAGE", (char *)ue_byte_stream_get_data(connection->message_to_send))) {
            for (i = 0; i < instance->tls_server->connections_number; i++) {
                if (!instance->tls_server || !instance->tls_server->connections || !instance->tls_server->connections[i]) {
                    continue;
                }
                if (!instance->tls_server->connections[i]->optional_data) {
                    continue;
                }
                if (ue_socket_client_connection_is_available(instance->tls_server->connections[i])) {
                    continue;
                }
                if (instance->tls_server->connections[i]->message_to_send->position == 0) {
                    instance->tls_server->connections[i]->state = UNKNOWNECHO_CONNECTION_READ_STATE;
                    continue;
                }
                sent = ue_socket_send_data(instance->tls_server->connections[i]->fd, ue_byte_stream_get_data(connection->message_to_send),
                    ue_byte_stream_get_size(connection->message_to_send), connection->tls);
                if (sent == 0) {
                    ue_logger_info("Client has disconnected.");
                    return true;
                }
                else if (sent < 0 || sent == ULLONG_MAX) {
                    ue_stacktrace_push_msg("Error while sending message")
                    ue_socket_client_connection_clean_up(instance->tls_server->connections[i]);
                    return false;
                }
                else {
                    instance->tls_server->connections[i]->state = UNKNOWNECHO_CONNECTION_READ_STATE;
                }
            }
        }
        else {
            sent = ue_socket_send_data(connection->fd, ue_byte_stream_get_data(connection->message_to_send),
                ue_byte_stream_get_size(connection->message_to_send), connection->tls);
            if (sent == 0) {
                ue_logger_info("Client has disconnected.");
                ue_socket_client_connection_clean_up(connection);
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
    }

    connection->state = UNKNOWNECHO_CONNECTION_READ_STATE;

    return true;
}

bool create_keystore() {
    bool result;
    ue_pkcs12_keystore *keystore;
    ue_x509_certificate *certificate, *ca_certificate;
    ue_private_key *private_key, *ca_private_key;

    result = false;
    keystore = NULL;
    certificate = NULL;
    private_key = NULL;
    ca_certificate = NULL;
    ca_private_key = NULL;

    if (!ue_is_file_exists(KEYSTORE_PATH)) {

        ue_x509_certificate_load_from_files(CA_CERTIFICATE_PATH, CA_KEY_PATH, "passphrase", &ca_certificate, &ca_private_key);

        /*if (!ue_x509_certificate_generate_self_signed_ca("FR", "SWA", &ca_certificate, &ca_private_key)) {
            ue_logger_error("Failed to generate self signed CA");
            goto clean_up;
        }*/

        if (!ue_x509_certificate_generate_signed(ca_certificate, ca_private_key, "FR", "SERVER", &certificate, &private_key)) {
            ue_stacktrace_push_msg("Failed to generate certificate signed by CA");
            goto clean_up;
        }

        if (!(keystore = ue_pkcs12_keystore_create(certificate, private_key, "server"))) {
            ue_stacktrace_push_msg("Failed to create PKCS12 keystore from specified certificate and private key");
            goto clean_up;
        }

        if (!ue_pkcs12_keystore_write(keystore, KEYSTORE_PATH, "password", "password")) {
            ue_stacktrace_push_msg("Failed to write keystore to '%s'", KEYSTORE_PATH);
            goto clean_up;
        }
    }

    result = true;

clean_up:
    ue_pkcs12_keystore_destroy(keystore);
    ue_x509_certificate_destroy(ca_certificate);
    ue_private_key_destroy(ca_private_key);
    ue_x509_certificate_destroy(certificate);
    ue_private_key_destroy(private_key);
    return result;
}

bool socket_server_manager_create(unsigned short int csr_server_port, unsigned short int tls_server_port) {
    int i;

    ue_safe_alloc(instance, socket_server_manager, 1)
    instance->csr_server = NULL;
    instance->tls_server = NULL;
    instance->tls_session = NULL;
    ue_safe_alloc(instance->channels, channel *, CHANNELS_NUMBER);
    instance->channels_number = CHANNELS_NUMBER;
    for (i = 0; i < instance->channels_number; i++) {
        instance->channels[i] = channel_create(NULL, NULL);
    }

    if (!create_keystore()) {
        ue_stacktrace_push_msg("Failed to create keystore");
        return false;
    }

    if (!(instance->csr_server = ue_socket_server_create(csr_server_port, csr_server_read_consumer, csr_server_write_consumer, NULL))) {
        ue_stacktrace_push_msg("Failed to start establisher server on port %d", csr_server_port);
        return false;
    }

    ue_logger_info("CSR server waiting on port %d", csr_server_port);

    if (!ue_x509_certificate_load_from_file(CA_CERTIFICATE_PATH, &instance->ca_certificate)) {
		ue_stacktrace_push_msg("Failed to load CA certificate from path '%s'", CA_CERTIFICATE_PATH);
		return false;
	}

    if (!(instance->tls_session = ue_tls_session_create(KEYSTORE_PATH, "password", "", ue_tls_method_create_v1_server(), instance->ca_certificate))) {
        ue_stacktrace_push_msg("Failed to create TLS session");
        return false;
    }

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
        ue_x509_certificate_destroy(instance->ca_certificate);
	    ue_safe_free(instance)
	}
}

int main() {
    if (!ue_init()) {
		printf("[ERROR] Failed to init LibUnknownEcho\n");
		exit(1);
	}

    //ue_logger_set_level(ue_logger_manager_get_logger(), LOG_DEBUG);

    if (!socket_server_manager_create(5002, 5001)) {
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
    socket_server_manager_destroy();

    if (ue_stacktrace_is_filled()) {
        ue_logger_error("Error(s) occurred with the following stacktrace(s) :");
        ue_stacktrace_print_all();
    }
    ue_uninit();
    return 0;
}
