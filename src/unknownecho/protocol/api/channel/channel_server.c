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

#include <unknownecho/protocol/api/channel/channel_server.h>
#include <unknownecho/protocol/api/channel/channel_server_struct.h>
#include <unknownecho/protocol/api/channel/channel_message_type.h>
#include <unknownecho/protocol/api/channel/channel.h>
#include <unknownecho/string/string_utility.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/errorHandling/check_parameter.h>
#include <unknownecho/alloc.h>
#include <unknownecho/input.h>
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
#include <unknownecho/crypto/api/key/public_key.h>
#include <unknownecho/crypto/api/key/private_key.h>
#include <unknownecho/crypto/api/certificate/x509_certificate.h>
#include <unknownecho/crypto/api/certificate/x509_csr.h>
#include <unknownecho/crypto/api/cipher/data_cipher.h>
#include <unknownecho/crypto/api/keystore/pkcs12_keystore.h>
#include <unknownecho/crypto/api/encryption/sym_encrypter.h>
#include <unknownecho/crypto/api/csr/csr_request.h>
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
#include <unknownecho/fileSystem/folder_utility.h>

#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <limits.h>


ue_channel_server *channel_server = NULL;


static size_t send_cipher_message(ue_socket_client_connection *connection, ue_byte_stream *message_to_send);

static size_t receive_cipher_message(ue_socket_client_connection *connection);

static bool create_keystores();

static bool csr_server_read_consumer(ue_socket_client_connection *connection);

static bool csr_server_write_consumer(ue_socket_client_connection *connection);

static bool csr_server_process_request(void *parameter);

static bool record_client_certificate(ue_x509_certificate *signed_certificate, int csr_sub_type, unsigned char *friendly_name, size_t friendly_name_size);

static bool distribute_client_certificate(ue_x509_certificate *signed_certificate, unsigned char *friendly_name, size_t friendly_name_size);

static bool tls_server_read_consumer(ue_socket_client_connection *connection);

static bool tls_server_write_consumer(ue_socket_client_connection *connection);

static bool tls_server_process_request(void *parameter);

static bool process_nickname_request(ue_socket_client_connection *connection, ue_byte_stream *request);

static bool process_channel_connection_request(ue_socket_client_connection *connection, ue_byte_stream *request, int current_channel_id);

static bool process_message_request(ue_socket_client_connection *connection, ue_byte_stream *request, int channel_id);

static bool process_channel_key_request_answer(ue_socket_client_connection *connection, ue_byte_stream *request);

static bool process_get_certificate_request(ue_socket_client_connection *connection, ue_byte_stream *request);

static bool check_suggest_nickname(const char *nickname);


bool ue_channel_server_create(char *persistent_path,
    int csr_server_port, int tls_server_port,
    char *keystore_password, int channels_number, char *key_password, void *user_context,
    bool (*initialization_begin_callback)(void *user_context), bool (*initialization_end_callback)(void *user_context),
    bool (*uninitialization_begin_callback)(void *user_context), bool (*uninitialization_end_callback)(void *user_context)) {

    bool result;
    int i;
    ue_x509_certificate **ca_certificates;
    char *keystore_folder_path;

    result = false;
    channel_server = NULL;
    ca_certificates = NULL;
    keystore_folder_path = NULL;

    ue_safe_alloc(channel_server, ue_channel_server, 1);
    channel_server->csr_server = NULL;
    channel_server->tls_server = NULL;
    channel_server->tls_session = NULL;
    channel_server->csr_keystore = NULL;
    channel_server->tls_keystore = NULL;
    channel_server->cipher_keystore = NULL;
    channel_server->signer_keystore = NULL;
    channel_server->persistent_path = ue_string_create_from(persistent_path);
    channel_server->logger_file_path = ue_strcat_variadic("ss", channel_server->persistent_path, "/server_logs.txt");
    channel_server->logs_file = NULL;
    channel_server->csr_server_certificate_path = NULL;
    channel_server->csr_server_key_path = NULL;
    channel_server->tls_server_certificate_path = NULL;
    channel_server->tls_server_key_path = NULL;
    channel_server->cipher_server_certificate_path = NULL;
    channel_server->cipher_server_key_path = NULL;
    channel_server->signer_server_certificate_path = NULL;
    channel_server->signer_server_key_path = NULL;
    channel_server->key_password = NULL;
    channel_server->csr_keystore_path = NULL;
    channel_server->tls_keystore_path = NULL;
    channel_server->cipher_keystore_path = NULL;
    channel_server->signer_keystore_path = NULL;
    channel_server->user_context = user_context;
    channel_server->initialization_begin_callback = initialization_begin_callback;
    channel_server->initialization_end_callback = initialization_end_callback;
    channel_server->uninitialization_begin_callback = uninitialization_begin_callback;
    channel_server->uninitialization_end_callback = uninitialization_end_callback;

    if (channel_server->initialization_begin_callback) {
        channel_server->initialization_begin_callback(user_context);
    }

    if (!(channel_server->logs_file = fopen(channel_server->logger_file_path, "a"))) {
        ue_stacktrace_push_msg("Failed to open logs file at path '%s'", channel_server->logger_file_path)
    } else {
        ue_logger_set_fp(ue_logger_manager_get_logger(), channel_server->logs_file);
        //ue_logger_set_details(ue_logger_manager_get_logger(), true);
    }

    channel_server->channels_number = channels_number;
    ue_safe_alloc(channel_server->channels, ue_channel *, channels_number);
    channel_server->channels_number = channels_number;
    for (i = 0; i < channel_server->channels_number; i++) {
        channel_server->channels[i] = ue_channel_create();
    }

    keystore_folder_path = ue_strcat_variadic("ss", channel_server->persistent_path, "/keystore");

	if (!ue_is_dir_exists(keystore_folder_path)) {
		ue_logger_info("Creating '%s'...", keystore_folder_path);
		if (!ue_create_folder(keystore_folder_path)) {
			ue_stacktrace_push_msg("Failed to create '%s'", keystore_folder_path);
            ue_safe_free(keystore_folder_path);
			goto clean_up;
		}
	}
    ue_safe_free(keystore_folder_path);

    channel_server->keystore_password = ue_string_create_from(keystore_password);

    channel_server->csr_server_certificate_path = ue_strcat_variadic("ss", channel_server->persistent_path, "/certificate/csr_server.pem");
    channel_server->csr_server_key_path = ue_strcat_variadic("ss", channel_server->persistent_path, "/certificate/csr_server_key.pem");
    channel_server->tls_server_certificate_path = ue_strcat_variadic("ss", channel_server->persistent_path, "/certificate/tls_server.pem");
    channel_server->tls_server_key_path = ue_strcat_variadic("ss", channel_server->persistent_path, "/certificate/tls_server_key.pem");
    channel_server->cipher_server_certificate_path = ue_strcat_variadic("ss", channel_server->persistent_path, "/certificate/cipher_server.pem");
    channel_server->cipher_server_key_path = ue_strcat_variadic("ss", channel_server->persistent_path, "/certificate/cipher_server_key.pem");
    channel_server->signer_server_certificate_path = ue_strcat_variadic("ss", channel_server->persistent_path, "/certificate/signer_server.pem");
    channel_server->signer_server_key_path = ue_strcat_variadic("ss", channel_server->persistent_path, "/certificate/signer_server_key.pem");

    channel_server->key_password = ue_string_create_from(key_password);

    channel_server->csr_keystore_path = ue_strcat_variadic("ss", channel_server->persistent_path, "/keystore/csr_server_keystore.p12");
    channel_server->tls_keystore_path = ue_strcat_variadic("ss", channel_server->persistent_path, "/keystore/tls_server_keystore.p12");
    channel_server->cipher_keystore_path = ue_strcat_variadic("ss", channel_server->persistent_path, "/keystore/cipher_server_keystore.p12");
    channel_server->signer_keystore_path = ue_strcat_variadic("ss", channel_server->persistent_path, "/keystore/signer_server_keystore.p12");

    if (!create_keystores(channel_server)) {
        ue_stacktrace_push_msg("Failed to create keystore");
        goto clean_up;
    }

    if (!(channel_server->csr_server = ue_socket_server_create(csr_server_port, csr_server_read_consumer, csr_server_write_consumer, NULL))) {
        ue_stacktrace_push_msg("Failed to start establisher server on port %d", csr_server_port);
        goto clean_up;
    }

    ue_logger_info("CSR server waiting on port %d", csr_server_port);

    ue_safe_alloc(ca_certificates, ue_x509_certificate *, 1);
    ca_certificates[0] = channel_server->tls_keystore->certificate;

    if (!(channel_server->tls_session = ue_tls_session_create_server(channel_server->tls_keystore_path, channel_server->keystore_password, ca_certificates, 1))) {
        ue_stacktrace_push_msg("Failed to create TLS session");
        goto clean_up;
    }

    ue_safe_free(ca_certificates);

    if (!(channel_server->tls_server = ue_socket_server_create(tls_server_port, tls_server_read_consumer, tls_server_write_consumer, channel_server->tls_session))) {
        ue_stacktrace_push_msg("Failed to tls start server on port %d", tls_server_port);
        goto clean_up;
    }

    ue_logger_info("TLS server waiting on port %d", tls_server_port);

    channel_server->tls_server_mutex = ue_thread_mutex_create();
    channel_server->tls_server_cond = ue_thread_cond_create();
    channel_server->tls_server_processing_state = FREE_STATE;
    channel_server->csr_server_mutex = ue_thread_mutex_create();
    channel_server->csr_server_cond = ue_thread_cond_create();
    channel_server->csr_server_processing_state = FREE_STATE;
    channel_server->signal_caught = false;

    result = true;

clean_up:
    if (channel_server->initialization_end_callback) {
        channel_server->initialization_end_callback(channel_server->user_context);
    }
    return result;
}

void ue_channel_server_destroy() {
    int i;

	if (channel_server) {
        if (channel_server->uninitialization_begin_callback) {
            channel_server->uninitialization_begin_callback(channel_server->user_context);
        }
		ue_thread_mutex_destroy(channel_server->tls_server_mutex);
        ue_thread_mutex_destroy(channel_server->csr_server_mutex);
	    ue_thread_cond_destroy(channel_server->tls_server_cond);
        ue_thread_cond_destroy(channel_server->csr_server_cond);
	    ue_socket_server_destroy(channel_server->tls_server);
        ue_socket_server_destroy(channel_server->csr_server);
	    ue_tls_session_destroy(channel_server->tls_session);
        for (i = 0; i < channel_server->channels_number; i++) {
            ue_channel_destroy(channel_server->channels[i]);
        }
        ue_safe_free(channel_server->channels);
        if (channel_server->signal_caught) {
            ue_safe_free(channel_server->csr_server_thread);
            ue_safe_free(channel_server->tls_server_thread);
        }
        ue_safe_free(channel_server->keystore_password);
        ue_pkcs12_keystore_destroy(channel_server->csr_keystore);
        ue_pkcs12_keystore_destroy(channel_server->tls_keystore);
        ue_pkcs12_keystore_destroy(channel_server->cipher_keystore);
    	ue_pkcs12_keystore_destroy(channel_server->signer_keystore);
        ue_safe_free(channel_server->persistent_path);
        ue_safe_free(channel_server->csr_server_certificate_path);
        ue_safe_free(channel_server->csr_server_key_path);
        ue_safe_free(channel_server->tls_server_certificate_path);
        ue_safe_free(channel_server->tls_server_key_path);
        ue_safe_free(channel_server->cipher_server_certificate_path);
        ue_safe_free(channel_server->cipher_server_key_path);
        ue_safe_free(channel_server->signer_server_certificate_path);
        ue_safe_free(channel_server->signer_server_key_path);
        ue_safe_free(channel_server->key_password);
        ue_safe_free(channel_server->csr_keystore_path);
        ue_safe_free(channel_server->tls_keystore_path);
        ue_safe_free(channel_server->cipher_keystore_path);
        ue_safe_free(channel_server->signer_keystore_path);
        ue_safe_free(channel_server->csr_server_port);
        ue_safe_free(channel_server->tls_server_port);
        ue_safe_free(channel_server->logger_file_path);
        if (channel_server->uninitialization_end_callback) {
            channel_server->uninitialization_end_callback(channel_server->user_context);
        }
        ue_safe_fclose(channel_server->logs_file);
	    ue_safe_free(channel_server)
	}
}

bool ue_channel_server_process() {
    _Pragma("GCC diagnostic push")
    _Pragma("GCC diagnostic ignored \"-Wpedantic\"")
        channel_server->csr_server_thread = ue_thread_create((void *)ue_socket_server_process_polling, (void *)channel_server->csr_server);
        channel_server->tls_server_thread = ue_thread_create((void *)ue_socket_server_process_polling, (void *)channel_server->tls_server);
    _Pragma("GCC diagnostic pop")

    ue_thread_join(channel_server->csr_server_thread, NULL);
    ue_thread_join(channel_server->tls_server_thread, NULL);

    return true;
}

void ue_channel_server_shutdown_signal_callback(int sig) {
    ue_logger_trace("Signal received %d", sig);
    ue_logger_info("Shuting down server...");
    channel_server->signal_caught = true;
    if (channel_server->tls_server) {
        channel_server->tls_server->running = false;
    }
    if (channel_server->csr_server) {
        channel_server->csr_server->running = false;
    }

    ue_thread_cancel(channel_server->csr_server_thread);
    ue_thread_cancel(channel_server->tls_server_thread);
}

static size_t send_cipher_message(ue_socket_client_connection *connection, ue_byte_stream *message_to_send) {
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

    if (!(client_certificate = ue_pkcs12_keystore_find_certificate_by_friendly_name(channel_server->cipher_keystore, (const unsigned char *)friendly_name, friendly_name_size))) {
        ue_stacktrace_push_msg("Failed to get cipher client certificate");
        goto clean_up;
    }

    if (!(client_public_key = ue_rsa_public_key_from_x509_certificate(client_certificate))) {
        ue_stacktrace_push_msg("Failed to get client public key from client certificate");
        goto clean_up;
    }

	if (!ue_cipher_plain_data(ue_byte_stream_get_data(message_stream), ue_byte_stream_get_size(message_stream),
	       client_public_key, channel_server->signer_keystore->private_key, &cipher_data, &cipher_data_size, "aes-256-cbc")) {

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

static size_t receive_cipher_message(ue_socket_client_connection *connection) {
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

    if (!(client_certificate = ue_pkcs12_keystore_find_certificate_by_friendly_name(channel_server->signer_keystore, (const unsigned char *)friendly_name, friendly_name_size))) {
		ue_stacktrace_push_msg("Failed to find client signer certificate");
		received = -1;
		goto clean_up;
	}

    if (!(client_public_key = ue_rsa_public_key_from_x509_certificate(client_certificate))) {
        ue_stacktrace_push_msg("Failed to get client public key from client certificate");
        goto clean_up;
    }

	if (!ue_decipher_cipher_data(ue_byte_stream_get_data(connection->received_message), ue_byte_stream_get_size(connection->received_message),
		channel_server->cipher_keystore->private_key, client_public_key, &plain_data, &plain_data_size, "aes-256-cbc")) {

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

static bool create_keystores() {
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

    if (!ue_is_file_exists(channel_server->csr_keystore_path)) {
        if (!ue_x509_certificate_load_from_files(channel_server->csr_server_certificate_path, channel_server->csr_server_key_path, channel_server->key_password, &csr_certificate, &csr_private_key)) {
            ue_stacktrace_push_msg("Failed to load certificate and key from files '%s' and '%s'", channel_server->csr_server_certificate_path, channel_server->csr_server_key_path);
            goto end;
        }

        if (!(channel_server->csr_keystore = ue_pkcs12_keystore_create(csr_certificate, csr_private_key, "SERVER"))) {
            ue_stacktrace_push_msg("Failed to create PKCS12 keystore from specified certificate and private key");
            goto end;
        }

        ue_logger_debug("channel_server->csr_keystore_path : %s", channel_server->csr_keystore_path);
        if (!ue_pkcs12_keystore_write(channel_server->csr_keystore, channel_server->csr_keystore_path, channel_server->keystore_password)) {
            ue_stacktrace_push_msg("Failed to write keystore to '%s'", channel_server->csr_keystore_path);
            goto end;
        }
    } else {
        if (!(channel_server->csr_keystore = ue_pkcs12_keystore_load(channel_server->csr_keystore_path, channel_server->keystore_password))) {
            ue_stacktrace_push_msg("Failed to load specified pkcs12 keystore");
            goto end;
        }
    }

    if (!ue_is_file_exists(channel_server->tls_keystore_path)) {
        if (!ue_x509_certificate_load_from_files(channel_server->tls_server_certificate_path, channel_server->tls_server_key_path, channel_server->key_password, &tls_certificate, &tls_private_key)) {
            ue_stacktrace_push_msg("Failed to load certificate and key from files '%s' and '%s'", channel_server->tls_server_certificate_path, channel_server->tls_server_key_path);
            goto end;
        }

        if (!(channel_server->tls_keystore = ue_pkcs12_keystore_create(tls_certificate, tls_private_key, "SERVER"))) {
            ue_stacktrace_push_msg("Failed to create PKCS12 keystore from specified certificate and private key");
            goto end;
        }

        if (!ue_pkcs12_keystore_write(channel_server->tls_keystore, channel_server->tls_keystore_path, channel_server->keystore_password)) {
            ue_stacktrace_push_msg("Failed to write keystore to '%s'", channel_server->tls_keystore_path);
            goto end;
        }
    } else {
        if (!(channel_server->tls_keystore = ue_pkcs12_keystore_load(channel_server->tls_keystore_path, channel_server->keystore_password))) {
            ue_stacktrace_push_msg("Failed to load specified pkcs12 keystore");
            goto end;
        }
    }

    if (!ue_is_file_exists(channel_server->cipher_keystore_path)) {
        if (!ue_x509_certificate_load_from_files(channel_server->cipher_server_certificate_path, channel_server->cipher_server_key_path, channel_server->key_password, &cipher_certificate, &cipher_private_key)) {
            ue_stacktrace_push_msg("Failed to load certificate and key from files '%s' and '%s'", channel_server->cipher_server_certificate_path, channel_server->cipher_server_key_path);
            goto end;
        }

        if (!(channel_server->cipher_keystore = ue_pkcs12_keystore_create(cipher_certificate, cipher_private_key, "SERVER"))) {
            ue_stacktrace_push_msg("Failed to create PKCS12 keystore from specified certificate and private key");
            goto end;
        }

        if (!ue_pkcs12_keystore_write(channel_server->cipher_keystore, channel_server->cipher_keystore_path, channel_server->keystore_password)) {
            ue_stacktrace_push_msg("Failed to write keystore to '%s'", channel_server->cipher_keystore_path);
            goto end;
        }
    } else {
        if (!(channel_server->cipher_keystore = ue_pkcs12_keystore_load(channel_server->cipher_keystore_path, channel_server->keystore_password))) {
            ue_stacktrace_push_msg("Failed to load specified pkcs12 keystore");
            goto end;
        }
    }

    if (!ue_is_file_exists(channel_server->signer_keystore_path)) {
        if (!ue_x509_certificate_load_from_files(channel_server->signer_server_certificate_path, channel_server->signer_server_key_path, channel_server->key_password, &signer_certificate, &signer_private_key)) {
            ue_stacktrace_push_msg("Failed to load certificate and key from files '%s' and '%s'", channel_server->signer_server_certificate_path, channel_server->signer_server_key_path);
            goto end;
        }

        if (!(channel_server->signer_keystore = ue_pkcs12_keystore_create(signer_certificate, signer_private_key, "SERVER"))) {
            ue_stacktrace_push_msg("Failed to create PKCS12 keystore from specified certificate and private key");
            goto end;
        }

        if (!ue_pkcs12_keystore_write(channel_server->signer_keystore, channel_server->signer_keystore_path, channel_server->keystore_password)) {
            ue_stacktrace_push_msg("Failed to write keystore to '%s'", channel_server->signer_keystore_path);
            goto end;
        }
    } else {
        if (!(channel_server->signer_keystore = ue_pkcs12_keystore_load(channel_server->signer_keystore_path, channel_server->keystore_password))) {
            ue_stacktrace_push_msg("Failed to load specified pkcs12 keystore");
            goto end;
        }
    }

    result = true;

end:
    return result;
}

static bool csr_server_read_consumer(ue_socket_client_connection *connection) {
    size_t received;
    ue_thread_id *request_processor_thread;

    if (!channel_server->csr_server->running) {
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

static bool csr_server_write_consumer(ue_socket_client_connection *connection) {
    size_t sent;

    if (!channel_server->csr_server->running) {
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

static bool csr_server_process_request(void *parameter) {
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

    ue_thread_mutex_lock(channel_server->csr_server_mutex);
    while (channel_server->csr_server_processing_state == WORKING_STATE) {
        if (!ue_thread_cond_wait(channel_server->csr_server_cond, channel_server->csr_server_mutex)) {
            ue_logger_warn("Wait failed. Possible deadlock detected.");
            channel_server->tls_server_processing_state = FREE_STATE;
            return false;
        }
    }
    ue_thread_mutex_unlock(channel_server->csr_server_mutex);
    channel_server->csr_server_processing_state = WORKING_STATE;

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
                ca_certificate = channel_server->tls_keystore->certificate;
                ca_private_key = channel_server->tls_keystore->private_key;
                if (!(friendly_name = ue_friendly_name_build(nickname, (size_t)nickname_size, "TLS", &friendly_name_size))) {
                    ue_stacktrace_push_msg("Failed to build friendly name for TLS keystore");
                    goto clean_up;
                }
                response_type = CSR_TLS_RESPONSE;
            }
            else if (csr_sub_type == CSR_CIPHER_REQUEST) {
                ca_certificate = channel_server->cipher_keystore->certificate;
                ca_private_key = channel_server->cipher_keystore->private_key;
                if (!(friendly_name = ue_friendly_name_build(nickname, (size_t)nickname_size, "CIPHER", &friendly_name_size))) {
                    ue_stacktrace_push_msg("Failed to build friendly name for CIPHER keystore");
                    goto clean_up;
                }
                response_type = CSR_CIPHER_RESPONSE;
            }
            else if (csr_sub_type == CSR_SIGNER_REQUEST) {
                ca_certificate = channel_server->signer_keystore->certificate;
                ca_private_key = channel_server->signer_keystore->private_key;
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

            if (!(signed_certificate_data = ue_csr_build_server_response(channel_server->csr_keystore->private_key, ca_certificate, ca_private_key,
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

    channel_server->csr_server_processing_state = FREE_STATE;

    return result;
}

static bool record_client_certificate(ue_x509_certificate *signed_certificate, int csr_sub_type, unsigned char *friendly_name, size_t friendly_name_size) {
    bool result;
    ue_pkcs12_keystore *keystore;
    const char *keystore_path;

    ue_check_parameter_or_return(signed_certificate);
    ue_check_parameter_or_return(friendly_name);
    ue_check_parameter_or_return(friendly_name_size > 0);

    result = false;
    keystore = NULL;

    if (csr_sub_type == CSR_TLS_REQUEST) {
        keystore = channel_server->tls_session->keystore;
        keystore_path = channel_server->tls_keystore_path;
    }
    else if (csr_sub_type == CSR_CIPHER_REQUEST) {
        keystore = channel_server->cipher_keystore;
        keystore_path = channel_server->cipher_keystore_path;
    }
    else if (csr_sub_type == CSR_SIGNER_REQUEST) {
        keystore = channel_server->signer_keystore;
        keystore_path = channel_server->signer_keystore_path;
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
    if (!ue_pkcs12_keystore_write(keystore, keystore_path, channel_server->keystore_password)) {
        ue_stacktrace_push_msg("Failed to write new keystore to '%s'", keystore_path);
        goto clean_up;
    }

    result = true;

clean_up:
    return result;
}

static bool distribute_client_certificate(ue_x509_certificate *signed_certificate, unsigned char *friendly_name, size_t friendly_name_size) {
    int i;
    char *certificate_data;

    ue_check_parameter_or_return(signed_certificate);
    ue_check_parameter_or_return(friendly_name);
    ue_check_parameter_or_return(friendly_name_size > 0);

    if (!(certificate_data = ue_x509_certificate_to_pem_string(signed_certificate))) {
        ue_stacktrace_push_msg("Failed to convert signed certificate from PEM to string");
        return false;
    }

    for (i = 0; i < channel_server->tls_server->connections_number; i++) {
        if (!channel_server->tls_server->connections[i]) {
            continue;
        }
        if (ue_socket_client_connection_is_available(channel_server->tls_server->connections[i])) {
            continue;
        }

        ue_byte_stream_clean_up(channel_server->tls_server->connections[i]->message_to_send);

        if (!ue_byte_writer_append_int(channel_server->tls_server->connections[i]->message_to_send, CERTIFICATE_RESPONSE)) {
            ue_logger_warn("Failed to write CERTIFICATE_RESPONSE type to connection %d", i);
            continue;
        }

        if (!ue_byte_writer_append_int(channel_server->tls_server->connections[i]->message_to_send, (int)friendly_name_size)) {
            ue_logger_warn("Failed to write friendly name size to connection %d", i);
            continue;
        }

        if (!ue_byte_writer_append_bytes(channel_server->tls_server->connections[i]->message_to_send, friendly_name, friendly_name_size)) {
            ue_logger_warn("Failed to write friendly name to connection %d", i);
            continue;
        }

        if (!ue_byte_writer_append_int(channel_server->tls_server->connections[i]->message_to_send, (int)strlen(certificate_data))) {
            ue_logger_warn("Failed to write certificate data size to connection %d", i);
            continue;
        }

        if (!ue_byte_writer_append_string(channel_server->tls_server->connections[i]->message_to_send, certificate_data)) {
            ue_logger_warn("Failed to write certificate data to connection %d", i);
            continue;
        }
    }

    ue_safe_free(certificate_data);

    return true;
}

static bool tls_server_read_consumer(ue_socket_client_connection *connection) {
    size_t received;
    ue_thread_id *request_processor_thread;

    if (!channel_server->tls_server->running) {
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

    if (channel_server->signal_caught) {
        ue_thread_cancel(channel_server->tls_server_thread);
        ue_thread_cancel(channel_server->csr_server_thread);
    }

    return true;
}

static bool tls_server_write_consumer(ue_socket_client_connection *connection) {
    size_t sent;
    int i;

    /* @todo detect possible deadlock */
    if (!channel_server->tls_server->running) {
        ue_logger_warn("Server isn't running");
        return false;
    }

    if (connection->message_to_send->position > 0) {
        if (ue_byte_read_is_int(connection->message_to_send, 0, MESSAGE)) {
            for (i = 0; i < channel_server->tls_server->connections_number; i++) {
                /* Check that server and connection are initialized */
                if (!channel_server->tls_server || !channel_server->tls_server->connections || !channel_server->tls_server->connections[i]) {
                    continue;
                }
                /* Check that optional_data (the channel id) is filled in current connection and specified connection, and equals  */
                if (!channel_server->tls_server->connections[i]->optional_data || !connection->optional_data ||
                    (*(int *)channel_server->tls_server->connections[i]->optional_data != *(int *)connection->optional_data)) {
                    continue;
                }
                /* Check that current connection is still established */
                if (ue_socket_client_connection_is_available(channel_server->tls_server->connections[i])) {
                    continue;
                }
                /* Check that current connection have a message to send, otherwise set it to read state */
                if (channel_server->tls_server->connections[i]->message_to_send->position == 0) {
                    channel_server->tls_server->connections[i]->state = UNKNOWNECHO_CONNECTION_READ_STATE;
                    continue;
                }
                /**
                 * If nickname is known, we can use it to retreive the public key of the client in the cipher keystore.
                 * Else we cannot proceed a cipher connection, and the message isn't send to him.
                 */
                if (channel_server->tls_server->connections[i]) {
                    sent = send_cipher_message(channel_server->tls_server->connections[i], connection->message_to_send);
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
                    ue_socket_client_connection_clean_up(channel_server->tls_server->connections[i]);
                    continue;
                }
                else if (sent < 0 || sent == ULLONG_MAX) {
                    ue_logger_warn("Error while sending message to client %d", i);
                    ue_socket_client_connection_clean_up(channel_server->tls_server->connections[i]);
                    continue;
                }
                else {
                    channel_server->tls_server->connections[i]->state = UNKNOWNECHO_CONNECTION_READ_STATE;
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

static bool tls_server_process_request(void *parameter) {
    bool result;
    ue_socket_client_connection *connection;
    int i, channel_id, type;
    ue_byte_stream *request;

    connection = (ue_socket_client_connection *)parameter;
    result = false;
    request = ue_byte_stream_create();

    ue_thread_mutex_lock(channel_server->tls_server_mutex);
    while (channel_server->tls_server_processing_state == WORKING_STATE) {
        if (!ue_thread_cond_wait(channel_server->tls_server_cond, channel_server->tls_server_mutex)) {
            ue_logger_warn("Wait failed. Possible deadlock detected. Exit process_request().");
            channel_server->tls_server_processing_state = FREE_STATE;
            return false;
        }
    }
    ue_thread_mutex_unlock(channel_server->tls_server_mutex);
    channel_server->tls_server_processing_state = WORKING_STATE;

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
            ue_channels_remove_connection_by_nickname(channel_server->channels, channel_server->channels_number, connection->nickname);
            ue_socket_client_connection_clean_up(connection);
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

    channel_server->tls_server_processing_state = FREE_STATE;

    return result;
}

static bool process_nickname_request(ue_socket_client_connection *connection, ue_byte_stream *request) {
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

static bool process_channel_connection_request(ue_socket_client_connection *connection, ue_byte_stream *request, int current_channel_id) {
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
    else if (channel_id < 0 || channel_id > channel_server->channels_number - 1) {
        ue_logger_warn("Channel id %d is out of range. Channels number of this instance : %d", channel_id, channel_server->channels_number);
        if (!ue_byte_writer_append_int(connection->message_to_send, 0)) {
            ue_stacktrace_push_msg("Failed to write FALSE answer to message to send");
            goto clean_up;
        }
    } else if (!ue_channel_add_connection(channel_server->channels[channel_id], connection)) {
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

        if (!connection->optional_data) {
            ue_safe_alloc(connection->optional_data, int, 1);
        }
        memcpy(connection->optional_data, &channel_id, sizeof(int));

        /* If this connection is the only one in this channel, he's the channel key creator */
        if (channel_server->channels[channel_id]->connections_number == 1) {
            if (!ue_byte_writer_append_int(connection->message_to_send, CHANNEL_KEY_CREATOR_STATE)) {
                ue_stacktrace_push_msg("Failed to write CHANNEL_KEY_CREATOR_STATE to message to send");
                goto clean_up;
            }
        }
        /* Else we have to the key from another client */
        else {
            if (!(channel_key_owner_connection = ue_channel_get_availabe_connection_for_channel_key(channel_server->channels[channel_id], connection))) {
                ue_stacktrace_push_msg("Failed to found channel key owner connection but connections_number of channel id %d is > 1 (%d)",
                    channel_id, channel_server->channels[channel_id]->connections_number);
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

static bool process_message_request(ue_socket_client_connection *connection, ue_byte_stream *request, int channel_id) {
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

    //if (!connection->optional_data) {
        ue_safe_alloc(connection->optional_data, int, 1);
    //}
    memcpy(connection->optional_data, &current_channel_id, sizeof(int));
    connection->state = UNKNOWNECHO_CONNECTION_WRITE_STATE;
    result = true;

clean_up:
    ue_safe_free(nickname);
    ue_safe_free(message);
    return result;
}

static bool process_channel_key_request_answer(ue_socket_client_connection *connection, ue_byte_stream *request) {
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

    for (i = 0; i < channel_server->tls_server->connections_number; i++) {
        if (channel_server->tls_server->connections[i] && memcmp(channel_server->tls_server->connections[i]->nickname, nickname, (size_t)nickname_size) == 0) {
            new_connection = channel_server->tls_server->connections[i];
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

static bool process_get_certificate_request(ue_socket_client_connection *connection, ue_byte_stream *request) {
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
        keystore = channel_server->cipher_keystore;
    } else if (bytes_contains(friendly_name, (size_t)friendly_name_size, (unsigned char *)"_SIGNER", strlen("_SIGNER"))) {
        keystore = channel_server->signer_keystore;
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

static bool check_suggest_nickname(const char *nickname) {
    int i;

    if (!nickname) {
        return false;
    }

    ue_logger_trace("Check if nickname is already in use.");

    for (i = 0; i < channel_server->tls_server->connections_number; i++) {
        if (ue_socket_client_connection_is_available(channel_server->tls_server->connections[i])) {
            continue;
        }

        if (channel_server->tls_server->connections[i]->nickname && strcmp(channel_server->tls_server->connections[i]->nickname, nickname) == 0) {
            return false;
        }
    }

    return true;
}
