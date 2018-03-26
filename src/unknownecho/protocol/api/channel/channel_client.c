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

#include <unknownecho/protocol/api/channel/channel_client.h>
#include <unknownecho/protocol/api/channel/channel_message_type.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/errorHandling/check_parameter.h>
#include <unknownecho/alloc.h>
#include <unknownecho/network/api/socket/socket_client_connection.h>
#include <unknownecho/network/api/socket/socket.h>
#include <unknownecho/network/api/socket/socket_send.h>
#include <unknownecho/network/api/socket/socket_receive.h>
#include <unknownecho/network/api/socket/socket_client.h>
#include <unknownecho/network/api/tls/tls_session.h>
#include <unknownecho/string/string_utility.h>
#include <unknownecho/thread/thread.h>
#include <unknownecho/thread/thread_id_struct.h>
#include <unknownecho/thread/thread_mutex.h>
#include <unknownecho/thread/thread_cond.h>
#include <unknownecho/crypto/api/keystore/pkcs12_keystore.h>
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
#include <unknownecho/crypto/api/csr/csr_request.h>
#include <unknownecho/crypto/factory/pkcs12_keystore_factory.h>
#include <unknownecho/crypto/factory/rsa_asym_key_factory.h>
#include <unknownecho/crypto/factory/sym_key_factory.h>
#include <unknownecho/crypto/factory/sym_encrypter_factory.h>
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
#include <unknownecho/time/sleep.h>

#include <string.h>
#include <limits.h>


typedef struct {
    unsigned char *data;
    size_t size;
} pushed_message;


static ue_channel_client **channel_clients = NULL;
static int max_channel_clients_number = 0;


#if defined(WIN32)
	#include <windows.h>
#elif defined(__UNIX__)
	#include <unistd.h>
    #include <sys/socket.h>
#endif


#define CSR_SERVER_CERTIFICATE_FILE_NAME    "csr_server.pem"
#define TLS_SERVER_CERTIFICATE_FILE_NAME    "tls_server.pem"
#define CIPHER_SERVER_CERTIFICATE_FILE_NAME "cipher_server.pem"
#define SIGNER_SERVER_CERTIFICATE_FILE_NAME "signer_server.pem"
#define TLS_KEYSTORE_PATH              		"/keystore/tls_client_keystore.p12"
#define CIPHER_KEYSTORE_PATH    	    	"/keystore/cipher_client_keystore.p12"
#define SIGNER_KEYSTORE_PATH           		"/keystore/signer_client_keystore.p12"
#define LOGGER_FILE_NAME               		"logs.txt"


static bool send_message(ue_channel_client *channel_client, ue_socket_client_connection *connection, ue_byte_stream *message_to_send);

static size_t receive_message(ue_channel_client *channel_client, ue_socket_client_connection *connection);

static bool send_cipher_message(ue_channel_client *channel_client, ue_socket_client_connection *connection, ue_byte_stream *message_to_send);

static size_t receive_cipher_message(ue_channel_client *channel_client, ue_socket_client_connection *connection);

static bool create_keystores(ue_channel_client *channel_client, const char *csr_server_host, unsigned short int csr_server_port, char *keystore_password);

static bool send_csr(ue_channel_client *channel_client, ue_csr_context *context, int csr_sub_type);

static bool csr_read_consumer(void *parameter);

static bool csr_process_response(void *parameter);

static bool process_user_input(ue_channel_client *channel_client, ue_socket_client_connection *connection,
    unsigned char *data, size_t data_size);

static bool tls_read_consumer(void *parameter);

static bool tls_write_consumer_stdin(void *parameter);

static bool tls_write_consumer_push(void *parameter);

static bool process_get_certificate_request(ue_channel_client *channel_client, ue_pkcs12_keystore *keystore,
	ue_socket_client_connection *connection, const unsigned char *friendly_name, size_t friendly_name_size);

static bool process_channel_key_request(ue_channel_client *channel_client, ue_socket_client_connection *connection,
	ue_byte_stream *request);

static bool send_nickname_request(ue_channel_client *channel_client, ue_socket_client_connection *connection);

static bool process_message_request(ue_channel_client *channel_client, ue_socket_client_connection *connection,
    unsigned char *data, size_t data_size);

static bool process_nickname_response(ue_channel_client *channel_client, ue_byte_stream *response);

static bool process_channel_connection_response(ue_channel_client *channel_client, ue_byte_stream *response);

static bool process_message_response(ue_channel_client *channel_client, ue_byte_stream *message);

static bool process_certificate_response(ue_channel_client *channel_client, ue_byte_stream *response);

static bool process_channel_key_response(ue_channel_client *channel_client, ue_socket_client_connection *connection,
	ue_byte_stream *response);

static bool generate_certificate(ue_x509_certificate **certificate, ue_private_key **private_key);


bool ue_channel_client_init(int channel_clients_number) {
	int i;

	ue_check_parameter_or_return(channel_clients_number > 0);

	max_channel_clients_number = channel_clients_number;

	ue_safe_alloc(channel_clients, ue_channel_client *, max_channel_clients_number);
	for (i = 0; i < max_channel_clients_number; i++) {
		channel_clients[i] = NULL;
	}

	return true;
}

void ue_channel_client_uninit() {
	ue_safe_free(channel_clients);
}

static int get_available_channel_client_index() {
	int i;

	for (i = 0; i < max_channel_clients_number; i++) {
		if (!channel_clients[i]) {
			return i;
		}
	}

	return -1;
}

ue_channel_client *ue_channel_client_create(char *persistent_path, char *nickname, const char *csr_server_host, int csr_server_port,
	const char *tls_server_host, int tls_server_port, char *keystore_password, const char *server_certificates_path, void *user_context,
	bool (*write_callback)(void *user_context, ue_byte_stream *printer), bool (*initialization_begin_callback)(void *user_context),
	bool (*initialization_end_callback)(void *user_context), bool (*uninitialization_begin_callback)(void *user_context),
	bool (*uninitialization_end_callback)(void *user_context), bool (*connection_begin_callback)(void *user_context),
	bool (*connection_end_callback)(void *user_context), char *(*user_input_callback)(void *user_context),
    const char *cipher_name, const char *digest_name, ue_user_input_mode user_input_mode) {

	ue_channel_client *channel_client;
	bool result;
	char *keystore_folder_path, *logs_file_name, *full_persistent_path;
	int available_channel_client_index;

	ue_check_parameter_or_return(persistent_path);
	ue_check_parameter_or_return(nickname);
	ue_check_parameter_or_return(csr_server_host);
	ue_check_parameter_or_return(csr_server_port > 0);
	if (csr_server_port <= 1024) {
		ue_logger_warn("CSR server port set to %d but it would be better if it > 1024");
	}
	ue_check_parameter_or_return(tls_server_host);
	ue_check_parameter_or_return(tls_server_port > 0);
	if (tls_server_port <= 1024) {
		ue_logger_warn("TLS server port set to %d but it would be better if it > 1024");
	}

	result = false;
	keystore_folder_path = NULL;
	logs_file_name = NULL;
	full_persistent_path = NULL;

	if ((available_channel_client_index = get_available_channel_client_index()) == -1) {
		ue_stacktrace_push_msg("No such channel client slot available")
		return NULL;
	}

	ue_safe_alloc(channel_clients[available_channel_client_index], ue_channel_client, 1);
	channel_client = channel_clients[available_channel_client_index];
    channel_client->fd = -1;
    channel_client->connection = NULL;
    channel_client->new_message = NULL;
    channel_client->running = false;
    channel_client->nickname = NULL;
    channel_client->read_thread = NULL;
    channel_client->write_thread = NULL;
    channel_client->tls_session = NULL;
	channel_client->channel_id = -1;
	channel_client->keystore_password = NULL;
	channel_client->tls_keystore_ok = false;
	channel_client->cipher_keystore_ok = false;
	channel_client->signer_keystore_ok = false;
	channel_client->tls_csr_context = NULL;
	channel_client->cipher_csr_context = NULL;
	channel_client->signer_csr_context = NULL;
	channel_client->tls_keystore = NULL;
	channel_client->cipher_keystore = NULL;
    channel_client->signer_keystore = NULL;
	channel_client->channel_key = NULL;
	channel_client->channel_iv = NULL;
	channel_client->channel_iv_size = 0;
	channel_client->persistent_path = NULL;
	channel_client->tls_server_host = NULL;
	channel_client->write_callback = write_callback;
	channel_client->initialization_begin_callback = initialization_begin_callback;
	channel_client->initialization_end_callback = initialization_end_callback;
	channel_client->connection_begin_callback = connection_begin_callback;
	channel_client->connection_end_callback = connection_end_callback;
	channel_client->user_input_callback = user_input_callback;
	channel_client->user_context = user_context;
	channel_client->csr_processing_state = FREE_STATE;
    channel_client->user_input_mode = user_input_mode;

	if (channel_client->initialization_begin_callback) {
		channel_client->initialization_begin_callback(channel_client->user_context);
	}

	if (!(channel_client->mutex = ue_thread_mutex_create())) {
		ue_stacktrace_push_msg("Failed to init channel_client->mutex");
		goto clean_up;
	}

	if (!(channel_client->cond = ue_thread_cond_create())) {
		ue_stacktrace_push_msg("Failed to init channel_client->cond");
		goto clean_up;
	}

    if (!(channel_client->push_mode_queue = ue_queue_create())) {
        ue_stacktrace_push_msg("Failed to create push mode queue");
		goto clean_up;
	}

	channel_client->nickname = ue_string_create_from(nickname);
	channel_client->persistent_path = ue_string_create_from(persistent_path);
	channel_client->tls_server_host = ue_string_create_from(tls_server_host);
	channel_client->tls_server_port = tls_server_port;
	channel_client->cipher_name = ue_string_create_from(cipher_name);
	channel_client->digest_name = ue_string_create_from(digest_name);

	full_persistent_path = ue_strcat_variadic("sss", channel_client->persistent_path, "/", channel_client->nickname);

	ue_create_folder(full_persistent_path);

	logs_file_name = ue_strcat_variadic("sss", full_persistent_path, "/", LOGGER_FILE_NAME);
	channel_client->logs_file = NULL;
    if (!(channel_client->logs_file = fopen(logs_file_name, "a"))) {
        ue_stacktrace_push_msg("Failed to open logs file at path '%s'", logs_file_name)
    }

	ue_logger_set_fp(ue_logger_manager_get_logger(), channel_client->logs_file);

    //ue_logger_set_details(ue_logger_manager_get_logger(), true);

	channel_client->csr_server_certificate_path = ue_strcat_variadic("sss", server_certificates_path, "/", CSR_SERVER_CERTIFICATE_FILE_NAME);
	channel_client->tls_server_certificate_path = ue_strcat_variadic("sss", server_certificates_path, "/", TLS_SERVER_CERTIFICATE_FILE_NAME);
	channel_client->cipher_server_certificate_path = ue_strcat_variadic("sss", server_certificates_path, "/", CIPHER_SERVER_CERTIFICATE_FILE_NAME);
	channel_client->signer_server_certificate_path = ue_strcat_variadic("sss", server_certificates_path, "/", SIGNER_SERVER_CERTIFICATE_FILE_NAME);
	channel_client->tls_keystore_path = ue_strcat_variadic("ss", full_persistent_path, TLS_KEYSTORE_PATH);
	channel_client->cipher_keystore_path = ue_strcat_variadic("ss", full_persistent_path, CIPHER_KEYSTORE_PATH);
	channel_client->signer_keystore_path = ue_strcat_variadic("ss", full_persistent_path, SIGNER_KEYSTORE_PATH);

	if (keystore_password) {
		channel_client->keystore_password = ue_string_create_from(keystore_password);
	}

	keystore_folder_path = ue_strcat_variadic("ssss", channel_client->persistent_path, "/", channel_client->nickname, "/keystore");

	if (!ue_is_dir_exists(keystore_folder_path)) {
		ue_logger_info("Creating '%s'...", keystore_folder_path);
		if (!ue_create_folder(keystore_folder_path)) {
			ue_stacktrace_push_msg("Failed to create '%s'", keystore_folder_path);
			goto clean_up;
		}
	}

	if (!ue_x509_certificate_load_from_file(channel_client->csr_server_certificate_path, &channel_client->csr_server_certificate)) {
		ue_stacktrace_push_msg("Failed to load CSR server certificate from path '%s'", channel_client->csr_server_certificate_path);
		goto clean_up;
	}

	if (!ue_x509_certificate_load_from_file(channel_client->tls_server_certificate_path, &channel_client->tls_server_certificate)) {
		ue_stacktrace_push_msg("Failed to load TLS server certificate from path '%s'", channel_client->tls_server_certificate_path);
		goto clean_up;
	}

	if (!ue_x509_certificate_load_from_file(channel_client->cipher_server_certificate_path, &channel_client->cipher_server_certificate)) {
		ue_stacktrace_push_msg("Failed to load cipher server certificate from path '%s'", channel_client->cipher_server_certificate_path);
		goto clean_up;
	}

	if (!ue_x509_certificate_load_from_file(channel_client->signer_server_certificate_path, &channel_client->signer_server_certificate)) {
		ue_stacktrace_push_msg("Failed to load signer server certificate from path '%s'", channel_client->signer_server_certificate_path);
		goto clean_up;
	}

	if (!create_keystores(channel_client, csr_server_host, csr_server_port, channel_client->keystore_password)) {
		ue_stacktrace_push_msg("Failed to create keystore");
		goto clean_up;
	}

	result = true;

clean_up:
	if (channel_client->initialization_end_callback) {
		channel_client->initialization_end_callback(channel_client->user_context);
	}
	ue_safe_free(keystore_folder_path);
	ue_safe_free(logs_file_name);
	ue_safe_free(full_persistent_path);
	if (!result) {
		ue_channel_client_destroy(channel_client);
		channel_client = NULL;
	}
	return channel_client;
}

void ue_channel_client_destroy(ue_channel_client *channel_client) {
	if (!channel_client) {
		return;
	}
	if (channel_client->uninitialization_begin_callback) {
		channel_client->uninitialization_begin_callback(channel_client->user_context);
	}
	ue_safe_free(channel_client->read_thread)
	ue_safe_free(channel_client->write_thread)
	ue_thread_mutex_destroy(channel_client->mutex);
	ue_thread_cond_destroy(channel_client->cond);
	if (channel_client->tls_session) {
		ue_tls_session_destroy(channel_client->tls_session);
	}
	ue_byte_stream_destroy(channel_client->new_message);
	ue_safe_str_free(channel_client->nickname)
	ue_safe_str_free(channel_client->keystore_password);
	if (channel_client->connection) {
		ue_socket_client_connection_destroy(channel_client->connection);
	}
	else {
		ue_socket_close(channel_client->fd);
	}
	ue_x509_certificate_destroy(channel_client->csr_server_certificate);
	ue_x509_certificate_destroy(channel_client->tls_server_certificate);
	ue_x509_certificate_destroy(channel_client->cipher_server_certificate);
	ue_x509_certificate_destroy(channel_client->signer_server_certificate);
	if (channel_client->tls_csr_context) {
		ue_sym_key_destroy(channel_client->tls_csr_context->future_key);
		ue_safe_free(channel_client->tls_csr_context->iv);
		ue_safe_free(channel_client->tls_csr_context);
	}
	if (channel_client->cipher_csr_context) {
		ue_sym_key_destroy(channel_client->cipher_csr_context->future_key);
		ue_safe_free(channel_client->cipher_csr_context->iv);
		ue_safe_free(channel_client->cipher_csr_context);
	}
	if (channel_client->signer_csr_context) {
		ue_sym_key_destroy(channel_client->signer_csr_context->future_key);
		ue_safe_free(channel_client->signer_csr_context->iv);
		ue_safe_free(channel_client->signer_csr_context);
	}
    //ue_pkcs12_keystore_destroy(channel_client->tls_keystore);
    //ue_pkcs12_keystore_destroy(channel_client->cipher_keystore);
    //ue_pkcs12_keystore_destroy(channel_client->signer_keystore);
	ue_safe_free(channel_client->csr_server_certificate_path);
	ue_safe_free(channel_client->tls_server_certificate_path);
	ue_safe_free(channel_client->cipher_server_certificate_path);
	ue_safe_free(channel_client->signer_server_certificate_path);
	ue_safe_free(channel_client->tls_keystore_path);
	ue_safe_free(channel_client->cipher_keystore_path);
	ue_safe_free(channel_client->signer_keystore_path);
	ue_sym_key_destroy(channel_client->channel_key);
	ue_safe_free(channel_client->channel_iv);
	ue_safe_free(channel_client->persistent_path);
	ue_safe_free(channel_client->tls_server_host);
	ue_safe_free(channel_client->cipher_name);
	ue_safe_free(channel_client->digest_name);
    ue_queue_destroy(channel_client->push_mode_queue);
	if (channel_client->uninitialization_end_callback) {
		channel_client->uninitialization_end_callback(channel_client->user_context);
	}
	ue_safe_fclose(channel_client->logs_file);
	ue_logger_set_fp(ue_logger_manager_get_logger(), NULL);
	ue_safe_free(channel_client);
}

bool ue_channel_client_start(ue_channel_client *channel_client) {

	ue_check_parameter_or_return(channel_client->tls_server_host);
	ue_check_parameter_or_return(channel_client->tls_server_port > 0);

    ue_x509_certificate **ca_certificates = NULL;
    ue_safe_alloc(ca_certificates, ue_x509_certificate *, 1);
    ca_certificates[0] = channel_client->tls_server_certificate;

	if (channel_client->connection_begin_callback) {
		channel_client->connection_begin_callback(channel_client->user_context);
	}

	/* @todo pass keystore ptr instead of path */
	if (!(channel_client->tls_session = ue_tls_session_create_client((char *)channel_client->tls_keystore_path, channel_client->keystore_password, ca_certificates, 1))) {
		ue_stacktrace_push_msg("Failed to create TLS session");
		if (channel_client->connection_end_callback) {
			channel_client->connection_end_callback(channel_client->user_context);
		}
		return false;
	}

	ue_safe_free(ca_certificates);

    channel_client->fd = ue_socket_open_tcp();
    if (!(channel_client->connection = ue_socket_connect(channel_client->fd, AF_INET, channel_client->tls_server_host, channel_client->tls_server_port, channel_client->tls_session))) {
        ue_stacktrace_push_msg("Failed to connect socket to server");
		if (channel_client->connection_end_callback) {
			channel_client->connection_end_callback(channel_client->user_context);
		}
        return false;
    }

	channel_client->running = true;
	channel_client->transmission_state = WRITING_STATE;
	channel_client->new_message = ue_byte_stream_create();
	channel_client->channel_id = -1;
	channel_client->connection->optional_data = channel_client;

    _Pragma("GCC diagnostic push")
    _Pragma("GCC diagnostic ignored \"-Wpedantic\"")
		channel_client->read_thread = ue_thread_create((void *)tls_read_consumer, (void *)channel_client->connection);
        if (channel_client->user_input_mode == UNKNOWNECHO_STDIN_INPUT) {
            channel_client->write_thread = ue_thread_create((void *)tls_write_consumer_stdin, (void *)channel_client->connection);
        } else if (channel_client->user_input_mode == UNKNOWNECHO_PUSH_INPUT) {
            channel_client->write_thread = ue_thread_create((void *)tls_write_consumer_push, (void *)channel_client->connection);
        } else {
            ue_stacktrace_push_msg("Unknown user input mode");
            return false;
        }
    _Pragma("GCC diagnostic pop")

	if (channel_client->connection_end_callback) {
		channel_client->connection_end_callback(channel_client->user_context);
	}

    ue_thread_join(channel_client->read_thread, NULL);
    ue_thread_join(channel_client->write_thread, NULL);

    return true;
}

void ue_channel_client_shutdown_signal_callback(int sig) {
	int i;

    ue_logger_trace("Signal received %d", sig);

	for (i = 0; i < max_channel_clients_number; i++) {
		if (!channel_clients[i]) {
			continue;
		}
		ue_logger_info("Shuting down client #%d...", i);
		channel_clients[i]->running = false;
		channel_clients[i]->transmission_state = CLOSING_STATE;
		ue_thread_cond_signal(channel_clients[i]->cond);
		ue_thread_cancel(channel_clients[i]->read_thread);
	}
}

bool ue_channel_client_set_user_input_mode(ue_channel_client *channel_client, ue_user_input_mode mode) {
    channel_client->user_input_mode = mode;
    return true;
}

bool ue_channel_client_push_message(ue_channel_client *channel_client, unsigned char *data, size_t data_size) {
    pushed_message message;
    message.data = data;
    message.size = data_size;

    return ue_queue_push_wait(channel_client->push_mode_queue, &message);
}

static bool send_message(ue_channel_client *channel_client, ue_socket_client_connection *connection, ue_byte_stream *message_to_send) {
	size_t sent;

	ue_check_parameter_or_return(connection);
	ue_check_parameter_or_return(connection->fd > 0);
	ue_check_parameter_or_return(message_to_send);
	ue_check_parameter_or_return(ue_byte_stream_get_size(message_to_send) > 0);

	ue_thread_mutex_lock(channel_client->mutex);
	channel_client->transmission_state = WRITING_STATE;
	sent = ue_socket_send_sync(connection);
	channel_client->transmission_state = READING_STATE;
	ue_thread_cond_signal(channel_client->cond);
	ue_thread_mutex_unlock(channel_client->mutex);

	if (sent < 0 || sent == ULLONG_MAX) {
		ue_logger_info("Connection is interrupted.");
		ue_stacktrace_push_msg("Failed to send message to server");
		channel_client->running = false;
		return false;
	}

	return true;
}

static size_t receive_message(ue_channel_client *channel_client, ue_socket_client_connection *connection) {
	size_t received;

	ue_thread_mutex_lock(channel_client->mutex);
    while (channel_client->transmission_state == WRITING_STATE) {
        ue_thread_cond_wait(channel_client->cond, channel_client->mutex);
    }
    ue_thread_mutex_unlock(channel_client->mutex);
	ue_byte_stream_clean_up(connection->received_message);
    received = ue_socket_receive_sync(connection);

    return received;
}

static bool send_cipher_message(ue_channel_client *channel_client, ue_socket_client_connection *connection, ue_byte_stream *message_to_send) {
	bool result;
	unsigned char *cipher_data;
	size_t cipher_data_size;
	ue_x509_certificate *server_certificate;
    ue_public_key *server_public_key;

	result = false;
	cipher_data = NULL;
	server_public_key = NULL;

	if (!(server_certificate = ue_pkcs12_keystore_find_certificate_by_friendly_name(channel_client->cipher_keystore, (const unsigned char *)"CIPHER_SERVER", strlen("CIPHER_SERVER")))) {
        ue_stacktrace_push_msg("Failed to get cipher client certificate");
        goto clean_up;
    }

    if (!(server_public_key = ue_rsa_public_key_from_x509_certificate(server_certificate))) {
        ue_stacktrace_push_msg("Failed to get server public key from server certificate");
        goto clean_up;
    }

	if (!ue_cipher_plain_data(ue_byte_stream_get_data(message_to_send), ue_byte_stream_get_size(message_to_send),
		server_public_key, channel_client->signer_keystore->private_key, &cipher_data, &cipher_data_size, channel_client->cipher_name,
		channel_client->digest_name)) {

        ue_stacktrace_push_msg("Failed to cipher plain data");
        goto clean_up;
    }

	ue_byte_stream_clean_up(connection->message_to_send);

	if (!ue_byte_writer_append_bytes(connection->message_to_send, cipher_data, cipher_data_size)) {
		ue_stacktrace_push_msg("Failed to write cipher data to message to send");
		goto clean_up;
	}

	if (!send_message(channel_client, connection, connection->message_to_send)) {
		ue_stacktrace_push_msg("Failed to send cipher message");
		goto clean_up;
	}

	result = true;

clean_up:
	ue_safe_free(cipher_data);
	ue_public_key_destroy(server_public_key);
	return result;
}

static size_t receive_cipher_message(ue_channel_client *channel_client, ue_socket_client_connection *connection) {
	unsigned char *plain_data;
    size_t received, plain_data_size;
	ue_x509_certificate *server_certificate;
	ue_public_key *server_public_key;

	plain_data = NULL;
	server_public_key = NULL;

	received = receive_message(channel_client, connection);

	if (received <= 0 || received == ULLONG_MAX) {
		ue_logger_warn("Connection with server is interrupted.");
		goto clean_up;
	}

	if (!(server_certificate = ue_pkcs12_keystore_find_certificate_by_friendly_name(channel_client->signer_keystore, (const unsigned char *)"SIGNER_SERVER", strlen("SIGNER_SERVER")))) {
		ue_stacktrace_push_msg("Failed to find server signer certificate");
		received = -1;
		goto clean_up;
	}

	if (!(server_public_key = ue_rsa_public_key_from_x509_certificate(server_certificate))) {
        ue_stacktrace_push_msg("Failed to get server public key from server certificate");
		received = -1;
        goto clean_up;
    }

	if (!ue_decipher_cipher_data(ue_byte_stream_get_data(connection->received_message), ue_byte_stream_get_size(connection->received_message),
		channel_client->cipher_keystore->private_key, server_public_key, &plain_data, &plain_data_size, channel_client->cipher_name, channel_client->digest_name)) {

		received = -1;
		ue_stacktrace_push_msg("Failed decipher message data");
		goto clean_up;
	}

	ue_byte_stream_clean_up(connection->received_message);

	if (!ue_byte_writer_append_bytes(connection->received_message, plain_data, plain_data_size)) {
		received = -1;
		ue_stacktrace_push_msg("Failed to write plain data to received message");
		goto clean_up;
	}

clean_up:
	ue_public_key_destroy(server_public_key);
	ue_safe_free(plain_data);
	return received;
}

static bool create_keystores(ue_channel_client *channel_client, const char *csr_server_host, unsigned short int csr_server_port, char *keystore_password) {
	bool result;
	bool tls_keystore_exists, cipher_keystore_exists, signer_keystore_exists;

	ue_check_parameter_or_return(csr_server_host);
	ue_check_parameter_or_return(csr_server_port > 0);
	ue_check_parameter_or_return(keystore_password);

	result = false;

	tls_keystore_exists = ue_is_file_exists(channel_client->tls_keystore_path);
	cipher_keystore_exists = ue_is_file_exists(channel_client->cipher_keystore_path);
	signer_keystore_exists = ue_is_file_exists(channel_client->signer_keystore_path);

	if (!tls_keystore_exists) {
		ue_safe_alloc(channel_client->tls_csr_context, ue_csr_context, 1);
		channel_client->tls_csr_context->signed_certificate = NULL;
		channel_client->tls_csr_context->private_key = NULL;
		channel_client->tls_csr_context->future_key = NULL;
		channel_client->tls_csr_context->iv = NULL;
	} else {
		if (!(channel_client->tls_keystore = ue_pkcs12_keystore_load(channel_client->tls_keystore_path, channel_client->keystore_password))) {
	        ue_stacktrace_push_msg("Failed to load cipher pkcs12 keystore");
	        goto clean_up;
	    }
	}

	if (!cipher_keystore_exists) {
		ue_safe_alloc(channel_client->cipher_csr_context, ue_csr_context, 1);
		channel_client->cipher_csr_context->signed_certificate = NULL;
		channel_client->cipher_csr_context->private_key = NULL;
		channel_client->cipher_csr_context->future_key = NULL;
		channel_client->cipher_csr_context->iv = NULL;
	} else {
		if (!(channel_client->cipher_keystore = ue_pkcs12_keystore_load(channel_client->cipher_keystore_path, channel_client->keystore_password))) {
	        ue_stacktrace_push_msg("Failed to load cipher pkcs12 keystore");
	        goto clean_up;
	    }
	}

	if (!signer_keystore_exists) {
		ue_safe_alloc(channel_client->signer_csr_context, ue_csr_context, 1);
		channel_client->signer_csr_context->signed_certificate = NULL;
		channel_client->signer_csr_context->private_key = NULL;
		channel_client->signer_csr_context->future_key = NULL;
		channel_client->signer_csr_context->iv = NULL;
	} else {
		if (!(channel_client->signer_keystore = ue_pkcs12_keystore_load(channel_client->signer_keystore_path, channel_client->keystore_password))) {
			ue_stacktrace_push_msg("Failed to load signer pkcs12 keystore");
			goto clean_up;
		}
	}

	if (!tls_keystore_exists || !cipher_keystore_exists || !signer_keystore_exists) {
		channel_client->fd = ue_socket_open_tcp();
		if (!(channel_client->connection = ue_socket_connect(channel_client->fd, AF_INET, csr_server_host, csr_server_port, NULL))) {
			ue_stacktrace_push_msg("Failed to connect socket to server");
			goto clean_up;
		}

		channel_client->running = true;
		channel_client->transmission_state = WRITING_STATE;
		channel_client->connection->optional_data = channel_client;

	    _Pragma("GCC diagnostic push")
	    _Pragma("GCC diagnostic ignored \"-Wpedantic\"")
			channel_client->read_thread = ue_thread_create((void *)csr_read_consumer, (void *)channel_client->connection);
			channel_client->connection->read_messages_consumer_thread = ue_thread_create((void *)csr_process_response, (void *)channel_client->connection);
	    _Pragma("GCC diagnostic pop")
	}

	if (!tls_keystore_exists) {
		ue_logger_info("TLS keystore doesn't exists. A CSR will be built.");
		if (!send_csr(channel_client, channel_client->tls_csr_context, CSR_TLS_REQUEST)) {
			ue_stacktrace_push_msg("Failed to process CSR exchange for TLS");
			goto clean_up;
		}
	} else {
		channel_client->tls_keystore_ok = true;
	}

	if (!cipher_keystore_exists) {
		ue_logger_info("Cipher keystore doesn't exists. A CSR will be built.");
		if (!send_csr(channel_client, channel_client->cipher_csr_context, CSR_CIPHER_REQUEST)) {
			ue_stacktrace_push_msg("Failed to process CSR exchange for cipher");
			goto clean_up;
		}
	} else {
		channel_client->cipher_keystore_ok = true;
	}

	if (!signer_keystore_exists) {
		ue_logger_info("Signer keystore doesn't exists. A CSR will be built.");
		if (!send_csr(channel_client, channel_client->signer_csr_context, CSR_SIGNER_REQUEST)) {
			ue_stacktrace_push_msg("Failed to process CSR exchange for signer");
			goto clean_up;
		}
	} else {
		channel_client->signer_keystore_ok = true;
	}

	if (!tls_keystore_exists || !cipher_keystore_exists || !signer_keystore_exists) {
		ue_thread_join(channel_client->read_thread, NULL);
		ue_thread_join(channel_client->connection->read_messages_consumer_thread, NULL);

		if (ue_stacktrace_is_filled()) {
			ue_logger_stacktrace("An error occurred while processing read_consumer()");
			ue_stacktrace_clean_up();
			goto clean_up;
		}
	}

	if (!tls_keystore_exists) {
		if (ue_x509_certificate_verify(channel_client->tls_csr_context->signed_certificate, channel_client->tls_server_certificate)) {
			ue_logger_info("Certificate is correctly signed by the CA");
		} else {
			ue_stacktrace_push_msg("Certificate isn't correctly signed by the CA");
			goto clean_up;
		}

		if (!(channel_client->tls_keystore = ue_pkcs12_keystore_create(channel_client->tls_csr_context->signed_certificate, channel_client->tls_csr_context->private_key, "TLS_CLIENT"))) {
			ue_stacktrace_push_msg("Failed to create keystore from specified signed certificate and private key");
			goto clean_up;
		}

		ue_pkcs12_keystore_add_certificate_from_file(channel_client->tls_keystore, channel_client->tls_server_certificate_path, (const unsigned char *)"TLS_SERVER", strlen("TLS_SERVER"));

		if (!ue_pkcs12_keystore_write(channel_client->tls_keystore, channel_client->tls_keystore_path, keystore_password)) {
			ue_stacktrace_push_msg("Failed to write keystore to '%s'", channel_client->tls_keystore_path);
			goto clean_up;
		}

		ue_logger_info("TLS keystore created.");
	}

	if (!cipher_keystore_exists) {
		if (ue_x509_certificate_verify(channel_client->cipher_csr_context->signed_certificate, channel_client->cipher_server_certificate)) {
			ue_logger_info("Certificate is correctly signed by the CA");
		} else {
			ue_stacktrace_push_msg("Certificate isn't correctly signed by the CA");
			goto clean_up;
		}

		if (!(channel_client->cipher_keystore = ue_pkcs12_keystore_create(channel_client->cipher_csr_context->signed_certificate, channel_client->cipher_csr_context->private_key,
			"CIPHER_CLIENT"))) {

			ue_stacktrace_push_msg("Failed to create keystore from specified signed certificate and private key");
			goto clean_up;
		}

		ue_pkcs12_keystore_add_certificate_from_file(channel_client->cipher_keystore, channel_client->cipher_server_certificate_path, (const unsigned char *)"CIPHER_SERVER", strlen("CIPHER_SERVER"));

		if (!ue_pkcs12_keystore_write(channel_client->cipher_keystore, channel_client->cipher_keystore_path, keystore_password)) {
			ue_stacktrace_push_msg("Failed to write keystore to '%s'", channel_client->cipher_keystore_path);
			goto clean_up;
		}

		ue_logger_info("Cipher keystore created.");
	}

	if (!signer_keystore_exists) {
		if (ue_x509_certificate_verify(channel_client->signer_csr_context->signed_certificate, channel_client->signer_server_certificate)) {
			ue_logger_info("Certificate is correctly signed by the CA");
		} else {
			ue_stacktrace_push_msg("Certificate isn't correctly signed by the CA");
			goto clean_up;
		}

		if (!(channel_client->signer_keystore = ue_pkcs12_keystore_create(channel_client->signer_csr_context->signed_certificate, channel_client->signer_csr_context->private_key,
			"SIGNER_CLIENT"))) {

			ue_stacktrace_push_msg("Failed to create keystore from specified signed certificate and private key");
			goto clean_up;
		}

		ue_pkcs12_keystore_add_certificate_from_file(channel_client->signer_keystore, channel_client->signer_server_certificate_path, (const unsigned char *)"SIGNER_SERVER", strlen("SIGNER_SERVER"));

		if (!ue_pkcs12_keystore_write(channel_client->signer_keystore, channel_client->signer_keystore_path, keystore_password)) {
			ue_stacktrace_push_msg("Failed to write keystore to '%s'", channel_client->signer_keystore_path);
			goto clean_up;
		}

		ue_logger_info("Signer keystore created.");
	}

	result = true;

clean_up:
	return result;
}

static bool send_csr(ue_channel_client *channel_client, ue_csr_context *context, int csr_sub_type) {
	bool result;
	ue_x509_certificate *certificate;
	size_t csr_request_size;
	unsigned char *csr_request;
	ue_byte_stream *stream;
	ue_public_key *ca_public_key;

	ue_check_parameter_or_return(channel_client);
	ue_check_parameter_or_return(channel_client->connection);
	ue_check_parameter_or_return(context);
	ue_check_parameter_or_return(csr_sub_type == CSR_TLS_REQUEST || csr_sub_type == CSR_CIPHER_REQUEST || csr_sub_type == CSR_SIGNER_REQUEST);
	if (channel_client->connection->tls) {
		ue_stacktrace_push_msg("TLS object of CSR connection isn't null but it should.");
		return false;
	}

	result = false;
	certificate = NULL;
	csr_request = NULL;
	stream = ue_byte_stream_create();
	ca_public_key = NULL;

	ue_logger_trace("Generating crypto random future key...");
	if (!(context->future_key = ue_sym_key_create_random())) {
		ue_stacktrace_push_msg("Failed to gen random sym key for server response encryption");
		goto clean_up;
	}

	ue_logger_trace("Generating crypto random IV...");
	/* @todo get correct IV size with a function */
	ue_safe_alloc(context->iv, unsigned char, 16);
	if (!(ue_crypto_random_bytes(context->iv, 16))) {
		ue_stacktrace_push_msg("Failed to get crypto random bytes for IV");
		goto clean_up;
	}
	context->iv_size = 16;

	ue_logger_trace("Extracting RSA public key from CSR X509 server certificate...");
	if (!(ca_public_key = ue_rsa_public_key_from_x509_certificate(channel_client->csr_server_certificate))) {
		ue_stacktrace_push_msg("Failed to extract RSA public key from CA certificate");
		goto clean_up;
	}

	ue_logger_info("Generating new certificate and private key...");
	if (!generate_certificate(&certificate, &context->private_key)) {
        ue_stacktrace_push_msg("Failed to generate x509 certificate and private key");
        goto clean_up;
    }

	ue_logger_trace("Building CSR request...");
	if (!(csr_request = ue_csr_build_client_request(certificate, context->private_key, ca_public_key, &csr_request_size, context->future_key, context->iv,
		context->iv_size, channel_client->cipher_name, channel_client->digest_name))) {

		ue_stacktrace_push_msg("Failed to build CSR request");
		goto clean_up;
	}

	if (!ue_byte_writer_append_int(stream, csr_sub_type)) {
		ue_stacktrace_push_msg("Failed to write CSR sub type to stream");
		goto clean_up;
	}
	if (!ue_byte_writer_append_int(stream, (int)strlen(channel_client->nickname))) {
		ue_stacktrace_push_msg("Failed to write nickname size to stream");
		goto clean_up;
	}
	if (!ue_byte_writer_append_bytes(stream, (unsigned char *)channel_client->nickname, strlen(channel_client->nickname))) {
		ue_stacktrace_push_msg("Failed to write nickname to stream");
		goto clean_up;
	}
	if (!ue_byte_writer_append_int(stream, (int)csr_request_size)) {
		ue_stacktrace_push_msg("Failed to write cipher data size to stream");
		goto clean_up;
	}
	if (!ue_byte_writer_append_bytes(stream, csr_request, csr_request_size)) {
		ue_stacktrace_push_msg("Failed to write CSR request to stream");
		goto clean_up;
	}

	ue_byte_stream_clean_up(channel_client->connection->message_to_send);
	if (!ue_byte_writer_append_bytes(channel_client->connection->message_to_send, ue_byte_stream_get_data(stream), ue_byte_stream_get_size(stream))) {
		ue_stacktrace_push_msg("Failed to write stream data to message to send");
		goto clean_up;
	}

	ue_logger_info("Sending CSR...");
	if (!send_message(channel_client, channel_client->connection, channel_client->connection->message_to_send)) {
		ue_stacktrace_push_msg("Failed to send message to send");
		goto clean_up;
	}

	result = true;

clean_up:
	ue_safe_free(csr_request);
	ue_byte_stream_destroy(stream);
	ue_public_key_destroy(ca_public_key);
	ue_x509_certificate_destroy(certificate);
	return result;
}

static bool csr_read_consumer(void *parameter) {
	size_t received;
	bool result;
	ue_socket_client_connection *connection;
	ue_channel_client *channel_client;

	result = true;
	connection = (ue_socket_client_connection *)parameter;
	channel_client = connection->optional_data;

	if (connection->tls) {
		ue_logger_error("TLS object of CSR connection isn't null but it should.");
		return false;
	}

	while (channel_client->running) {
		received = receive_message(channel_client, connection);
		result = true;

		// @todo set timeout in case of server lag or reboot
		if (received < 0 || received == ULLONG_MAX) {
			ue_logger_warn("Connection with server is interrupted. Stopping client...");
			if (ue_stacktrace_is_filled()) {
				ue_stacktrace_push_msg("Failed to receive server message");
			}
			channel_client->running = false;
			result = false;
		}
		else if (received == 0) {
            ue_logger_trace("Timeout 10ms...");
			ue_millisleep(10);
		}
		else {
			if (ue_byte_stream_get_size(connection->received_message) > 0) {
				ue_queue_push_wait(connection->received_messages, (void *)connection->received_message);
			} else {
				ue_logger_warn("Received message is empty");
			}
		}

		/* @todo convert to percent print */
		ue_logger_debug("channel_client->tls_keystore_ok : %d", channel_client->tls_keystore_ok);
		ue_logger_debug("channel_client->cipher_keystore_ok : %d", channel_client->cipher_keystore_ok);
		ue_logger_debug("channel_client->signer_keystore_ok : %d", channel_client->signer_keystore_ok);

		if (channel_client->tls_keystore_ok && channel_client->cipher_keystore_ok && channel_client->signer_keystore_ok) {
			channel_client->running = false;
		}
	}

	result = true;

	return result;
}

static bool csr_process_response(void *parameter) {
	int csr_sub_type, csr_response_size;
	unsigned char *csr_response;
	ue_socket_client_connection *connection;
	ue_channel_client *channel_client;
	ue_byte_stream *received_message;

	csr_response = NULL;
	connection = (ue_socket_client_connection *)parameter;
	channel_client = connection->optional_data;
	received_message = NULL;

    while (!channel_client->tls_keystore_ok ||
        !channel_client->cipher_keystore_ok ||
		!channel_client->signer_keystore_ok) {

		received_message = ue_queue_front_wait(connection->received_messages);

		ue_byte_stream_set_position(received_message, 0);

		if (!ue_byte_read_next_int(received_message, &csr_sub_type)) {
			ue_stacktrace_push_msg("Failed to read CSR sub type in response");
			goto clean_up;
		}

		if (csr_sub_type != CSR_TLS_RESPONSE &&
			csr_sub_type != CSR_CIPHER_RESPONSE &&
			csr_sub_type != CSR_SIGNER_RESPONSE) {
			ue_logger_warn("Invalid CSR sub type");
			goto clean_up;
		}

		if (!ue_byte_read_next_int(received_message, &csr_response_size)) {
			ue_stacktrace_push_msg("Failed to read CSR response size in response");
			goto clean_up;
		}
		if (!ue_byte_read_next_bytes(received_message, &csr_response, (size_t)csr_response_size)) {
			ue_stacktrace_push_msg("Failed to read CSR response in response");
			goto clean_up;
		}

		if (csr_sub_type == CSR_TLS_RESPONSE) {
			ue_logger_trace("Received CSR_TLS_RESPONSE");

			if (!(channel_client->tls_csr_context->signed_certificate = ue_csr_process_server_response(csr_response,
				(size_t)csr_response_size, channel_client->tls_csr_context->future_key, channel_client->tls_csr_context->iv,
				channel_client->tls_csr_context->iv_size))) {

				ue_stacktrace_push_msg("Failed to process CSR TLS response");
			} else {
				channel_client->tls_keystore_ok = true;
			}
		}
		else if (csr_sub_type == CSR_CIPHER_RESPONSE) {
			ue_logger_trace("Received CSR_CIPHER_RESPONSE");

			if (!(channel_client->cipher_csr_context->signed_certificate = ue_csr_process_server_response(csr_response,
				(size_t)csr_response_size, channel_client->cipher_csr_context->future_key, channel_client->cipher_csr_context->iv,
				channel_client->cipher_csr_context->iv_size))) {

				ue_stacktrace_push_msg("Failed to process CSR CIPHER response");
			} else {
				channel_client->cipher_keystore_ok = true;
			}
		}
		else if (csr_sub_type == CSR_SIGNER_RESPONSE) {
			ue_logger_trace("Received CSR_SIGNER_RESPONSE");

			if (!(channel_client->signer_csr_context->signed_certificate = ue_csr_process_server_response(csr_response,
				(size_t)csr_response_size, channel_client->signer_csr_context->future_key, channel_client->signer_csr_context->iv,
				channel_client->signer_csr_context->iv_size))) {

				ue_stacktrace_push_msg("Failed to process CSR SIGNER response");
			} else {
				channel_client->signer_keystore_ok = true;
			}
		}

clean_up:
		ue_safe_free(csr_response);
		if (ue_stacktrace_is_filled()) {
			ue_stacktrace_push_msg("The processing of a client CSR failed");
			/* @todo send a response to the client in case of error */
			ue_logger_stacktrace("An error occured with the following stacktrace :");
			ue_stacktrace_clean_up();
		}
		ue_queue_pop(connection->received_messages);
	}

	return true;
}

static bool process_user_input(ue_channel_client *channel_client, ue_socket_client_connection *connection,
    unsigned char *data, size_t data_size) {

    bool result;
    int channel_id;
    char *string_data;

    result = false;
    channel_id = -1;
    string_data = NULL;

    ue_byte_stream_clean_up(connection->message_to_send);
    if (!ue_byte_writer_append_int(connection->message_to_send, channel_client->channel_id)) {
        ue_stacktrace_push_msg("Failed to write channel id to message to send");
        goto clean_up;
    }

    if (memcmp(data, "-q", data_size) == 0) {
        if (!ue_byte_writer_append_int(connection->message_to_send, DISCONNECTION_NOW_REQUEST)) {
            ue_stacktrace_push_msg("Failed to write DISCONNECTION_NOW_REQUEST type to message to send");
            goto clean_up;
        }
        if (!(result = send_cipher_message(channel_client, connection, connection->message_to_send))) {
            ue_stacktrace_push_msg("Failed to send cipher message");
            goto clean_up;
        }
        channel_client->running = false;
    }
    else if (ue_bytes_starts_with(data, data_size, (unsigned char *)"@channel_connection", strlen("@channel_connection"))) {
        string_data = ue_string_create_from_bytes(data, data_size);
        if (!ue_string_to_int(string_data + strlen("@channel_connection") + 1, &channel_id, 10)) {
            ue_logger_warn("Specified channel id is invalid. Usage : --channel <number>");
        }
        else if (channel_id == -1) {
            ue_logger_warn("Specified channel id is invalid. It have to be >= 0");
        }
        else {
            if (!ue_byte_writer_append_int(connection->message_to_send, CHANNEL_CONNECTION_REQUEST)) {
                ue_stacktrace_push_msg("Failed to write CHANNEL_CONNECTION_REQUEST type to message to send");
                goto clean_up;
            }
            if (!ue_byte_writer_append_int(connection->message_to_send, channel_id)) {
                ue_stacktrace_push_msg("Failed to write channel id to message to send");
                goto clean_up;
            }

            if (!(result = send_cipher_message(channel_client, connection, connection->message_to_send))) {
                ue_stacktrace_push_msg("Failed to send cipher message");
                goto clean_up;
            }
        }
    }
    else {
        if (!(result = process_message_request(channel_client, connection, data, data_size))) {
            ue_stacktrace_push_msg("Failed to process message request");
            goto clean_up;
        }
    }

    result = true;

clean_up:
    ue_safe_free(string_data);
    return result;
}

static bool tls_read_consumer(void *parameter) {
	bool result;
	size_t received;
	int type;
	ue_socket_client_connection *connection;
	ue_channel_client *channel_client;

	result = true;
	connection = (ue_socket_client_connection *)parameter;
	channel_client = connection->optional_data;

	while (channel_client->running) {
		received = receive_cipher_message(channel_client, connection);
		result = true;

		// @todo set timeout in case of server lag or reboot
		if (received <= 0 || received == ULLONG_MAX) {
			ue_logger_warn("Stopping client...");
			if (ue_stacktrace_is_filled()) {
				ue_logger_stacktrace("An error occured while receving a cipher message with the following stacktrace :");
				ue_stacktrace_clean_up();
			}
			channel_client->running = false;
			result = false;
		}
		else {
			ue_byte_stream_clean_up(connection->tmp_stream);
			if (!ue_byte_writer_append_bytes(connection->tmp_stream, ue_byte_stream_get_data(connection->received_message), ue_byte_stream_get_size(connection->received_message))) {
				ue_logger_error("Failed to write received message to working stream");
				continue;
			}
			ue_byte_stream_set_position(connection->tmp_stream, 0);

			ue_byte_read_next_int(connection->tmp_stream, &type);

			if (type == ALREADY_CONNECTED_RESPONSE) {
				ue_logger_warn("Already connected");
				channel_client->running = false;
				result = false;
			}
			else if (type == NICKNAME_RESPONSE) {
				result = process_nickname_response(channel_client, connection->tmp_stream);
				ue_logger_trace("Server has accepted this nickname.");
			}
			else if (type == CHANNEL_CONNECTION_RESPONSE) {
				ue_logger_trace("CHANNEL_CONNECTION_RESPONSE");
				result = process_channel_connection_response(channel_client, connection->tmp_stream);
			}
			else if (type == MESSAGE && !channel_client->channel_key) {
				ue_logger_warn("Cannot decipher received message for now, because we doesn't have to channel key");
			}
			else if (type == MESSAGE && channel_client->channel_key) {
				ue_logger_trace("MESSAGE received");
				result = process_message_response(channel_client, connection->tmp_stream);
			}
			else if (type == CERTIFICATE_RESPONSE) {
				result = process_certificate_response(channel_client, connection->tmp_stream);
			}
			else if (type == CHANNEL_KEY_RESPONSE) {
				ue_logger_trace("CHANNEL_KEY_RESPONSE");
				result = process_channel_key_response(channel_client, connection, connection->tmp_stream);
			}
			else if (type == CHANNEL_KEY_REQUEST && !channel_client->channel_key) {
				ue_logger_warn("Receive a channel key request but we doesn't have it");
			}
			else if (type == CHANNEL_KEY_REQUEST && channel_client->channel_key) {
				ue_logger_trace("CHANNEL_KEY_REQUEST");
				result = process_channel_key_request(channel_client, connection, connection->tmp_stream);
			}
			else if (channel_client->channel_id >= 0 && !channel_client->channel_key) {
				ue_logger_warn("Cannot decrypt server data because we don't know channel key for now");
			} else {
				ue_logger_warn("Received invalid data type from server '%d'.", type);
			}
		}

		if (!result) {
			if (ue_stacktrace_is_filled()) {
				ue_stacktrace_push_msg("Failed to process server response");
				ue_logger_stacktrace("An error occured in this reading iteration with the following stacktrace :");
				ue_stacktrace_clean_up();
			}
		}
	}

	return result;
}

static bool tls_write_consumer_stdin(void *parameter) {
	bool result;
	char *input;
	ue_socket_client_connection *connection;
	ue_channel_client *channel_client;
    unsigned char *bytes_input;

	result = true;
	input = NULL;
    bytes_input = NULL;
	connection = (ue_socket_client_connection *)parameter;
	channel_client = connection->optional_data;

    if (!send_nickname_request(channel_client, connection)) {
        ue_stacktrace_push_msg("Failed to send nickname request");
        return false;
    }

	while (channel_client->running) {
		if (ue_stacktrace_is_filled()) {
			ue_logger_stacktrace("An error occured in the last input iteration, with the following stacktrace :");
			ue_stacktrace_clean_up();
		}

        ue_safe_free(input);
        ue_safe_free(bytes_input);

        if (channel_client->user_input_callback) {
            input = channel_client->user_input_callback(channel_client->user_context);
        } else {
            input = ue_input_string(">");
        }

        if (!input) {
            continue;
        }

        if (!(bytes_input = ue_bytes_create_from_string(input))) {
            ue_stacktrace_push_msg("Failed to convert string input to bytes input");
            continue;
        }

        if (!process_user_input(channel_client, connection, bytes_input, strlen(input))) {
            ue_stacktrace_push_msg("Failed to process user input");
        }
	}

	ue_safe_free(input);
    ue_safe_free(bytes_input);

	return result;
}

static bool tls_write_consumer_push(void *parameter) {
    ue_socket_client_connection *connection;
    ue_channel_client *channel_client;
    pushed_message *message;

    connection = (ue_socket_client_connection *)parameter;
    channel_client = connection->optional_data;

    if (!send_nickname_request(channel_client, connection)) {
        ue_stacktrace_push_msg("Failed to send nickname request");
        return false;
    }

    while (channel_client->running) {
        if (ue_stacktrace_is_filled()) {
            ue_logger_stacktrace("An error occured in the last input iteration, with the following stacktrace :");
            ue_stacktrace_clean_up();
        }

        message = ue_queue_front_wait(channel_client->push_mode_queue);

        if (!process_user_input(channel_client, connection, message->data, message->size)) {
            ue_stacktrace_push_msg("Failed to process user input");
        }
    }

    return true;
}

static bool process_get_certificate_request(ue_channel_client *channel_client, ue_pkcs12_keystore *keystore,
	ue_socket_client_connection *connection, const unsigned char *friendly_name, size_t friendly_name_size) {
	bool result;
	ue_byte_stream *request, *response;
	unsigned char *certificate_data;
	int type, certificate_data_size;

	ue_check_parameter_or_return(keystore);
	ue_check_parameter_or_return(connection);
	ue_check_parameter_or_return(friendly_name);
	ue_check_parameter_or_return(friendly_name_size > 0);

	result = false;
	request = ue_byte_stream_create();
	response = ue_byte_stream_create();
	certificate_data = NULL;

	if (!ue_byte_writer_append_int(request, channel_client->channel_id)) {
		ue_stacktrace_push_msg("Failed to write channel id to request");
		goto clean_up;
	}
	if (!ue_byte_writer_append_int(request, GET_CERTIFICATE_REQUEST)) {
		ue_stacktrace_push_msg("Failed to write GET_CERTIFICATE_REQUEST type to request");
		goto clean_up;
	}
	if (!ue_byte_writer_append_int(request, (int)friendly_name_size)) {
		ue_stacktrace_push_msg("Failed to write friendly name size to request");
		goto clean_up;
	}
	if (!ue_byte_writer_append_bytes(request, (unsigned char *)friendly_name, friendly_name_size)) {
		ue_stacktrace_push_msg("Failed to write friendly name to request");
		goto clean_up;
	}

	if (!send_cipher_message(channel_client, connection, request)) {
		ue_stacktrace_push_msg("Failed to send GET_CERTIFICATE request to server");
		goto clean_up;
	}

	connection->state = READING_STATE;
	if (receive_cipher_message(channel_client, connection) <= 0) {
		ue_stacktrace_push_msg("Failed to receive cipher message response of GET_CERTIFICATE request");
		goto clean_up;
	}

	if (!ue_byte_writer_append_bytes(response, ue_byte_stream_get_data(connection->received_message), ue_byte_stream_get_size(connection->received_message))) {
		ue_stacktrace_push_msg("Failed to write received message to response");
		goto clean_up;
	}
	ue_byte_stream_set_position(response, 0);
	if (!ue_byte_read_next_int(response, &type)) {
		ue_stacktrace_push_msg("Failed to read request type in response");
		goto clean_up;
	}
	if (type != CERTIFICATE_RESPONSE) {
		ue_logger_error("GET_CERTIFICATE request received an invalid response type");
		goto clean_up;
	}

	if (!ue_byte_read_next_int(response, &certificate_data_size)) {
		ue_stacktrace_push_msg("Failed to read certificate data size in response");
		goto clean_up;
	}
	if (!ue_byte_read_next_bytes(response, &certificate_data, (size_t)certificate_data_size)) {
		ue_stacktrace_push_msg("Failed to read certificate data in response");
		goto clean_up;
	}

	ue_logger_info("Missing certificate received. Trying to add it to the cipher keystore...");
	if (!(ue_pkcs12_keystore_add_certificate_from_bytes(keystore, certificate_data, (size_t)certificate_data_size,
		(const unsigned char *)friendly_name, friendly_name_size))) {

		ue_stacktrace_push_msg("Failed to add received certificate to cipher keystore");
		goto clean_up;
	}

	result = true;

clean_up:
	ue_byte_stream_destroy(request);
	ue_byte_stream_destroy(response);
	ue_safe_free(certificate_data);
	return result;
}

static bool process_channel_key_request(ue_channel_client *channel_client, ue_socket_client_connection *connection,
	ue_byte_stream *request) {
	bool result;
	unsigned char *cipher_data, *friendly_name, *nickname;
	size_t cipher_data_size, friendly_name_size;
	ue_x509_certificate *client_certificate;
	ue_public_key *client_public_key;
	ue_byte_stream *channel_key_stream;
	int nickname_size;

	ue_check_parameter_or_return(connection);
	ue_check_parameter_or_return(request);

	result = false;
	client_certificate = NULL;
	cipher_data = NULL;
	friendly_name = NULL;
	client_public_key = NULL;
	nickname = NULL;
	channel_key_stream = ue_byte_stream_create();

	if (!ue_byte_read_next_int(request, &nickname_size)) {
		ue_stacktrace_push_msg("Failed to read nickname size in request");
		goto clean_up;
	}
	if (!ue_byte_read_next_bytes(request, &nickname, (size_t)nickname_size)) {
		ue_stacktrace_push_msg("Failed to read nickname in request");
		goto clean_up;
	}

	if (!(friendly_name = ue_friendly_name_build(nickname, (size_t)nickname_size, "CIPHER", &friendly_name_size))) {
		ue_stacktrace_push_msg("Failed to build friendly name for CIPHER keystore");
		goto clean_up;
	}

	if (!(client_certificate = ue_pkcs12_keystore_find_certificate_by_friendly_name(channel_client->cipher_keystore, (const unsigned char *)friendly_name, friendly_name_size))) {
		ue_logger_warn("Cipher certificate of client was not found. Requesting the server...");

		if (!process_get_certificate_request(channel_client, channel_client->cipher_keystore, connection, (const unsigned char *)friendly_name, friendly_name_size)) {
			ue_stacktrace_push_msg("Failed to get missing certificate");
			goto clean_up;
		}

		if (!ue_pkcs12_keystore_write(channel_client->cipher_keystore, channel_client->cipher_keystore_path, channel_client->keystore_password)) {
			ue_stacktrace_push_msg("Failed to write keystore to '%s'", channel_client->cipher_keystore_path);
			goto clean_up;
		}

		ue_logger_info("Retrying find cipher certificate...");

		if (!(client_certificate = ue_pkcs12_keystore_find_certificate_by_friendly_name(channel_client->cipher_keystore, (const unsigned char *)friendly_name, friendly_name_size))) {
			ue_stacktrace_push_msg("Failed to retreive client cipher certificate, while it should not happen");
			goto clean_up;
		}
	}

	if (!(client_public_key = ue_rsa_public_key_from_x509_certificate(client_certificate))) {
		ue_stacktrace_push_msg("Failed to extract public key of client cipher certificate");
		goto clean_up;
	}

	if (!ue_byte_writer_append_int(channel_key_stream, (int)channel_client->channel_key->size)) {
		ue_stacktrace_push_msg("Failed to write channel key size to stream");
		goto clean_up;
	}
	if (!ue_byte_writer_append_int(channel_key_stream, (int)channel_client->channel_iv_size)) {
		ue_stacktrace_push_msg("Failed to write channel IV size to stream");
		goto clean_up;
	}
	if (!ue_byte_writer_append_bytes(channel_key_stream, channel_client->channel_key->data, channel_client->channel_key->size)) {
		ue_stacktrace_push_msg("Failed to write channel key to stream");
		goto clean_up;
	}
	if (!ue_byte_writer_append_bytes(channel_key_stream, channel_client->channel_iv, channel_client->channel_iv_size)) {
		ue_stacktrace_push_msg("Failed to write channel IV to stream");
		goto clean_up;
	}

	if (!ue_cipher_plain_data(ue_byte_stream_get_data(channel_key_stream), ue_byte_stream_get_size(channel_key_stream),
		   client_public_key, channel_client->signer_keystore->private_key, &cipher_data, &cipher_data_size, channel_client->cipher_name,
	   	   channel_client->digest_name)) {

		ue_stacktrace_push_msg("Failed to cipher plain data");
		goto clean_up;
	}

	// Build message to send : CHANNEL_KEY_REQUEST_ANSWER|<receiver_nickname>|<ciphered channel key>|
	ue_byte_stream_clean_up(channel_key_stream);
	if (!ue_byte_writer_append_int(channel_key_stream, channel_client->channel_id)) {
		ue_stacktrace_push_msg("Failed to write channel id to response");
		goto clean_up;
	}
	if (!ue_byte_writer_append_int(channel_key_stream, CHANNEL_KEY_REQUEST_ANSWER)) {
		ue_stacktrace_push_msg("Failed to write CHANNEL_KEY_REQUEST_ANSWER to response");
		goto clean_up;
	}
	if (!ue_byte_writer_append_int(channel_key_stream, nickname_size)) {
		ue_stacktrace_push_msg("Failed to write nickname size to response");
		goto clean_up;
	}
	if (!ue_byte_writer_append_bytes(channel_key_stream, nickname, (size_t)nickname_size)) {
		ue_stacktrace_push_msg("Failed to write nickname to response");
		goto clean_up;
	}
	if (!ue_byte_writer_append_int(channel_key_stream, (int)cipher_data_size)) {
		ue_stacktrace_push_msg("Failed to write cipher data size to response");
		goto clean_up;
	}
	if (!ue_byte_writer_append_bytes(channel_key_stream, cipher_data, cipher_data_size)) {
		ue_stacktrace_push_msg("Failed to write cipher data to response");
		goto clean_up;
	}

	if (!send_cipher_message(channel_client, connection, channel_key_stream)) {
		ue_stacktrace_push_msg("Send the stream in a cipher message failed");
		goto clean_up;
	}

	result = true;

clean_up:
	ue_safe_free(cipher_data);
	ue_safe_free(friendly_name);
	ue_public_key_destroy(client_public_key);
	ue_byte_stream_destroy(channel_key_stream);
	ue_safe_free(nickname);
	return result;
}

static bool send_nickname_request(ue_channel_client *channel_client, ue_socket_client_connection *connection) {
	ue_check_parameter_or_return(connection);

	ue_byte_stream_clean_up(connection->message_to_send);
	if (!ue_byte_writer_append_int(connection->message_to_send, channel_client->channel_id)) {
		ue_stacktrace_push_msg("Failed to write channel id to message to send");
		return false;
	}
	if (!ue_byte_writer_append_int(connection->message_to_send, NICKNAME_REQUEST)) {
		ue_stacktrace_push_msg("Failed to write NICKNAME_REQUEST type to message to send");
		return false;
	}
	if (!ue_byte_writer_append_int(connection->message_to_send, (int)strlen(channel_client->nickname))) {
		ue_stacktrace_push_msg("Failed to write nickname size to message to send");
		return false;
	}
	if (!ue_byte_writer_append_bytes(connection->message_to_send, (unsigned char *)channel_client->nickname, strlen(channel_client->nickname))) {
		ue_stacktrace_push_msg("Failed to write nickname to message to send");
		return false;
	}

    if (!send_message(channel_client, connection, connection->message_to_send)) {
        ue_stacktrace_push_msg("Failed to send nickname request");
        return false;
    }

	return true;
}

static bool process_message_request(ue_channel_client *channel_client, ue_socket_client_connection *connection,
    unsigned char *data, size_t data_size) {

	bool result;
	ue_sym_encrypter *encrypter;
	unsigned char *cipher_data, *bytes_input;
	size_t cipher_data_size;

	ue_check_parameter_or_return(connection);
    ue_check_parameter_or_return(data);
    ue_check_parameter_or_return(data_size > 0);

	result = false;
	encrypter = NULL;
	cipher_data = NULL;
	bytes_input = NULL;

	if (channel_client->channel_id >= 0 && channel_client->channel_key) {
		ue_byte_writer_append_int(connection->message_to_send, MESSAGE);
		ue_byte_writer_append_int(connection->message_to_send, (int)strlen(channel_client->nickname));
		ue_byte_writer_append_bytes(connection->message_to_send, (unsigned char *)channel_client->nickname, (int)strlen(channel_client->nickname));

		if (channel_client->channel_key) {
			if (!(encrypter = ue_sym_encrypter_default_create(channel_client->channel_key))) {
				ue_stacktrace_push_msg("Failed to create sym encrypter with this channel key");
				goto clean_up;
			}
            else if (!ue_sym_encrypter_encrypt(encrypter, data, data_size,
				channel_client->channel_iv, &cipher_data, &cipher_data_size)) {

				ue_stacktrace_push_msg("Failed to encrypt this input");
				goto clean_up;
			}
			else if (!ue_byte_writer_append_int(connection->message_to_send, (int)cipher_data_size)) {
				ue_stacktrace_push_msg("Failed to append cipher data size");
				goto clean_up;
			}
			else if (!ue_byte_writer_append_bytes(connection->message_to_send, cipher_data, cipher_data_size)) {
				ue_stacktrace_push_msg("Failed to append cipher data to message to send");
				goto clean_up;
			}
		} else {
            ue_byte_writer_append_bytes(connection->message_to_send, data, data_size);
		}

		result = send_cipher_message(channel_client, connection, connection->message_to_send);
	}
	else if (channel_client->channel_id < 0) {
		ue_logger_warn("Cannot send message because no channel is selected");
	} else {
		ue_logger_warn("Cannot send message because we don't know channel key for now");
	}

	result = true;

clean_up:
	ue_sym_encrypter_destroy(encrypter);
	ue_safe_free(cipher_data);
	ue_safe_free(bytes_input);
	return result;
}

static bool process_nickname_response(ue_channel_client *channel_client, ue_byte_stream *response) {
	bool result;
	int is_accepted;

	ue_check_parameter_or_return(response);

	result = false;

	if (!ue_byte_read_next_int(response, &is_accepted)) {
		ue_stacktrace_push_msg("Failed to read is accepted field in response");
		goto clean_up;
	}

	if (is_accepted == 0) {
		ue_logger_info("This nickname is already in use.");
		channel_client->running = false;
		goto clean_up;
	}
	else if (is_accepted != 1) {
		ue_logger_warn("Response of nickname request is incomprehensible.");
		channel_client->running = false;
		goto clean_up;
	}

	result = true;

clean_up:
	return result;
}

static bool process_channel_connection_response(ue_channel_client *channel_client, ue_byte_stream *response) {
	bool result;
	int is_accepted, channel_key_state;

	result = false;

	ue_check_parameter_or_return(response);

	if (!ue_byte_read_next_int(response, &is_accepted)) {
		ue_stacktrace_push_msg("Failed to read is accepted field in response");
		goto clean_up;
	}

	if (is_accepted == 0) {
		ue_logger_info("This channel is already in use or cannot be use right now.");
		channel_client->running = false;
		goto clean_up;
	}
	else if (is_accepted != 1) {
		ue_logger_warn("Response of channel connection request is incomprehensible.");
		goto clean_up;
	} else {
		if (!ue_byte_read_next_int(response, &channel_client->channel_id)) {
			ue_stacktrace_push_msg("Failed to read channel id in response");
			goto clean_up;
		}
		ue_logger_trace("Channel connection has been accepted by the server with channel id %d.", channel_client->channel_id);

		if (!ue_byte_read_next_int(response, &channel_key_state)) {
			ue_stacktrace_push_msg("Failed to read channel key state in response");
			goto clean_up;
		}

		if (channel_key_state == CHANNEL_KEY_CREATOR_STATE) {
			ue_logger_info("Generate random channel key");
			channel_client->channel_key = ue_sym_key_create_random();
			ue_safe_alloc(channel_client->channel_iv, unsigned char, 16);
			if (!(ue_crypto_random_bytes(channel_client->channel_iv, 16))) {
				ue_stacktrace_push_msg("Failed to get crypto random bytes for IV");
				goto clean_up;
			}
			channel_client->channel_iv_size = 16;
		}
		else if (channel_key_state == WAIT_CHANNEL_KEY_STATE) {
			ue_logger_info("Waiting the channel key");
		}
		else {
			ue_logger_warn("Unknown channel key action type. Default is waiting the channel key");
			goto clean_up;
		}
	}

	result = true;

clean_up:
	return result;
}

static bool process_message_response(ue_channel_client *channel_client, ue_byte_stream *message) {
	bool result;
	ue_sym_encrypter *decrypter;
	unsigned char *cipher_data, *decipher_data, *nickname;
	size_t decipher_data_size;
	int cipher_data_size, nickname_size;
	ue_byte_stream *printer;

	ue_check_parameter_or_return(message);

	result = false;
	decrypter = NULL;
	cipher_data = NULL;
	decipher_data = NULL;
	nickname = NULL;
	printer = ue_byte_stream_create();

	if (!ue_byte_read_next_int(message, &nickname_size)) {
		ue_stacktrace_push_msg("Failed to read nickname size in message");
		goto clean_up;
	}
	if (!ue_byte_read_next_bytes(message, &nickname, (size_t)nickname_size)) {
		ue_stacktrace_push_msg("Failed to read nickname in message");
		goto clean_up;
	}
	if (!ue_byte_read_next_int(message, &cipher_data_size)) {
		ue_stacktrace_push_msg("Failed to read cipher data size in message");
		goto clean_up;
	}
	if (!ue_byte_read_next_bytes(message, &cipher_data, (size_t)cipher_data_size)) {
		ue_stacktrace_push_msg("Failed to read cipher data in message");
		goto clean_up;
	}

	if (!ue_byte_writer_append_bytes(printer, nickname, (size_t)nickname_size)) {
		ue_stacktrace_push_msg("Failed to write nickname to printer");
		goto clean_up;
	}
	if (!ue_byte_writer_append_string(printer, ": ")) {
		ue_stacktrace_push_msg("Failed to write ':' delimiter to printer");
		goto clean_up;
	}

	if (!(decrypter = ue_sym_encrypter_default_create(channel_client->channel_key))) {
		ue_stacktrace_push_msg("Failed to create default sym decrypter with channel_client channel key");
		goto clean_up;
	}
	if  (!ue_sym_encrypter_decrypt(decrypter, cipher_data, (size_t)cipher_data_size,
		channel_client->channel_iv, &decipher_data, &decipher_data_size)) {
		ue_stacktrace_push_msg("Failed to decrypt cipher data");
		goto clean_up;
	}
	if (!ue_byte_writer_append_bytes(printer, decipher_data, decipher_data_size)) {
		ue_stacktrace_push_msg("Failed to write decipher data to printer");
		goto clean_up;
	}

	if (!channel_client->write_callback(channel_client->user_context, printer)) {
		ue_logger_warn("Failed to write the message with user write consumer");
		goto clean_up;
	}

	result = true;

clean_up:
	ue_sym_encrypter_destroy(decrypter);
	ue_safe_free(cipher_data);
	ue_safe_free(decipher_data);
	ue_safe_free(nickname);
	ue_byte_stream_destroy(printer);
	return result;
}

static bool process_certificate_response(ue_channel_client *channel_client, ue_byte_stream *response) {
	bool result;
	ue_pkcs12_keystore *keystore;
	unsigned char *friendly_name, *certificate_data;
	int friendly_name_size, certificate_data_size;

	ue_check_parameter_or_return(response);
	ue_check_parameter_or_return(ue_byte_stream_get_size(response));

	result = false;
	keystore = NULL;
	friendly_name = NULL;
	certificate_data = NULL;

	if (!ue_byte_read_next_int(response, &friendly_name_size)) {
		ue_stacktrace_push_msg("Failed to read friendly name size in response");
		goto clean_up;
	}
	if (!ue_byte_read_next_bytes(response, &friendly_name, (size_t)friendly_name_size)) {
		ue_stacktrace_push_msg("Failed to read friendly name in response");
		goto clean_up;
	}
	if (!ue_byte_read_next_int(response, &certificate_data_size)) {
		ue_stacktrace_push_msg("Failed to read certificate data size in response");
		goto clean_up;
	}
	if (!ue_byte_read_next_bytes(response, &certificate_data, (size_t)certificate_data_size)) {
		ue_stacktrace_push_msg("Failed to read certificate data in response");
		goto clean_up;
	}

    if (ue_bytes_contains(friendly_name, friendly_name_size, (unsigned char *)"_CIPHER", strlen("_CIPHER"))) {
		keystore = channel_client->cipher_keystore;
    } else if (ue_bytes_contains(friendly_name, friendly_name_size, (unsigned char *)"_SIGNER", strlen("_SIGNER"))) {
		keystore = channel_client->signer_keystore;
	} else {
		ue_logger_warn("Invalid friendly name in GET_CERTIFICATE request");
		goto clean_up;
	}

	if (!ue_pkcs12_keystore_add_certificate_from_bytes(keystore, certificate_data, certificate_data_size, friendly_name, friendly_name_size)) {
		ue_stacktrace_push_msg("Failed to add new certificate from bytes");
		goto clean_up;
	}

	result = true;

clean_up:
	return result;
}

static bool process_channel_key_response(ue_channel_client *channel_client, ue_socket_client_connection *connection,
	ue_byte_stream *response) {
	bool result;
	ue_x509_certificate *key_owner_certificate;
	unsigned char *friendly_name, *plain_data, *key, *nickname, *cipher_data;
	ue_public_key *key_owner_public_key;
	ue_byte_stream *channel_key_stream;
	int key_size, nickname_size, cipher_data_size, read_int;
	size_t friendly_name_size, plain_data_size;

	ue_check_parameter_or_return(connection);
	ue_check_parameter_or_return(response);
	ue_check_parameter_or_return(ue_byte_stream_get_size(response) > 0);

	result = false;
	key_owner_certificate = NULL;
	friendly_name = NULL;
	plain_data = NULL;
	key = NULL;
	nickname = NULL;
	cipher_data = NULL;
	key_owner_public_key = NULL;
	channel_key_stream = ue_byte_stream_create();

	if (!ue_byte_read_next_int(response, &nickname_size)) {
		ue_stacktrace_push_msg("Failed to read nickname size in response");
		goto clean_up;
	}
	if (!ue_byte_read_next_bytes(response, &nickname, (size_t)nickname_size)) {
		ue_stacktrace_push_msg("Failed to read nickname in response");
		goto clean_up;
	}

	if (!(friendly_name = ue_friendly_name_build(nickname, (size_t)nickname_size, "SIGNER", &friendly_name_size))) {
		ue_stacktrace_push_msg("Failed to build friendly name for SIGNER keystore");
		goto clean_up;
	}

	if (!(key_owner_certificate = ue_pkcs12_keystore_find_certificate_by_friendly_name(channel_client->signer_keystore,
		(const unsigned char *)friendly_name, friendly_name_size))) {

		ue_logger_warn("Signer certificate of client was not found. Requesting the server...");

		if (!process_get_certificate_request(channel_client, channel_client->signer_keystore, connection, (const unsigned char *)friendly_name, friendly_name_size)) {
			ue_stacktrace_push_msg("Failed to get missing certificate");
			goto clean_up;
		}

		if (!ue_pkcs12_keystore_write(channel_client->signer_keystore, channel_client->signer_keystore_path, channel_client->keystore_password)) {
			ue_stacktrace_push_msg("Failed to write keystore to '%s'", channel_client->signer_keystore_path);
			goto clean_up;
		}

		ue_logger_info("Retrying find signer certificate...");

		if (!(key_owner_certificate = ue_pkcs12_keystore_find_certificate_by_friendly_name(channel_client->signer_keystore, (const unsigned char *)friendly_name, friendly_name_size))) {
			ue_stacktrace_push_msg("Failed to retreive client signer certificate, while it should not happen");
			goto clean_up;
		}
	}

	if (!(key_owner_public_key = ue_rsa_public_key_from_x509_certificate(key_owner_certificate))) {
		ue_stacktrace_push_msg("Failed to get client public key from client certificate");
		goto clean_up;
	}

	if (!ue_byte_read_next_int(response, &cipher_data_size)) {
		ue_stacktrace_push_msg("Failed to read cipher data size in response");
		goto clean_up;
	}
	if (!ue_byte_read_next_bytes(response, &cipher_data, cipher_data_size)) {
		ue_stacktrace_push_msg("Failed to read cipher data in response");
		goto clean_up;
	}

	if (!ue_decipher_cipher_data(cipher_data, cipher_data_size, channel_client->cipher_keystore->private_key,
		key_owner_public_key, &plain_data, &plain_data_size, channel_client->cipher_name, channel_client->digest_name)) {

		ue_stacktrace_push_msg("Failed decipher message data");
		goto clean_up;
	}

	if (!ue_byte_writer_append_bytes(channel_key_stream, plain_data, plain_data_size)) {
		ue_stacktrace_push_msg("Failed to append plain data into channel key stream");
		goto clean_up;
	}
	ue_byte_stream_set_position(channel_key_stream, 0);

	if (!ue_byte_read_next_int(channel_key_stream, &read_int)) {
		ue_stacktrace_push_msg("Failed to read channel key size");
		goto clean_up;
	}
	key_size = (size_t)read_int;

	if (!ue_byte_read_next_int(channel_key_stream, &read_int)) {
		ue_stacktrace_push_msg("Failed to read channel iv size");
		goto clean_up;
	}
	channel_client->channel_iv_size = (size_t)read_int;

	if (!ue_byte_read_next_bytes(channel_key_stream, &key, key_size)) {
		ue_stacktrace_push_msg("Failed to read channel key bytes");
		goto clean_up;
	}

	if (!ue_byte_read_next_bytes(channel_key_stream, &channel_client->channel_iv, channel_client->channel_iv_size)) {
		ue_stacktrace_push_msg("Failed to read channel iv bytes");
		goto clean_up;
	}

	if (!(channel_client->channel_key = ue_sym_key_create(key, key_size))) {
		ue_stacktrace_push_msg("Failed to create sym key based on parsed deciphered data");
		goto clean_up;
	}

	ue_logger_info("Channel key successfully received.");

	result = true;

clean_up:
	ue_public_key_destroy(key_owner_public_key);
	ue_safe_free(friendly_name);
	ue_safe_free(plain_data);
	ue_safe_free(key);
	ue_safe_free(nickname);
	ue_safe_free(cipher_data);
	ue_byte_stream_destroy(channel_key_stream);
	return result;
}

static bool generate_certificate(ue_x509_certificate **certificate, ue_private_key **private_key) {
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
