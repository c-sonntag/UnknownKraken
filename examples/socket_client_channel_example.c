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
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/bool.h>
#include <unknownecho/system/alloc.h>
#include <unknownecho/network/api/socket/socket_client_connection.h>
#include <unknownecho/network/api/socket/socket.h>
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
#include <unknownecho/crypto/factory/pkcs12_keystore_factory.h>
#include <unknownecho/crypto/factory/rsa_asym_key_factory.h>
#include <unknownecho/crypto/factory/sym_key_factory.h>
#include <unknownecho/crypto/factory/sym_encrypter_factory.h>
#include <unknownecho/crypto/utils/crypto_random.h>
#include <unknownecho/byte/byte_utility.h>
#include <unknownecho/byte/byte_writer.h>
#include <unknownecho/byte/byte_reader.h>
#include <unknownecho/byte/byte_stream.h>
#include <unknownecho/byte/byte_split.h>
#include <unknownecho/container/byte_vector.h>
#include <unknownecho/fileSystem/file_utility.h>

#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <sys/socket.h>

typedef enum {
	READING_STATE,
	WRITING_STATE,
	CLOSING_STATE
} data_transmission_state;

typedef struct {
	ue_x509_certificate *signed_certificate;
	ue_private_key *private_key;
	ue_sym_key *future_key;
	unsigned char *iv;
	size_t iv_size;
} csr_context;

typedef struct {
	int fd;
	int child_pid;
	char *nickname, *keystore_password;
	ue_tls_session *tls_session;
	ue_socket_client_connection *connection;
	ue_thread_id *read_thread, *write_thread;
	ue_thread_mutex *mutex;
	ue_thread_cond *cond;
	data_transmission_state transmission_state;
	bool running;
	int fds[2];
	ue_byte_stream *new_message;
	int channel_id;
	ue_x509_certificate *csr_server_certificate, *tls_server_certificate, *cipher_server_certificate, *signer_server_certificate;
	bool tls_keystore_ok, cipher_keystore_ok, signer_keystore_ok;
	csr_context *tls_csr_context, *cipher_csr_context, *signer_csr_context;
	ue_pkcs12_keystore *tls_keystore, *cipher_keystore, *signer_keystore;
	const char *csr_server_certificate_path;
	const char *tls_server_certificate_path;
	const char *cipher_server_certificate_path;
	const char *signer_server_certificate_path;
	const char *tls_keystore_path;
	const char *cipher_keystore_path;
	const char *signer_keystore_path;
} socket_client_manager;

socket_client_manager *instance = NULL;

#if defined(WIN32)
	#include <windows.h>
#elif defined(__UNIX__)
	#include <unistd.h>
#endif

#define ROOT_PATH                      "out/"
#define CSR_SERVER_CERTIFICATE_PATH    "/certificate/csr_server.pem"
#define TLS_SERVER_CERTIFICATE_PATH    "/certificate/tls_server.pem"
#define CIPHER_SERVER_CERTIFICATE_PATH "/certificate/cipher_server.pem"
#define SIGNER_SERVER_CERTIFICATE_PATH "/certificate/signer_server.pem"
#define TLS_KEYSTORE_PATH              "/keystore/tls_client_keystore.p12"
#define CIPHER_KEYSTORE_PATH    	   "/keystore/cipher_client_keystore.p12"
#define SIGNER_KEYSTORE_PATH           "/keystore/signer_client_keystore.p12"
/*#define CSR_SERVER_CERTIFICATE_PATH    "out/client/certificate/csr_server.pem"
#define TLS_SERVER_CERTIFICATE_PATH    "out/client/certificate/tls_server.pem"
#define CIPHER_SERVER_CERTIFICATE_PATH "out/client/certificate/cipher_server.pem"
#define SIGNER_SERVER_CERTIFICATE_PATH "out/client/certificate/signer_server.pem"
#define TLS_KEYSTORE_PATH              "out/client/keystore/tls_client_keystore.p12"
#define CIPHER_KEYSTORE_PATH    	   "out/client/keystore/cipher_client_keystore.p12"
#define SIGNER_KEYSTORE_PATH           "out/client/keystore/signer_client_keystore.p12"*/
#define CSR_SERVER_HOST                "127.0.0.1"
#define CSR_SERVER_PORT                5002
#define TLS_SERVER_HOST                "127.0.0.1"
#define TLS_SERVER_PORT                5001


bool socket_client_manager_create();

void socket_client_manager_destroy();

ue_x509_certificate *client_process_server_response(unsigned char *server_response, size_t server_response_size, ue_sym_key *key, unsigned char *iv, size_t iv_size);


void handle_signal(int sig, void (*h)(int), int options) {
    struct sigaction s;

    s.sa_handler = h;
    sigemptyset(&s.sa_mask);
    s.sa_flags = options;
    if (sigaction(sig, &s, NULL) < 0) {
        ue_stacktrace_push_errno()
    }
}

void shutdown_client(int sig) {
    ue_logger_trace("Signal received %d", sig);
    ue_logger_info("Shuting down client...");
   	instance->running = false;
   	instance->transmission_state = CLOSING_STATE;
   	ue_thread_cond_signal(instance->cond);
}

static size_t receive_message(ue_socket_client_connection *connection) {
	size_t received;

	ue_thread_mutex_lock(instance->mutex);
    while (instance->transmission_state == WRITING_STATE) {
        ue_thread_cond_wait(instance->cond, instance->mutex);
    }
    ue_thread_mutex_unlock(instance->mutex);
	ue_byte_stream_clean_up(connection->received_message);
    received = ue_socket_receive_bytes_sync(connection->fd, connection->received_message, false, connection->tls);

    return received;
}

bool csr_read_consumer(void *parameter) {
	size_t received;
	bool result;
	ue_socket_client_connection *connection;

	result = true;
	connection = (ue_socket_client_connection *)parameter;

	//ue_logger_set_level(ue_logger_manager_get_logger(), LOG_DEBUG);

	while (instance->running) {
		received = receive_message(connection);
		result = true;

		/* @todo set timeout in case of server lag or reboot */
		if (received <= 0 || received == ULLONG_MAX) {
			ue_logger_warn("Connection with server is interrupted. Stopping client...");
			if (ue_stacktrace_is_filled()) {
				ue_stacktrace_push_msg("Failed to receive server message");
			}
			instance->running = false;
			result = false;
		}
		else {
			if (memcmp(ue_byte_stream_get_data(connection->received_message), "CSRTLS___", 9) == 0) {
				ue_logger_debug("Received CSRTLS___");

				if (!(instance->tls_csr_context->signed_certificate = client_process_server_response(ue_byte_stream_get_data(connection->received_message) + 9,
					ue_byte_stream_get_size(connection->received_message) - 9, instance->tls_csr_context->future_key, instance->tls_csr_context->iv,
					instance->tls_csr_context->iv_size))) {

					ue_stacktrace_push_msg("Failed to process server response");
					instance->running = false;
					return false;
				}
				instance->tls_keystore_ok = true;
			}
			else if (memcmp(ue_byte_stream_get_data(connection->received_message), "CSRCIPHER", 9) == 0) {
				ue_logger_debug("Received CSRCIPHER");

				if (!(instance->cipher_csr_context->signed_certificate = client_process_server_response(ue_byte_stream_get_data(connection->received_message) + 9,
					ue_byte_stream_get_size(connection->received_message) - 9, instance->cipher_csr_context->future_key, instance->cipher_csr_context->iv,
					instance->cipher_csr_context->iv_size))) {

					ue_stacktrace_push_msg("Failed to process server response");
					instance->running = false;
					return false;
				}
				instance->cipher_keystore_ok = true;
			}
			else if (memcmp(ue_byte_stream_get_data(connection->received_message), "CSRSIGNER", 9) == 0) {
				ue_logger_debug("Received CSRSIGNER");

				if (!(instance->signer_csr_context->signed_certificate = client_process_server_response(ue_byte_stream_get_data(connection->received_message) + 9,
					ue_byte_stream_get_size(connection->received_message) - 9, instance->signer_csr_context->future_key, instance->signer_csr_context->iv,
					instance->signer_csr_context->iv_size))) {

					ue_stacktrace_push_msg("Failed to process server response");
					instance->running = false;
					return false;
				}
				instance->signer_keystore_ok = true;
			} else {
				ue_stacktrace_push_msg("Received CSR response have no valid type");
				instance->running = false;
				return false;
			}
		}

		if (instance->tls_keystore_ok && instance->cipher_keystore_ok && instance->signer_keystore_ok) {
			instance->running = false;
		}
	}

	return result;
}

static bool send_message(ue_socket_client_connection *connection) {
	size_t sent;

	ue_thread_mutex_lock(instance->mutex);
	instance->transmission_state = WRITING_STATE;
	sent = ue_socket_send_data(connection->fd, ue_byte_stream_get_data(connection->message_to_send), ue_byte_stream_get_size(connection->message_to_send), connection->tls);
	instance->transmission_state = READING_STATE;
	ue_thread_cond_signal(instance->cond);
	ue_thread_mutex_unlock(instance->mutex);

	if (sent < 0 || sent == ULLONG_MAX) {
		ue_logger_info("Connection is interrupted.");
		ue_stacktrace_push_msg("Failed to send message to server");
		instance->running = false;
		return false;
	}

	return true;
}

bool send_cipher_message(ue_socket_client_connection *connection) {
	bool result;
	unsigned char *cipher_data;
	size_t cipher_data_size;
	ue_x509_certificate *server_certificate;
    ue_public_key *server_public_key;

	result = false;
	cipher_data = NULL;
	server_public_key = NULL;

	if (!(server_certificate = ue_pkcs12_keystore_find_certificate_by_friendly_name(instance->cipher_keystore, (const unsigned char *)"server_CIPHER", strlen("server_CIPHER")))) {
        ue_stacktrace_push_msg("Failed to get cipher client certificate");
        goto clean_up;
    }

    if (!(server_public_key = ue_rsa_public_key_from_x509_certificate(server_certificate))) {
        ue_stacktrace_push_msg("Failed to get server public key from server certificate");
        goto clean_up;
    }

	if (!cipher_plain_data(ue_byte_stream_get_data(connection->message_to_send), ue_byte_stream_get_size(connection->message_to_send),
		server_public_key, instance->signer_keystore->private_key, &cipher_data, &cipher_data_size, NULL)) {

        ue_stacktrace_push_msg("Failed to cipher plain data");
        goto clean_up;
    }

	ue_byte_stream_clean_up(connection->message_to_send);
	ue_byte_writer_append_bytes(connection->message_to_send, cipher_data, cipher_data_size);

	if (!send_message(connection)) {
		ue_stacktrace_push_msg("Failed to send cipher message");
		goto clean_up;
	}

	result = true;

clean_up:
	ue_public_key_destroy(server_public_key);
	ue_safe_free(cipher_data);
	return result;
}

size_t receive_cipher_message(ue_socket_client_connection *connection) {
	unsigned char *plain_data;
    size_t received, plain_data_size;
	ue_x509_certificate *server_certificate;
	ue_public_key *server_public_key;

	plain_data = NULL;
	server_public_key = NULL;

	received = receive_message(connection);
	if (received <= 0 || received == ULLONG_MAX) {
		ue_logger_warn("Connection with server is interrupted.");
		goto clean_up;
	}

	if (!(server_certificate = ue_pkcs12_keystore_find_certificate_by_friendly_name(instance->signer_keystore, (const unsigned char *)"server_SIGNER", strlen("server_SIGNER")))) {
		ue_stacktrace_push_msg("Failed to find server signer certificate");
		received = -1;
		goto clean_up;
	}

	if (!(server_public_key = ue_rsa_public_key_from_x509_certificate(server_certificate))) {
        ue_stacktrace_push_msg("Failed to get server public key from server certificate");
		received = -1;
        goto clean_up;
    }

	if (!decipher_cipher_data(ue_byte_stream_get_data(connection->received_message), ue_byte_stream_get_size(connection->received_message),
		instance->cipher_keystore->private_key, server_public_key, &plain_data, &plain_data_size)) {

		received = -1;
		ue_stacktrace_push_msg("Failed decipher message data");
		goto clean_up;
	}

	ue_byte_stream_clean_up(connection->received_message);
	ue_byte_writer_append_bytes(connection->received_message, plain_data, plain_data_size);

clean_up:
	ue_public_key_destroy(server_public_key);
	ue_safe_free(plain_data);
	return received;
}

bool tls_read_consumer(void *parameter) {
	size_t received;
	ue_byte_vector_element *type, *content, *content2;
	bool result;
	ue_socket_client_connection *connection;

	result = true;
	connection = (ue_socket_client_connection *)parameter;

	//ue_logger_set_level(ue_logger_manager_get_logger(), LOG_DEBUG);

	while (instance->running) {
		received = receive_cipher_message(connection);
		result = true;

		/* @todo set timeout in case of server lag or reboot */
		if (received <= 0 || received == ULLONG_MAX) {
			ue_logger_warn("Stopping client...");
			if (ue_stacktrace_is_filled()) {
				ue_logger_error("An error occured while receving a cipher message with the following stacktrace :");
				ue_stacktrace_print();
				ue_stacktrace_clean_up();
			}
			instance->running = false;
			result = false;
		}
		else {
			ue_byte_vector_clean_up(connection->split_message);
			ue_byte_split_append(connection->split_message, ue_byte_stream_get_data(connection->received_message), ue_byte_stream_get_size(connection->received_message),
				(unsigned char *)"|", 1);
			type = ue_byte_vector_get(connection->split_message, 0);
			content = ue_byte_vector_get(connection->split_message, 1);

			if (memcmp(type->data, "ALREADY_CONNECTED", type->size) == 0) {
				ue_logger_warn("Already connected");
				instance->running = false;
				result = false;
			}
			else if (memcmp(type->data, "NICKNAME", type->size) == 0) {
				if (memcmp(content->data, "FALSE", content->size) == 0) {
					ue_logger_info("This nickname is already in use.");
					instance->running = false;
					result = false;
				}
				else if (memcmp(content->data, "TRUE", content->size) != 0) {
					ue_logger_warn("Response of nickname request is incomprehensible.");
					instance->running = false;
					result = false;
				}
				ue_logger_trace("Server has accepted this nickname.");
			}
			else if (memcmp(type->data, "CHANNEL_CONNECTION", type->size) == 0) {
				if (memcmp(content->data, "FALSE", content->size) == 0) {
					ue_logger_info("This channel is already in use or cannot be use right now.");
					instance->running = false;
					result = false;
				}
				else if (memcmp(content->data, "TRUE", content->size) != 0) {
					ue_logger_warn("Response of channel connection request is incomprehensible.");
					result = false;
				} else {
					char *buffer;
					content2 = ue_byte_vector_get(connection->split_message, 2);
					buffer = ue_string_create_from_bytes(content2->data, content2->size);
					instance->channel_id = atoi(buffer);
					ue_logger_trace("Channel connection has been accepted by the server with channel id %d.", instance->channel_id);
					ue_safe_free(buffer);
				}
			}
			else if (memcmp(type->data, "MESSAGE", type->size) == 0) {
				/* Here data is the nickname of the sender and data2 the real message */
				content2 = ue_byte_vector_get(connection->split_message, 2);
				ue_byte_stream_clean_up(instance->new_message);
				ue_byte_writer_append_bytes(instance->new_message, content->data, content->size);
				ue_byte_writer_append_string(instance->new_message, ": ");
				ue_byte_writer_append_bytes(instance->new_message, content2->data, content2->size);
				ue_byte_writer_append_string(instance->new_message, "\n");
                if (!write(instance->fds[1], ue_byte_stream_get_data(instance->new_message), ue_byte_stream_get_size(instance->new_message))) {
                    ue_logger_warn("Failed to write the message on console");
                    return false;
                }
			}
			else {
				ue_logger_warn("Received invalid data from server '%s'.", (unsigned char *)content->data);
			}
		}
	}

	return result;
}

static char *get_input(char *prefix) {
	char input[256], *result;
	int i;

	result = NULL;

	printf("%s", prefix);

  	if (fgets(input, 256, stdin)) {
  		if (input[0] == 10) {
  			return NULL;
  		}
  		for (i = 0; i < 256; i++) {
  			if (input[i] != ' ') {
  				result = ue_string_create_from(input);
  				ue_remove_last_char(result);
  				break;
  			}
  		}
  	}

  	return result;
}

static bool send_nickname_request(ue_socket_client_connection *connection) {
	char buffer [4];

	ue_byte_stream_clean_up(connection->message_to_send);
	ue_byte_writer_append_string(connection->message_to_send, "CHANNEL_ID:");
	ue_int_to_string(instance->channel_id, buffer, 10);
	ue_byte_writer_append_string(connection->message_to_send, buffer);
	ue_byte_writer_append_string(connection->message_to_send, "|");
	ue_byte_writer_append_string(connection->message_to_send, "NICKNAME|");
	ue_byte_writer_append_string(connection->message_to_send, instance->nickname);
	ue_byte_writer_append_string(connection->message_to_send, "|EOFEOFEOF");

    if (!send_message(connection)) {
        ue_stacktrace_push_msg("Failed to send nickname request");
        return false;
    }

	return true;
}

bool tls_write_consumer(void *parameter) {
	char *input;
	bool result;
	ue_socket_client_connection *connection;
	int channel_id;
	char buffer [4];

	result = true;
	connection = (ue_socket_client_connection *)parameter;

	//ue_logger_set_level(ue_logger_manager_get_logger(), LOG_DEBUG);

    if (!send_nickname_request(connection)) {
        ue_stacktrace_push_msg("Failed to send nickname request");
        return false;
    }

	while (instance->running) {
		input = get_input(">");

		if (!input) {
			continue;
		}

		channel_id = -1;
		ue_byte_stream_clean_up(connection->message_to_send);
		ue_byte_writer_append_string(connection->message_to_send, "CHANNEL_ID:");
		ue_int_to_string(instance->channel_id, buffer, 10);
		ue_byte_writer_append_string(connection->message_to_send, buffer);
		ue_byte_writer_append_string(connection->message_to_send, "|");

		if (strcmp(input, "-q") == 0) {
			ue_byte_writer_append_string(connection->message_to_send, "DISCONNECTION|NOW|EOFEOFEOF");
			result = send_cipher_message(connection);
			instance->running = false;
		}
		else if (strcmp(input, "-s") == 0) {
			ue_byte_writer_append_string(connection->message_to_send, "SHUTDOWN|NOW|EOFEOFEOF");
			result = send_cipher_message(connection);
			instance->running = false;
		}
		else if (ue_starts_with("@channel_connection", input)) {
			if (!ue_string_to_int(input + strlen("@channel_connection") + 1, &channel_id, 10)) {
				ue_logger_warn("Specified channel id is invalid. Usage : --channel <number>");
			}
			else if (channel_id == -1) {
				ue_logger_warn("Specified channel id is invalid. It have to be >= 0");
			}
			else {
				ue_byte_writer_append_string(connection->message_to_send, "CHANNEL_CONNECTION|");
				ue_byte_writer_append_string(connection->message_to_send, input + strlen("@channel_connection") + 1);
				ue_byte_writer_append_string(connection->message_to_send, "|EOFEOFEOF");
				result = send_cipher_message(connection);
				if (!result) {
					ue_logger_warn("Failed to send channel connection request");
				}
			}
		}
		else {
			if (instance->channel_id >= 0) {
				ue_byte_writer_append_string(connection->message_to_send, "MESSAGE|");
				ue_byte_writer_append_string(connection->message_to_send, instance->nickname);
				ue_byte_writer_append_string(connection->message_to_send, "|");
				ue_byte_writer_append_string(connection->message_to_send, input);
				ue_byte_writer_append_string(connection->message_to_send, "|EOFEOFEOF");
				result = send_cipher_message(connection);
			}
			else {
				ue_logger_warn("Cannot send message because no channel is selected");
			}
		}

		ue_safe_free(input);
	}

	return result;
}

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

unsigned char *client_build_request(ue_x509_certificate *certificate, ue_private_key *private_key, ue_public_key *ca_public_key, size_t *cipher_data_size, ue_sym_key *future_key, unsigned char *iv, size_t iv_size) {
    char *csr_string;
    ue_public_key *public_key;
    ue_byte_stream *stream;
    unsigned char *cipher_data;

    csr_string = NULL;
    public_key = NULL;
    stream = ue_byte_stream_create();
    cipher_data = NULL;

    csr_string = generate_csr_string(certificate, private_key);

    ue_byte_writer_append_int(stream, (int)strlen(csr_string));
    ue_byte_writer_append_int(stream, (int)future_key->size);
    ue_byte_writer_append_int(stream, (int)iv_size);
    ue_byte_writer_append_string(stream, csr_string);
    ue_byte_writer_append_bytes(stream, future_key->data, future_key->size);
    ue_byte_writer_append_bytes(stream, iv, iv_size);

    if (!cipher_plain_data(ue_byte_stream_get_data(stream), ue_byte_stream_get_size(stream), ca_public_key, NULL, &cipher_data, cipher_data_size, NULL)) {
        ue_stacktrace_push_msg("Failed to cipher plain data");
        goto clean_up;
    }

clean_up:
    ue_public_key_destroy(public_key);
    ue_byte_stream_destroy(stream);
    ue_safe_free(csr_string);
    return cipher_data;
}

ue_x509_certificate *client_process_server_response(unsigned char *server_response, size_t server_response_size, ue_sym_key *key, unsigned char *iv, size_t iv_size) {
    ue_sym_encrypter *sym_encrypter;
    ue_x509_certificate *signed_certificate;
    unsigned char *signed_certificate_buffer;
    size_t signed_certificate_buffer_size;

    signed_certificate = NULL;

    sym_encrypter = ue_sym_encrypter_default_create(key);
	if (!(signed_certificate_buffer = ue_sym_encrypter_decrypt(sym_encrypter, server_response, server_response_size, iv, iv_size, &signed_certificate_buffer_size))) {
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

bool send_csr(csr_context *context, char *type) {
	bool result;
	ue_x509_certificate *certificate;
	size_t cipher_data_size/*, sent*/;
	unsigned char *csr_request;
	ue_byte_stream *stream;
	ue_public_key *ca_public_key;

	result = false;
	csr_request = NULL;
	stream = ue_byte_stream_create();
	ca_public_key = NULL;

	if (!(context->future_key = ue_sym_key_create_random())) {
		ue_stacktrace_push_msg("Failed to gen random sym key for server response encryption");
		goto clean_up;
	}

	ue_safe_alloc(context->iv, unsigned char, 16);
	if (!(ue_crypto_random_bytes(context->iv, 16))) {
		ue_stacktrace_push_msg("Failed to get crypto random bytes for IV");
		goto clean_up;
	}
	context->iv_size = 16;

	if (!(ca_public_key = ue_rsa_public_key_from_x509_certificate(instance->csr_server_certificate))) {
		ue_stacktrace_push_msg("Failed to extract RSA public key from CA certificate");
		goto clean_up;
	}

	if (!generate_certificate(&certificate, &context->private_key)) {
        ue_stacktrace_push_msg("Failed to generate x509 certificate and private key");
        goto clean_up;
    }

	if (!(csr_request = client_build_request(certificate, context->private_key, ca_public_key, &cipher_data_size, context->future_key, context->iv,
		context->iv_size))) {

		ue_stacktrace_push_msg("Failed to build CSR request");
		goto clean_up;
	}

	ue_byte_writer_append_int(stream, (int)(strlen("CSR") + strlen(type) + 8 + strlen(instance->nickname)));
	ue_byte_writer_append_string(stream, "CSR");
	ue_byte_writer_append_string(stream, type);
	ue_byte_writer_append_int(stream, (int)strlen(instance->nickname));
	ue_byte_writer_append_string(stream, instance->nickname);
	ue_byte_writer_append_bytes(stream, csr_request, cipher_data_size);
	ue_byte_writer_append_string(stream, "||||||||||||EOFEOFEOF");

	ue_byte_stream_clean_up(instance->connection->message_to_send);
	ue_byte_writer_append_bytes(instance->connection->message_to_send, ue_byte_stream_get_data(stream), ue_byte_stream_get_size(stream));

	send_message(instance->connection);

	result = true;

clean_up:
	ue_safe_free(csr_request);
	ue_byte_stream_destroy(stream);
	ue_public_key_destroy(ca_public_key);
	return result;
}

bool socket_client_manager_start(const char *host, unsigned short int tls_port) {
    if (pipe(instance->fds) == -1) {
        abort();
    }

    instance->child_pid = fork();
    if (instance->child_pid == -1) {
        abort();
    }

    if (instance->child_pid == 0) {
        close(instance->fds[1]);
        char f[PATH_MAX + 1];
        sprintf(f, "/dev/fd/%d", instance->fds[0]);
        execlp("xterm", "xterm", "-e", "cat", f, NULL);
        abort();
    }

    if (instance->child_pid != 0) {
    	close(instance->fds[0]);

	    handle_signal(SIGINT, shutdown_client, 0);
	    handle_signal(SIGPIPE, SIG_IGN, SA_RESTART);

	    ue_x509_certificate **ca_certificates = NULL;
	    ue_safe_alloc(ca_certificates, ue_x509_certificate *, 1);
	    ca_certificates[0] = instance->tls_server_certificate;

		/* @todo pass keystore ptr instead of path */
		if (!(instance->tls_session = ue_tls_session_create_client((char *)instance->tls_keystore_path, instance->keystore_password, ca_certificates, 1))) {
			ue_stacktrace_push_msg("Failed to create TLS session");
			return false;
		}

		ue_safe_free(ca_certificates);

		ue_safe_str_free(instance->keystore_password);

	    instance->fd = ue_socket_open_tcp();
        if (!(instance->connection = ue_socket_connect(instance->fd, AF_INET, host, tls_port, instance->tls_session))) {
            ue_stacktrace_push_msg("Failed to connect socket to server");
            return false;
        }

		instance->running = true;
		instance->transmission_state = WRITING_STATE;
		instance->new_message = ue_byte_stream_create();
		instance->channel_id = -1;

	    _Pragma("GCC diagnostic push")
	    _Pragma("GCC diagnostic ignored \"-Wpedantic\"")
			instance->read_thread = ue_thread_create((void *)tls_read_consumer, (void *)instance->connection);
			instance->write_thread = ue_thread_create((void *)tls_write_consumer, (void *)instance->connection);
	    _Pragma("GCC diagnostic pop")

	    ue_thread_join(instance->read_thread, NULL);
	    ue_thread_join(instance->write_thread, NULL);
    }

    return true;
}

bool create_keystores(const char *csr_server_host, unsigned short int csr_server_port, char *keystore_password) {
	bool result;
	bool tls_keystore_exists, cipher_keystore_exists, signer_keystore_exists;

	result = false;

	tls_keystore_exists = ue_is_file_exists(instance->tls_keystore_path);
	cipher_keystore_exists = ue_is_file_exists(instance->cipher_keystore_path);
	signer_keystore_exists = ue_is_file_exists(instance->signer_keystore_path);

	if (!tls_keystore_exists) {
		ue_safe_alloc(instance->tls_csr_context, csr_context, 1);
		instance->tls_csr_context->signed_certificate = NULL;
		instance->tls_csr_context->private_key = NULL;
		instance->tls_csr_context->future_key = NULL;
		instance->tls_csr_context->iv = NULL;
	} else {
		if (!(instance->tls_keystore = ue_pkcs12_keystore_load(instance->tls_keystore_path, instance->keystore_password))) {
	        ue_stacktrace_push_msg("Failed to load cipher pkcs12 keystore");
	        goto clean_up;
	    }
	}

	if (!cipher_keystore_exists) {
		ue_safe_alloc(instance->cipher_csr_context, csr_context, 1);
		instance->cipher_csr_context->signed_certificate = NULL;
		instance->cipher_csr_context->private_key = NULL;
		instance->cipher_csr_context->future_key = NULL;
		instance->cipher_csr_context->iv = NULL;
	} else {
		if (!(instance->cipher_keystore = ue_pkcs12_keystore_load(instance->cipher_keystore_path, instance->keystore_password))) {
	        ue_stacktrace_push_msg("Failed to load cipher pkcs12 keystore");
	        goto clean_up;
	    }
	}

	if (!signer_keystore_exists) {
		ue_safe_alloc(instance->signer_csr_context, csr_context, 1);
		instance->signer_csr_context->signed_certificate = NULL;
		instance->signer_csr_context->private_key = NULL;
		instance->signer_csr_context->future_key = NULL;
		instance->signer_csr_context->iv = NULL;
	} else {
		if (!(instance->signer_keystore = ue_pkcs12_keystore_load(instance->signer_keystore_path, instance->keystore_password))) {
			ue_stacktrace_push_msg("Failed to load signer pkcs12 keystore");
			goto clean_up;
		}
	}

	if (!tls_keystore_exists || !cipher_keystore_exists || !signer_keystore_exists) {
		instance->fd = ue_socket_open_tcp();
		if (!(instance->connection = ue_socket_connect(instance->fd, AF_INET, csr_server_host, csr_server_port, NULL))) {
			ue_stacktrace_push_msg("Failed to connect socket to server");
			goto clean_up;
		}

		instance->running = true;
		instance->transmission_state = WRITING_STATE;

	    _Pragma("GCC diagnostic push")
	    _Pragma("GCC diagnostic ignored \"-Wpedantic\"")
			instance->read_thread = ue_thread_create((void *)csr_read_consumer, (void *)instance->connection);
	    _Pragma("GCC diagnostic pop")
	}

	if (!tls_keystore_exists) {
		ue_logger_info("TLS keystore doesn't exists. A CSR will be built.");
		if (!send_csr(instance->tls_csr_context, "TLS___")) {
			ue_stacktrace_push_msg("Failed to process CSR exchange for TLS");
			goto clean_up;
		}
	} else {
		instance->tls_keystore_ok = true;
	}

	if (!cipher_keystore_exists) {
		ue_logger_info("Cipher keystore doesn't exists. A CSR will be built.");

		if (!send_csr(instance->cipher_csr_context, "CIPHER")) {
			ue_stacktrace_push_msg("Failed to process CSR exchange for cipher");
			goto clean_up;
		}
	} else {
		instance->cipher_keystore_ok = true;
	}

	if (!signer_keystore_exists) {
		ue_logger_info("Signer keystore doesn't exists. A CSR will be built.");

		if (!send_csr(instance->signer_csr_context, "SIGNER")) {
			ue_stacktrace_push_msg("Failed to process CSR exchange for signer");
			goto clean_up;
		}
	} else {
		instance->signer_keystore_ok = true;
	}

	if (!tls_keystore_exists || !cipher_keystore_exists || !signer_keystore_exists) {
		ue_thread_join(instance->read_thread, NULL);

		if (ue_stacktrace_is_filled()) {
			ue_logger_error("An error occurred while processing read_consumer()");
			ue_stacktrace_print();
			ue_stacktrace_clean_up();
			goto clean_up;
		}
	}

	if (!tls_keystore_exists) {
		if (ue_x509_certificate_verify(instance->tls_csr_context->signed_certificate, instance->tls_server_certificate)) {
			ue_logger_info("Certificate is correctly signed by the CA");
		} else {
			ue_stacktrace_push_msg("Certificate isn't correctly signed by the CA");
			goto clean_up;
		}

		if (!(instance->tls_keystore = ue_pkcs12_keystore_create(instance->tls_csr_context->signed_certificate, instance->tls_csr_context->private_key, "tls_client"))) {
			ue_stacktrace_push_msg("Failed to create keystore from specified signed certificate and private key");
			goto clean_up;
		}

		ue_pkcs12_keystore_add_certificate_from_file(instance->tls_keystore, instance->tls_server_certificate_path, (const unsigned char *)"server_TLS", strlen("server_TLS"));

		if (!ue_pkcs12_keystore_write(instance->tls_keystore, instance->tls_keystore_path, keystore_password)) {
			ue_stacktrace_push_msg("Failed to write keystore to '%s'", instance->tls_keystore_path);
			goto clean_up;
		}

		ue_logger_info("TLS keystore created.");
	}

	if (!cipher_keystore_exists) {
		if (ue_x509_certificate_verify(instance->cipher_csr_context->signed_certificate, instance->cipher_server_certificate)) {
			ue_logger_info("Certificate is correctly signed by the CA");
		} else {
			ue_stacktrace_push_msg("Certificate isn't correctly signed by the CA");
			goto clean_up;
		}

		if (!(instance->cipher_keystore = ue_pkcs12_keystore_create(instance->cipher_csr_context->signed_certificate, instance->cipher_csr_context->private_key,
			"cipher_client"))) {

			ue_stacktrace_push_msg("Failed to create keystore from specified signed certificate and private key");
			goto clean_up;
		}

		ue_pkcs12_keystore_add_certificate_from_file(instance->cipher_keystore, instance->cipher_server_certificate_path, (const unsigned char *)"server_CIPHER", strlen("server_CIPHER"));

		if (!ue_pkcs12_keystore_write(instance->cipher_keystore, instance->cipher_keystore_path, keystore_password)) {
			ue_stacktrace_push_msg("Failed to write keystore to '%s'", instance->cipher_keystore_path);
			goto clean_up;
		}

		ue_logger_info("Cipher keystore created.");
	}

	if (!signer_keystore_exists) {
		if (ue_x509_certificate_verify(instance->signer_csr_context->signed_certificate, instance->signer_server_certificate)) {
			ue_logger_info("Certificate is correctly signed by the CA");
		} else {
			ue_stacktrace_push_msg("Certificate isn't correctly signed by the CA");
			goto clean_up;
		}

		if (!(instance->signer_keystore = ue_pkcs12_keystore_create(instance->signer_csr_context->signed_certificate, instance->signer_csr_context->private_key,
			"signer_client"))) {

			ue_stacktrace_push_msg("Failed to create keystore from specified signed certificate and private key");
			goto clean_up;
		}

		ue_pkcs12_keystore_add_certificate_from_file(instance->signer_keystore, instance->signer_server_certificate_path, (const unsigned char *)"server_SIGNER", strlen("server_SIGNER"));

		if (!ue_pkcs12_keystore_write(instance->signer_keystore, instance->signer_keystore_path, keystore_password)) {
			ue_stacktrace_push_msg("Failed to write keystore to '%s'", instance->signer_keystore_path);
			goto clean_up;
		}

		ue_logger_info("Signer keystore created.");
	}

	result = true;

clean_up:
	return result;
}

bool socket_client_manager_create() {
	ue_safe_alloc(instance, socket_client_manager, 1);
    instance->fd = -1;
    instance->connection = NULL;
    instance->new_message = NULL;
    instance->running = false;
    instance->nickname = NULL;
    instance->read_thread = NULL;
    instance->write_thread = NULL;
    instance->tls_session = NULL;
	instance->channel_id = -1;
	instance->keystore_password = NULL;
	instance->tls_keystore_ok = false;
	instance->cipher_keystore_ok = false;
	instance->signer_keystore_ok = false;
	instance->tls_csr_context = NULL;
	instance->cipher_csr_context = NULL;
	instance->signer_csr_context = NULL;
	instance->tls_keystore = NULL;
	instance->cipher_keystore = NULL;
    instance->signer_keystore = NULL;

	if (!(instance->mutex = ue_thread_mutex_create())) {
		ue_stacktrace_push_msg("Failed to init instance->mutex");
		return false;
	}

	if (!(instance->cond = ue_thread_cond_create())) {
		ue_stacktrace_push_msg("Failed to init instance->cond");
		return false;
	}

	if (!(instance->nickname = get_input("Nickname : "))) {
        ue_stacktrace_push_msg("Specified nickname isn't valid");
        return false;
    }

	instance->csr_server_certificate_path = ue_strcat_variadic("sss", ROOT_PATH, instance->nickname, CSR_SERVER_CERTIFICATE_PATH);
	instance->tls_server_certificate_path = ue_strcat_variadic("sss", ROOT_PATH, instance->nickname, TLS_SERVER_CERTIFICATE_PATH);
	instance->cipher_server_certificate_path = ue_strcat_variadic("sss", ROOT_PATH, instance->nickname, CIPHER_SERVER_CERTIFICATE_PATH);
	instance->signer_server_certificate_path = ue_strcat_variadic("sss", ROOT_PATH, instance->nickname, SIGNER_SERVER_CERTIFICATE_PATH);
	instance->tls_keystore_path = ue_strcat_variadic("sss", ROOT_PATH, instance->nickname, TLS_KEYSTORE_PATH);
	instance->cipher_keystore_path = ue_strcat_variadic("sss", ROOT_PATH, instance->nickname, CIPHER_KEYSTORE_PATH);
	instance->signer_keystore_path = ue_strcat_variadic("sss", ROOT_PATH, instance->nickname, SIGNER_KEYSTORE_PATH);

	/*if (!(instance->keystore_password = get_input("Password : "))) {
        ue_stacktrace_push_msg("Specified password isn't valid");
        return false;
    }*/

	//instance->nickname = ue_string_create_from("swa");
	instance->keystore_password = ue_string_create_from("password");

	if (!ue_x509_certificate_load_from_file(instance->csr_server_certificate_path, &instance->csr_server_certificate)) {
		ue_stacktrace_push_msg("Failed to load CSR server certificate from path '%s'", instance->csr_server_certificate_path);
		ue_safe_free(instance);
		return false;
	}

	if (!ue_x509_certificate_load_from_file(instance->tls_server_certificate_path, &instance->tls_server_certificate)) {
		ue_stacktrace_push_msg("Failed to load TLS server certificate from path '%s'", instance->tls_server_certificate_path);
		ue_safe_free(instance);
		return false;
	}

	if (!ue_x509_certificate_load_from_file(instance->cipher_server_certificate_path, &instance->cipher_server_certificate)) {
		ue_stacktrace_push_msg("Failed to load cipher server certificate from path '%s'", instance->cipher_server_certificate_path);
		ue_safe_free(instance);
		return false;
	}

	if (!ue_x509_certificate_load_from_file(instance->signer_server_certificate_path, &instance->signer_server_certificate)) {
		ue_stacktrace_push_msg("Failed to load signer server certificate from path '%s'", instance->signer_server_certificate_path);
		ue_safe_free(instance);
		return false;
	}

	if (!create_keystores(CSR_SERVER_HOST, CSR_SERVER_PORT, instance->keystore_password)) {
		ue_stacktrace_push_msg("Failed to create keystore");
		socket_client_manager_destroy();
		return false;
	}

	return true;
}

void socket_client_manager_destroy() {
	if (!instance) {
		return;
	}
	if (instance->child_pid != 0) {
		ue_safe_free(instance->read_thread)
		ue_safe_free(instance->write_thread)
		ue_thread_mutex_destroy(instance->mutex);
		ue_thread_cond_destroy(instance->cond);
	}
	if (instance->tls_session) {
		ue_tls_session_destroy(instance->tls_session);
	}
	close(instance->fds[1]);
	ue_byte_stream_destroy(instance->new_message);
	ue_safe_str_free(instance->nickname)
	ue_safe_str_free(instance->keystore_password);
	if (instance->connection) {
		ue_socket_client_connection_destroy(instance->connection);
	}
	else {
		ue_socket_close(instance->fd);
	}
	ue_x509_certificate_destroy(instance->csr_server_certificate);
	ue_x509_certificate_destroy(instance->tls_server_certificate);
	ue_x509_certificate_destroy(instance->cipher_server_certificate);
	ue_x509_certificate_destroy(instance->signer_server_certificate);
	if (instance->tls_csr_context) {
		ue_sym_key_destroy(instance->tls_csr_context->future_key);
		ue_safe_free(instance->tls_csr_context->iv);
		ue_safe_free(instance->tls_csr_context);
	}
	if (instance->cipher_csr_context) {
		ue_sym_key_destroy(instance->cipher_csr_context->future_key);
		ue_safe_free(instance->cipher_csr_context->iv);
		ue_safe_free(instance->cipher_csr_context);
	}
	if (instance->signer_csr_context) {
		ue_sym_key_destroy(instance->signer_csr_context->future_key);
		ue_safe_free(instance->signer_csr_context->iv);
		ue_safe_free(instance->signer_csr_context);
	}
	ue_pkcs12_keystore_destroy(instance->tls_keystore);
	ue_pkcs12_keystore_destroy(instance->cipher_keystore);
	ue_pkcs12_keystore_destroy(instance->signer_keystore);
	ue_safe_free(instance->csr_server_certificate_path);
	ue_safe_free(instance->tls_server_certificate_path);
	ue_safe_free(instance->cipher_server_certificate_path);
	ue_safe_free(instance->signer_server_certificate_path);
	ue_safe_free(instance->tls_keystore_path);
	ue_safe_free(instance->cipher_keystore_path);
	ue_safe_free(instance->signer_keystore_path);
	ue_safe_free(instance)
}

int main() {
    if (!ue_init()) {
		printf("[ERROR] Failed to init LibUnknownEcho\n");
		exit(1);
	}

	//ue_logger_set_level(ue_logger_manager_get_logger(), LOG_DEBUG);

	if (!socket_client_manager_create()) {
		ue_stacktrace_push_msg("Failed to create socket client manager");
		goto end;
	}

	if (!socket_client_manager_start(TLS_SERVER_HOST, TLS_SERVER_PORT)) {
		ue_stacktrace_push_msg("Failed to start socket client manager");
	}

end:
	socket_client_manager_destroy();
	if (ue_stacktrace_is_filled()) {
		ue_logger_error("An error occurred with the following stacktrace :");
		ue_stacktrace_print_all();
	}
    ue_uninit();
    return 0;
}
