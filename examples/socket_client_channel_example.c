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
#include <unknownecho/network/api/tls/tls_method.h>
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
	int fd;
	int child_pid;
	char *nickname;
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
	ue_x509_certificate *ca_certificate;
} socket_client_manager;

socket_client_manager *instance = NULL;

#if defined(WIN32)
	#include <windows.h>
#elif defined(__UNIX__)
	#include <unistd.h>
#endif


#define CA_CERTIFICATE_PATH "res/ah/ca.crt"
#define KEYSTORE_PATH       "res/keystore.p12"


bool socket_client_manager_create();

void socket_client_manager_destroy();


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

bool read_consumer(void *parameter) {
	size_t received;
	ue_byte_vector_element *type, *content, *content2;
	bool result;
	ue_socket_client_connection *connection;

	result = true;
	connection = (ue_socket_client_connection *)parameter;

	//ue_logger_set_level(ue_logger_manager_get_logger(), LOG_DEBUG);

	while (instance->running) {
		received = receive_message(connection);
		result = true;

		if (received == 0) {
			ue_logger_warn("Connection is interrupted. Stopping consumer...");
			instance->running = false;
			result = false;
		}
		else if (received < 0 || received == ULLONG_MAX) {
			ue_stacktrace_push_msg("Failed to send client input to server");
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
					ue_logger_warn("Response of nickname request is incomprehensible");
					instance->running = false;
					result = false;
				}
			}
			else if (memcmp(type->data, "CHANNEL_CONNECTION", type->size) == 0) {
				if (memcmp(content->data, "FALSE", content->size) == 0) {
					ue_logger_info("This channel is already in use or cannot be use right now.");
					instance->running = false;
					result = false;
				}
				else if (memcmp(content->data, "TRUE", content->size) != 0) {
					ue_logger_warn("Response of channel connection request is incomprehensible");
					result = false;
				} else {
					content2 = ue_byte_vector_get(connection->split_message, 2);
					ue_string_to_int((char *)content2->data, &instance->channel_id, 10);
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

static bool send_message(ue_socket_client_connection *connection) {
	size_t sent;

	ue_thread_mutex_lock(instance->mutex);
	instance->transmission_state = WRITING_STATE;
	ue_logger_info("Message to send : %s", (char *)ue_byte_stream_get_data(connection->message_to_send));
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

bool write_consumer(void *parameter) {
	char *input;
	bool result;
	ue_socket_client_connection *connection;
	int channel_id;
	char buffer [4];

	result = true;
	connection = (ue_socket_client_connection *)parameter;

	ue_logger_set_level(ue_logger_manager_get_logger(), LOG_DEBUG);

    if (!(instance->nickname = get_input("Nickname : "))) {
        ue_stacktrace_push_msg("Specified nickname isn't valid");
        return false;
    }

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
			result = send_message(connection);
			instance->running = false;
		}
		else if (strcmp(input, "-s") == 0) {
			ue_byte_writer_append_string(connection->message_to_send, "SHUTDOWN|NOW|EOFEOFEOF");
			result = send_message(connection);
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
				//ue_string_builder_append(connection->message_to_send, input + strlen("@channel_connection") + 1, strlen(input + strlen("@channel_connection") + 1));
				ue_byte_writer_append_string(connection->message_to_send, "|EOFEOFEOF");
				result = send_message(connection);
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
				result = send_message(connection);
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

bool process_csr(unsigned short int csr_port, ue_x509_certificate **signed_certificate, ue_private_key **private_key) {
	bool result;
	ue_x509_certificate *certificate;
	int fd;
	ue_socket_client_connection *connection;
	size_t iv_size, cipher_data_size;
	unsigned char *iv, *csr_request;
	ue_sym_key *future_key;
	ue_byte_stream *stream;
	ue_public_key *ca_public_key;

	result = false;
	csr_request = NULL;
	fd = -1;
	future_key = NULL;
	stream = ue_byte_stream_create();
	iv = NULL;
	ca_public_key = NULL;
	*signed_certificate = NULL;
	*private_key = NULL;

	fd = ue_socket_open_tcp();
	if (!(connection = ue_socket_connect(fd, AF_INET, "127.0.0.1", csr_port, NULL))) {
		ue_stacktrace_push_msg("Failed to connect socket to server");
		goto clean_up;
	}

	future_key = ue_sym_key_create_random();
	ue_safe_alloc(iv, unsigned char, 16);
	if (!(ue_crypto_random_bytes(iv, 16))) {
		ue_stacktrace_push_msg("Failed to get crypto random bytes for IV");
		goto clean_up;
	}
	iv_size = 16;

	ca_public_key = ue_rsa_public_key_from_x509_certificate(instance->ca_certificate);

	if (!generate_certificate(&certificate, private_key)) {
        ue_stacktrace_push_msg("Failed to generate x509 certificate and private key");
        goto clean_up;
    }

	if (!(csr_request = client_build_request(certificate, *private_key, ca_public_key, &cipher_data_size, future_key, iv, iv_size))) {
		ue_stacktrace_push_msg("Failed to build CSR request");
		goto clean_up;
	}

	//ue_byte_writer_append_string(stream, "CSR|");
	ue_byte_writer_append_bytes(stream, csr_request, cipher_data_size);
	//ue_byte_writer_append_string(stream, "|EOFEOFEOF");

	size_t sent = ue_socket_send_data(fd, ue_byte_stream_get_data(stream), ue_byte_stream_get_size(stream), NULL);
	ue_logger_trace("CSR bytes sent is %ld", sent);

	size_t received = ue_socket_receive_bytes_sync(fd, connection->received_message, false, NULL);
	ue_logger_trace("Size of the received response : %ld", received);

	*signed_certificate = client_process_server_response(ue_byte_stream_get_data(connection->received_message),
		ue_byte_stream_get_size(connection->received_message), future_key, iv, iv_size);

	if (ue_x509_certificate_verify(*signed_certificate, instance->ca_certificate)) {
        ue_logger_info("Certificate is correctly signed by the CA");
    } else {
        ue_logger_error("Certificate isn't correctly signed by the CA");
    }

	ue_x509_certificate_print(*signed_certificate, stdout);

	result = true;

clean_up:
	ue_socket_client_connection_destroy(connection);
	ue_safe_free(iv);
	ue_safe_free(csr_request);
	ue_sym_key_destroy(future_key);
	ue_byte_stream_destroy(stream);
	ue_public_key_destroy(ca_public_key);
	if (!result) {
		if (*private_key) {
			ue_private_key_destroy(*private_key);
		}
	}
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

        if (!(instance->mutex = ue_thread_mutex_create())) {
            ue_stacktrace_push_msg("Failed to init instance->mutex");
            return false;
        }

        if (!(instance->cond = ue_thread_cond_create())) {
            ue_stacktrace_push_msg("Failed to init instance->cond");
            return false;
        }

	    handle_signal(SIGINT, shutdown_client, 0);
	    handle_signal(SIGPIPE, SIG_IGN, SA_RESTART);

		instance->tls_session = ue_tls_session_create(KEYSTORE_PATH, "password", "", ue_tls_method_create_v1_client(), instance->ca_certificate);

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
			instance->read_thread = ue_thread_create((void *)read_consumer, (void *)instance->connection);
			instance->write_thread = ue_thread_create((void *)write_consumer, (void *)instance->connection);
	    _Pragma("GCC diagnostic pop")

	    ue_thread_join(instance->read_thread, NULL);
	    ue_thread_join(instance->write_thread, NULL);
    }

    return true;
}

bool create_keystore(unsigned short int csr_server_port) {
	bool result;
	ue_pkcs12_keystore *keystore;
	ue_x509_certificate *signed_certificate;
	ue_private_key *private_key;

	result = false;
	keystore = NULL;
	signed_certificate = NULL;
	private_key = NULL;

	if (!ue_is_file_exists(KEYSTORE_PATH)) {

		if (!process_csr(csr_server_port, &signed_certificate, &private_key)) {
			ue_stacktrace_push_msg("Failed to process CSR");
			goto clean_up;
		}

		if (!(keystore = ue_pkcs12_keystore_create(signed_certificate, private_key, "client"))) {
			ue_stacktrace_push_msg("Failed to create keystore from specified signed certificate and private key");
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
	ue_x509_certificate_destroy(signed_certificate);
	ue_private_key_destroy(private_key);
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

	if (!ue_x509_certificate_load_from_file(CA_CERTIFICATE_PATH, &instance->ca_certificate)) {
		ue_stacktrace_push_msg("Failed to load CA certificate from path '%s'", CA_CERTIFICATE_PATH);
		ue_safe_free(instance);
		return false;
	}

	if (!create_keystore(5002)) {
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
	if (instance->connection) {
		ue_socket_client_connection_destroy(instance->connection);
	}
	else {
		ue_socket_close(instance->fd);
	}
	ue_x509_certificate_destroy(instance->ca_certificate);
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

	if (!socket_client_manager_start("127.0.0.1", 5001)) {
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
