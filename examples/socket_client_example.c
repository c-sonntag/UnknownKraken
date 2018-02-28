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
#include <unknownecho/crypto/factory/pkcs12_keystore_factory.h>
#include <unknownecho/container/byte_vector.h>
#include <unknownecho/byte/byte_split.h>
#include <unknownecho/byte/byte_writer.h>
#include <unknownecho/byte/byte_stream.h>
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
} ue_socket_client_manager;

ue_socket_client_manager *instance = NULL;

#if defined(WIN32)
	#include <windows.h>
#elif defined(__UNIX__)
	#include <unistd.h>
#endif


#define KEYSTORE_PATH "res/keystore.p12"


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

	ue_logger_set_level(ue_logger_manager_get_logger(), LOG_DEBUG);

	while (instance->running) {
		received = receive_message(connection);

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
				ue_logger_warn("Received invalid data from server '%s'.", (char *)content->data);
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
	ue_byte_stream_clean_up(connection->message_to_send);
	ue_byte_writer_append_string(connection->message_to_send, "NICKNAME|");
	ue_byte_writer_append_string(connection->message_to_send, instance->nickname);

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

		ue_byte_stream_clean_up(connection->message_to_send);

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
		else {
			ue_byte_writer_append_string(connection->message_to_send, "MESSAGE|");
			ue_byte_writer_append_string(connection->message_to_send, instance->nickname);
			ue_byte_writer_append_string(connection->message_to_send, "|");
			ue_byte_writer_append_string(connection->message_to_send, input);
			ue_byte_writer_append_string(connection->message_to_send, "|EOFEOFEOF");
			result = send_message(connection);
		}

		ue_safe_free(input);
	}

	return result;
}

bool create_keystore() {
	bool result;
	ue_pkcs12_keystore *keystore;

	result = false;
	keystore = NULL;

	if (!ue_is_file_exists(KEYSTORE_PATH)) {

		if (!(keystore = ue_pkcs12_keystore_create_random("CLIENT", "name"))) {
			ue_stacktrace_push_msg("Failed to create random keystore");
			goto clean_up;
		}

		if (!ue_pkcs12_keystore_write(keystore, KEYSTORE_PATH, "password")) {
			ue_stacktrace_push_msg("Failed to write keystore to '%s'", KEYSTORE_PATH);
			goto clean_up;
		}
	}

	result = true;

clean_up:
	ue_pkcs12_keystore_destroy(keystore);
	return result;
}

bool socket_client_manager_create() {
	ue_safe_alloc(instance, ue_socket_client_manager, 1);
    instance->fd = -1;
    instance->connection = NULL;
    instance->new_message = NULL;
    instance->running = false;
    instance->nickname = NULL;
    instance->read_thread = NULL;
    instance->write_thread = NULL;
    instance->tls_session = NULL;

	if (!create_keystore()) {
		ue_stacktrace_push_msg("Failed to create keystore");
		socket_client_manager_destroy();
		return false;
	}

	return true;
}

bool socket_client_manager_start(const char *host, unsigned short int port) {
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

		if (!(instance->tls_session = ue_tls_session_create(KEYSTORE_PATH, "password", ue_tls_method_create_client(), NULL, 0))) {
			ue_stacktrace_push_msg("Failed to create TLS session");
			return false;
		}

	    instance->fd = ue_socket_open_tcp();

        if (!(instance->connection = ue_socket_connect(instance->fd, AF_INET, host, port, instance->tls_session))) {
            ue_stacktrace_push_msg("Failed to connect socket to server");
            return false;
        }

		instance->running = true;
		instance->transmission_state = WRITING_STATE;
		instance->new_message = ue_byte_stream_create();

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
	ue_safe_free(instance)
}

int main() {
	if (!ue_init()) {
		printf("[ERROR] Failed to init LibUnknownEcho\n");
		exit(1);
	}

	ue_logger_set_level(ue_logger_manager_get_logger(), LOG_DEBUG);

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
