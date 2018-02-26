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
#include <unknownecho/crypto/api/keystore/pkcs12_keystore.h>
#include <unknownecho/crypto/factory/pkcs12_keystore_factory.h>
#include <unknownecho/byte/byte_utility.h>
#include <unknownecho/byte/byte_split.h>
#include <unknownecho/byte/byte_stream.h>
#include <unknownecho/byte/byte_writer.h>
#include <unknownecho/container/byte_vector.h>
#include <unknownecho/fileSystem/file_utility.h>

#include <stdlib.h>
#include <signal.h>
#include <stddef.h>
#include <string.h>
#include <limits.h>

typedef enum {
    WORKING_STATE,
    FREE_STATE
} request_processing_state;

typedef struct {
	ue_socket_server *server;
	ue_thread_mutex *mutex;
	ue_thread_cond *cond;
	request_processing_state processing_state;
	ue_tls_session *tls_session;
} ue_socket_server_manager;

ue_socket_server_manager *instance = NULL;

#define KEYSTORE_PATH "res/server_keystore.p12"

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
    if (instance->server) {
        instance->server->running = false;
    }
}

static bool check_suggest_nickname(const char *nickname) {
    int i;

    if (!nickname) {
        return false;
    }

    for (i = 0; i < instance->server->connections_number; i++) {
        if (ue_socket_client_connection_is_available(instance->server->connections[i])) {
            continue;
        }

        if (instance->server->connections[i]->nickname && strcmp(instance->server->connections[i]->nickname, nickname) == 0) {
            return false;
        }
    }

    return true;
}

static bool process_request(void *parameter) {
    ue_socket_client_connection *connection;
    ue_byte_vector_element *type, *content, *content2;
    bool result;
    int i;

    //ue_logger_set_level(ue_logger_manager_get_logger(), LOG_DEBUG);

    connection = (ue_socket_client_connection *)parameter;
    result = false;

    ue_thread_mutex_lock(instance->mutex);
    while (instance->processing_state == WORKING_STATE) {
        ue_thread_cond_wait(instance->cond, instance->mutex);
    }
    ue_thread_mutex_unlock(instance->mutex);
    instance->processing_state = WORKING_STATE;

    for (i = 0; i < ue_byte_vector_size(connection->all_messages); i++) {

        if (!ue_byte_vector_get(connection->all_messages, i) || !ue_byte_vector_get(connection->all_messages, i)->data) {
            continue;
        }

        ue_byte_vector_clean_up(connection->current_message);

        /* @todo fix unknown error of splitting here */
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
            ue_socket_client_connection_clean_up(connection);
            result = true;
        } else if (memcmp(type->data, "SHUTDOWN", type->size) == 0) {
            ue_logger_info("Shutdown detected");
            instance->server->running = false;
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
        } else if (memcmp(type->data, "MESSAGE", type->size) == 0) {
            /* Here data is the nickname of the sender and data2 the real message */
            content2 = ue_byte_vector_get(connection->current_message, 2);
            ue_byte_stream_clean_up(connection->message_to_send);
            ue_byte_writer_append_bytes(connection->message_to_send, type->data, type->size);
            ue_byte_writer_append_string(connection->message_to_send, "|");
            ue_byte_writer_append_bytes(connection->message_to_send, content->data, content->size);
            ue_byte_writer_append_string(connection->message_to_send, "|");
            ue_byte_writer_append_bytes(connection->message_to_send, content2->data, content2->size);
            connection->state = UNKNOWNECHO_CONNECTION_WRITE_STATE;
            result = true;
        } else {
            ue_logger_warn("Received invalid data from client '%s'.", (char *)content->data);
        }
        ue_byte_vector_remove(connection->all_messages, i);
    }

    instance->processing_state = FREE_STATE;

    return result;
}

bool read_consumer(ue_socket_client_connection *connection) {
    size_t received;
    ue_thread_id *request_processor_thread;

    if (!instance->server->running) {
        return false;
    }

    ue_logger_set_level(ue_logger_manager_get_logger(), LOG_DEBUG);

    request_processor_thread = NULL;

    ue_byte_stream_clean_up(connection->received_message);
    received = ue_socket_receive_bytes_sync(connection->fd, connection->received_message, false, connection->tls);

    if (received == 0) {
        ue_logger_info("Client has disconnected.");
        if (instance->server->running) {
            ue_socket_client_connection_clean_up(connection);
        }
    }
    else if (received < 0 || received == ULLONG_MAX) {
        ue_stacktrace_push_msg("Error while receiving message")
        return false;
    }
    else {
        ue_byte_vector_clean_up(connection->tmp_message);
        ue_byte_split_append(connection->tmp_message, ue_byte_stream_get_data(connection->received_message), ue_byte_stream_get_size(connection->received_message),
            (unsigned char *)"|EOFEOFEOF", strlen("|EOFEOFEOF"));
        ue_byte_vector_append_vector(connection->tmp_message, connection->all_messages);
        _Pragma("GCC diagnostic push")
        _Pragma("GCC diagnostic ignored \"-Wpedantic\"")
            request_processor_thread = ue_thread_create((void *)process_request, (void *)connection);
        _Pragma("GCC diagnostic pop")
        ue_thread_join(request_processor_thread, NULL);
    }

    ue_safe_free(request_processor_thread)

    return true;
}

bool write_consumer(ue_socket_client_connection *connection) {
    size_t sent;
    int i;

    if (!instance->server->running) {
        return false;
    }

    ue_logger_set_level(ue_logger_manager_get_logger(), LOG_DEBUG);

    if (connection->message_to_send->position > 0) {
        if (ue_starts_with("MESSAGE", (char *)ue_byte_stream_get_data(connection->message_to_send))) {
            for (i = 0; i < instance->server->connections_number; i++) {
                if (ue_socket_client_connection_is_available(instance->server->connections[i])) {
                    continue;
                }
                if (instance->server->connections[i]->message_to_send->position == 0) {
                    instance->server->connections[i]->state = UNKNOWNECHO_CONNECTION_READ_STATE;
                    continue;
                }
                sent = ue_socket_send_data(instance->server->connections[i]->fd, ue_byte_stream_get_data(connection->message_to_send),
                    ue_byte_stream_get_size(connection->message_to_send), connection->tls);
                if (sent == 0) {
                    ue_logger_info("Client has disconnected.");
                    return true;
                }
                else if (sent < 0 || sent == ULLONG_MAX) {
                    ue_stacktrace_push_msg("Error while sending message")
                    ue_socket_client_connection_clean_up(instance->server->connections[i]);
                    return false;
                }
                else {
                    instance->server->connections[i]->state = UNKNOWNECHO_CONNECTION_READ_STATE;
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

    result = false;
    keystore = NULL;

    if (!ue_is_file_exists(KEYSTORE_PATH)) {

        if (!(keystore = ue_pkcs12_keystore_create_random("SERVER", "name"))) {
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

bool socket_server_manager_create(unsigned short int port) {
    ue_safe_alloc(instance, ue_socket_server_manager, 1)
    instance->server = NULL;
    instance->tls_session = NULL;

    if (!(instance->tls_session = ue_tls_session_create(KEYSTORE_PATH, "password", ue_tls_method_create_v1_server(), NULL))) {
        ue_stacktrace_push_msg("Failed to create TLS session");
        return false;
    }

    if (!(instance->server = ue_socket_server_create(port, read_consumer, write_consumer, instance->tls_session))) {
        ue_stacktrace_push_msg("Failed to start server on port %d", port);
        return false;
    }

    ue_logger_info("Server waiting on port %d", port);

    handle_signal(SIGINT, shutdown_server, 0);
    handle_signal(SIGPIPE, SIG_IGN, SA_RESTART);

    instance->mutex = ue_thread_mutex_create();
    instance->cond = ue_thread_cond_create();
    instance->processing_state = FREE_STATE;

    ue_socket_server_process_polling(instance->server);

    return true;
}

void ue_socket_server_manager_destroy() {
	if (instance) {
		ue_thread_mutex_destroy(instance->mutex);
	    ue_thread_cond_destroy(instance->cond);
        /* @todo fix double free of disconnected client */
	    ue_socket_server_destroy(instance->server);
	    ue_tls_session_destroy(instance->tls_session);
	    ue_safe_free(instance)
	}
}

int main() {
    if (!ue_init()) {
		printf("[ERROR] Failed to init LibUnknownEcho\n");
		exit(1);
	}

    ue_logger_set_level(ue_logger_manager_get_logger(), LOG_DEBUG);

    if (!socket_server_manager_create(5001)) {
        ue_stacktrace_push_msg("Failed to create socket server manager");
    }

    ue_socket_server_manager_destroy();

    if (ue_stacktrace_is_filled()) {
        ue_logger_error("Error(s) occurred with the following stacktrace(s) :");
        ue_stacktrace_print_all();
    }

    ue_uninit();

    return 0;
}
