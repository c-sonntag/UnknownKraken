#include <unknownecho/init.h>
#include <unknownecho/network/api/socket/socket_server.h>
#include <unknownecho/network/api/socket/socket_client_connection.h>
#include <unknownecho/network/api/socket/socket.h>
#include <unknownecho/network/api/tls/tls_context.h>
#include <unknownecho/string/string_builder.h>
#include <unknownecho/string/string_utility.h>
#include <unknownecho/string/string_split.h>
#include <unknownecho/thread/thread_id_struct.h>
#include <unknownecho/thread/thread.h>
#include <unknownecho/thread/thread_mutex.h>
#include <unknownecho/thread/thread_cond.h>
#include <unknownecho/system/alloc.h>
#include <unknownecho/bool.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/model/manager/pgp_keystore_manager.h>
#include <unknownecho/model/manager/tls_keystore_manager.h>

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
	ue_pgp_keystore_manager *pgp_ks_manager;
	ue_tls_keystore_manager *tls_ks_manager;
} ue_socket_server_manager;

ue_socket_server_manager *instance = NULL;

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
    char *type, *data, *data2;
    bool result;
    int i;

    ue_logger_set_level(ue_logger_manager_get_logger(), LOG_DEBUG);

    connection = (ue_socket_client_connection *)parameter;
    result = false;

    ue_thread_mutex_lock(instance->mutex);
    while (instance->processing_state == WORKING_STATE) {
        ue_thread_cond_wait(instance->cond, instance->mutex);
    }
    ue_thread_mutex_unlock(instance->mutex);
    instance->processing_state = WORKING_STATE;

    for (i = 0; i < ue_string_vector_size(connection->all_messages); i++) {
        ue_string_vector_clean_up(connection->current_message);
        ue_string_split_append_one_delim(connection->current_message, ue_string_vector_get(connection->all_messages, i), "|");

        if (ue_string_vector_is_empty(connection->current_message)) {
            ue_logger_warn("Failed to split current message");
            continue;
        }

        if (ue_string_vector_size(connection->current_message) < 2) {
            ue_logger_warn("Specified message isn't formatted correctly");
            continue;
        }

        type = ue_string_vector_get(connection->current_message, 0);
        data = ue_string_vector_get(connection->current_message, 1);

        if (strcmp(type, "DISCONNECTION") == 0) {
            ue_logger_info("Client disconnection.");
            ue_socket_client_connection_clean_up(connection);
            result = true;
        } else if (strcmp(type, "SHUTDOWN") == 0) {
            ue_logger_info("Shutdown detected");
            instance->server->running = false;
            result = true;
        } else if (strcmp(type, "NICKNAME") == 0) {
            if (check_suggest_nickname(data)) {
                connection->nickname = ue_string_create_from((char *)data);
                ue_string_builder_clean_up(connection->message_to_send);
                if (!ue_string_builder_append(connection->message_to_send, "NICKNAME|TRUE", strlen("NICKNAME|TRUE"))) {
                    ue_logger_warn("Failed to create response of nickname-request (true)");;
                    result = false;
                    break;
                } else {
                    result = true;
                }
            }
            else {
                ue_string_builder_clean_up(connection->message_to_send);
                if (ue_string_builder_append(connection->message_to_send, "NICKNAME|FALSE", strlen("NICKNAME|FALSE"))) {
                    ue_logger_warn("Failed to create response of nickname-request (false)");
                    result = false;
                    break;
                } else {
                    result = true;
                }
            }
        } else if (strcmp(type, "MESSAGE") == 0) {
            /* Here data is the nickname of the sender and data2 the real message */
            data2 = ue_string_vector_get(connection->current_message, 2);
            ue_string_builder_clean_up(connection->message_to_send);
            ue_string_builder_append(connection->message_to_send, type, strlen(type));
            ue_string_builder_append(connection->message_to_send, "|", strlen("|"));
            ue_string_builder_append(connection->message_to_send, data, strlen(data));
            ue_string_builder_append(connection->message_to_send, "|", strlen("|"));
            ue_string_builder_append(connection->message_to_send, data2, strlen(data2));
            connection->state = UNKNOWNECHO_CONNECTION_WRITE_STATE;
            result = true;
        } else {
            ue_logger_warn("Received invalid data from client '%s'.", data);
        }
        ue_string_vector_remove(connection->all_messages, i);
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

    ue_string_builder_clean_up(connection->received_message);
    received = ue_socket_receive_string_sync(connection->fd, connection->received_message, false, connection->tls);

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
        ue_string_vector_clean_up(connection->tmp_message);
        ue_string_split_append(connection->tmp_message, ue_string_builder_get_data(connection->received_message), "|EOFEOFEOF");
        ue_string_vector_append_vector(connection->tmp_message, connection->all_messages);
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
        if (ue_starts_with("MESSAGE", ue_string_builder_get_data(connection->message_to_send))) {
            for (i = 0; i < instance->server->connections_number; i++) {
                if (ue_socket_client_connection_is_available(instance->server->connections[i])) {
                    continue;
                }
                if (instance->server->connections[i]->message_to_send->position == 0) {
                    instance->server->connections[i]->state = UNKNOWNECHO_CONNECTION_READ_STATE;
                    continue;
                }
                sent = ue_socket_send_string(instance->server->connections[i]->fd, ue_string_builder_get_data(connection->message_to_send), connection->tls);
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
            sent = ue_socket_send_string(connection->fd, ue_string_builder_get_data(connection->message_to_send), connection->tls);
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

bool ue_socket_server_manager_create_and_start(unsigned short int port) {
    ue_tls_method *method;

    ue_safe_alloc(instance, ue_socket_server_manager, 1)
    instance->server = NULL;
    instance->tls_ks_manager = NULL;
    instance->pgp_ks_manager = NULL;

    if (!(method = ue_tls_method_create_v1_server())) {
        ue_stacktrace_push_msg("Failed to create tls server method");
        return false;
    }

    //instance->tls_ks_manager = ue_tls_keystore_manager_init("res/tls2/ca.crt", "res/tls2/ssl_server.crt", "res/tls2/ssl_server.key", method, "passphraseserver", NULL);
    instance->tls_ks_manager = ue_tls_keystore_manager_init("res/tls3/ca.pem", "res/tls3/ssl_server.crt", "res/tls3/ssl_server.key", method, "", NULL);
    ue_tls_method_destroy(method);
    if (!instance->tls_ks_manager) {
        ue_stacktrace_push_msg("Failed to init tls keystore manager")
        return false;
    }

    if (!(instance->pgp_ks_manager = ue_pgp_keystore_manager_init("res/pem/c1_pgp_pub.pem", "res/pem/c1_pgp_priv.pem", "res/pem/server_pgp_pub.pem", NULL))) {
        ue_stacktrace_push_msg("Failed to init pgp keystore manager")
        return false;
    }

    if (!(instance->server = ue_socket_server_create(port, read_consumer, write_consumer, instance->tls_ks_manager))) {
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
	    ue_socket_server_destroy(instance->server);
	    ue_tls_keystore_manager_uninit(instance->tls_ks_manager);
	    ue_pgp_keystore_manager_uninit(instance->pgp_ks_manager);
	    ue_safe_free(instance)
	}
}

int main() {
    ue_init();

    ue_logger_set_level(ue_logger_manager_get_logger(), LOG_DEBUG);

    ue_socket_server_manager_create_and_start(5001);

    ue_socket_server_manager_destroy();

    if (ue_stacktrace_is_filled()) {
        ue_logger_error("Error(s) occurred with the following stacktrace(s) :");
        ue_stacktrace_print_all();
    }

    ue_uninit();

    return 0;
}
