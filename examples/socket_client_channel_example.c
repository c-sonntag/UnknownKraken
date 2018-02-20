#include <unknownecho/init.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/bool.h>
#include <unknownecho/system/alloc.h>
#include <unknownecho/network/api/socket/socket_client_connection.h>
#include <unknownecho/network/api/socket/socket.h>
#include <unknownecho/network/api/socket/socket_client.h>
#include <unknownecho/network/api/tls/tls_method.h>
#include <unknownecho/string/string_builder.h>
#include <unknownecho/string/string_utility.h>
#include <unknownecho/string/string_split.h>
#include <unknownecho/thread/thread.h>
#include <unknownecho/thread/thread_id_struct.h>
#include <unknownecho/thread/thread_mutex.h>
#include <unknownecho/thread/thread_cond.h>
#include <unknownecho/model/manager/pgp_keystore_manager.h>
#include <unknownecho/model/manager/tls_keystore_manager.h>

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
	ue_pgp_keystore_manager *pgp_ks_manager;
	ue_tls_keystore_manager *tls_ks_manager;
	ue_socket_client_connection *connection;
	ue_thread_id *read_thread, *write_thread;
	ue_thread_mutex *mutex;
	ue_thread_cond *cond;
	data_transmission_state transmission_state;
	bool running;
	int fds[2];
	ue_string_builder *new_message;
    ue_tls_method *method;
	int channel_id;
} socket_client_manager;

socket_client_manager *instance = NULL;

#if defined(WIN32)
	#include <windows.h>
#elif defined(__UNIX__)
	#include <unistd.h>
#endif


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
    ue_string_builder_clean_up(connection->received_message);
    received = ue_socket_receive_string_sync(connection->fd, connection->received_message, false, connection->tls);

    return received;
}

bool read_consumer(void *parameter) {
	size_t received;
	char *type, *data, *data2;
	bool result;
	ue_socket_client_connection *connection;

	result = true;
	connection = (ue_socket_client_connection *)parameter;

	ue_logger_set_level(ue_logger_manager_get_logger(), LOG_DEBUG);

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
			ue_string_vector_clean_up(connection->split_message);
			ue_string_split_append_one_delim(connection->split_message, ue_string_builder_get_data(connection->received_message), "|");
			type = ue_string_vector_get(connection->split_message, 0);
			data = ue_string_vector_get(connection->split_message, 1);

			if (strcmp(type, "ALREADY_CONNECTED") == 0) {
				ue_logger_warn("Already connected");
				instance->running = false;
				result = false;
			}
			else if (strcmp(type, "NICKNAME") == 0) {
				if (strcmp(data, "FALSE") == 0) {
					ue_logger_info("This nickname is already in use.");
					instance->running = false;
					result = false;
				}
				else if (strcmp(data, "TRUE") != 0) {
					ue_logger_warn("Response of nickname request is incomprehensible");
					instance->running = false;
					result = false;
				}
			}
			else if (strcmp(type, "CHANNEL_CONNECTION") == 0) {
				if (strcmp(data, "FALSE") == 0) {
					ue_logger_info("This channel is already in use or cannot be use right now.");
					instance->running = false;
					result = false;
				}
				else if (strcmp(data, "TRUE") != 0) {
					ue_logger_warn("Response of channel connection request is incomprehensible");
					result = false;
				} else {
					data2 = ue_string_vector_get(connection->split_message, 2);
					if (!ue_string_to_int(data2, &instance->channel_id, 10)) {
						ue_logger_warn("Failed to convert channel id from string to int");
						result = false;
					} else {
						ue_logger_info("Connection with channel id %d correctly establish", instance->channel_id);
					}
				}
			}
			else if (strcmp(type, "MESSAGE") == 0) {
				/* Here data is the nickname of the sender and data2 the real message */
				data2 = ue_string_vector_get(connection->split_message, 2);
				ue_string_builder_clean_up(instance->new_message);
				ue_string_builder_append(instance->new_message, data, strlen(data));
				ue_string_builder_append(instance->new_message, ": ", strlen(": "));
				ue_string_builder_append(instance->new_message, data2, strlen(data2));
				ue_string_builder_append(instance->new_message, "\n", strlen("\n"));
                if (!write(instance->fds[1], ue_string_builder_get_data(instance->new_message), strlen(ue_string_builder_get_data(instance->new_message)))) {
                    ue_logger_warn("Failed to write the message on console");
                    return false;
                }
			}
			else {
				ue_logger_warn("Received invalid data from server '%s'.", data);
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
	sent = ue_socket_send_string(connection->fd, ue_string_builder_get_data(connection->message_to_send), connection->tls);
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
	ue_string_builder_clean_up(connection->message_to_send);
	ue_string_builder_append_variadic(connection->message_to_send, "CHANNEL_ID:%d|", instance->channel_id);
	ue_string_builder_append(connection->message_to_send, "NICKNAME|", strlen("NICKNAME|"));
	ue_string_builder_append(connection->message_to_send, instance->nickname, strlen(instance->nickname));

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
		ue_string_builder_clean_up(connection->message_to_send);
		ue_string_builder_append_variadic(connection->message_to_send, "CHANNEL_ID:%d|", instance->channel_id);

		if (strcmp(input, "-q") == 0) {
			ue_string_builder_append(connection->message_to_send, "DISCONNECTION|NOW", strlen("DISCONNECTION|NOW"));
			ue_string_builder_append(connection->message_to_send, "|EOFEOFEOF", strlen("|EOFEOFEOF"));
			result = send_message(connection);
			instance->running = false;
		}
		else if (strcmp(input, "-s") == 0) {
			ue_string_builder_append(connection->message_to_send, "SHUTDOWN|NOW", strlen("SHUTDOWN|NOW"));
			ue_string_builder_append(connection->message_to_send, "|EOFEOFEOF", strlen("|EOFEOFEOF"));
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
				ue_string_builder_append(connection->message_to_send, "CHANNEL_CONNECTION|", strlen("CHANNEL_CONNECTION|"));
				ue_string_builder_append(connection->message_to_send, input + strlen("@channel_connection") + 1, strlen(input + strlen("@channel_connection") + 1));
				ue_string_builder_append(connection->message_to_send, "|EOFEOFEOF", strlen("|EOFEOFEOF"));
				result = send_message(connection);
				if (!result) {
					ue_logger_warn("Failed to send channel connection request");
				}
			}
		}
		else {
			if (instance->channel_id >= 0) {
				ue_string_builder_append(connection->message_to_send, "MESSAGE|", strlen("MESSAGE|"));
				ue_string_builder_append(connection->message_to_send, instance->nickname, strlen(instance->nickname));
				ue_string_builder_append(connection->message_to_send, "|", strlen("|"));
				ue_string_builder_append(connection->message_to_send, input, strlen(input));
				ue_string_builder_append(connection->message_to_send, "|EOFEOFEOF", strlen("|EOFEOFEOF"));
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

bool socket_client_manager_create_and_start(const char *host, unsigned short int port) {
	ue_safe_alloc(instance, socket_client_manager, 1);
    instance->fd = -1;
    instance->connection = NULL;
    instance->new_message = NULL;
    instance->running = false;
    instance->nickname = NULL;
    instance->read_thread = NULL;
    instance->write_thread = NULL;
    instance->pgp_ks_manager = NULL;
    instance->tls_ks_manager = NULL;
    instance->method = ue_tls_method_create_v1_client();
	instance->channel_id = -1;

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
            goto end;
        }

        if (!(instance->cond = ue_thread_cond_create())) {
            ue_stacktrace_push_msg("Failed to init instance->cond");
            goto end;
        }

	    handle_signal(SIGINT, shutdown_client, 0);
	    handle_signal(SIGPIPE, SIG_IGN, SA_RESTART);

        //if (!(instance->tls_ks_manager = ue_tls_keystore_manager_init("res/tls2/ca.crt", "res/tls2/ssl_client.crt", "res/tls2/ssl_client.key", instance->method, "passphraseclient", NULL))) {
		/*if (!(instance->tls_ks_manager = ue_tls_keystore_manager_init("res/tls3/ca.pem", "res/tls3/ssl_client1.crt", "res/tls3/ssl_client1.key", instance->method, "passphraseclient", NULL))) {
            ue_stacktrace_push_msg("Failed to init tls keystore manager");
            goto end;
        }*/

	    if (!(instance->pgp_ks_manager = ue_pgp_keystore_manager_init("res/pem/c2_pgp_pub.pem", "res/pem/c2_pgp_priv.pem", "res/pem/server_pgp_pub.pem", NULL))) {
            ue_stacktrace_push_msg("Failed to init pgp keystore manager");
            goto end;
        }

	    instance->fd = ue_socket_open_tcp();

        if (!(instance->connection = ue_socket_connect(instance->fd, AF_INET, host, port, instance->tls_ks_manager))) {
            ue_stacktrace_push_msg("Failed to connect socket to server");
            goto end;
        }

		instance->running = true;
		instance->transmission_state = WRITING_STATE;
		instance->new_message = ue_string_builder_create();

	    _Pragma("GCC diagnostic push")
	    _Pragma("GCC diagnostic ignored \"-Wpedantic\"")
			instance->read_thread = ue_thread_create((void *)read_consumer, (void *)instance->connection);
			instance->write_thread = ue_thread_create((void *)write_consumer, (void *)instance->connection);
	    _Pragma("GCC diagnostic pop")

	    ue_thread_join(instance->read_thread, NULL);
	    ue_thread_join(instance->write_thread, NULL);
    }

    return true;

end:
	socket_client_manager_destroy();
    return false;
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
	if (instance->tls_ks_manager) {
		ue_tls_keystore_manager_uninit(instance->tls_ks_manager);
	}
	if (instance->pgp_ks_manager) {
		ue_pgp_keystore_manager_uninit(instance->pgp_ks_manager);
	}
	close(instance->fds[1]);
	ue_string_builder_destroy(instance->new_message);
	ue_safe_str_free(instance->nickname)
	if (instance->connection) {
		ue_socket_client_connection_destroy(instance->connection);
	}
	else {
		ue_socket_close(instance->fd);
	}
    ue_tls_method_destroy(instance->method);
	ue_safe_free(instance)
}

int main() {
    ue_init();

	ue_logger_set_level(ue_logger_manager_get_logger(), LOG_DEBUG);

    socket_client_manager_create_and_start("127.0.0.1", 5001);

    socket_client_manager_destroy();

    if (ue_stacktrace_is_filled()) {
        ue_logger_error("An error occurred with the following stacktrace :");
        ue_stacktrace_print_all();
    }

    ue_uninit();

    return 0;
}
