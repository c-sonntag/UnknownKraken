#include <unknownecho/protocol/client_channel.h>
#include <unknownecho/system/alloc.h>
#include <unknownecho/time/sleep.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/network/api/socket/socket.h>
#include <unknownecho/network/api/socket/socket_client.h>
#include <unknownecho/network/api/socket/socket_client_connection.h>
#include <unknownecho/string/string_utility.h>
#include <unknownecho/string/string_split.h>
#include <unknownecho/byte/byte_writer.h>
#include <unknownecho/model/message/decipher_message.h>

#include <sys/socket.h>
#include <stddef.h>
#include <stdio.h>
#include <limits.h>


static bool send_message(ue_client_channel *client_channel);

static size_t receive_message(ue_client_channel *client_channel);

static size_t receive_message(ue_client_channel *client_channel);

static bool read_consumer(void *parameter);

static bool write_consumer(void *parameter);

static char *get_input(char *prefix);

static bool send_simple_request(ue_client_channel *client_channel, char *request);

static bool send_handshake_request(ue_client_channel *client_channel);

static bool send_terminate_request(ue_client_channel *client_channel);

static bool send_nickname_request(ue_client_channel *client_channel);


ue_client_channel *ue_client_channel_create(ue_relay_point *relay_point) {
    ue_client_channel *client_channel;
    int fd;

    ue_safe_alloc(client_channel, ue_client_channel, 1);
    client_channel->method = ue_tls_method_create_v1_client();
    client_channel->connection = NULL;
    client_channel->new_message = NULL;
    client_channel->running = false;
    client_channel->nickname = NULL;
    client_channel->read_thread = NULL;
    client_channel->write_thread = NULL;
    client_channel->pgp_ks_manager = NULL;
    client_channel->tls_ks_manager = NULL;
	client_channel->pmsg = ue_plain_message_create_empty();
	client_channel->cmsg = NULL;
    client_channel->communicating = false;

    fd = -1;

    if (!(client_channel->mutex = ue_thread_mutex_create())) {
        ue_stacktrace_push_msg("Failed to init client_channel->mutex");
        ue_client_channel_destroy(client_channel);
        return NULL;
    }

    if (!(client_channel->cond = ue_thread_cond_create())) {
        ue_stacktrace_push_msg("Failed to init client_channel->cond");
        ue_client_channel_destroy(client_channel);
        return NULL;
    }

    if (!(client_channel->tls_ks_manager = ue_tls_keystore_manager_init("res/tls/ca.crt", "res/tls/ssl_client.crt", "res/tls/ssl_client.key", client_channel->method, "passphraseclient", NULL))) {
        ue_stacktrace_push_msg("Failed to init tls keystore manager");
        ue_client_channel_destroy(client_channel);
        return NULL;
    }

    if (!(client_channel->pgp_ks_manager = ue_pgp_keystore_manager_init("res/pem/c2_pgp_pub.pem", "res/pem/c2_pgp_priv.pem", "res/pem/server_pgp_pub.pem", NULL))) {
        ue_stacktrace_push_msg("Failed to init pgp keystore manager");
        ue_client_channel_destroy(client_channel);
        return NULL;
    }

    if ((fd = ue_socket_open_tcp()) == -1) {
        ue_stacktrace_push_msg("Failed to create new TCP socket");
        ue_client_channel_destroy(client_channel);
        return NULL;
    }

    if (!(client_channel->connection = ue_socket_connect(fd, AF_INET, relay_point->host, relay_point->port, client_channel->tls_ks_manager))) {
        ue_stacktrace_push_msg("Failed to connect socket to server");
        ue_client_channel_destroy(client_channel);
        return NULL;
    }

    client_channel->running = true;
    client_channel->transmission_state = UNKNOWNECHO_CLIENT_WRITING_STATE;
    client_channel->new_message = ue_string_builder_create();

    return client_channel;
}

void ue_client_channel_destroy(ue_client_channel *client_channel) {
    if (client_channel) {
        ue_thread_mutex_destroy(client_channel->mutex);
	    ue_thread_cond_destroy(client_channel->cond);
        ue_safe_free(client_channel->read_thread);
        ue_safe_free(client_channel->write_thread);
	    ue_tls_keystore_manager_uninit(client_channel->tls_ks_manager);
	    ue_pgp_keystore_manager_uninit(client_channel->pgp_ks_manager);
        ue_tls_method_destroy(client_channel->method);
        ue_socket_client_connection_destroy(client_channel->connection);
        ue_safe_free(client_channel->nickname);
        ue_string_builder_destroy(client_channel->new_message);
        ue_plain_message_destroy(client_channel->pmsg);
        ue_cipher_message_destroy(client_channel->cmsg);
        ue_safe_free(client_channel);
    }
}

bool ue_client_channel_start(ue_client_channel *client_channel) {
    client_channel->transmission_state = UNKNOWNECHO_CLIENT_WRITING_STATE;

    _Pragma("GCC diagnostic push");
    _Pragma("GCC diagnostic ignored \"-Wpedantic\"");
        client_channel->read_thread = ue_thread_create((void *)read_consumer, (void *)client_channel);
        client_channel->write_thread = ue_thread_create((void *)write_consumer, (void *)client_channel);
    _Pragma("GCC diagnostic pop");

    return client_channel->read_thread && client_channel->write_thread;
}

void ue_client_channel_wait(ue_client_channel *client_channel) {
    ue_thread_join(client_channel->read_thread, NULL);
    ue_thread_join(client_channel->write_thread, NULL);
}

static bool send_message(ue_client_channel *client_channel) {
	size_t sent, encrypted_message_size;
    unsigned char *encrypted_message;

	if (!ue_thread_mutex_lock(client_channel->mutex) && client_channel->running) {
        ue_stacktrace_push_msg("Failed to lock mutex");
    }

    encrypted_message = NULL;

	client_channel->transmission_state = UNKNOWNECHO_CLIENT_WRITING_STATE;

    //sent = ue_socket_send_string(client_channel->connection->fd, ue_string_builder_get_data(client_channel->connection->message_to_send), client_channel->connection->tls);
    if (!ue_plain_message_fill(client_channel->pmsg, client_channel->pgp_ks_manager, "dest", client_channel->nickname, ue_string_builder_get_data(client_channel->connection->message_to_send), "MSG")) {
        ue_stacktrace_push_msg("Failed to fill plain message");
        return false;
    }
    ue_logger_debug("Plain message filled :");
    ue_plain_message_print(client_channel->pmsg);
    if (!(client_channel->cmsg = ue_message_build_encrypted_as_client(client_channel->pgp_ks_manager, client_channel->pmsg))) {
        ue_stacktrace_push_msg("Failed to cipher plain message as client");
        return false;
    }
    if (!(encrypted_message = ue_cipher_message_to_data(client_channel->cmsg, &encrypted_message_size))) {
        ue_stacktrace_push_msg("Failed to convert cipher message to raw data");
        ue_cipher_message_destroy(client_channel->cmsg);
        return false;
    }
    ue_cipher_message_destroy(client_channel->cmsg);
    sent = ue_socket_send_data(client_channel->connection->fd, encrypted_message, encrypted_message_size, client_channel->connection->tls);
    ue_safe_free(encrypted_message);

	client_channel->transmission_state = UNKNOWNECHO_CLIENT_READING_STATE;

	if (!ue_thread_cond_signal(client_channel->cond) && client_channel->running) {
        ue_logger_warn("Failed to signal thread condition");
    }
	if (!ue_thread_mutex_unlock(client_channel->mutex) && client_channel->running) {
        ue_logger_warn("Failed to unlock mutex");
    }

	if (sent < 0 || sent == ULLONG_MAX) {
		ue_logger_info("Connection is interrupted.");
		ue_stacktrace_push_msg("Failed to send message to server");
		client_channel->running = false;
		return false;
	}

	return true;
}

static size_t receive_message(ue_client_channel *client_channel) {
	size_t received;
    ue_plain_message *pmsg;

    pmsg = NULL;

    if (!ue_thread_mutex_lock(client_channel->mutex) && client_channel->running) {
        ue_logger_warn("Failed to lock mutex");
    }
    while (client_channel->transmission_state == UNKNOWNECHO_CLIENT_WRITING_STATE) {
        if (!ue_thread_cond_wait(client_channel->cond, client_channel->mutex) && client_channel->running) {
            ue_logger_warn("Failed to wait thread condition");
        }
    }
    if (!ue_thread_mutex_unlock(client_channel->mutex) && client_channel->running) {
        ue_logger_warn("Failed to unlock mutex");
    }
    ue_string_builder_clean_up(client_channel->connection->received_message);
    //received = ue_socket_receive_string_sync(client_channel->connection->fd, client_channel->connection->received_message, false, client_channel->connection->tls);
    ue_byte_stream_clean_up(client_channel->connection->received_message_stream);
    received = ue_socket_receive_bytes_sync(client_channel->connection->fd, client_channel->connection->received_message_stream, false, client_channel->connection->tls);
    if (received > 0) {
        client_channel->cmsg = ue_data_to_cipher_message(ue_byte_stream_get_data(client_channel->connection->received_message_stream), ue_byte_stream_get_size(client_channel->connection->received_message_stream));
        pmsg = ue_message_build_decrypted_as_client(client_channel->pgp_ks_manager, client_channel->cmsg);
        ue_cipher_message_destroy(client_channel->cmsg);
        ue_string_builder_append(client_channel->connection->received_message, ue_string_create_from_bytes(pmsg->content, pmsg->content_len), pmsg->content_len);
        ue_plain_message_destroy(pmsg);
    }

    return received;
}

static bool read_consumer(void *parameter) {
	size_t received;
	char *type, *data, *data2;
	bool result;
    ue_client_channel *client_channel;
	ue_socket_client_connection *connection;

	result = true;
	client_channel = (ue_client_channel *)parameter;
    connection = client_channel->connection;

	while (client_channel->running) {
		received = receive_message(client_channel);

		if (received == 0) {
			ue_logger_warn("Connection is interrupted. Stopping consumer...");
			client_channel->running = false;
			result = false;
		}
		else if (received < 0 || received == ULLONG_MAX) {
			ue_stacktrace_push_msg("Failed to send client input to server");
			client_channel->running = false;
			result = false;
		}
		else {
			ue_string_vector_clean_up(connection->split_message);
			ue_string_split_append(connection->split_message, ue_string_builder_get_data(connection->received_message), "|");
			type = ue_string_vector_get(connection->split_message, 0);
			data = ue_string_vector_get(connection->split_message, 1);

			if (strcmp(type, "ALREADY_CONNECTED") == 0) {
				ue_logger_warn("Already connected");
				client_channel->running = false;
				result = false;
			}
			else if (strcmp(type, "NICKNAME") == 0) {
				if (strcmp(data, "FALSE") == 0) {
					ue_logger_info("This nickname is already in use.");
					client_channel->running = false;
					result = false;
				}
				else if (strcmp(data, "TRUE") != 0) {
					ue_stacktrace_push_msg("Response of nickname request is incomprehensible");
					client_channel->running = false;
					result = false;
				}
			}
			else if (strcmp(type, "MESSAGE") == 0) {
				/* Here data is the nickname of the sender and data2 the real message */
				data2 = ue_string_vector_get(connection->split_message, 2);
				ue_string_builder_clean_up(client_channel->new_message);
				ue_string_builder_append(client_channel->new_message, data, strlen(data));
				ue_string_builder_append(client_channel->new_message, ": ", strlen(": "));
				ue_string_builder_append(client_channel->new_message, data2, strlen(data2));
				ue_string_builder_append(client_channel->new_message, "\n", strlen("\n"));
                /*if (!write(client_channel->fds[1], ue_string_builder_get_data(client_channel->new_message), strlen(ue_string_builder_get_data(client_channel->new_message)))) {
                    ue_stacktrace_push_msg("Failed to write the message on console");
                    return false;
                }*/
                /* @TODO send data to view */
                printf("[ECHO] %s\n", ue_string_builder_get_data(client_channel->new_message));
			}
            else if (strcmp(type, "HANDSHAKE_ACK") == 0) {
                /* @TODO record that */
                ue_logger_trace("Handshake ack received");
                client_channel->communicating = true;
            }
            else if (strcmp(type, "TERMINATE_ACK") == 0) {
                /* @TODO record that */
                ue_logger_trace("Terminate ack received");
                ue_logger_trace("Stopping connection...");
                client_channel->running = false;
            }
			else {
				ue_logger_warn("Received invalid data from server '%s'.", type);
			}
		}
	}

	return result;
}

static bool write_consumer(void *parameter) {
	char *input;
	bool result;
    ue_client_channel *client_channel;
	ue_socket_client_connection *connection;

	result = true;
	client_channel = (ue_client_channel *)parameter;
    connection = client_channel->connection;

    /* @TODO Replace by getting the nickname before that */
    if (!(client_channel->nickname = get_input("Nickname : "))) {
        ue_stacktrace_push_msg("Specified nickname isn't valid");
        return false;
    }

    if (!send_nickname_request(client_channel)) {
        ue_stacktrace_push_msg("Failed to send nickname request");
        return false;
    }

    if (!send_handshake_request(client_channel)) {
        ue_stacktrace_push_msg("Failed to send handshake request");
        return false;
    }

	while (client_channel->running) {
        /* @TODO Replace by waiting a callback in view */
		input = get_input(">");

		if (!input) {
            ue_logger_warn("Invalid user input");
			continue;
		}

        if (!client_channel->communicating) {
            ue_logger_warn("Cannot send message until the server ack the handshake request");
            continue;
        }

		ue_string_builder_clean_up(connection->message_to_send);

		if (strcmp(input, "-q") == 0) {
			/*ue_string_builder_append(connection->message_to_send, "DISCONNECTION|NOW", strlen("DISCONNECTION|NOW"));
			ue_string_builder_append(connection->message_to_send, "EOFEOFEOF", strlen("EOFEOFEOF"));
			result = send_message(client_channel);*/
            ue_logger_info("Processing terminate request...");
            result = send_terminate_request(client_channel);
            if (result) {
                ue_logger_info("Terminate request process done successfully");
            } else {
                ue_logger_error("Failed to process terminate request");
            }
            ue_logger_info("Waiting terminate ack to stop connection...");
			//client_channel->running = false;
		}
        /* @TODO Remove or keep for test purpose ? */
		else if (strcmp(input, "-s") == 0) {
			ue_string_builder_append(connection->message_to_send, "SHUTDOWN|NOW", strlen("SHUTDOWN|NOW"));
			ue_string_builder_append(connection->message_to_send, "EOFEOFEOF", strlen("EOFEOFEOF"));
			result = send_message(client_channel);
			client_channel->running = false;
		}
		else {
			ue_string_builder_append(connection->message_to_send, "MESSAGE|", strlen("MESSAGE|"));
			ue_string_builder_append(connection->message_to_send, client_channel->nickname, strlen(client_channel->nickname));
			ue_string_builder_append(connection->message_to_send, "|", strlen("|"));
			ue_string_builder_append(connection->message_to_send, input, strlen(input));
			ue_string_builder_append(connection->message_to_send, "EOFEOFEOF", strlen("EOFEOFEOF"));
			result = send_message(client_channel);
		}

		ue_safe_free(input);
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

static bool send_simple_request(ue_client_channel *client_channel, char *request) {
    ue_socket_client_connection *connection;

    connection = client_channel->connection;

	ue_string_builder_clean_up(connection->message_to_send);
    ue_string_builder_append(connection->message_to_send, request, strlen(request));
	ue_string_builder_append(connection->message_to_send, "|", strlen("|"));
	ue_string_builder_append(connection->message_to_send, client_channel->nickname, strlen(client_channel->nickname));

    if (!send_message(client_channel)) {
        ue_stacktrace_push_msg("Failed to send '%s' request", request);
        return false;
    }

	return true;
}

static bool send_handshake_request(ue_client_channel *client_channel) {
    return send_simple_request(client_channel, "HANDSHAKE");
}

static bool send_terminate_request(ue_client_channel *client_channel) {
    return send_simple_request(client_channel, "TERMINATE");
}

static bool send_nickname_request(ue_client_channel *client_channel) {
    return send_simple_request(client_channel, "NICKNAME");
}
