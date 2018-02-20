#include <unknownecho/protocol/server_channel.h>
#include <unknownecho/system/alloc.h>
#include <unknownecho/thread/thread_id_struct.h>
#include <unknownecho/thread/thread.h>
#include <unknownecho/system/alloc.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/string/string_builder.h>
#include <unknownecho/string/string_split.h>
#include <unknownecho/string/string_utility.h>
#include <unknownecho/network/api/socket/socket.h>
#include <unknownecho/model/message/plain_message.h>
#include <unknownecho/model/message/cipher_message.h>
#include <unknownecho/model/message/decipher_message.h>

#include <limits.h>
#include <stddef.h>


static bool read_consumer(ue_socket_client_connection *connection);

static size_t send_message(int fd, ue_server_channel *server_channel, ue_socket_client_connection *connection, ue_pgp_keystore_manager *pgp_ks_manager, char *string);

static bool write_consumer(ue_socket_client_connection *connection);

static bool process_request(void *parameter);

static bool check_suggest_nickname(const char *nickname);


ue_server_channel *local_server_channel;


ue_server_channel *ue_server_channel_create(ue_relay_point *relay_point) {
    ue_server_channel *server_channel;

    ue_safe_alloc(server_channel, ue_server_channel, 1);
    server_channel->method = ue_tls_method_create_v1_server();
    server_channel->pgp_ks_manager = NULL;
    server_channel->tls_ks_manager = NULL;
    server_channel->server = NULL;
    server_channel->mutex = NULL;
    server_channel->cond = NULL;
    server_channel->processing_state = UNKNOWNECHO_SERVER_FREE_STATE;

    if (!(server_channel->mutex = ue_thread_mutex_create())) {
        ue_stacktrace_push_msg("Failed to init server_channel->mutex");
        ue_server_channel_destroy(server_channel);
        return NULL;
    }

    if (!(server_channel->cond = ue_thread_cond_create())) {
        ue_stacktrace_push_msg("Failed to init server_channel->cond");
        ue_server_channel_destroy(server_channel);
        return NULL;
    }

    if (!(server_channel->tls_ks_manager = ue_tls_keystore_manager_init("res/tls/ca.crt", "res/tls/ssl_server.crt", "res/tls/ssl_server.key", server_channel->method, "passphraseserver", NULL))) {
        ue_stacktrace_push_msg("Failed to init tls keystore manager");
        ue_server_channel_destroy(server_channel);
        return NULL;
    }

    if (!(server_channel->pgp_ks_manager = ue_pgp_keystore_manager_init("res/pem/server_pgp_pub.pem", "res/pem/server_pgp_priv.pem", "res/pem/server_pgp_pub.pem", NULL))) {
        ue_stacktrace_push_msg("Failed to init pgp keystore manager");
        ue_server_channel_destroy(server_channel);
        return NULL;
    }

    if (!(server_channel->server = ue_socket_server_create(relay_point->port, read_consumer, write_consumer, server_channel->tls_ks_manager))) {
        ue_stacktrace_push_msg("Failed to start server at port %d", relay_point->port);
        ue_server_channel_destroy(server_channel);
        return NULL;
    }

    ue_logger_info("Server configured on port %d", relay_point->port);

    local_server_channel = server_channel;

    return server_channel;
}

void ue_server_channel_destroy(ue_server_channel *server_channel) {
    if (server_channel) {
        ue_thread_mutex_destroy(server_channel->mutex);
	    ue_thread_cond_destroy(server_channel->cond);
	    ue_socket_server_destroy(server_channel->server);
	    ue_tls_keystore_manager_uninit(server_channel->tls_ks_manager);
	    ue_pgp_keystore_manager_uninit(server_channel->pgp_ks_manager);
        ue_tls_method_destroy(server_channel->method);
        ue_safe_free(server_channel);
    }
}

void ue_server_channel_start(ue_server_channel *server_channel) {
    if (!server_channel) {
        ue_logger_error("Specified server channel is null");
        return;
    }

    if (!server_channel->server) {
        ue_logger_error("Specified server is null");
        return;
    }

    ue_socket_server_process_polling(server_channel->server);
}

static bool read_consumer(ue_socket_client_connection *connection) {
    size_t received;
    ue_thread_id *request_processor_thread;
    ue_cipher_message *cmsg;
    ue_plain_message *pmsg;

    cmsg = NULL;
    pmsg = NULL;

    if (!local_server_channel->server->running) {
        return false;
    }

    ue_string_builder_clean_up(connection->received_message);
    //received = ue_socket_receive_string_sync(connection->fd, connection->received_message, false, connection->tls);
    received = ue_socket_receive_bytes_sync(connection->fd, connection->received_message_stream, false, connection->tls);
    request_processor_thread = NULL;

    if (received == 0) {
        ue_logger_info("Client has disconnected.");
        if (local_server_channel->server->running) {
            ue_socket_client_connection_clean_up(connection);
        }
    }
    else if (received < 0 || received == ULLONG_MAX) {
        ue_stacktrace_push_msg("Error while receiving message");
        return false;
    }
    else {
        if (!(cmsg = ue_data_to_cipher_message(ue_byte_stream_get_data(connection->received_message_stream), ue_byte_stream_get_size(connection->received_message_stream)))) {
            ue_stacktrace_push_msg("Failed to convert received data to cipher message");
            return false;
        }
        if (!(pmsg = ue_message_build_decrypted_as_server(local_server_channel->pgp_ks_manager, cmsg))) {
            ue_stacktrace_push_msg("Failed to decipher cmsg as server");
            ue_cipher_message_destroy(cmsg);
            return false;
        }
        ue_logger_trace("Message decipher as server. Destination nickname len : %ld", pmsg->destination_nickname_len);
        char *header = ue_plain_message_header_to_string(pmsg);
        ue_logger_debug("Header message : %s", header);
        ue_safe_free(header);
        ue_cipher_message_destroy(cmsg);
        ue_string_builder_append(connection->received_message, ue_string_create_from_bytes(pmsg->content, pmsg->content_len), pmsg->content_len);
        ue_plain_message_destroy(pmsg);

        ue_string_vector_clean_up(connection->tmp_message);
        ue_string_split_append(connection->tmp_message, ue_string_builder_get_data(connection->received_message), "EOFEOFEOF");
        ue_string_vector_append_vector(connection->tmp_message, connection->all_messages);
        _Pragma("GCC diagnostic push");
        _Pragma("GCC diagnostic ignored \"-Wpedantic\"");
            if (!(request_processor_thread = ue_thread_create((void *)process_request, (void *)connection))) {
                ue_stacktrace_push_msg("Failed to create process request thread");
                return false;
            }
        _Pragma("GCC diagnostic pop");
        ue_thread_join(request_processor_thread, NULL);
    }

    ue_safe_free(request_processor_thread);

    return true;
}

static size_t send_message(int fd, ue_server_channel *server_channel, ue_socket_client_connection *connection, ue_pgp_keystore_manager *pgp_ks_manager, char *string) {
    ue_plain_message *pmsg;
    ue_cipher_message *cmsg;
    unsigned char *encrypted_message;
    size_t encrypted_message_size, sent;

    pmsg = NULL;
    cmsg = NULL;
    encrypted_message = NULL;

    if (!(pmsg = ue_plain_message_create(server_channel->pgp_ks_manager, connection->nickname, "dest", string, "MSG"))) {
        ue_stacktrace_push_msg("Failed to create plain message");
        return -1;
    }
    if (!(cmsg = ue_message_build_encrypted_as_client(server_channel->pgp_ks_manager, pmsg))) {
        ue_stacktrace_push_msg("Failed encrypt plain message as client");
        ue_plain_message_destroy(pmsg);
        return -1;
    }
    ue_plain_message_destroy(pmsg);
    if (!(encrypted_message = ue_cipher_message_to_data(cmsg, &encrypted_message_size))) {
        ue_stacktrace_push_msg("Failed to convert cipher message to raw data");
        ue_cipher_message_destroy(cmsg);
        return -1;
    }
    ue_cipher_message_destroy(cmsg);
    sent = ue_socket_send_data(fd, encrypted_message, encrypted_message_size, connection->tls);
    ue_safe_free(encrypted_message);

    return sent;
}

static bool write_consumer(ue_socket_client_connection *connection) {
    size_t sent;
    int i;

    if (!local_server_channel->server->running) {
        return false;
    }

    if (connection->message_to_send->position > 0) {
        if (ue_starts_with("MESSAGE", ue_string_builder_get_data(connection->message_to_send))) {
            for (i = 0; i < local_server_channel->server->connections_number; i++) {
                if (ue_socket_client_connection_is_available(local_server_channel->server->connections[i])) {
                    continue;
                }
                if (local_server_channel->server->connections[i]->message_to_send->position == 0) {
                    local_server_channel->server->connections[i]->state = UNKNOWNECHO_CONNECTION_READ_STATE;
                    continue;
                }
                //sent = ue_socket_send_string(local_server_channel->server->connections[i]->fd, ue_string_builder_get_data(connection->message_to_send), connection->tls);
                sent = send_message(local_server_channel->server->connections[i]->fd, local_server_channel, local_server_channel->server->connections[i],
                    local_server_channel->pgp_ks_manager, ue_string_builder_get_data(connection->message_to_send));
                if (sent == 0) {
                    ue_logger_info("Client has disconnected.");
                    return true;
                }
                else if (sent < 0 || sent == ULLONG_MAX) {
                    ue_stacktrace_push_msg("Error while sending message");
                    ue_socket_client_connection_clean_up(local_server_channel->server->connections[i]);
                    return false;
                }
                else {
                    local_server_channel->server->connections[i]->state = UNKNOWNECHO_CONNECTION_READ_STATE;
                }
            }
        }
        else {
            //sent = ue_socket_send_string(connection->fd, ue_string_builder_get_data(connection->message_to_send), connection->tls);
            sent = send_message(connection->fd, local_server_channel, connection, local_server_channel->pgp_ks_manager, ue_string_builder_get_data(connection->message_to_send));
            if (sent == 0) {
                ue_logger_info("Client has disconnected.");
                ue_socket_client_connection_clean_up(connection);
                return true;
            }
            else if (sent < 0 || sent == ULLONG_MAX) {
                ue_stacktrace_push_msg("Error while sending message");
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

static bool process_request(void *parameter) {
    ue_socket_client_connection *connection;
    char *type, *data, *data2;
    bool result;
    int i;

    connection = (ue_socket_client_connection *)parameter;
    result = false;

    ue_thread_mutex_lock(local_server_channel->mutex);
    while (local_server_channel->processing_state == UNKNOWNECHO_SERVER_WORKING_STATE) {
        ue_thread_cond_wait(local_server_channel->cond, local_server_channel->mutex);
    }
    ue_thread_mutex_unlock(local_server_channel->mutex);

    local_server_channel->processing_state = UNKNOWNECHO_SERVER_WORKING_STATE;

    for (i = 0; i < ue_string_vector_size(connection->all_messages); i++) {
        ue_string_vector_clean_up(connection->current_message);
        ue_string_split_append(connection->current_message, ue_string_vector_get(connection->all_messages, i), "|");

        if (ue_string_vector_is_empty(connection->current_message)) {
            ue_stacktrace_push_msg("Failed to split current message");
            continue;
        }

        if (ue_string_vector_size(connection->current_message) < 2) {
            ue_stacktrace_push_msg("Specified message isn't formatted correctly");
            continue;
        }

        type = ue_string_vector_get(connection->current_message, 0);
        data = ue_string_vector_get(connection->current_message, 1);

        if (strcmp(type, "DISCONNECTION") == 0) {
            ue_logger_info("Client disconnection.");
            ue_socket_client_connection_clean_up(connection);
            result = true;
        } else if (strcmp(type, "SHUTDOWN") == 0) {
            local_server_channel->server->running = false;
            result = true;
        } else if (strcmp(type, "NICKNAME") == 0) {
            if (check_suggest_nickname(data)) {
                connection->nickname = ue_string_create_from((char *)data);
                ue_string_builder_clean_up(connection->message_to_send);
                if (!ue_string_builder_append(connection->message_to_send, "NICKNAME|TRUE", strlen("NICKNAME|TRUE"))) {
                    ue_stacktrace_push_msg("Failed to create response of nickname-request (true)");
                    return false;
                }
                result = true;
            }
            else {
                ue_string_builder_clean_up(connection->message_to_send);
                if (ue_string_builder_append(connection->message_to_send, "NICKNAME|FALSE", strlen("NICKNAME|FALSE"))) {
                    ue_stacktrace_push_msg("Failed to create response of nickname-request (false)");
                    return false;
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
        } else if (strcmp(type, "HANDSHAKE") == 0) {
            ue_logger_trace("Receive client handshake request");
            ue_logger_info("Building response...");
            ue_string_builder_clean_up(connection->message_to_send);
            ue_string_builder_append(connection->message_to_send, "HANDSHAKE_ACK", strlen("HANDSHAKE_ACK"));
            connection->state = UNKNOWNECHO_CONNECTION_WRITE_STATE;
            result = true;
        } else if (strcmp(type, "TERMINATE") == 0) {
            ue_logger_trace("Receive client terminate request");
            ue_logger_info("Building response...");
            ue_string_builder_clean_up(connection->message_to_send);
            ue_string_builder_append(connection->message_to_send, "TERMINATE_ACK", strlen("TERMINATE_ACK"));
            connection->state = UNKNOWNECHO_CONNECTION_WRITE_STATE;
            ue_logger_info("Client disconnection.");
            ue_socket_client_connection_clean_up(connection);
            result = true;
        } else {
            ue_stacktrace_push_msg("Received invalid data from client '%s'.", data);
        }
        ue_string_vector_remove(connection->all_messages, i);
    }

    local_server_channel->processing_state = UNKNOWNECHO_SERVER_FREE_STATE;

    return result;
}

static bool check_suggest_nickname(const char *nickname) {
    int i;

    if (!nickname) {
        return false;
    }

    for (i = 0; i < local_server_channel->server->connections_number; i++) {
        if (ue_socket_client_connection_is_available(local_server_channel->server->connections[i])) {
            continue;
        }

        if (local_server_channel->server->connections[i]->nickname && strcmp(local_server_channel->server->connections[i]->nickname, nickname) == 0) {
            return false;
        }
    }

    return true;
}
