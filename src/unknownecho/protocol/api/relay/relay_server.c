/*******************************************************************************
 * Copyright (C) 2018 by Charly Lamothe                                        *
 *                                                                             *
 * This file is part of LibUnknownEcho.                                        *
 *                                                                             *
 *   LibUnknownEcho is free software: you can redistribute it and/or modify    *
 *   it under the terms of the GNU General Public License as published by      *
 *   the Free Software Foundation, either version 3 of the License, or         *
 *   (at your option) any later version.                                       *
 *                                                                             *
 *   LibUnknownEcho is distributed in the hope that it will be useful,         *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of            *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the             *
 *   GNU General Public License for more details.                              *
 *                                                                             *
 *   You should have received a copy of the GNU General Public License         *
 *   along with LibUnknownEcho.  If not, see <http://www.gnu.org/licenses/>.   *
 *******************************************************************************/

#include <unknownecho/protocol/api/relay/relay_server.h>
#include <unknownecho/protocol/api/relay/relay_received_message_struct.h>
#include <unknownecho/protocol/api/relay/relay_received_message.h>
#include <unknownecho/protocol/api/relay/relay_message_decoder.h>
#include <unknownecho/protocol/api/relay/relay_message_encoder.h>
#include <unknownecho/protocol/api/relay/relay_client.h>
#include <unknownecho/protocol/api/relay/relay_step.h>
#include <unknownecho/protocol/api/relay/relay_step_struct.h>
#include <unknownecho/protocol/api/protocol_id.h>
#include <unknownecho/network/api/communication/communication.h>
#include <unknownecho/network/factory/communication_factory.h>
#include <ueum/ueum.h>
#include <uecm/uecm.h>
#include <ei/ei.h>

#include <limits.h>
#include <string.h>


ue_relay_server *global_relay_server = NULL;


static bool read_consumer(void *connection);

static bool write_consumer(void *connection);

static bool server_process_messages(void *connection);

static bool server_process_message(ueum_byte_stream *message, void *connection);

static void disconnect_client_from_server(void *connection);

static ue_relay_client *find_relay_client(ue_communication_metadata *our_communication_metadata,
    ue_communication_metadata *client_communication_metadata, uecm_crypto_metadata *our_crypto_metadata);

static ue_relay_client *create_relay_client(ue_communication_metadata *our_communication_metadata,
    ue_communication_metadata *target_communication_metadata, uecm_crypto_metadata *our_crypto_metadata);

static ue_relay_client *create_relay_client_from_connection(ue_communication_metadata *our_communication_metadata,
    ue_communication_metadata *target_communication_metadata, uecm_crypto_metadata *our_crypto_metadata,
    void *read_connection, void *write_connection);

static int process_client_establishing(ueum_byte_stream *message, void *connection);

ue_relay_server *ue_relay_server_create(ue_communication_metadata *communication_metadata, void *user_context,
    uecm_crypto_metadata *our_crypto_metadata, bool (*user_received_callback)(void *user_context, ueum_byte_stream *received_message)) {

    ue_relay_server *relay_server;
    void *server_parameters;

    /* Check if communication metadata objet is valid */
    if (!ue_communication_metadata_is_valid(communication_metadata)) {
        ei_stacktrace_push_msg("Specified communication metadata object is invalid");
        return NULL;
    }

    ei_check_parameter_or_return(our_crypto_metadata);

    relay_server = NULL;

    ueum_safe_alloc(relay_server, ue_relay_server, 1);
    relay_server->our_communication_metadata = communication_metadata;
    relay_server->communication_context = ue_communication_build_from_type(ue_communication_metadata_get_type(communication_metadata));
    relay_server->communication_server = NULL;
    //relay_server->server_thread = NULL;
    relay_server->user_received_callback = user_received_callback;
    relay_server->user_context = user_context;
    relay_server->signal_caught = false;
    relay_server->relay_clients = NULL;
    relay_server->relay_clients_number = 0;

    /**
     * Build server parameters from communication context or record an error if it's failed.
     * @warning at this point of the POC, the 4th optional parameter, the secure layer, isn't used.
     */
    if (!(server_parameters = ue_communication_build_server_parameters(relay_server->communication_context, 3,
        ue_communication_metadata_get_port(communication_metadata), read_consumer, write_consumer))) {

        ue_relay_server_destroy(relay_server);
        relay_server = NULL;
        ei_stacktrace_push_msg("Failed to build communication server parameters context");
        goto clean_up;
    }

    /* Finally, the server is created or it record an error if it's failed */
    if (!(relay_server->communication_server = ue_communication_server_create(relay_server->communication_context,
        server_parameters))) {

        ue_relay_server_destroy(relay_server);
        relay_server = NULL;
        ei_stacktrace_push_msg("Failed to start establisher server");
        goto clean_up;
    }

    relay_server->our_crypto_metadata = our_crypto_metadata;

    /**
     * @todo replace by a thread safe version
     */
    global_relay_server = relay_server;

clean_up:
    ueum_safe_free(server_parameters);
    return relay_server;
}

void ue_relay_server_destroy(ue_relay_server *relay_server) {
    int i;

    if (relay_server) {
        ue_communication_server_destroy(relay_server->communication_context, relay_server->communication_server);
        ue_communication_destroy(relay_server->communication_context);
        //if (!relay_server->signal_caught) {
            //ueum_safe_free(relay_server->server_thread);
        //}
        if (relay_server->relay_clients) {
            for (i = 0; i < relay_server->relay_clients_number; i++) {
                ue_relay_client_destroy(relay_server->relay_clients[i]);
            }
            ueum_safe_free(relay_server->relay_clients);
        }
        ueum_safe_free(relay_server);
    }
}

bool ue_relay_server_is_valid(ue_relay_server *relay_server) {
    if (!relay_server) {
        ei_stacktrace_push_msg("Specified relay server object is null");
        return false;
    }

    if (!ue_communication_context_is_valid(relay_server->communication_context)) {
        ei_stacktrace_push_msg("Communication context is invalid");
        return false;
    }

    if (relay_server->communication_context->communication_server_is_valid_impl &&
        !relay_server->communication_context->communication_server_is_valid_impl(relay_server->communication_server)) {
        ei_stacktrace_push_msg("Communication server implementation is invalid");
        return false;
    }

    return true;
}

bool ue_relay_server_start(ue_relay_server *relay_server) {
    /* Check if the relay server object is valid */
    if (!ue_relay_server_is_valid(relay_server)) {
        ei_stacktrace_push_msg("Specified relay server isn't valid");
        return false;
    }

    /* Get the server process impl of communication context or record an error if it failed */
    void (*communication_server_process_impl)(void *);
    communication_server_process_impl = NULL;
    if (!ue_communication_server_get_process_impl(relay_server->communication_context, &communication_server_process_impl)) {
        ei_stacktrace_push_msg("Failed to get server process impl");
        return false;
    }

_Pragma("GCC diagnostic push")
_Pragma("GCC diagnostic ignored \"-Wpedantic\"")
    relay_server->server_thread = ueum_thread_create(communication_server_process_impl, relay_server->communication_server);
_Pragma("GCC diagnostic pop")

    return true;
}

bool ue_relay_server_stop(ue_relay_server *relay_server) {
    /* Check if the relay server object is valid */
    if (!ue_relay_server_is_valid(relay_server)) {
        ei_stacktrace_push_msg("Specified relay server isn't valid");
        return false;
    }

    /**
     * Try to stop the server or record an error if it failed
     * @todo check if it will be better to log in place of record an error
     * in the stacktrace.
     */
    if (!ue_communication_server_stop(relay_server->communication_context, relay_server->communication_server)) {
        ei_stacktrace_push_msg("Failed to stop communication server");
        return false;
    }

    return true;
}

bool ue_relay_server_wait(ue_relay_server *relay_server) {
    /* Check if the relay server object is valid */
    if (!ue_relay_server_is_valid(relay_server)) {
        ei_stacktrace_push_msg("Specified relay server isn't valid");
        return false;
    }

    /* Wait the server thread finished */
    ueum_thread_join(relay_server->server_thread, NULL);

    return true;
}

ue_communication_context *ue_relay_server_get_communication_context(ue_relay_server *relay_server) {

    /* Check if the relay server object is valid */
    if (!ue_relay_server_is_valid(relay_server)) {
        ei_stacktrace_push_msg("Specified relay server isn't valid");
        return NULL;
    }

    return relay_server->communication_context;
}

void *ue_relay_server_get_communication_server(ue_relay_server *relay_server) {
    /* Check if the relay server object is valid */
    if (!ue_relay_server_is_valid(relay_server)) {
        ei_stacktrace_push_msg("Specified relay server isn't valid");
        return NULL;
    }

    return relay_server->communication_server;
}

void ue_relay_server_shutdown_signal_callback(int sig) {
    ei_logger_trace("Signal received %d", sig);
    ei_logger_info("Shuting down server...");
    global_relay_server->signal_caught = true;
    if (global_relay_server->communication_server) {
        ue_communication_server_stop(global_relay_server->communication_context, global_relay_server->communication_server);
    }

    /* @todo cancel the thread properly */
    exit(0);
}

static bool read_consumer(void *connection) {
    ue_communication_context *server_communication_context;
    size_t received;
    ueum_byte_stream *received_message;

    ei_check_parameter_or_return(connection);

    /**
     * @todo replace global relay_server variable by a thread storage one
     */
    server_communication_context = ue_relay_server_get_communication_context(global_relay_server);
    received = 0;

    received_message = ue_communication_client_connection_get_received_message(server_communication_context, connection);
    ueum_byte_stream_clean_up(received_message);

    received = ue_communication_receive_sync(server_communication_context, connection, received_message);
    if (received == 0) {
        ei_logger_info("read_consumer: client has disconnected.");
        //ue_communication_server_disconnect(server_communication_context, communication_server, connection);
        disconnect_client_from_server(connection);
    }
    else if (received == ULLONG_MAX) {
        ei_stacktrace_push_msg("Error while receiving message")
        ue_communication_client_connection_clean_up(server_communication_context, connection);
        return false;
    }
    else {
        ueum_byte_stream *message = ueum_byte_stream_create();
        ueum_byte_writer_append_bytes(message, ueum_byte_stream_get_data(received_message), ueum_byte_stream_get_size(received_message));
        ueum_queue_push_wait(ue_communication_client_connection_get_received_messages(global_relay_server->communication_context, connection), (void *)message);
        if (!server_process_messages(connection)) {
            ei_logger_error("Failed to proceed messages queue");
        }
    }

    ue_communication_client_connection_set_state(server_communication_context, connection, UNKNOWNECHO_COMMUNICATION_CONNECTION_WRITE_STATE);

    return true;
}

static bool write_consumer(void *connection) {
    ueum_byte_stream *current_message_to_send, *message_to_send;
    ueum_queue *messages_to_send;
    size_t sent;

    if (!global_relay_server->communication_server || !ue_communication_server_is_running(global_relay_server->communication_context,
        global_relay_server->communication_server)) {

        return false;
    }

    if (ue_communication_client_connection_is_available(global_relay_server->communication_context, connection)) {
        ei_logger_error("Client connection isn't available");
        return false;
    }

    current_message_to_send = NULL;
    message_to_send = ue_communication_client_connection_get_message_to_send(global_relay_server->communication_context, connection);
    messages_to_send = ue_communication_client_connection_get_messages_to_send(global_relay_server->communication_context, connection);

    while (!ueum_queue_empty(messages_to_send)) {
        current_message_to_send = ueum_queue_front_wait(messages_to_send);

        if (current_message_to_send->position > 0) {
            ueum_byte_stream_clean_up(message_to_send);
            ueum_byte_writer_append_bytes(message_to_send, ueum_byte_stream_get_data(current_message_to_send),
                ueum_byte_stream_get_size(current_message_to_send));
            sent = ue_communication_send_sync(global_relay_server->communication_context, connection, message_to_send);
            if (sent == 0) {
                ei_logger_warn("write_consumer: client has disconnected.");
                disconnect_client_from_server(connection);
            }
            else if (sent == ULLONG_MAX) {
                ei_logger_error("Error while sending message");
                ue_communication_client_connection_clean_up(global_relay_server->communication_context, connection);
            }
        } else {
            ei_logger_warn("Received message is empty.");
        }

        ueum_queue_pop(messages_to_send);
    }

    ue_communication_client_connection_set_state(global_relay_server->communication_context, connection, UNKNOWNECHO_COMMUNICATION_CONNECTION_READ_STATE);

    return true;
}

static bool server_process_messages(void *connection) {
    ueum_queue *received_messages;
    ueum_byte_stream *received_message;

    received_messages = ue_communication_client_connection_get_received_messages(global_relay_server->communication_context, connection);

    while (!ueum_queue_empty(received_messages)) {
        received_message = ueum_queue_front_wait(received_messages);
        if (!server_process_message(received_message, connection)) {
            if (!ei_stacktrace_is_filled()) {
                ei_logger_error("Current received message failed to proceed, but there's no stacktrace to record");
            } else {
                ei_logger_stacktrace("Failed to proceed current message");
                ei_stacktrace_clean_up();
            }
        }
        ueum_queue_pop(received_messages);
    }

    return true;

}

static bool server_process_message(ueum_byte_stream *message, void *connection) {
    bool result;
    ue_relay_received_message *received_message;
    ueum_queue *messages_to_send;
    ue_relay_client *relay_client;

    ei_check_parameter_or_return(connection);

    result = false;
    received_message = NULL;
    if (!(messages_to_send = ue_communication_client_connection_get_messages_to_send(global_relay_server->communication_context,
        connection))) {

        ei_stacktrace_push_msg("Failed to get messages to send queue from specified connection");
        return false;
    }

    /**
     * @brief Quick fix to get the client uid.
     * 
     * @todo get this in a more proper way
     */
    switch (process_client_establishing(message, connection)) {
        case 0:
            ei_logger_trace("Isn't the establish message id. Nothing to do");
            break;
        
        case 1:
            return true;
            break;

        case -1:
            ei_stacktrace_push_msg("Failed to establish client");
            goto clean_up;
            break;
    }

    if (!(received_message = ue_relay_message_decode(message, global_relay_server->our_crypto_metadata))) {
        ei_stacktrace_push_msg("Failed to decode message");
        goto clean_up;
    }

    if (received_message->protocol_id != UNKNOWNECHO_PROTOCOL_ID_RELAY) {
        ei_stacktrace_push_msg("Receive message with invalid protocol id: %d", received_message->protocol_id);
        goto clean_up;
    }

    /**
     * @todo build a reverse route to send an ACK msg
     */
    if (received_message->unsealed_payload) {
        ei_logger_trace("Send the unsealed message to the user callback");
        global_relay_server->user_received_callback(global_relay_server->user_context, received_message->payload);
    } else {
        ei_logger_debug("Before calling find_relay_client()");
        ei_logger_debug("received_message->next_step: %s", ue_communication_metadata_get_uid(
            ue_relay_step_get_target_communication_metadata(received_message->next_step)));

        if (!(relay_client = find_relay_client(global_relay_server->our_communication_metadata,
            ue_relay_step_get_target_communication_metadata(received_message->next_step),
            ue_relay_step_get_our_crypto_metadata(received_message->next_step)))) {

            ei_logger_trace("No relay client with this communication metadata exists. Creating a new relay client...");
            if (!(relay_client = create_relay_client(global_relay_server->our_communication_metadata,
                    ue_relay_step_get_target_communication_metadata(received_message->next_step),
                    ue_relay_step_get_our_crypto_metadata(received_message->next_step)))) {

                ei_stacktrace_push_msg("Failed to create new client to relay the received message");
                goto clean_up;
            }
            ei_logger_trace("New relay client created");
        } else {
            ei_logger_trace("Relay client already exists");
        }

        /**
         * @todo wait for an ACK message, or do it in low level of network module
         */
        ei_logger_trace("Relaying the message...");
        if (!ue_relay_client_relay_message(relay_client, received_message)) {
            ei_stacktrace_push_msg("Failed to relay the message");
            goto clean_up;
        }
        ei_logger_trace("It appears that the message has been relayed successfully");
    }

    result = true;

clean_up:
    ue_relay_received_message_destroy(received_message);
    return result;
}

static void disconnect_client_from_server(void *connection) {
    if (connection) {
        if (!global_relay_server) {
            ei_logger_error("Relay server ptr is null but it shouldn't");
            return;
        }
        if (!global_relay_server->communication_context) {
            ei_logger_error("Communication context ptr is null but it shouldn't");
            return;
        }
        if (!global_relay_server->communication_server) {
            ei_logger_error("Communication server ptr is null but if shouldn't");
            return;
        }
        ue_communication_server_disconnect(global_relay_server->communication_context, global_relay_server->communication_server, connection);
        ue_communication_client_connection_clean_up(global_relay_server->communication_context, connection);
    }
}

static ue_relay_client *find_relay_client(ue_communication_metadata *our_communication_metadata,
    ue_communication_metadata *client_communication_metadata, uecm_crypto_metadata *our_crypto_metadata) {

    int i, j;
    ue_communication_metadata *current_communication_metadata;
    void *current_connection, *read_connection, *write_connection;

    read_connection = NULL;
    write_connection = NULL;

    ei_logger_trace("Searching relay client with this communication metadata...");

    ei_logger_debug("Searching on %d already exists relay clients", global_relay_server->relay_clients_number);

    for (i = 0; i < global_relay_server->relay_clients_number; i++) {
        if (!(current_communication_metadata = ue_communication_client_connection_get_communication_metadata(
            ue_relay_client_get_communication_context(global_relay_server->relay_clients[i]),
            ue_relay_client_get_write_connection(global_relay_server->relay_clients[i])))) {

            ei_logger_warn("Failed to get communication metadata of client #%d from global_relay_server", i);
            continue;
        }

        ei_logger_debug("0 ue_communication_metadata_get_uid(current_communication_metadata): %s",
            ue_communication_metadata_get_uid(current_communication_metadata));

        ei_logger_debug("0 ue_communication_metadata_get_uid(client_communication_metadata): %s",
            ue_communication_metadata_get_uid(client_communication_metadata));

        /*if (ue_communication_metadata_equals(current_communication_metadata, client_communication_metadata)) {
            return global_relay_server->relay_clients[i];
        }*/

        if (strcmp(ue_communication_metadata_get_uid(current_communication_metadata),
            ue_communication_metadata_get_uid(client_communication_metadata)) == 0 &&
            current_communication_metadata->destination_type == client_communication_metadata->destination_type) {

            return global_relay_server->relay_clients[i];
        }
    }

    ei_logger_debug("Searching on maximum %d clients connected but not as relay for now", ue_communication_server_get_connections_number(
        global_relay_server->communication_context, global_relay_server->communication_server));

    for (i = 0; i < ue_communication_server_get_connections_number(
        global_relay_server->communication_context, global_relay_server->communication_server); i++) {
        
        if (!(current_connection = ue_communication_server_get_connection(
            global_relay_server->communication_context, global_relay_server->communication_server, i))) {

            ei_logger_warn("Failed to get connection #%d from communication server", i);
            continue;
        }

        if (!ue_communication_client_connection_is_established(global_relay_server->communication_context, current_connection)) {
            ei_logger_debug("Skipping unestablished connection");
            continue;
        }
        
        if (!(current_communication_metadata = ue_communication_client_connection_get_communication_metadata(
            global_relay_server->communication_context, current_connection))) {

            ei_logger_warn("Failed to get communication metadata of client %d from communication_server", i);
            continue;
        }

        /*if (ue_communication_metadata_equals(current_communication_metadata, client_communication_metadata)) {
            return create_relay_client_from_connection(client_communication_metadata, our_crypto_metadata,
                current_connection);
        }*/

        ei_logger_debug("ue_communication_metadata_get_uid(current_communication_metadata): %s",
            ue_communication_metadata_get_uid(current_communication_metadata));

        ei_logger_debug("ue_communication_metadata_get_uid(client_communication_metadata): %s",
            ue_communication_metadata_get_uid(client_communication_metadata));

        if (strcmp(ue_communication_metadata_get_uid(current_communication_metadata),
            ue_communication_metadata_get_uid(client_communication_metadata)) == 0) {

            if (ue_communication_client_connection_get_direction(global_relay_server->communication_context,
                current_connection) == UNKNOWNECHO_COMMUNICATION_CONNECTION_UNIDIRECTIONAL_READ) {
                read_connection = current_connection;
            } else {
                write_connection = current_connection;
            }

            return create_relay_client_from_connection(our_communication_metadata,
                client_communication_metadata, our_crypto_metadata, read_connection,
                write_connection);
        }
    }

    return NULL;
}

static ue_relay_client *create_relay_client(ue_communication_metadata *our_communication_metadata,
    ue_communication_metadata *target_communication_metadata, uecm_crypto_metadata *our_crypto_metadata) {

    ue_relay_client *relay_client;

    if (!(relay_client = ue_relay_client_create_as_relay(our_communication_metadata, target_communication_metadata, our_crypto_metadata))) {
        ei_stacktrace_push_msg("Failed to create new relay client from received message next step");
        return NULL;
    }

    if (!global_relay_server->relay_clients) {
        ueum_safe_alloc(global_relay_server->relay_clients, ue_relay_client *, 1);
    } else {
        ueum_safe_realloc(global_relay_server->relay_clients, ue_relay_client *, global_relay_server->relay_clients_number, 1);
    }
    global_relay_server->relay_clients[global_relay_server->relay_clients_number] = relay_client;
    global_relay_server->relay_clients_number++;

    return relay_client;
}

static ue_relay_client *create_relay_client_from_connection(ue_communication_metadata *our_communication_metadata,
    ue_communication_metadata *target_communication_metadata, uecm_crypto_metadata *our_crypto_metadata,
    void *read_connection, void *write_connection) {

    ue_relay_client *relay_client;

    if (!(relay_client = ue_relay_client_create_as_relay_from_connection(our_communication_metadata,
        target_communication_metadata, our_crypto_metadata, read_connection, write_consumer))) {

        ei_stacktrace_push_msg("Failed to create new relay client from received message next step");
        return NULL;
    }

    if (!global_relay_server->relay_clients) {
        ueum_safe_alloc(global_relay_server->relay_clients, ue_relay_client *, 1);
    } else {
        ueum_safe_realloc(global_relay_server->relay_clients, ue_relay_client *, global_relay_server->relay_clients_number, 1);
    }
    global_relay_server->relay_clients[global_relay_server->relay_clients_number] = relay_client;
    global_relay_server->relay_clients_number++;

    return relay_client;
}

static int process_client_establishing(ueum_byte_stream *message, void *connection) {
    ue_communication_metadata *communication_metadata;
    int uid_length, read_int;
    const char *uid;
    ueum_byte_stream *ack_message;
    int connection_direction;

    ei_check_parameter_or_return(message);
    ei_check_parameter_or_return(connection);

    /* Set the virtual cursor of the encoded message stream to the begining */
    ueum_byte_stream_set_position(message, 0);

    /* Check protocol id */
    ueum_byte_read_next_int(message, &read_int);
    if (!ue_protocol_id_is_valid(read_int)) {
        ei_stacktrace_push_msg("Specified protocol id '%d' is invalid", read_int);
        return -1;
    }
    ei_logger_trace("Protocol id: %d", read_int);

    /* Check message id */
    ueum_byte_read_next_int(message, &read_int);
    if (ue_relay_message_id_is_valid(read_int)) {
        if ((ue_relay_message_id)read_int != UNKNOWNECHO_RELAY_MESSAGE_ID_ESTABLISH) {
            return 0;
        }
    } else {
        ei_stacktrace_push_msg("Specified relay message id '%d' is invalid", read_int);
        return -1;
    }
    ei_logger_trace("Message id: %d", read_int);

    if (!(communication_metadata = ue_communication_client_connection_get_communication_metadata(
        global_relay_server->communication_context, connection))) {

        ei_stacktrace_push_msg("Failed to get communication metadata of this connection");
        return -1;
    }

    if (!ueum_byte_read_next_int(message, &uid_length)) {
        ei_stacktrace_push_msg("Failed to read uid length from received message");
        return -1;
    }

    if (!ueum_byte_read_next_int(message, &connection_direction)) {
        ei_stacktrace_push_msg("Failed to read connection direction from received message");
        return -1;
    }

    /**
     * @todo delegate the direction protocol setting inside the communication connection
     * and not the above protocol
     */
    ue_communication_client_connection_set_direction(global_relay_server->communication_context,
        connection, (ue_communication_connection_direction)connection_direction);

    if (!ueum_byte_read_next_string(message, &uid, (size_t)uid_length)) {
        ei_stacktrace_push_msg("Failed to read uid from received message");
        return -1;
    }

    if (!ue_communication_metadata_set_uid(communication_metadata, uid)) {
        ei_stacktrace_push_msg("Failed to set uid to communication metadata of this connection");
        return -1;
    }

    ack_message = ueum_byte_stream_create();
    ueum_byte_writer_append_string(ack_message, "ACK");

    if (!ue_communication_send_sync(global_relay_server->communication_context, connection, ack_message)) {
        ei_stacktrace_push_msg("Failed to send ack message in synchronous mode");
        ueum_byte_stream_destroy(ack_message);
        return -1;
    }

    ueum_byte_stream_destroy(ack_message);

    return 1;
}
