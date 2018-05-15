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
#include <unknownecho/alloc.h>
#include <unknownecho/errorHandling/check_parameter.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/thread/thread.h>
#include <unknownecho/byte/byte_stream.h>
#include <unknownecho/byte/byte_writer.h>
#include <unknownecho/container/queue.h>

#include <limits.h>


ue_relay_server *global_relay_server = NULL;


static bool read_consumer(void *connection);

static bool write_consumer(void *connection);

static bool server_process_messages(void *connection);

static bool server_process_message(ue_byte_stream *message, void *connection);

static void disconnect_client_from_server(void *connection);

static ue_relay_client *find_relay_client(ue_communication_metadata *client_communication_metadata);

static ue_relay_client *create_relay_client(ue_communication_metadata *target_communication_metadata,
    ue_crypto_metadata *our_crypto_metadata);


ue_relay_server *ue_relay_server_create(ue_communication_metadata *communication_metadata, void *user_context,
    ue_crypto_metadata *our_crypto_metadata, bool (*user_received_callback)(void *user_context, ue_byte_stream *received_message)) {

    ue_relay_server *relay_server;
    void *server_parameters;

    /* Check if communication metadata objet is valid */
    if (!ue_communication_metadata_is_valid(communication_metadata)) {
        ue_stacktrace_push_msg("Specified communication metadata object is invalid");
        return NULL;
    }

    ue_check_parameter_or_return(our_crypto_metadata);

    ue_safe_alloc(relay_server, ue_relay_server, 1);
    relay_server->communication_context = ue_communication_build_from_type(ue_communication_metadata_get_type(communication_metadata));
    relay_server->communication_server = NULL;
    relay_server->server_thread = NULL;
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
        ue_stacktrace_push_msg("Failed to build communication server parameters context");
        goto clean_up;
    }

    /* Finally, the server is created or it record an error if it's failed */
    if (!(relay_server->communication_server = ue_communication_server_create(relay_server->communication_context,
        server_parameters))) {

        ue_relay_server_destroy(relay_server);
        relay_server = NULL;
        ue_stacktrace_push_msg("Failed to start establisher server");
        goto clean_up;
    }

    relay_server->our_crypto_metadata = our_crypto_metadata;

    /**
     * @todo replace by a thread safe version
     */
    global_relay_server = relay_server;

clean_up:
    ue_safe_free(server_parameters);
    return relay_server;
}

void ue_relay_server_destroy(ue_relay_server *relay_server) {
    int i;

    if (relay_server) {
        ue_communication_server_destroy(relay_server->communication_context, relay_server->communication_server);
        ue_communication_destroy(relay_server->communication_context);
        if (!relay_server->signal_caught) {
            ue_safe_free(relay_server->server_thread);
        }
        if (relay_server->relay_clients) {
            for (i = 0; i < relay_server->relay_clients_number; i++) {
                ue_relay_client_destroy(relay_server->relay_clients[i]);
            }
            ue_safe_free(relay_server->relay_clients);
        }
        ue_safe_free(relay_server);
    }
}

bool ue_relay_server_is_valid(ue_relay_server *relay_server) {
    if (!relay_server) {
        ue_stacktrace_push_msg("Specified relay server object is null");
        return false;
    }

    if (!ue_communication_context_is_valid(relay_server->communication_context)) {
        ue_stacktrace_push_msg("Communication context is invalid");
        return false;
    }

    if (relay_server->communication_context->communication_server_is_valid_impl &&
        !relay_server->communication_context->communication_server_is_valid_impl(relay_server->communication_server)) {
        ue_stacktrace_push_msg("Communication server implementation is invalid");
        return false;
    }

    return true;
}

bool ue_relay_server_start(ue_relay_server *relay_server) {
    /* Check if the relay server object is valid */
    if (!ue_relay_server_is_valid(relay_server)) {
        ue_stacktrace_push_msg("Specified relay server isn't valid");
        return false;
    }

    /* Temporaly ignored -Wpedantic flag as it prevent cast of void * ptr */
    _Pragma("GCC diagnostic push")
    _Pragma("GCC diagnostic ignored \"-Wpedantic\"")
        /* Get the server process impl of communication context or record an error if it failed */
        bool (*communication_server_process_impl)(void *);
        communication_server_process_impl = NULL;
        if (!ue_communication_server_get_process_impl(relay_server->communication_context, &communication_server_process_impl)) {
            ue_stacktrace_push_msg("Failed to get server process impl");
            return false;
        }

        /* Start the server processing in another thread or record an error if it failed */
        if (!(relay_server->server_thread = ue_thread_create((void *)communication_server_process_impl, (void *)relay_server->communication_server))) {
            ue_stacktrace_push_msg("Failed to create server thread");
            return false;
        }
    _Pragma("GCC diagnostic pop")

    return true;
}

bool ue_relay_server_stop(ue_relay_server *relay_server) {
    /* Check if the relay server object is valid */
    if (!ue_relay_server_is_valid(relay_server)) {
        ue_stacktrace_push_msg("Specified relay server isn't valid");
        return false;
    }

    /**
     * Try to stop the server or record an error if it failed
     * @todo check if it will be better to log in place of record an error
     * in the stacktrace.
     */
    if (!ue_communication_server_stop(relay_server->communication_context, relay_server->communication_server)) {
        ue_stacktrace_push_msg("Failed to stop communication server");
        return false;
    }

    return true;
}

bool ue_relay_server_wait(ue_relay_server *relay_server) {
    /* Check if the relay server object is valid */
    if (!ue_relay_server_is_valid(relay_server)) {
        ue_stacktrace_push_msg("Specified relay server isn't valid");
        return false;
    }

    /* Wait the server thread finished */
    ue_thread_join(relay_server->server_thread, NULL);

    return true;
}

ue_communication_context *ue_relay_server_get_communication_context(ue_relay_server *relay_server) {

    /* Check if the relay server object is valid */
    if (!ue_relay_server_is_valid(relay_server)) {
        ue_stacktrace_push_msg("Specified relay server isn't valid");
        return NULL;
    }

    return relay_server->communication_context;
}

void *ue_relay_server_get_communication_server(ue_relay_server *relay_server) {
    /* Check if the relay server object is valid */
    if (!ue_relay_server_is_valid(relay_server)) {
        ue_stacktrace_push_msg("Specified relay server isn't valid");
        return NULL;
    }

    return relay_server->communication_server;
}

void ue_relay_server_shutdown_signal_callback(int sig) {
    ue_logger_trace("Signal received %d", sig);
    ue_logger_info("Shuting down server...");
    global_relay_server->signal_caught = true;
    if (global_relay_server->communication_server) {
        ue_communication_server_stop(global_relay_server->communication_context, global_relay_server->communication_server);
    }

    ue_thread_cancel(global_relay_server->server_thread);
}

static bool read_consumer(void *connection) {
    ue_communication_context *server_communication_context;
    size_t received;
    ue_byte_stream *received_message;

    ue_check_parameter_or_return(connection);

    /**
     * @todo replace global relay_server variable by a thread storage one
     */
    server_communication_context = ue_relay_server_get_communication_context(global_relay_server);
    received = 0;

    received_message = ue_communication_client_connection_get_received_message(server_communication_context, connection);
    ue_byte_stream_clean_up(received_message);

    received = ue_communication_receive_sync(server_communication_context, connection, received_message);
    if (received == 0) {
        ue_logger_info("read_consumer: client has disconnected.");
        //ue_communication_server_disconnect(server_communication_context, communication_server, connection);
        disconnect_client_from_server(connection);
    }
    else if (received == ULLONG_MAX) {
        ue_stacktrace_push_msg("Error while receiving message")
        ue_communication_client_connection_clean_up(server_communication_context, connection);
        return false;
    }
    else {
        ue_byte_stream *message = ue_byte_stream_create();
        ue_byte_writer_append_bytes(message, ue_byte_stream_get_data(received_message), ue_byte_stream_get_size(received_message));
        ue_queue_push_wait(ue_communication_client_connection_get_received_messages(global_relay_server->communication_context, connection), (void *)message);
        if (!server_process_messages(connection)) {
            ue_logger_error("Failed to proceed messages queue");
        }
    }

    ue_communication_client_connection_set_state(server_communication_context, connection, UNKNOWNECHO_COMMUNICATION_CONNECTION_WRITE_STATE);

    return true;
}

static bool write_consumer(void *connection) {
    ue_byte_stream *current_message_to_send, *message_to_send;
    ue_queue *messages_to_send;
    size_t sent;

    if (!global_relay_server->communication_server || !ue_communication_server_is_running(global_relay_server->communication_context,
        global_relay_server->communication_server)) {

        return false;
    }

    if (ue_communication_client_connection_is_available(global_relay_server->communication_context, connection)) {
        ue_logger_error("Client connection isn't available");
        return false;
    }

    current_message_to_send = NULL;
    message_to_send = ue_communication_client_connection_get_message_to_send(global_relay_server->communication_context, connection);
    messages_to_send = ue_communication_client_connection_get_messages_to_send(global_relay_server->communication_context, connection);

    while (!ue_queue_empty(messages_to_send)) {
        current_message_to_send = ue_queue_front_wait(messages_to_send);

        if (current_message_to_send->position > 0) {
            ue_byte_stream_clean_up(message_to_send);
            ue_byte_writer_append_bytes(message_to_send, ue_byte_stream_get_data(current_message_to_send),
                ue_byte_stream_get_size(current_message_to_send));
            sent = ue_communication_send_sync(global_relay_server->communication_context, connection, message_to_send);
            if (sent == 0) {
                ue_logger_warn("write_consumer: client has disconnected.");
                disconnect_client_from_server(connection);
            }
            else if (sent == ULLONG_MAX) {
                ue_logger_error("Error while sending message");
                ue_communication_client_connection_clean_up(global_relay_server->communication_context, connection);
            }
        } else {
            ue_logger_warn("Received message is empty.");
        }

        ue_queue_pop(messages_to_send);
    }

    ue_communication_client_connection_set_state(global_relay_server->communication_context, connection, UNKNOWNECHO_COMMUNICATION_CONNECTION_READ_STATE);

    return true;
}

static bool server_process_messages(void *connection) {
    ue_queue *received_messages;
    ue_byte_stream *received_message;

    received_messages = ue_communication_client_connection_get_received_messages(global_relay_server->communication_context, connection);

    while (!ue_queue_empty(received_messages)) {
        received_message = ue_queue_front_wait(received_messages);
        if (!server_process_message(received_message, connection)) {
            if (!ue_stacktrace_is_filled()) {
                ue_logger_error("Current received message failed to proceed, but there's no stacktrace to record");
            } else {
                ue_logger_stacktrace("Failed to proceed current message");
                ue_stacktrace_clean_up();
            }
        }
        ue_queue_pop(received_messages);
    }

    return true;

}

static bool server_process_message(ue_byte_stream *message, void *connection) {
    bool result;
    ue_relay_received_message *received_message;
    ue_queue *messages_to_send;
    ue_relay_client *relay_client;

    ue_check_parameter_or_return(connection);

    result = false;
    received_message = NULL;
    if (!(messages_to_send = ue_communication_client_connection_get_messages_to_send(global_relay_server->communication_context,
        connection))) {

        ue_stacktrace_push_msg("Failed to get messages to send queue from specified connection");
        return false;
    }

    if (!(received_message = ue_relay_message_decode(message, global_relay_server->our_crypto_metadata))) {
        ue_stacktrace_push_msg("Failed to decode message");
        goto clean_up;
    }

    if (received_message->protocol_id != UNKNOWNECHO_PROTOCOL_ID_RELAY) {
        ue_stacktrace_push_msg("Receive message with invalid protocol id: %d", received_message->protocol_id);
        goto clean_up;
    }

    /**
     * @todo build a reverse route to send an ACK msg
     */
    if (received_message->unsealed_payload) {
        ue_logger_trace("Send the unsealed message to the user callback");
        global_relay_server->user_received_callback(global_relay_server->user_context, received_message->payload);
    } else {
        if (!(relay_client = find_relay_client(ue_relay_step_get_target_communication_metadata(received_message->next_step)))) {
            ue_logger_trace("No relay client with this communication metadata exists. Creating a new relay client...");
            if (!(relay_client = create_relay_client(ue_relay_step_get_target_communication_metadata(received_message->next_step),
                    ue_relay_step_get_our_crypto_metadata(received_message->next_step)))) {

                ue_stacktrace_push_msg("Failed to create new client to relay the received message");
                goto clean_up;
            }
            ue_logger_trace("New relay client created");
        } else {
            ue_logger_trace("Relay client already exists");
        }

        ue_logger_trace("Relaying the message...");
        if (!ue_relay_client_relay_message(relay_client, received_message)) {
            ue_stacktrace_push_msg("Failed to relay the message");
            goto clean_up;
        }
    }

    result = true;

clean_up:
    ue_relay_received_message_destroy(received_message);
    return result;
}

static void disconnect_client_from_server(void *connection) {
    if (connection) {
        if (!global_relay_server) {
            ue_logger_error("Relay server ptr is null but it shouldn't");
            return;
        }
        if (!global_relay_server->communication_context) {
            ue_logger_error("Communication context ptr is null but it shouldn't");
            return;
        }
        if (!global_relay_server->communication_server) {
            ue_logger_error("Communication server ptr is null but if shouldn't");
            return;
        }
        ue_communication_server_disconnect(global_relay_server->communication_context, global_relay_server->communication_server, connection);
        ue_communication_client_connection_clean_up(global_relay_server->communication_context, connection);
    }
}

static ue_relay_client *find_relay_client(ue_communication_metadata *client_communication_metadata) {
    int i;
    ue_communication_metadata *current_communication_metadata;

    ue_logger_trace("Searching relay client with this communication metadata...");

    if (!global_relay_server->relay_clients) {
        return NULL;
    }

    for (i = 0; i < global_relay_server->relay_clients_number; i++) {
        if (!(current_communication_metadata = ue_communication_client_connection_get_communication_metadata(
            ue_relay_client_get_communication_context(global_relay_server->relay_clients[i]),
            ue_relay_client_get_connection(global_relay_server->relay_clients[i])))) {

            ue_logger_warn("Failed to communication metadata of client #%d", i);
            continue;
        }

        if (ue_communication_metadata_equals(current_communication_metadata, client_communication_metadata)) {
            return global_relay_server->relay_clients[i];
        }
    }

    return NULL;
}

static ue_relay_client *create_relay_client(ue_communication_metadata *target_communication_metadata,
    ue_crypto_metadata *our_crypto_metadata) {

    ue_relay_client *relay_client;

    if (!(relay_client = ue_relay_client_create_as_relay(target_communication_metadata, our_crypto_metadata))) {
        ue_stacktrace_push_msg("Failed to create new relay client from received message next step");
        return NULL;
    }

    if (!global_relay_server->relay_clients) {
        ue_safe_alloc(global_relay_server->relay_clients, ue_relay_client *, 1);
    } else {
        ue_safe_realloc(global_relay_server->relay_clients, ue_relay_client *, global_relay_server->relay_clients_number, 1);
    }
    global_relay_server->relay_clients[global_relay_server->relay_clients_number] = relay_client;
    global_relay_server->relay_clients_number++;

    return relay_client;
}
