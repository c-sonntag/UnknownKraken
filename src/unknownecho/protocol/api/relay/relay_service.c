#include <unknownecho/protocol/api/relay/relay_service.h>
#include <unknownecho/protocol/api/relay/relay_server.h>
#include <unknownecho/protocol/api/relay/relay_client.h>
#include <unknownecho/alloc.h>
#include <unknownecho/errorHandling/check_parameter.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/string/string_utility.h>
#include <unknownecho/network/api/communication/communication.h>
#include <unknownecho/network/api/communication/communication_connection_state.h>
#include <unknownecho/thread/thread.h>
#include <unknownecho/byte/byte_stream.h>
#include <unknownecho/byte/byte_writer.h>

#include <stddef.h>
#include <limits.h>


static ue_relay_service *ue_relay_service_create(ue_communication_metadata *server_communication_metadata);

static void ue_relay_service_destroy(ue_relay_service *service);

static ue_relay_service_client *ue_relay_service_client_create(ue_relay_client *relay_client);

static void ue_relay_service_client_destroy(ue_relay_service_client *relay_service_client);

static bool server_read_consumer(void *connection);

static bool server_write_consumer(void *connection);

static bool server_process_request(ue_byte_stream *request);

static bool client_read_consumer(void *parameter);

static bool client_write_consumer(void *parameter);


ue_relay_service *service = NULL;


bool ue_relay_service_init(ue_communication_metadata *server_communication_metadata) {
    if (service) {
        ue_logger_warn("Relay service already initialized");
        return true;
    }

    if (!(service = ue_relay_service_create(server_communication_metadata))) {
        ue_stacktrace_push_msg("Failed to create new relay service");
        return false;
    }

    return true;
}

bool ue_relay_service_uninit() {
    if (!service) {
        ue_logger_warn("Relay service already uninitialized");
        return true;
    }

    ue_relay_service_destroy(service);

    return true;
}

bool ue_relay_service_start() {
    bool result;

    ue_check_parameter_or_return(service);

    result = false;

    service->running = true;
    result = true;

    return result;
}

bool ue_relay_service_stop() {
    bool result;

    if (!ue_relay_service_is_valid()) {
        ue_stacktrace_push_msg("Specified relay service object isn't valid");
        return false;
    }

    result = false;

    result = true;

    return result;
}

bool ue_relay_service_is_valid() {
    return service && ue_relay_server_is_valid(service->server);
}

bool ue_relay_service_wait() {
    if (!ue_relay_service_is_valid()) {
        ue_stacktrace_push_msg("Specified relay service object isn't valid");
        return false;
    }

    if (!ue_relay_server_wait(service->server)) {
        ue_stacktrace_push_msg("Relay server of service failed during waiting");
        return false;
    }

    return true;
}

const char *ue_relay_service_status() {
    const char *status;

    status = NULL;

    if (!ue_relay_service_is_valid()) {
        status = ue_string_create_from("[?]");
    }
    else if (!ue_communication_server_is_running(ue_relay_server_get_communication_context(service->server),
        ue_relay_server_get_communication_server(service->server))) {
        status = ue_string_create_from("[-]");
    } else {
        status = ue_string_create_from("[+]");
    }

    return status;
}

const char *ue_relay_service_human_readable_status() {
    const char *status;

    status = NULL;

    if (!ue_relay_service_is_valid()) {
        status = ue_string_create_from("[?] Specified service isn't valid.");
    }
    else if (!ue_communication_server_is_running(ue_relay_server_get_communication_context(service->server),
        ue_relay_server_get_communication_server(service->server))) {
        status = ue_string_create_from("[-] Service isn't running.");
    } else {
        status = ue_strcat_variadic("sds", "[+] Service is running with %d client(s).", service->clients_number);
    }

    return status;
}

bool ue_relay_service_running() {
    if (!ue_relay_service_is_valid()) {
        ue_stacktrace_push_msg("Specified relay service object isn't valid");
        return false;
    }

    return service->running;
}

bool ue_relay_service_attach_client(ue_relay_client *relay_client) {
    if (!ue_relay_service_is_valid()) {
        ue_stacktrace_push_msg("Specified relay service object isn't valid");
        return false;
    }

    if (!ue_relay_client_is_valid(relay_client)) {
        ue_stacktrace_push_msg("Specified relay client object isn't valid");
        return false;
    }

    if (!service->clients) {
        ue_safe_alloc(service->clients, ue_relay_service_client *, 1);
    } else {
        ue_safe_realloc(service->clients, ue_relay_service_client *, service->clients_number, 1);
    }
    service->clients[service->clients_number] = ue_relay_service_client_create(relay_client);
    service->clients_number++;

    _Pragma("GCC diagnostic push")
    _Pragma("GCC diagnostic ignored \"-Wpedantic\"")
        service->clients[service->clients_number]->read_consumer_thread = ue_thread_create((void *)client_read_consumer, (void *)service->clients[service->clients_number]);
        service->clients[service->clients_number]->write_consumer_thread = ue_thread_create((void *)client_write_consumer, (void *)service->clients[service->clients_number]);
    _Pragma("GCC diagnostic pop")

    return true;
}

static ue_relay_service *ue_relay_service_create(ue_communication_metadata *server_communication_metadata) {
    ue_relay_service *service;

    ue_safe_alloc(service, ue_relay_service, 1);
    service->clients = NULL;
    service->clients_number = 0;
    service->server = ue_relay_server_create(server_communication_metadata, server_read_consumer,
        server_write_consumer);
    service->running = false;

    return service;
}

static void ue_relay_service_destroy(ue_relay_service *service) {
    int i;

    if (service) {
        ue_relay_server_destroy(service->server);
        if (service->clients) {
            for (i = 0; i < service->clients_number; i++) {
                ue_relay_service_client_destroy(service->clients[i]);
            }
            ue_safe_free(service->clients);
        }
        ue_safe_free(service);
    }
}

static ue_relay_service_client *ue_relay_service_client_create(ue_relay_client *relay_client) {
    ue_relay_service_client *relay_service_client;

    ue_safe_alloc(relay_service_client, ue_relay_service_client, 1);
    relay_service_client->client = relay_client;
    relay_service_client->read_consumer_thread = NULL;
    relay_service_client->write_consumer_thread = NULL;
    relay_service_client->running = false;

    return relay_service_client;
}

static void ue_relay_service_client_destroy(ue_relay_service_client *relay_service_client) {
    if (relay_service_client) {
        if (relay_service_client->running) {
            ue_logger_warn("Client still running. Cancelling consumer threads...");
            ue_thread_cancel(relay_service_client->read_consumer_thread);
            ue_thread_cancel(relay_service_client->write_consumer_thread);
        }
        ue_safe_free(relay_service_client);
    }
}

static bool server_read_consumer(void *connection) {
    ue_communication_context *server_communication_context;
    void *communication_server;
    size_t received;
    ue_byte_stream *received_message;

    ue_check_parameter_or_return(connection);

    server_communication_context = ue_relay_server_get_communication_context(service->server);
    communication_server = ue_relay_server_get_communication_server(service->server);
    received = 0;

    received_message = ue_communication_client_connection_get_received_message(server_communication_context, connection);
    ue_byte_stream_clean_up(received_message);

    received = ue_communication_receive_sync(server_communication_context, connection, received_message);
    if (received == 0) {
        ue_logger_info("Client has disconnected.");
        ue_communication_server_disconnect(server_communication_context, communication_server, connection);
    }
    else if (received == ULLONG_MAX) {
        ue_stacktrace_push_msg("Error while receiving message")
        ue_communication_client_connection_clean_up(server_communication_context, connection);
        return false;
    }
    else {
        ue_byte_stream *request = ue_byte_stream_create();
        ue_byte_writer_append_bytes(request, ue_byte_stream_get_data(received_message), ue_byte_stream_get_size(received_message));
        server_process_request(request);
    }

    ue_communication_client_connection_set_state(server_communication_context, connection, UNKNOWNECHO_COMMUNICATION_CONNECTION_WRITE_STATE);

    return true;
}

static bool server_write_consumer(void *connection) {
    /*ue_communication_context *server_communication_context;
    void *communication_server;

    ue_check_parameter_or_return(connection);

    server_communication_context = ue_relay_server_get_communication_context(service->server);
    communication_server = ue_relay_server_get_communication_server(service->server);

    while (service->running) {

    }

    ue_communication_client_connection_set_state(server_communication_context, connection, UNKNOWNECHO_COMMUNICATION_CONNECTION_READ_STATE);

    return true;*/

    ue_stacktrace_push_msg("Not implemented");
    return false;
}

static bool server_process_request(ue_byte_stream *request) {
    bool result;

    ue_check_parameter_or_return(request);

    result = false;

    if (ue_byte_stream_get_size(request) == 0) {
        ue_stacktrace_push_msg("Specified request has an invalid size");
        goto clean_up;
    }

    result = true;

clean_up:
    return result;
}

static bool client_read_consumer(void *parameter) {
    ue_relay_service_client *relay_service_client;

    ue_check_parameter_or_return(parameter);
    relay_service_client = (ue_relay_service_client *)parameter;
    ue_check_parameter_or_return(relay_service_client);

    while (service->running && relay_service_client->running) {

    }

    return true;
}

static bool client_write_consumer(void *parameter) {
    ue_relay_service_client *relay_service_client;

    ue_check_parameter_or_return(parameter);
    relay_service_client = (ue_relay_service_client *)parameter;
    ue_check_parameter_or_return(relay_service_client);

    while (service->running && relay_service_client->running) {

    }

    return true;
}
