#include <unknownecho/protocol/api/relay/relay_server.h>
#include <unknownecho/network/api/communication/communication.h>
#include <unknownecho/network/factory/communication_factory.h>
#include <unknownecho/alloc.h>
#include <unknownecho/errorHandling/check_parameter.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/thread/thread.h>

ue_relay_server *ue_relay_server_create(ue_communication_metadata *communication_metadata,
    bool (*read_consumer)(void *connection),
    bool (*write_consumer)(void *connection)) {

    ue_relay_server *relay_server;
    void *server_parameters;

    /* Check if communication metadata objet is valid */
    if (!ue_communication_metadata_is_valid(communication_metadata)) {
        ue_stacktrace_push_msg("Specified communication metadata object is invalid");
        return NULL;
    }

    ue_check_parameter_or_return(read_consumer);
    ue_check_parameter_or_return(write_consumer);

    ue_safe_alloc(relay_server, ue_relay_server, 1);
    relay_server->communication_context = ue_communication_build_from_type(ue_communication_metadata_get_type(communication_metadata));
    relay_server->communication_server = NULL;
    relay_server->server_thread = NULL;

    /**
     * Build server parameters from communication context or record an error if it's failed.
     * @warning at this point of the POC, the 4th optional parameter, the secure layer, isn't used.
     */
    if (!(server_parameters = ue_communication_build_server_parameters(relay_server->communication_context, 3,
        ue_communication_metadata_get_port(communication_metadata), read_consumer, write_consumer))) {

        ue_relay_server_destroy(relay_server);
        ue_stacktrace_push_msg("Failed to build communication server parameters context");
        goto clean_up;
    }

    /* Finally, the server is created or it record an error if it's failed */
    if (!(relay_server->communication_server = ue_communication_server_create(relay_server->communication_context,
        server_parameters))) {

        ue_relay_server_destroy(relay_server);
        ue_stacktrace_push_msg("Failed to start establisher server");
        goto clean_up;
    }

clean_up:
    ue_safe_free(server_parameters);
    return relay_server;
}

void ue_relay_server_destroy(ue_relay_server *relay_server) {
    if (relay_server) {
        ue_communication_server_destroy(relay_server->communication_context, relay_server->communication_server);
        ue_communication_destroy(relay_server->communication_context);
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
