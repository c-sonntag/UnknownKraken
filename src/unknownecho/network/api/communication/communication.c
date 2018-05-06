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

#include <unknownecho/network/api/communication/communication.h>
#include <unknownecho/alloc.h>
#include <unknownecho/string/string_utility.h>
#include <unknownecho/errorHandling/check_parameter.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/logger.h>

ue_communication_context *ue_communication_create(const char *communication_type,
    void *(*communication_connect_impl)(void *parameter),
    void (*communication_client_connection_destroy_impl)(void *connection),
    void (*communication_client_connection_clean_up_impl)(void *connection),
    bool (*communication_client_connection_is_available_impl)(void *connection),
    bool (*communication_client_connection_is_established_impl)(void *connection),
    void *(*communication_client_connection_get_user_data_impl)(void *connection),
    bool (*communication_client_connection_set_user_data_impl)(void *connection, void *user_data),
    char *(*communication_client_connection_get_uid_impl)(void *connection),
    bool (*communication_client_connection_set_uid_impl)(void *connection, char *uid),
    void *(*communication_client_connection_get_received_message_impl)(void *connection),
    void *(*communication_client_connection_get_message_to_send_impl)(void *connection),
    void *(*communication_client_connection_get_received_messages_impl)(void *connection),
    void *(*communication_client_connection_get_messages_to_send_impl)(void *connection),
    ue_communication_connection_state (*communication_client_connection_get_state_impl)(void *connection),
    bool (*communication_client_connection_set_state_impl)(void *connection, ue_communication_connection_state state),

    size_t (*communication_receive_sync_impl)(void *connection, void *received_message),
    size_t (*communication_send_sync_impl)(void *connection, void *message_to_send),

    void *(*communication_server_create_impl)(void *parameters),
    bool (*communication_server_is_valid_impl)(void *server),
    bool (*communication_server_is_running_impl)(void *server),
    void (*communication_server_destroy_impl)(void *server),
    bool (*communication_server_process_impl)(void *server),
    bool (*communication_server_disconnect_impl)(void *server, void *connection),
    bool (*communication_server_stop_impl)(void *server),
    int (*communication_server_get_connections_number_impl)(void *server),
    void *(*communication_server_get_connection_impl)(void *server, int index)) {

    ue_communication_context *context;

    ue_check_parameter_or_return(communication_type);
    ue_check_parameter_or_return(communication_connect_impl);
    ue_check_parameter_or_return(communication_client_connection_destroy_impl);
    ue_check_parameter_or_return(communication_client_connection_clean_up_impl);

    if (!communication_client_connection_is_available_impl) {
        ue_logger_warn("Optional parameter communication_client_connection_is_available_impl ptr is null.");
    }

    if (!communication_client_connection_is_established_impl) {
        ue_logger_warn("Optional parameter communication_client_connection_is_established_impl ptr is null.");
    }

    ue_check_parameter_or_return(communication_receive_sync_impl);
    ue_check_parameter_or_return(communication_send_sync_impl);
    ue_check_parameter_or_return(communication_server_create_impl);
    ue_check_parameter_or_return(communication_server_is_valid_impl);
    ue_check_parameter_or_return(communication_server_is_running_impl);
    ue_check_parameter_or_return(communication_server_destroy_impl);
    ue_check_parameter_or_return(communication_server_process_impl);
    ue_check_parameter_or_return(communication_server_disconnect_impl);

    ue_safe_alloc(context, ue_communication_context, 1);

    context->communication_type = (const char *)ue_string_create_from(communication_type);

    context->communication_connect_impl = communication_connect_impl;
    context->communication_client_connection_destroy_impl = communication_client_connection_destroy_impl;
    context->communication_client_connection_clean_up_impl = communication_client_connection_clean_up_impl;
    context->communication_client_connection_is_available_impl = communication_client_connection_is_available_impl;
    context->communication_client_connection_is_established_impl = communication_client_connection_is_established_impl;
    context->communication_client_connection_get_user_data_impl = communication_client_connection_get_user_data_impl;
    context->communication_client_connection_set_user_data_impl = communication_client_connection_set_user_data_impl;
    context->communication_client_connection_get_uid_impl = communication_client_connection_get_uid_impl;
    context->communication_client_connection_set_uid_impl = communication_client_connection_set_uid_impl;
    context->communication_client_connection_get_received_message_impl = communication_client_connection_get_received_message_impl;
    context->communication_client_connection_get_message_to_send_impl = communication_client_connection_get_message_to_send_impl;
    context->communication_client_connection_get_received_messages_impl = communication_client_connection_get_received_messages_impl;
    context->communication_client_connection_get_messages_to_send_impl = communication_client_connection_get_messages_to_send_impl;
    context->communication_client_connection_get_state_impl = communication_client_connection_get_state_impl;
    context->communication_client_connection_set_state_impl = communication_client_connection_set_state_impl;

    context->communication_receive_sync_impl = communication_receive_sync_impl;
    context->communication_send_sync_impl = communication_send_sync_impl;

    context->communication_server_create_impl = communication_server_create_impl;
    context->communication_server_is_valid_impl = communication_server_is_valid_impl;
    context->communication_server_is_running_impl = communication_server_is_running_impl;
    context->communication_server_destroy_impl = communication_server_destroy_impl;
    context->communication_server_process_impl = communication_server_process_impl;
    context->communication_server_disconnect_impl = communication_server_disconnect_impl;
    context->communication_server_stop_impl = communication_server_stop_impl;
    context->communication_server_get_connections_number_impl = communication_server_get_connections_number_impl;
    context->communication_server_get_connection_impl = communication_server_get_connection_impl;

    return context;
}

void ue_communication_destroy(ue_communication_context *context) {
    if (context) {
        ue_safe_free(context->communication_type);
        ue_safe_free(context);
    }
}

bool ue_communication_context_is_valid(ue_communication_context *context) {
    ue_check_parameter_or_return(context);

    ue_check_parameter_or_return(context->communication_type);
    ue_check_parameter_or_return(context->communication_connect_impl);
    ue_check_parameter_or_return(context->communication_client_connection_destroy_impl);
    ue_check_parameter_or_return(context->communication_client_connection_clean_up_impl);

    ue_check_parameter_or_return(context->communication_receive_sync_impl);
    ue_check_parameter_or_return(context->communication_send_sync_impl);
    ue_check_parameter_or_return(context->communication_server_create_impl);
    ue_check_parameter_or_return(context->communication_server_is_valid_impl);
    ue_check_parameter_or_return(context->communication_server_is_running_impl);
    ue_check_parameter_or_return(context->communication_server_destroy_impl);
    ue_check_parameter_or_return(context->communication_server_process_impl);
    ue_check_parameter_or_return(context->communication_server_disconnect_impl);

    return true;
}

/* Handle connection as a client */

void *ue_communication_connect(ue_communication_context *context, void *parameter) {
    void *result;

    ue_check_parameter_or_return(context);
    ue_check_parameter_or_return(parameter);

    if (!(result = context->communication_connect_impl(parameter))) {
        ue_stacktrace_push_msg("communication_connect_impl() returned an null result");
    }

    return result;
}

bool ue_communication_client_connection_destroy(ue_communication_context *context, void *connection) {
    ue_check_parameter_or_return(context);

    context->communication_client_connection_destroy_impl(connection);

    return true;
}

bool ue_communication_client_connection_clean_up(ue_communication_context *context, void *connection) {
    ue_check_parameter_or_return(context);

    context->communication_client_connection_clean_up_impl(connection);

    return true;
}

bool ue_communication_client_connection_is_available(ue_communication_context *context, void *connection) {
    ue_check_parameter_or_return(context);
    ue_check_parameter_or_return(context->communication_client_connection_is_available_impl);

    return context->communication_client_connection_is_available_impl(connection);
}

bool ue_communication_client_connection_is_established(ue_communication_context *context, void *connection) {
    ue_check_parameter_or_return(context);

    return context->communication_client_connection_is_established_impl(connection);
}

void *ue_communication_client_connection_get_user_data(ue_communication_context *context, void *connection)  {
    ue_check_parameter_or_return(context);
    ue_check_parameter_or_return(connection);

    return context->communication_client_connection_get_user_data_impl(connection);
}

bool ue_communication_client_connection_set_user_data(ue_communication_context *context, void *connection, void *user_data)  {
    ue_check_parameter_or_return(context);
    ue_check_parameter_or_return(connection);

    return context->communication_client_connection_set_user_data_impl(connection, user_data);
}

char *ue_communication_client_connection_get_uid(ue_communication_context *context, void *connection) {
    ue_check_parameter_or_return(context);
    ue_check_parameter_or_return(connection);

    return context->communication_client_connection_get_uid_impl(connection);
}

bool ue_communication_client_connection_set_uid(ue_communication_context *context, void *connection, char *uid) {
    ue_check_parameter_or_return(context);
    ue_check_parameter_or_return(connection);

    return context->communication_client_connection_set_uid_impl(connection, uid);
}

void *ue_communication_client_connection_get_received_message(ue_communication_context *context, void *connection) {
    ue_check_parameter_or_return(context);
    ue_check_parameter_or_return(connection);

    return context->communication_client_connection_get_received_message_impl(connection);
}

void *ue_communication_client_connection_get_message_to_send(ue_communication_context *context, void *connection) {
    ue_check_parameter_or_return(context);
    ue_check_parameter_or_return(connection);

    return context->communication_client_connection_get_message_to_send_impl(connection);
}

void *ue_communication_client_connection_get_received_messages(ue_communication_context *context, void *connection) {
    ue_check_parameter_or_return(context);
    ue_check_parameter_or_return(connection);

    return context->communication_client_connection_get_received_messages_impl(connection);
}

void *ue_communication_client_connection_get_messages_to_send(ue_communication_context *context, void *connection) {
    ue_check_parameter_or_return(context);
    ue_check_parameter_or_return(connection);

    return context->communication_client_connection_get_messages_to_send_impl(connection);
}

ue_communication_connection_state ue_communication_client_connection_get_state(ue_communication_context *context, void *connection) {
    ue_check_parameter_or_return(context);
    ue_check_parameter_or_return(connection);

    return context->communication_client_connection_get_state_impl(connection);
}

bool ue_communication_client_connection_set_state(ue_communication_context *context, void *connection, ue_communication_connection_state state) {
    ue_check_parameter_or_return(context);
    ue_check_parameter_or_return(connection);

    return context->communication_client_connection_set_state_impl(connection, state);
}

/* Send and receive message for both client/server */

size_t ue_communication_receive_sync(ue_communication_context *context, void *connection, void *received_message) {
    size_t result;

    if (!context) {
        ue_stacktrace_push_code(UNKNOWNECHO_INVALID_PARAMETER);
        return 0;
    }

    if ((result = context->communication_receive_sync_impl(connection, received_message)) == 0) {
        ue_stacktrace_push_msg("communication_receive_sync_impl() returned 0. The communication was interrupted");
    }

    return result;
}

size_t ue_communication_send_sync(ue_communication_context *context, void *connection, void *message_to_send) {
    size_t result;

    if (!context) {
        ue_stacktrace_push_code(UNKNOWNECHO_INVALID_PARAMETER);
        return 0;
    }

    if ((result = context->communication_send_sync_impl(connection, message_to_send)) == 0) {
        ue_stacktrace_push_msg("communication_send_sync_impl() returned 0. The communication was interrupted");
    }

    return result;
}

/* Handle server functions */

void *ue_communication_server_create(ue_communication_context *context, void *parameters) {
    void *result;

    ue_check_parameter_or_return(context);

    if (!(result = context->communication_server_create_impl(parameters))) {
        ue_stacktrace_push_msg("communication_server_create_impl returned false. Failed to create communication server");
    }

    return result;
}

bool ue_communication_server_is_valid(ue_communication_context *context, void *server) {
    ue_check_parameter_or_return(context);

    return context->communication_server_is_valid_impl(server);
}

bool ue_communication_server_is_running(ue_communication_context *context, void *server) {
    ue_check_parameter_or_return(context);

    return context->communication_server_is_running_impl(server);
}

bool ue_communication_server_destroy(ue_communication_context *context, void *server) {
    ue_check_parameter_or_return(context);

    context->communication_server_destroy_impl(server);

    return true;
}

bool ue_communication_server_process(ue_communication_context *context, void *server) {
    ue_check_parameter_or_return(context);

    if (!context->communication_server_process_impl(server)) {
        ue_stacktrace_push_msg("communication_server_process_impl returned false. Failed to process server");
        return false;
    }

    return true;
}

bool ue_communication_server_get_process_impl(ue_communication_context *context, bool (**communication_server_process_impl)(void *)) {
    ue_check_parameter_or_return(context);

    if (context->communication_server_process_impl) {
        *communication_server_process_impl = context->communication_server_process_impl;
        return true;
    }

    ue_stacktrace_push_msg("No implementation found for communication server process");
    return false;
}

bool ue_communication_server_disconnect(ue_communication_context *context, void *server, void *connection) {
    ue_check_parameter_or_return(context);

    if (!context->communication_server_disconnect_impl(server, connection)) {
        ue_stacktrace_push_msg("communication_server_disconnect_impl returned false. Failed to disconnect client from server");
        return false;
    }

    return true;
}

bool ue_communication_server_stop(ue_communication_context *context, void *server) {
    ue_check_parameter_or_return(context);

    if (!context->communication_server_stop_impl(server)) {
        ue_stacktrace_push_msg("communication_server_stop_impl retuned false. Failed to stop server");
        return false;
    }

    return true;
}

int ue_communication_server_get_connections_number(ue_communication_context *context, void *server) {
    ue_check_parameter_or_return(context);

    return context->communication_server_get_connections_number_impl(server);
}

void *ue_communication_server_get_connection(ue_communication_context *context, void *server, int index) {
    ue_check_parameter_or_return(context);

    return context->communication_server_get_connection_impl(server, index);
}
