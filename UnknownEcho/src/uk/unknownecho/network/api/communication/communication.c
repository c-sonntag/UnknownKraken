/*******************************************************************************
 * Copyright (C) 2018 Charly Lamothe                                           *
 *                                                                             *
 * This file is part of LibUnknownEcho.                                        *
 *                                                                             *
 *   Licensed under the Apache License, Version 2.0 (the "License");           *
 *   you may not use this file except in compliance with the License.          *
 *   You may obtain a copy of the License at                                   *
 *                                                                             *
 *   http://www.apache.org/licenses/LICENSE-2.0                                *
 *                                                                             *
 *   Unless required by applicable law or agreed to in writing, software       *
 *   distributed under the License is distributed on an "AS IS" BASIS,         *
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  *
 *   See the License for the specific language governing permissions and       *
 *   limitations under the License.                                            *
 *******************************************************************************/

#include <uk/unknownecho/network/api/communication/communication.h>
#include <uk/utils/ueum.h>
#include <uk/utils/ei.h>

uk_ue_communication_context *uk_ue_communication_create(const char *communication_type,
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
    uk_ue_communication_connection_state (*communication_client_connection_get_state_impl)(void *connection),
    bool (*communication_client_connection_set_state_impl)(void *connection, uk_ue_communication_connection_state state),
    uk_ue_communication_metadata *(*communication_client_connection_get_communication_metadata_impl)(void *connection),
    uk_ue_communication_connection_direction (*communication_client_connection_get_direction_impl)(void *connection),
    bool (*communication_client_connection_set_direction_impl)(void *connection, uk_ue_communication_connection_direction
        connection_direction),

    size_t (*communication_receive_sync_impl)(void *connection, void *received_message),
    size_t (*communication_send_sync_impl)(void *connection, void *message_to_send),

    void *(*communication_server_create_impl)(void *parameters),
    bool (*communication_server_is_valid_impl)(void *server),
    bool (*communication_server_is_running_impl)(void *server),
    void (*communication_server_destroy_impl)(void *server),
    void (*communication_server_process_impl)(void *server),
    bool (*communication_server_disconnect_impl)(void *server, void *connection),
    bool (*communication_server_stop_impl)(void *server),
    int (*communication_server_get_connections_number_impl)(void *server),
    void *(*communication_server_get_connection_impl)(void *server, int index)) {

    uk_ue_communication_context *context;

    uk_utils_check_parameter_or_return(communication_type);
    uk_utils_check_parameter_or_return(communication_connect_impl);
    uk_utils_check_parameter_or_return(communication_client_connection_destroy_impl);
    uk_utils_check_parameter_or_return(communication_client_connection_clean_up_impl);

    if (!communication_client_connection_is_available_impl) {
        uk_utils_logger_warn("Optional parameter communication_client_connection_is_available_impl ptr is null.");
    }

    if (!communication_client_connection_is_established_impl) {
        uk_utils_logger_warn("Optional parameter communication_client_connection_is_established_impl ptr is null.");
    }

    uk_utils_check_parameter_or_return(communication_receive_sync_impl);
    uk_utils_check_parameter_or_return(communication_send_sync_impl);
    uk_utils_check_parameter_or_return(communication_server_create_impl);
    uk_utils_check_parameter_or_return(communication_server_is_valid_impl);
    uk_utils_check_parameter_or_return(communication_server_is_running_impl);
    uk_utils_check_parameter_or_return(communication_server_destroy_impl);
    uk_utils_check_parameter_or_return(communication_server_process_impl);
    uk_utils_check_parameter_or_return(communication_server_disconnect_impl);

    context = NULL;

    uk_utils_safe_alloc(context, uk_ue_communication_context, 1);

    context->communication_type = (const char *)uk_utils_string_create_from(communication_type);

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
    context->communication_client_connection_get_communication_metadata_impl = communication_client_connection_get_communication_metadata_impl;
    context->communication_client_connection_get_direction_impl = communication_client_connection_get_direction_impl;
    context->communication_client_connection_set_direction_impl = communication_client_connection_set_direction_impl;

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

void uk_ue_communication_destroy(uk_ue_communication_context *context) {
    if (context) {
        uk_utils_safe_free(context->communication_type);
        uk_utils_safe_free(context);
    }
}

bool uk_ue_communication_context_is_valid(uk_ue_communication_context *context) {
    uk_utils_check_parameter_or_return(context);

    uk_utils_check_parameter_or_return(context->communication_type);
    uk_utils_check_parameter_or_return(context->communication_connect_impl);
    uk_utils_check_parameter_or_return(context->communication_client_connection_destroy_impl);
    uk_utils_check_parameter_or_return(context->communication_client_connection_clean_up_impl);

    uk_utils_check_parameter_or_return(context->communication_receive_sync_impl);
    uk_utils_check_parameter_or_return(context->communication_send_sync_impl);
    uk_utils_check_parameter_or_return(context->communication_server_create_impl);
    uk_utils_check_parameter_or_return(context->communication_server_is_valid_impl);
    uk_utils_check_parameter_or_return(context->communication_server_is_running_impl);
    uk_utils_check_parameter_or_return(context->communication_server_destroy_impl);
    uk_utils_check_parameter_or_return(context->communication_server_process_impl);
    uk_utils_check_parameter_or_return(context->communication_server_disconnect_impl);

    return true;
}

/* Handle connection as a client */

void *uk_ue_communication_connect(uk_ue_communication_context *context, void *parameter) {
    void *result;

    uk_utils_check_parameter_or_return(context);
    uk_utils_check_parameter_or_return(parameter);

    if (!(result = context->communication_connect_impl(parameter))) {
        uk_utils_stacktrace_push_msg("communication_connect_impl() returned an null result");
    }

    return result;
}

bool uk_ue_communication_client_connection_destroy(uk_ue_communication_context *context, void *connection) {
    uk_utils_check_parameter_or_return(context);

    context->communication_client_connection_destroy_impl(connection);

    return true;
}

bool uk_ue_communication_client_connection_clean_up(uk_ue_communication_context *context, void *connection) {
    uk_utils_check_parameter_or_return(context);

    context->communication_client_connection_clean_up_impl(connection);

    return true;
}

bool uk_ue_communication_client_connection_is_available(uk_ue_communication_context *context, void *connection) {
    uk_utils_check_parameter_or_return(context);
    uk_utils_check_parameter_or_return(context->communication_client_connection_is_available_impl);

    return context->communication_client_connection_is_available_impl(connection);
}

bool uk_ue_communication_client_connection_is_established(uk_ue_communication_context *context, void *connection) {
    uk_utils_check_parameter_or_return(context);

    return context->communication_client_connection_is_established_impl(connection);
}

void *uk_ue_communication_client_connection_get_user_data(uk_ue_communication_context *context, void *connection)  {
    uk_utils_check_parameter_or_return(context);
    uk_utils_check_parameter_or_return(connection);

    return context->communication_client_connection_get_user_data_impl(connection);
}

bool uk_ue_communication_client_connection_set_user_data(uk_ue_communication_context *context, void *connection, void *user_data)  {
    uk_utils_check_parameter_or_return(context);
    uk_utils_check_parameter_or_return(connection);

    return context->communication_client_connection_set_user_data_impl(connection, user_data);
}

char *uk_ue_communication_client_connection_get_uid(uk_ue_communication_context *context, void *connection) {
    uk_utils_check_parameter_or_return(context);
    uk_utils_check_parameter_or_return(connection);

    return context->communication_client_connection_get_uid_impl(connection);
}

bool uk_ue_communication_client_connection_set_uid(uk_ue_communication_context *context, void *connection, char *uid) {
    uk_utils_check_parameter_or_return(context);
    uk_utils_check_parameter_or_return(connection);

    return context->communication_client_connection_set_uid_impl(connection, uid);
}

void *uk_ue_communication_client_connection_get_received_message(uk_ue_communication_context *context, void *connection) {
    uk_utils_check_parameter_or_return(context);
    uk_utils_check_parameter_or_return(connection);

    return context->communication_client_connection_get_received_message_impl(connection);
}

void *uk_ue_communication_client_connection_get_message_to_send(uk_ue_communication_context *context, void *connection) {
    uk_utils_check_parameter_or_return(context);
    uk_utils_check_parameter_or_return(connection);

    return context->communication_client_connection_get_message_to_send_impl(connection);
}

void *uk_ue_communication_client_connection_get_received_messages(uk_ue_communication_context *context, void *connection) {
    uk_utils_check_parameter_or_return(context);
    uk_utils_check_parameter_or_return(connection);

    return context->communication_client_connection_get_received_messages_impl(connection);
}

void *uk_ue_communication_client_connection_get_messages_to_send(uk_ue_communication_context *context, void *connection) {
    uk_utils_check_parameter_or_return(context);
    uk_utils_check_parameter_or_return(connection);

    return context->communication_client_connection_get_messages_to_send_impl(connection);
}

uk_ue_communication_connection_state uk_ue_communication_client_connection_get_state(uk_ue_communication_context *context, void *connection) {
    uk_utils_check_parameter_or_return(context);
    uk_utils_check_parameter_or_return(connection);

    return context->communication_client_connection_get_state_impl(connection);
}

bool uk_ue_communication_client_connection_set_state(uk_ue_communication_context *context, void *connection, uk_ue_communication_connection_state state) {
    uk_utils_check_parameter_or_return(context);
    uk_utils_check_parameter_or_return(connection);

    return context->communication_client_connection_set_state_impl(connection, state);
}

uk_ue_communication_metadata *uk_ue_communication_client_connection_get_communication_metadata(uk_ue_communication_context *context, void *connection) {
    uk_utils_check_parameter_or_return(context);
    uk_utils_check_parameter_or_return(connection);

    return context->communication_client_connection_get_communication_metadata_impl(connection);
}

uk_ue_communication_connection_direction uk_ue_communication_client_connection_get_direction(uk_ue_communication_context *context, void *connection) {
    return context->communication_client_connection_get_direction_impl(connection);
}

bool uk_ue_communication_client_connection_set_direction(uk_ue_communication_context *context, void *connection,
    uk_ue_communication_connection_direction connection_direction) {

    uk_utils_check_parameter_or_return(context);
    uk_utils_check_parameter_or_return(connection);

    return context->communication_client_connection_set_direction_impl(connection, connection_direction);
}

/* Send and receive message for both client/server */

size_t uk_ue_communication_receive_sync(uk_ue_communication_context *context, void *connection, void *received_message) {
    if (!context) {
        uk_utils_stacktrace_push_code(UnknownKrakenUtils_INVALID_PARAMETER);
        return 0;
    }

    return context->communication_receive_sync_impl(connection, received_message);
}

size_t uk_ue_communication_send_sync(uk_ue_communication_context *context, void *connection, void *message_to_send) {
    if (!context) {
        uk_utils_stacktrace_push_code(UnknownKrakenUtils_INVALID_PARAMETER);
        return 0;
    }

    return context->communication_send_sync_impl(connection, message_to_send);
}

/* Handle server functions */

void *uk_ue_communication_server_create(uk_ue_communication_context *context, void *parameters) {
    void *result;

    uk_utils_check_parameter_or_return(context);

    if (!(result = context->communication_server_create_impl(parameters))) {
        uk_utils_stacktrace_push_msg("communication_server_create_impl returned false. Failed to create communication server");
    }

    return result;
}

bool uk_ue_communication_server_is_valid(uk_ue_communication_context *context, void *server) {
    uk_utils_check_parameter_or_return(context);

    return context->communication_server_is_valid_impl(server);
}

bool uk_ue_communication_server_is_running(uk_ue_communication_context *context, void *server) {
    uk_utils_check_parameter_or_return(context);

    return context->communication_server_is_running_impl(server);
}

bool uk_ue_communication_server_destroy(uk_ue_communication_context *context, void *server) {
    uk_utils_check_parameter_or_return(context);

    context->communication_server_destroy_impl(server);

    return true;
}

bool uk_ue_communication_server_process(uk_ue_communication_context *context, void *server) {
    uk_utils_check_parameter_or_return(context);
    uk_utils_check_parameter_or_return(server);

    context->communication_server_process_impl(server);

    return true;
}

bool uk_ue_communication_server_get_process_impl(uk_ue_communication_context *context, void (**communication_server_process_impl)(void *)) {
    uk_utils_check_parameter_or_return(context);

    if (context->communication_server_process_impl) {
        *communication_server_process_impl = context->communication_server_process_impl;
        return true;
    }

    uk_utils_stacktrace_push_msg("No implementation found for communication server process");
    return false;
}

bool uk_ue_communication_server_disconnect(uk_ue_communication_context *context, void *server, void *connection) {
    uk_utils_check_parameter_or_return(context);

    if (!context->communication_server_disconnect_impl(server, connection)) {
        uk_utils_stacktrace_push_msg("communication_server_disconnect_impl returned false. Failed to disconnect client from server");
        return false;
    }

    return true;
}

bool uk_ue_communication_server_stop(uk_ue_communication_context *context, void *server) {
    uk_utils_check_parameter_or_return(context);

    if (!context->communication_server_stop_impl(server)) {
        uk_utils_stacktrace_push_msg("communication_server_stop_impl retuned false. Failed to stop server");
        return false;
    }

    return true;
}

int uk_ue_communication_server_get_connections_number(uk_ue_communication_context *context, void *server) {
    uk_utils_check_parameter_or_return(context);

    return context->communication_server_get_connections_number_impl(server);
}

void *uk_ue_communication_server_get_connection(uk_ue_communication_context *context, void *server, int index) {
    uk_utils_check_parameter_or_return(context);

    return context->communication_server_get_connection_impl(server, index);
}
