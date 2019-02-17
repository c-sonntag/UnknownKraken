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

#ifndef UnknownKrakenUnknownEcho_COMMUNICATION_H
#define UnknownKrakenUnknownEcho_COMMUNICATION_H

#include <uk/unknownecho/network/api/communication/communication_context.h>
#include <uk/unknownecho/network/api/communication/communication_metadata.h>
#include <uk/unknownecho/network/api/communication/communication_connection_direction.h>
#include <uk/utils/ueum.h>

#include <stddef.h>

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
    void *(*communication_server_get_connection_impl)(void *server, int index));

void uk_ue_communication_destroy(uk_ue_communication_context *context);

bool uk_ue_communication_context_is_valid(uk_ue_communication_context *context);

/* Handle connection as a client */

void *uk_ue_communication_connect(uk_ue_communication_context *context, void *parameter);

bool uk_ue_communication_client_connection_destroy(uk_ue_communication_context *context, void *connection);

bool uk_ue_communication_client_connection_clean_up(uk_ue_communication_context *context, void *connection);

bool uk_ue_communication_client_connection_is_available(uk_ue_communication_context *context, void *connection);

bool uk_ue_communication_client_connection_is_established(uk_ue_communication_context *context, void *connection);

void *uk_ue_communication_client_connection_get_user_data(uk_ue_communication_context *context, void *connection);

bool uk_ue_communication_client_connection_set_user_data(uk_ue_communication_context *context, void *connection, void *user_data);

char *uk_ue_communication_client_connection_get_uid(uk_ue_communication_context *context, void *connection);

bool uk_ue_communication_client_connection_set_uid(uk_ue_communication_context *context, void *connection, char *uid);

void *uk_ue_communication_client_connection_get_received_message(uk_ue_communication_context *context, void *connection);

void *uk_ue_communication_client_connection_get_message_to_send(uk_ue_communication_context *context, void *connection);

void *uk_ue_communication_client_connection_get_received_messages(uk_ue_communication_context *context, void *connection);

void *uk_ue_communication_client_connection_get_messages_to_send(uk_ue_communication_context *context, void *connection);

uk_ue_communication_connection_state uk_ue_communication_client_connection_get_state(uk_ue_communication_context *context, void *connection);

bool uk_ue_communication_client_connection_set_state(uk_ue_communication_context *context, void *connection, uk_ue_communication_connection_state state);

uk_ue_communication_metadata *uk_ue_communication_client_connection_get_communication_metadata(uk_ue_communication_context *context, void *connection);

uk_ue_communication_connection_direction uk_ue_communication_client_connection_get_direction(uk_ue_communication_context *context, void *connection);

bool uk_ue_communication_client_connection_set_direction(uk_ue_communication_context *context, void *connection,
    uk_ue_communication_connection_direction connection_direction);

/* Send and receive message for both client/server */

size_t uk_ue_communication_receive_sync(uk_ue_communication_context *context, void *connection, void *received_message);

size_t uk_ue_communication_send_sync(uk_ue_communication_context *context, void *connection, void *message_to_send);

/* Handle server functions */

void *uk_ue_communication_server_create(uk_ue_communication_context *context, void *parameters);

bool uk_ue_communication_server_is_valid(uk_ue_communication_context *context, void *server);

bool uk_ue_communication_server_is_running(uk_ue_communication_context *context, void *server);

bool uk_ue_communication_server_destroy(uk_ue_communication_context *context, void *server);

bool uk_ue_communication_server_process(uk_ue_communication_context *context, void *server);

bool uk_ue_communication_server_get_process_impl(uk_ue_communication_context *context, void (**communication_server_process_impl)(void *));

bool uk_ue_communication_server_disconnect(uk_ue_communication_context *context, void *server, void *connection);

bool uk_ue_communication_server_stop(uk_ue_communication_context *context, void *server);

int uk_ue_communication_server_get_connections_number(uk_ue_communication_context *context, void *server);

void *uk_ue_communication_server_get_connection(uk_ue_communication_context *context, void *server, int index);

#endif
