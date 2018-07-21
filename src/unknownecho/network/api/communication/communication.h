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

#ifndef UNKNOWNECHO_COMMUNICATION_H
#define UNKNOWNECHO_COMMUNICATION_H

#include <unknownecho/network/api/communication/communication_context.h>
#include <unknownecho/network/api/communication/communication_metadata.h>
#include <unknownecho/network/api/communication/communication_connection_direction.h>
#include <ueum/ueum.h>

#include <stddef.h>

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
    ue_communication_metadata *(*communication_client_connection_get_communication_metadata_impl)(void *connection),
    ue_communication_connection_direction (*communication_client_connection_get_direction_impl)(void *connection),
    bool (*communication_client_connection_set_direction_impl)(void *connection, ue_communication_connection_direction
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

void ue_communication_destroy(ue_communication_context *context);

bool ue_communication_context_is_valid(ue_communication_context *context);

/* Handle connection as a client */

void *ue_communication_connect(ue_communication_context *context, void *parameter);

bool ue_communication_client_connection_destroy(ue_communication_context *context, void *connection);

bool ue_communication_client_connection_clean_up(ue_communication_context *context, void *connection);

bool ue_communication_client_connection_is_available(ue_communication_context *context, void *connection);

bool ue_communication_client_connection_is_established(ue_communication_context *context, void *connection);

void *ue_communication_client_connection_get_user_data(ue_communication_context *context, void *connection);

bool ue_communication_client_connection_set_user_data(ue_communication_context *context, void *connection, void *user_data);

char *ue_communication_client_connection_get_uid(ue_communication_context *context, void *connection);

bool ue_communication_client_connection_set_uid(ue_communication_context *context, void *connection, char *uid);

void *ue_communication_client_connection_get_received_message(ue_communication_context *context, void *connection);

void *ue_communication_client_connection_get_message_to_send(ue_communication_context *context, void *connection);

void *ue_communication_client_connection_get_received_messages(ue_communication_context *context, void *connection);

void *ue_communication_client_connection_get_messages_to_send(ue_communication_context *context, void *connection);

ue_communication_connection_state ue_communication_client_connection_get_state(ue_communication_context *context, void *connection);

bool ue_communication_client_connection_set_state(ue_communication_context *context, void *connection, ue_communication_connection_state state);

ue_communication_metadata *ue_communication_client_connection_get_communication_metadata(ue_communication_context *context, void *connection);

ue_communication_connection_direction ue_communication_client_connection_get_direction(ue_communication_context *context, void *connection);

bool ue_communication_client_connection_set_direction(ue_communication_context *context, void *connection,
    ue_communication_connection_direction connection_direction);

/* Send and receive message for both client/server */

size_t ue_communication_receive_sync(ue_communication_context *context, void *connection, void *received_message);

size_t ue_communication_send_sync(ue_communication_context *context, void *connection, void *message_to_send);

/* Handle server functions */

void *ue_communication_server_create(ue_communication_context *context, void *parameters);

bool ue_communication_server_is_valid(ue_communication_context *context, void *server);

bool ue_communication_server_is_running(ue_communication_context *context, void *server);

bool ue_communication_server_destroy(ue_communication_context *context, void *server);

bool ue_communication_server_process(ue_communication_context *context, void *server);

bool ue_communication_server_get_process_impl(ue_communication_context *context, void (**communication_server_process_impl)(void *));

bool ue_communication_server_disconnect(ue_communication_context *context, void *server, void *connection);

bool ue_communication_server_stop(ue_communication_context *context, void *server);

int ue_communication_server_get_connections_number(ue_communication_context *context, void *server);

void *ue_communication_server_get_connection(ue_communication_context *context, void *server, int index);

#endif
