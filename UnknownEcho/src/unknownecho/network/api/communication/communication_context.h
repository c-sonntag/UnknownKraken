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

#ifndef UNKNOWNECHO_COMMUNICATION_CONTEXT_H
#define UNKNOWNECHO_COMMUNICATION_CONTEXT_H

#include <ueum/ueum.h>
#include <unknownecho/network/api/communication/communication_connection_state.h>
#include <unknownecho/network/api/communication/communication_metadata.h>
#include <unknownecho/network/api/communication/communication_connection_direction.h>

#include <stddef.h>

typedef struct {
    /**
     * Supported type :
     * - SOCKET
     */
    const char *communication_type;

    /* Implementations of communication functions */

    /* Handle connection as a client */
    void *(*communication_connect_impl)(void *parameter);
    void (*communication_client_connection_destroy_impl)(void *connection);
    void (*communication_client_connection_clean_up_impl)(void *connection);
    bool (*communication_client_connection_is_available_impl)(void *connection);
    bool (*communication_client_connection_is_established_impl)(void *connection);
    void *(*communication_client_connection_get_user_data_impl)(void *connection);
    bool (*communication_client_connection_set_user_data_impl)(void *connection, void *user_data);
    char *(*communication_client_connection_get_uid_impl)(void *connection);
    bool (*communication_client_connection_set_uid_impl)(void *connection, char *uid);
    void *(*communication_client_connection_get_received_message_impl)(void *connection);
    void *(*communication_client_connection_get_message_to_send_impl)(void *connection);
    void *(*communication_client_connection_get_received_messages_impl)(void *connection);
    void *(*communication_client_connection_get_messages_to_send_impl)(void *connection);
    ue_communication_connection_state (*communication_client_connection_get_state_impl)(void *connection);
    bool (*communication_client_connection_set_state_impl)(void *connection, ue_communication_connection_state state);
    ue_communication_metadata *(*communication_client_connection_get_communication_metadata_impl)(void *connection);
    ue_communication_connection_direction (*communication_client_connection_get_direction_impl)(void *connection);
    bool (*communication_client_connection_set_direction_impl)(void *connection, ue_communication_connection_direction
        connection_direction);

    /* Send and receive message for both client/server */
    size_t (*communication_receive_sync_impl)(void *connection, void *received_message);
    size_t (*communication_send_sync_impl)(void *connection, void *message_to_send);

    /* Handle server functions */
    void *(*communication_server_create_impl)(void *parameters);
    bool (*communication_server_is_valid_impl)(void *server);
    bool (*communication_server_is_running_impl)(void *server);
    void (*communication_server_destroy_impl)(void *server);
    void (*communication_server_process_impl)(void *server);
    bool (*communication_server_disconnect_impl)(void *server, void *connection);
    bool (*communication_server_stop_impl)(void *server);
    int (*communication_server_get_connections_number_impl)(void *server);
    void *(*communication_server_get_connection_impl)(void *server, int index);
} ue_communication_context;

#endif