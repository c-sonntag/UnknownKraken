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

#include <uk/unknownecho/network/api/socket/socket_exchange.h>
#include <uk/unknownecho/network/api/socket/socket_send.h>
#include <uk/unknownecho/network/api/socket/socket_receive.h>
#include <uk/utils/ueum.h>
#include <uk/utils/ei.h>

#include <stddef.h>
#include <string.h>

bool uk_ue_socket_exchange_send(uk_ue_socket_client_connection *connection, uk_utils_byte_stream *message_to_send) {
    bool result;
    size_t sent, received;
    uk_utils_byte_stream *received_message;

    uk_utils_check_parameter_or_return(connection->fd > 0);
    uk_utils_check_parameter_or_return(uk_utils_byte_stream_get_size(connection->message_to_send) > 0);

    result = false;
    received_message = uk_utils_byte_stream_create();

    if ((sent = uk_ue_socket_send_sync(connection, message_to_send)) <= 0) {
        uk_utils_stacktrace_push_msg("Failed to send specified data in synchronous socket");
        goto clean_up;
    }

    uk_utils_logger_trace("%d bytes sent, waiting for an ACK", sent);

    if ((received = uk_ue_socket_receive_sync(connection, received_message)) <= 0) {
        uk_utils_stacktrace_push_msg("Failed to receive ACK response, the connection was interrupted");
        goto clean_up;
    }

    uk_utils_logger_trace("%d bytes received for the ACK message", received);

    if (memcmp(uk_utils_byte_stream_get_data(received_message), "ACK", 3) != 0) {
        uk_utils_stacktrace_push_msg("Received message isn't an valid ACK response");
        goto clean_up;
    }

    result = true;

clean_up:
    uk_utils_byte_stream_destroy(received_message);
    return result;
}

bool uk_ue_socket_exchange_receive(uk_ue_socket_client_connection *connection, uk_utils_byte_stream *received_message) {
    bool result;
    size_t received, sent;
    uk_utils_byte_stream *message_to_send;

    result = false;
    message_to_send = uk_utils_byte_stream_create();

    if ((received = uk_ue_socket_receive_sync(connection, received_message)) <= 0) {
        uk_utils_stacktrace_push_msg("Failed to receive ACK response, connection was interrupted");
        goto clean_up;
    }

    uk_utils_logger_trace("%d bytes received, sending ACK response...", received);

    uk_utils_byte_writer_append_string(message_to_send, "ACK");

    if ((sent = uk_ue_socket_send_sync(connection, message_to_send)) <= 0) {
        uk_utils_stacktrace_push_msg("Failed to send ACK repsonse, the connection was interrupted");
        goto clean_up;
    }

    uk_utils_logger_trace("%d bytes sent for the ACK response", sent);

    result = true;

clean_up:
    uk_utils_byte_stream_destroy(message_to_send);
    return result;
}
