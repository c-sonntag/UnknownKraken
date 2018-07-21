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

#include <unknownecho/network/api/socket/socket_exchange.h>
#include <unknownecho/network/api/socket/socket_send.h>
#include <unknownecho/network/api/socket/socket_receive.h>
#include <ueum/ueum.h>
#include <ei/ei.h>

#include <stddef.h>
#include <string.h>

bool ue_socket_exchange_send(ue_socket_client_connection *connection, ueum_byte_stream *message_to_send) {
    bool result;
    size_t sent, received;
    ueum_byte_stream *received_message;

    ei_check_parameter_or_return(connection->fd > 0);
    ei_check_parameter_or_return(ueum_byte_stream_get_size(connection->message_to_send) > 0);

    result = false;
    received_message = ueum_byte_stream_create();

    if ((sent = ue_socket_send_sync(connection, message_to_send)) <= 0) {
        ei_stacktrace_push_msg("Failed to send specified data in synchronous socket");
        goto clean_up;
    }

    ei_logger_trace("%d bytes sent, waiting for an ACK", sent);

    if ((received = ue_socket_receive_sync(connection, received_message)) <= 0) {
        ei_stacktrace_push_msg("Failed to receive ACK response, the connection was interrupted");
        goto clean_up;
    }

    ei_logger_trace("%d bytes received for the ACK message", received);

    if (memcmp(ueum_byte_stream_get_data(received_message), "ACK", 3) != 0) {
        ei_stacktrace_push_msg("Received message isn't an valid ACK response");
        goto clean_up;
    }

    result = true;

clean_up:
    ueum_byte_stream_destroy(received_message);
    return result;
}

bool ue_socket_exchange_receive(ue_socket_client_connection *connection, ueum_byte_stream *received_message) {
    bool result;
    size_t received, sent;
    ueum_byte_stream *message_to_send;

    result = false;
    message_to_send = ueum_byte_stream_create();

    if ((received = ue_socket_receive_sync(connection, received_message)) <= 0) {
        ei_stacktrace_push_msg("Failed to receive ACK response, connection was interrupted");
        goto clean_up;
    }

    ei_logger_trace("%d bytes received, sending ACK response...", received);

    ueum_byte_writer_append_string(message_to_send, "ACK");

    if ((sent = ue_socket_send_sync(connection, message_to_send)) <= 0) {
        ei_stacktrace_push_msg("Failed to send ACK repsonse, the connection was interrupted");
        goto clean_up;
    }

    ei_logger_trace("%d bytes sent for the ACK response", sent);

    result = true;

clean_up:
    ueum_byte_stream_destroy(message_to_send);
    return result;
}
