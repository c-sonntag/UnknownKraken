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

#include <unknownecho/network/api/socket/socket_exchange.h>
#include <unknownecho/network/api/socket/socket_send.h>
#include <unknownecho/network/api/socket/socket_receive.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/check_parameter.h>
#include <unknownecho/errorHandling/logger.h>

bool ue_socket_exchange_send(ue_socket_client_connection *connection) {
    /*bool result;
    size_t sent, receive;

    ue_check_parameter_or_return(connection->fd > 0);
    ue_check_parameter_or_return(ue_byte_stream_get_size(connection->message_to_send) > 0);

    result = false;

    if ((sent = ue_socket_send_sync(connection)) <= 0) {
        ue_stacktrace_push_msg("Failed to send specified data in synchronous socket");
        return false;
    }

    ue_logger_trace("%d bytes sent, waiting for an ACK");

    if (receive = ue_socket_receive_sync()) {

    }

    result = true;

    return result;*/

    return false;
}

bool ue_socket_exchange_receive(ue_socket_client_connection *connection) {
    bool result;

    result = false;

    result = true;

    return result;
}
