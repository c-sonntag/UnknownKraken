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

#include <unknownecho/network/api/socket/socket_send.h>
#include <unknownecho/network/api/tls/tls_connection_write.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/check_parameter.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/alloc.h>
#include <unknownecho/network/api/tls/tls_connection.h>
#include <unknownecho/byte/byte_stream.h>

#include <limits.h>

#if defined(__unix__)
    #include <sys/socket.h>
    #include <sys/types.h>
    #include <netdb.h>
    #include <netinet/in.h>
    #include <unistd.h>
#elif defined(_WIN32) || defined(_WIN64)
    #include <windows.h>
#else
    #error "OS not supported"
#endif

size_t ue_socket_send_sync(ue_socket_client_connection *connection) {
    size_t sent, size;
    unsigned char *data;

    #if defined(__unix__)
        size_t bytes;
    #elif defined(_WIN32) || defined(_WIN64)
        char *error_buffer;
    #endif

    ue_check_parameter_or_return(connection->fd > 0);
    ue_check_parameter_or_return(ue_byte_stream_get_size(connection->message_to_send) > 0);

    data = ue_byte_stream_get_data(connection->message_to_send);
    size = ue_byte_stream_get_size(connection->message_to_send);
    sent = 0;

    if (!connection->tls) {
        #if defined(__unix__)
            sent = 0;
            do {
                bytes = write(connection->fd, data + sent, size - sent);
                if (bytes < 0) {
                    ue_stacktrace_push_errno();
                    return -1;
                }
                if (bytes == 0) {
                    break;
                }
                sent += bytes;
            } while (sent < size);
        #elif defined(_WIN32) || defined(_WIN64)
            if((sent = send((SOCKET)connection->fd, (char *)data, size, 0)) < 0) {
                ue_get_last_wsa_error(error_buffer);
                ue_stacktrace_push_msg(error_buffer);
                ue_safe_free(error_buffer);
                return -1;
            }
        #else
            #error "OS not supported"
        #endif
    } else {
        sent = ue_tls_connection_write_sync(connection->tls, data, size);
    }

    ue_logger_trace("%lu bytes sent", sent);
    /*for (size_t i = 0; i < sent; i++) {
        printf("%02X ", ue_byte_stream_get_data(connection->message_to_send)[i]);
    }
    printf("\n");*/

    return sent;
}
