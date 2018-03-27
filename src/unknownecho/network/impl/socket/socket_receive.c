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

#include <unknownecho/network/api/socket/socket_receive.h>
#include <unknownecho/network/api/socket/socket.h>
#include <unknownecho/network/api/tls/tls_connection_read.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/alloc.h>
#include <unknownecho/time/sleep.h>
#include <unknownecho/time/current_time.h>
#include <unknownecho/byte/byte_writer.h>

#include <string.h>

#if defined(__unix__)
    #include <sys/socket.h>
    #include <sys/types.h>
    #include <netdb.h>
    #include <netinet/in.h>
    #include <unistd.h>
    #include <sys/time.h>
    #include <fcntl.h>
#elif defined(_WIN32) || defined(_WIN64)
    #include <windows.h>
#else
    #error "OS not supported"
#endif

 size_t ue_socket_receive_sync(ue_socket_client_connection *connection) {
    struct timeval begin, now;
    double timediff;
    int timeout, received, total, bytes;

#if defined(_WIN32) || defined(_WIN64)
    char response[2048];
#else
    unsigned char response[2048];
#endif

    if (connection->fd <= 0) {
        ue_stacktrace_push_code(UNKNOWNECHO_INVALID_PARAMETER);
        return -1;
    }

    timeout = 1;

    if (!connection->tls) {
        memset(response, 0, sizeof(response));
        total = sizeof(response) - 1;
        received = 0;

        ue_socket_set_blocking_mode(connection->fd, true);

        ue_time_of_day(&begin);

        do {
            ue_time_of_day(&now);

            /* time elapsed in seconds */
            timediff = (now.tv_sec - begin.tv_sec) + 1e-6 * (now.tv_usec - begin.tv_usec);

            /* if you got some data, then break after timeout */
            if (received > 0 && timediff > timeout) {
                ue_logger_debug("ue_socket_receive_sync() received > 0 && timediff > timeout. break");
                break;
            }
            /* if you got no data at all, wait a little longer, twice the timeout */
            else if (timediff > timeout) {
                ue_logger_debug("ue_socket_receive_sync() timediff > timeout. break.");
                break;
            }

            memset(response, 0, sizeof(response));

#if defined(_WIN32) || defined(_WIN64)
            if ((bytes = recv((SOCKET)connection->fd, response, 2048, 0)) <= 0) {
#else
            if ((bytes = recv(connection->fd, response, 2048, 0)) <= 0) {
#endif
                /* if nothing was received then we want to wait a little before trying again, 1 ms */
                ue_millisleep(1);
            }
            else {
                received += bytes;
                /* reset beginning time  */
                ue_time_of_day(&begin);
                if (!ue_byte_writer_append_bytes(connection->received_message, (unsigned char *)response, bytes)) {
                    ue_stacktrace_push_msg("Failed to append in byte stream socket response");
                    return -1;
                }
                break;
            }
        } while (1);

        if (received == total) {
            ue_stacktrace_push_msg("Failed storing complete response from socket");
            return -1;
        }
    } else {
        received = ue_tls_connection_read_sync(connection->tls, connection->received_message);
    }

    ue_logger_trace("%ld bytes received", received);

    return received;
}

size_t ue_socket_receive_all_sync(int fd, unsigned char **bytes, size_t size, ue_tls_connection *tls) {
    size_t received, total;
#if defined(_WIN32) || defined(_WIN64)
        char **temp_bytes = NULL;
#endif

    received = -1;

    if (fd <= 0) {
        ue_stacktrace_push_code(UNKNOWNECHO_INVALID_PARAMETER);
        return -1;
    }

    if (!tls) {
#if defined(__unix__)
        ue_safe_alloc(*bytes, unsigned char, size);
#elif defined(_WIN32) || defined(_WIN64)
        ue_safe_alloc(*temp_bytes, char, size);
#endif
        for (total = 0; total < size;) {
#if defined(__unix__)
            received = recv(fd, bytes[total], size - total, MSG_WAITALL);
#elif defined(_WIN32) || defined(_WIN64)
            received = recv((SOCKET)fd, temp_bytes[total], size - total, 0x8);
#endif
            if (received < 0) {
                ue_safe_free(*bytes);
                return -1;
            }
            total += received;
        }
    } else {

    }

#if defined(_WIN32) || defined(_WIN64)
    bytes = (unsigned char **)temp_bytes;
#endif

    return received;
}

size_t ue_socket_receive_async(int fd, bool (*flow_consumer)(void *flow, size_t flow_size), ue_tls_connection *tls) {
    size_t received, total, bytes;
    char response[4096];

    if (fd <= 0 || !flow_consumer) {
        ue_stacktrace_push_code(UNKNOWNECHO_INVALID_PARAMETER);
        return -1;
    }

    if (!tls) {
        memset(response, 0, sizeof(response));
        total = sizeof(response) - 1;
        received = 0;

        do {
            memset(response, 0, sizeof(response));
            bytes = recv(fd, response, 1024, 0);
            if (bytes < 0) {
                ue_stacktrace_push_errno();
                return -1;
            }
            if (bytes == 0) {
                break;
            }
            received += bytes;
            if (!flow_consumer(response, bytes)) {
                ue_stacktrace_push_msg("Flow consumer failed");
                return -1;
            }
        } while (1);

        if (received == total) {
            ue_stacktrace_push_msg("Failed storing complete response from socket");
            return -1;
        }
    } else {
        received = ue_tls_connection_read_async(tls, flow_consumer);
    }

    ue_logger_trace("%ld bytes received", received);

    return received;
}
