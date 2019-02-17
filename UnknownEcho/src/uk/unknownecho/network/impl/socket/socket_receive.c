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

#include <uk/unknownecho/network/api/socket/socket_receive.h>
#include <uk/unknownecho/network/api/socket/socket.h>
#include <uk/unknownecho/network/api/tls/tls_connection_read.h>
#include <uk/utils/ueum.h>
#include <uk/utils/ei.h>

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

 size_t uk_ue_socket_receive_sync(uk_ue_socket_client_connection *connection, uk_utils_byte_stream *received_message) {
    struct timeval begin, now;
    double timediff;
    int timeout, received, total, bytes;

#if defined(_WIN32) || defined(_WIN64)
    char response[4096];
#else
    unsigned char response[4096];
#endif

    if (connection->fd <= 0) {
        uk_utils_stacktrace_push_code(UnknownKrakenUtils_INVALID_PARAMETER);
        return -1;
    }

    timeout = 1;

    if (!connection->tls) {
        memset(response, 0, sizeof(response));
        total = sizeof(response) - 1;
        received = 0;

        uk_ue_socket_set_blocking_mode(connection->fd, true);

        uk_utils_time_of_day(&begin);

        do {
            uk_utils_time_of_day(&now);

            /* time elapsed in seconds */
            timediff = (now.tv_sec - begin.tv_sec) + 1e-6 * (now.tv_usec - begin.tv_usec);

            /* if you got some data, then break after timeout */
            if (received > 0 && timediff > timeout) {
                uk_utils_logger_debug("uk_ue_socket_receive_sync() received > 0 && timediff > timeout. break");
                break;
            }
            /* if you got no data at all, wait a little longer, twice the timeout */
            else if (timediff > timeout) {
                uk_utils_logger_debug("uk_ue_socket_receive_sync() timediff > timeout. break.");
                break;
            }

            memset(response, 0, sizeof(response));

#if defined(_WIN32) || defined(_WIN64)
            if ((bytes = recv((SOCKET)connection->fd, response, 4096, 0)) <= 0) {
#else
            if ((bytes = recv(connection->fd, response, 4096, 0)) <= 0) {
#endif
                /* if nothing was received then we want to wait a little before trying again, 1 ms */
                uk_utils_millisleep(1);
            }
            else {
                received += bytes;
                /* reset beginning time  */
                uk_utils_time_of_day(&begin);
                if (!uk_utils_byte_writer_append_bytes(received_message, (unsigned char *)response, bytes)) {
                    uk_utils_stacktrace_push_msg("Failed to append in byte stream socket response");
                    return -1;
                }
                break;
            }
        } while (1);

        if (received == total) {
            uk_utils_stacktrace_push_msg("Failed storing complete response from socket");
            return -1;
        }
    } else {
        received = uk_crypto_tls_connection_read_sync(connection->tls, received_message);
    }

    uk_utils_logger_trace("%ld bytes received", received);

    return received;
}

size_t uk_ue_socket_receive_all_sync(int fd, unsigned char **bytes, size_t size, uk_crypto_tls_connection *tls) {
    size_t received, total;
#if defined(_WIN32) || defined(_WIN64)
        char **temp_bytes = NULL;
#endif

    if (fd <= 0) {
        uk_utils_stacktrace_push_code(UnknownKrakenUtils_INVALID_PARAMETER);
        return -1;
    }

    received = -1;
    *bytes = NULL;

    if (!tls) {
#if defined(__unix__)
        uk_utils_safe_alloc(*bytes, unsigned char, size);
#elif defined(_WIN32) || defined(_WIN64)
    *temp_bytes = NULL;
    uk_utils_safe_alloc(*temp_bytes, char, size);
#endif
        for (total = 0; total < size;) {
#if defined(__unix__)
            received = recv(fd, bytes[total], size - total, MSG_WAITALL);
#elif defined(_WIN32) || defined(_WIN64)
            received = recv((SOCKET)fd, temp_bytes[total], size - total, 0x8);
#endif
            if (received < 0) {
                uk_utils_safe_free(*bytes);
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

size_t uk_ue_socket_receive_async(int fd, bool (*flow_consumer)(void *flow, size_t flow_size), uk_crypto_tls_connection *tls) {
    size_t received, total, bytes;
    char response[1024];

    if (fd <= 0 || !flow_consumer) {
        uk_utils_stacktrace_push_code(UnknownKrakenUtils_INVALID_PARAMETER);
        return -1;
    }

    if (!tls) {
        memset(response, 0, sizeof(response));
        total = sizeof(response) - 1;
        received = 0;

        do {
            memset(response, 0, sizeof(response));
            //bytes = recv(fd, response, 4096, 0);
            bytes = recv(fd, response, 1024, 0);
            if (bytes < 0) {
                uk_utils_stacktrace_push_errno();
                return -1;
            }
            if (bytes == 0) {
                break;
            }
            received += bytes;
            if (!flow_consumer(response, bytes)) {
                uk_utils_stacktrace_push_msg("Flow consumer failed");
                return -1;
            }
        } while (1);

        if (received == total) {
            uk_utils_stacktrace_push_msg("Failed storing complete response from socket");
            return -1;
        }
    } else {
        received = uk_crypto_tls_connection_read_async(tls, flow_consumer);
    }

    uk_utils_logger_trace("%ld bytes received", received);

    return received;
}
