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

#include <uk/unknownecho/network/api/socket/socket_send.h>
#include <uk/unknownecho/network/api/tls/tls_connection_write.h>
#include <uk/unknownecho/network/api/tls/tls_connection.h>
#include <uk/utils/ueum.h>
#include <uk/utils/ei.h>

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

size_t uk_ue_socket_send_sync(uk_ue_socket_client_connection *connection, uk_utils_byte_stream *message_to_send) {
    size_t sent, size;
    unsigned char *data;

    #if defined(__unix__)
        size_t bytes;
    #elif defined(_WIN32) || defined(_WIN64)
        char *error_buffer;
    #endif

    uk_utils_check_parameter_or_return(connection->fd > 0);
    uk_utils_check_parameter_or_return(uk_utils_byte_stream_get_size(message_to_send) > 0);

    data = uk_utils_byte_stream_get_data(message_to_send);
    size = uk_utils_byte_stream_get_size(message_to_send);
    sent = 0;

    if (!connection->tls) {
        #if defined(__unix__)
            sent = 0;
            do {
                bytes = write(connection->fd, data + sent, size - sent);
                if (bytes < 0) {
                    uk_utils_stacktrace_push_errno();
                    return -1;
                }
                if (bytes == 0) {
                    break;
                }
                sent += bytes;
            } while (sent < size);
        #elif defined(_WIN32) || defined(_WIN64)
            if((sent = send((SOCKET)connection->fd, (char *)data, size, 0)) < 0) {
                uk_utils_get_last_wsa_error(error_buffer);
                uk_utils_stacktrace_push_msg(error_buffer);
                uk_utils_safe_free(error_buffer);
                return -1;
            }
        #else
            #error "OS not supported"
        #endif
    } else {
        sent = uk_crypto_tls_connection_write_sync(connection->tls, data, size);
    }

    uk_utils_logger_trace("%lu bytes sent", sent);

    return sent;
}
