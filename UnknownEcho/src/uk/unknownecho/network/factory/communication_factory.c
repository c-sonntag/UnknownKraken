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

#include <uk/unknownecho/network/factory/communication_factory.h>
#include <uk/unknownecho/network/api/communication/communication.h>
#include <uk/unknownecho/network/api/communication/communication_metadata.h>
#include <uk/unknownecho/network/api/communication/communication_connection_direction.h>
#include <uk/unknownecho/network/api/socket/socket.h>
#include <uk/unknownecho/network/api/socket/socket_client_connection.h>
#include <uk/unknownecho/network/api/socket/socket_receive.h>
#include <uk/unknownecho/network/api/socket/socket_send.h>
#include <uk/unknownecho/network/api/socket/socket_client.h>
#include <uk/unknownecho/network/api/socket/socket_server.h>
#include <uk/unknownecho/network/api/socket/socket_client_connection_parameters.h>
#include <uk/unknownecho/network/api/socket/socket_server_parameters.h>
#include <uk/unknownecho/network/api/tls/tls_session.h>
#include <uk/unknownecho/defines.h>
#include <uk/utils/ueum.h>

#include <uk/utils/ei.h>

#include <stddef.h>
#include <string.h>
#include <stdarg.h>

#if defined(__unix__)
    #include <sys/socket.h>
#elif defined(_WIN32) || defined(_WIN64)
    #include <windows.h>
#else
    #error "OS not supported"
#endif

uk_ue_communication_context *uk_ue_communication_build_from_type(uk_ue_communication_type type) {
    uk_ue_communication_context *context;

    context = NULL;

    if (type == UnknownKrakenUnknownEcho_COMMUNICATION_TYPE_SOCKET) {
        if (!(context = uk_ue_communication_build_socket())) {
            uk_utils_stacktrace_push_msg("Failed to create socket communication context");
        }
    } else {
        uk_utils_stacktrace_push_msg("Unknown communication type");
    }

    return context;
}

uk_ue_communication_context *uk_ue_communication_build_socket() {
    uk_ue_communication_context *context;

    context = uk_ue_communication_create("SOCKET",
        (void *(*)(void *))uk_ue_socket_connect,
        (void (*)(void *))uk_ue_socket_client_connection_destroy,
        (void (*)(void *))uk_ue_socket_client_connection_clean_up,
        (bool (*)(void *))uk_ue_socket_client_connection_is_available,
        (bool (*)(void *))uk_ue_socket_client_connection_is_established,
        (void *(*)(void *))uk_ue_socket_client_connection_get_user_data,
        (bool (*)(void *, void *))uk_ue_socket_client_connection_set_user_data,
        (char *(*)(void *))uk_ue_socket_client_connection_get_nickname,
        (bool(*)(void *, char *))uk_ue_socket_client_connection_set_nickname,
        (void *(*)(void *))uk_ue_socket_client_connection_get_received_message,
        (void *(*)(void *))uk_ue_socket_client_connection_get_message_to_send,
        (void *(*)(void *))uk_ue_socket_client_connection_get_received_messages,
        (void *(*)(void *))uk_ue_socket_client_connection_get_messages_to_send,
        (uk_ue_communication_connection_state (*)(void *))uk_ue_socket_client_connection_get_state,
        (bool (*)(void *, uk_ue_communication_connection_state))uk_ue_socket_client_connection_set_state,
        (uk_ue_communication_metadata *(*)(void *))uk_ue_socket_client_connection_get_communication_metadata,
        (uk_ue_communication_connection_direction(*)(void *))uk_ue_socket_client_connection_get_direction,
        (bool (*)(void *, uk_ue_communication_connection_direction))uk_ue_socket_client_connection_set_direction,

        (size_t (*)(void *connection, void *))uk_ue_socket_receive_sync,
        (size_t (*)(void *, void *))uk_ue_socket_send_sync,

        (void *(*)(void *))uk_ue_socket_server_create,
        (bool (*)(void *))uk_ue_socket_server_is_valid,
        (bool (*)(void *))uk_ue_socket_server_is_running,
        (void (*)(void *))uk_ue_socket_server_destroy,
        (void (*)(void *))uk_ue_socket_server_process_polling,
        (bool (*)(void *, void *))uk_ue_socket_server_disconnect,
        (bool (*)(void *))uk_ue_socket_server_stop,
        (int (*)(void *))uk_ue_socket_server_get_connections_number,
        (void *(*)(void *, int ))uk_ue_socket_server_get_connection);

    if (!context) {
        uk_utils_stacktrace_push_msg("Failed to create communication context");
        return NULL;
    }

    return context;
}

void *uk_ue_communication_build_client_connection_parameters(uk_ue_communication_context *context,  int count, ...) {
    void *parameters;
    va_list ap;
    int fd, domain;
    const char *tls_server_host;
    unsigned short int tls_server_port;
    uk_crypto_tls_session *tls_session;

    uk_utils_check_parameter_or_return(context);
    uk_utils_check_parameter_or_return(count > 0);

    parameters = NULL;

    if (strcmp(context->communication_type, "SOCKET") == 0) {
        if (count != 2 && count != 3) {
            uk_utils_stacktrace_push_msg("Specified number of argments doesn't fit with communication type SOCKET");
            return NULL;
        }
        va_start(ap, count);
        fd = uk_ue_socket_open_tcp();
        domain = AF_INET;
        tls_server_host = va_arg(ap, const char *);
        tls_server_port = (unsigned short int)va_arg(ap, int);
        if (count == 2) {
            tls_session = NULL;
        } else {
            tls_session = va_arg(ap, uk_crypto_tls_session *);
        }
        va_end(ap);
        if (!(parameters = (void *)uk_ue_socket_client_connection_parameters_build(
            fd, domain, tls_server_host, tls_server_port, tls_session))) {
            uk_utils_stacktrace_push_msg("Failed to build socket client connection parameters");
        }
    } else {
        uk_utils_stacktrace_push_msg("Unknown communication type");
    }

    return parameters;
}

void *uk_ue_communication_build_server_parameters(uk_ue_communication_context *context,  int count, ...) {
    void *parameters;
    va_list ap;
    unsigned short int server_port;
    bool (*read_consumer)(uk_ue_socket_client_connection *connection);
    bool (*write_consumer)(uk_ue_socket_client_connection *connection);
    uk_crypto_tls_session *tls_session;

    if (!context) {
        uk_utils_stacktrace_push_msg("Specified context object is null");
        return false;
    }

    if (count <= 0) {
        uk_utils_stacktrace_push_msg("Specified parameter number is invalid");
        return false;
    }

    parameters = NULL;

    if (strcmp(context->communication_type, "SOCKET") == 0) {
        if (count != 3 && count != 4) {
            uk_utils_stacktrace_push_msg("Specified number of argments doesn't fit with communication type SOCKET");
            return NULL;
        }
        va_start(ap, count);
        server_port = (unsigned short int)va_arg(ap, int);
        read_consumer = va_arg(ap, bool (*)(uk_ue_socket_client_connection *));
        write_consumer = va_arg(ap, bool (*)(uk_ue_socket_client_connection *));
        if (count == 3) {
            tls_session = NULL;
        } else {
            tls_session = va_arg(ap, uk_crypto_tls_session *);
        }
        va_end(ap);
        if (!(parameters = uk_ue_socket_server_parameters_build(server_port, read_consumer, write_consumer, tls_session))) {
            uk_utils_stacktrace_push_msg("Failed to build socket server parameters");
        }
    } else {
        uk_utils_stacktrace_push_msg("Unknown communication type");
    }

    return parameters;
}

const char *uk_ue_communication_get_default_type() {
    return UnknownKrakenUnknownEcho_DEFAULT_COMMUNICATION_TYPE;
}
