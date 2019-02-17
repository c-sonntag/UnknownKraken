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

#include <uk/unknownecho/network/api/socket/socket_client.h>
#include <uk/unknownecho/network/api/socket/socket_client_connection.h>
#include <uk/unknownecho/network/api/socket/socket.h>
#include <uk/unknownecho/network/api/tls/tls_connection.h>
#include <uk/unknownecho/network/api/tls/tls_context.h>
#include <uk/utils/ueum.h>
#include <uk/crypto/uecm.h>

#include <uk/utils/ei.h>

#include <string.h>

#if defined(__unix__)
    #include <sys/socket.h>
    #include <sys/types.h>
    #include <netdb.h>
    #include <netinet/in.h>
    #include <unistd.h>
    #include <arpa/inet.h>
#elif defined(_WIN32) || defined(_WIN64)
    #include <windows.h>
#else
    #error "OS not supported"
#endif

uk_ue_socket_client_connection *uk_ue_socket_connect(uk_ue_socket_client_connection_parameters *parameter) {
    struct sockaddr_in serv_addr;
    uk_ue_socket_client_connection *connection;
    uk_crypto_tls_connection *tls;

    tls = NULL;

    if (uk_ue_socket_is_valid(parameter->fd) <= 0) {
        uk_utils_stacktrace_push_msg("Specified socket fd isn't valid");
        return NULL;
    }

    if (!uk_ue_socket_is_valid_domain(parameter->domain)) {
        uk_utils_stacktrace_push_msg("Specified domain isn't valid");
        return NULL;
    }

    uk_utils_check_parameter_or_return(parameter->host);
    uk_utils_check_parameter_or_return(parameter->port > 0);

    serv_addr.sin_addr.s_addr = inet_addr(parameter->host);
    serv_addr.sin_family = parameter->domain;
    serv_addr.sin_port = htons(parameter->port);

    /* Connect the socket */
    if (connect(parameter->fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) != UnknownKrakenUtils_SUCCESS) {
        uk_utils_stacktrace_push_errno();
        return NULL;
    }

    if (parameter->tls_session) {
        uk_utils_logger_info("Keystore manager isn't null, so it will create a TLS connection");

        uk_utils_logger_info("Creating TLS connection...");
        tls = uk_crypto_tls_connection_create(parameter->tls_session->ctx);
        if (!tls) {
            uk_utils_logger_error("Failed to create TLS connection");
            uk_utils_stacktrace_push_msg("Failed to create tls connection");
            uk_crypto_tls_connection_destroy(tls);
            return NULL;
        }
        uk_utils_logger_info("TLS connection created");

        uk_utils_logger_info("Setting socket file descriptor %d to TLS connection...", parameter->fd);
        if (!uk_crypto_tls_connection_set_fd(tls, parameter->fd)) {
            uk_utils_stacktrace_push_msg("Failed to set socket fd to tls connection");
            uk_crypto_tls_connection_destroy(tls);
            return NULL;
        }
        uk_utils_logger_info("Socket file descriptor linked to TLS connection");

        uk_utils_logger_info("Establishing TLS connection...");
        if (!uk_crypto_tls_connection_connect(tls)) {
            uk_utils_stacktrace_push_msg("Failed to establish TLS connection");
            uk_crypto_tls_connection_destroy(tls);
            return NULL;
        }
        uk_utils_logger_info("TLS connection established");

        if (parameter->tls_session->verify_peer && !uk_crypto_tls_connection_verify_peer_certificate(tls)) {
            uk_utils_logger_error("Verify peer is enable but peer certificate isn't valid");
            uk_utils_stacktrace_push_msg("Peer certificate verification failed");
            uk_crypto_tls_connection_destroy(tls);
            return NULL;
        } else if (parameter->tls_session->verify_peer) {
            uk_utils_logger_info("Verify peer is enable and peer certificate is valid");
        }
    } else {
        uk_utils_logger_warn("Keystore manager is null, so it will create an unsecure connection");
    }

    if (!(connection = uk_ue_socket_client_connection_init())) {
        uk_utils_stacktrace_push_msg("Failed to create socket connection");
        uk_crypto_tls_connection_destroy(tls);
        return NULL;
    }

    if (!uk_ue_socket_client_connection_establish(connection, parameter->fd)) {
        uk_utils_stacktrace_push_msg("Failed to establish socket connection");
        uk_ue_socket_client_connection_destroy(connection);
        uk_crypto_tls_connection_destroy(tls);
        return NULL;
    }

    if (parameter->tls_session) {
        connection->tls = tls;
        parameter->tls_session->tls = tls;
        if (parameter->tls_session->verify_peer) {
            connection->peer_certificate = uk_crypto_tls_connection_get_peer_certificate(connection->tls);
        }
    }

    uk_utils_logger_info("Socket connection is established");

    return connection;
}

uk_ue_socket_client_connection *uk_ue_socket_connect_s(uk_ue_socket_client_connection_parameters *parameter) {
    uk_ue_socket_client_connection *connection;

    parameter->domain = atoi(parameter->domain_s);
    parameter->port = atoi(parameter->port_s);

    if ((connection = uk_ue_socket_connect(parameter)) == NULL) {

        uk_utils_stacktrace_push_msg("Failed to connect socket from str parameters");
        return NULL;
    }

    return connection;
}
