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

#include <unknownecho/network/api/socket/socket_client.h>
#include <unknownecho/network/api/socket/socket_client_connection.h>
#include <unknownecho/network/api/socket/socket.h>
#include <unknownecho/network/api/tls/tls_connection.h>
#include <unknownecho/network/api/tls/tls_context.h>
#include <ueum/ueum.h>
#include <uecm/uecm.h>

#include <ei/ei.h>

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

ue_socket_client_connection *ue_socket_connect(ue_socket_client_connection_parameters *parameter) {
    struct sockaddr_in serv_addr;
    ue_socket_client_connection *connection;
    uecm_tls_connection *tls;

    tls = NULL;

    if (ue_socket_is_valid(parameter->fd) <= 0) {
        ei_stacktrace_push_msg("Specified socket fd isn't valid");
        return NULL;
    }

    if (!ue_socket_is_valid_domain(parameter->domain)) {
        ei_stacktrace_push_msg("Specified domain isn't valid");
        return NULL;
    }

    ei_check_parameter_or_return(parameter->host);
    ei_check_parameter_or_return(parameter->port > 0);

    serv_addr.sin_addr.s_addr = inet_addr(parameter->host);
    serv_addr.sin_family = parameter->domain;
    serv_addr.sin_port = htons(parameter->port);

    /* Connect the socket */
    if (connect(parameter->fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) != ERRORINTERCEPTOR_SUCCESS) {
        ei_stacktrace_push_errno();
        return NULL;
    }

    if (parameter->tls_session) {
        ei_logger_info("Keystore manager isn't null, so it will create a TLS connection");

        ei_logger_info("Creating TLS connection...");
        tls = uecm_tls_connection_create(parameter->tls_session->ctx);
        if (!tls) {
            ei_logger_error("Failed to create TLS connection");
            ei_stacktrace_push_msg("Failed to create tls connection");
            uecm_tls_connection_destroy(tls);
            return NULL;
        }
        ei_logger_info("TLS connection created");

        ei_logger_info("Setting socket file descriptor %d to TLS connection...", parameter->fd);
        if (!uecm_tls_connection_set_fd(tls, parameter->fd)) {
            ei_stacktrace_push_msg("Failed to set socket fd to tls connection");
            uecm_tls_connection_destroy(tls);
            return NULL;
        }
        ei_logger_info("Socket file descriptor linked to TLS connection");

        ei_logger_info("Establishing TLS connection...");
        if (!uecm_tls_connection_connect(tls)) {
            ei_stacktrace_push_msg("Failed to establish TLS connection");
            uecm_tls_connection_destroy(tls);
            return NULL;
        }
        ei_logger_info("TLS connection established");

        if (parameter->tls_session->verify_peer && !uecm_tls_connection_verify_peer_certificate(tls)) {
            ei_logger_error("Verify peer is enable but peer certificate isn't valid");
            ei_stacktrace_push_msg("Peer certificate verification failed");
            uecm_tls_connection_destroy(tls);
            return NULL;
        } else if (parameter->tls_session->verify_peer) {
            ei_logger_info("Verify peer is enable and peer certificate is valid");
        }
    } else {
        ei_logger_warn("Keystore manager is null, so it will create an unsecure connection");
    }

    if (!(connection = ue_socket_client_connection_init())) {
        ei_stacktrace_push_msg("Failed to create socket connection");
        uecm_tls_connection_destroy(tls);
        return NULL;
    }

    if (!ue_socket_client_connection_establish(connection, parameter->fd)) {
        ei_stacktrace_push_msg("Failed to establish socket connection");
        ue_socket_client_connection_destroy(connection);
        uecm_tls_connection_destroy(tls);
        return NULL;
    }

    if (parameter->tls_session) {
        connection->tls = tls;
        parameter->tls_session->tls = tls;
        if (parameter->tls_session->verify_peer) {
            connection->peer_certificate = uecm_tls_connection_get_peer_certificate(connection->tls);
        }
    }

    ei_logger_info("Socket connection is established");

    return connection;
}

ue_socket_client_connection *ue_socket_connect_s(ue_socket_client_connection_parameters *parameter) {
    ue_socket_client_connection *connection;

    parameter->domain = atoi(parameter->domain_s);
    parameter->port = atoi(parameter->port_s);

    if ((connection = ue_socket_connect(parameter)) == NULL) {

        ei_stacktrace_push_msg("Failed to connect socket from str parameters");
        return NULL;
    }

    return connection;
}
