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

#include <unknownecho/network/api/socket/socket_server.h>
#include <unknownecho/network/api/socket/socket.h>
#include <unknownecho/network/api/socket/socket_client_connection.h>
#include <unknownecho/network/api/communication/communication_metadata.h>
#include <unknownecho/network/api/tls/tls_connection.h>
#include <ueum/ueum.h>
#include <uecm/uecm.h>
#include <ei/ei.h>

#include <string.h>
#include <errno.h>

#if defined(__unix__)
    #include <sys/socket.h>
    #include <sys/types.h>
    #include <netdb.h>
    #include <netinet/in.h>
    #include <unistd.h>
    #include <sys/select.h>
#elif defined(_WIN32) || defined(_WIN64)
    #include <windows.h>
#else
    #error "OS not supported"
#endif

#define DEFAULT_CONNECTIONS_NUMBER 10
#define DEFAULT_SIMULTANEOUS_CONNECTIONS_NUMBER 5

bool ue_socket_listen(ue_socket_server *server);

int ue_socket_accept(int ue_socket_fd, struct sockaddr *sa);

bool ue_socket_bind(int ue_socket_fd, int domain, unsigned short int port);

bool ue_socket_bind_s(int ue_socket_fd, const char *domain, const char *port);

void ue_socket_server_process_connection(ue_socket_server *server, ue_socket_client_connection *connection, fd_set *read_set, fd_set *write_set);

void init_select(ue_socket_server *server, int *max_fd, fd_set *read_set, fd_set *write_set);


ue_socket_server *ue_socket_server_create(ue_socket_server_parameters *parameters) {

    ue_socket_server *server;
    int i;

    server = NULL;

    ueum_safe_alloc_or_goto(server, ue_socket_server, 1, clean_up);

    server->tls_session = parameters->tls_session;
    if ((server->ue_socket_fd = ue_socket_open_tcp()) == -1) {
        ei_stacktrace_push_msg("Failed to create main socket context");
        goto clean_up;
    }
    server->connections_number = DEFAULT_CONNECTIONS_NUMBER;
    server->simultaneous_connections_number = DEFAULT_SIMULTANEOUS_CONNECTIONS_NUMBER;
    server->read_consumer = parameters->read_consumer;
    server->write_consumer = parameters->write_consumer;
    ueum_safe_alloc_or_goto(server->connections, ue_socket_client_connection *, server->connections_number, clean_up);
    for (i = 0; i < server->connections_number; i++) {
        if ((server->connections[i] = ue_socket_client_connection_init()) == NULL) {
            ei_stacktrace_push_msg("Failed to init client connections");
            goto clean_up;
        }
    }

    if (!ue_socket_bind(server->ue_socket_fd, AF_INET, parameters->port)) {
        ei_stacktrace_push_msg("Failed to bind socket to this port");
        goto clean_up;
    }

    if (!ue_socket_listen(server)) {
        ei_stacktrace_push_msg("Failed to listen socket to this port");
        goto clean_up;
    }

    server->running = true;

    return server;

clean_up:
    ue_socket_server_destroy(server);
    return NULL;
}

void ue_socket_server_destroy(ue_socket_server *server) {
    int i;

    if (server) {
        if (server->connections) {
            for (i = 0; i < server->connections_number; i++) {
                if (server->connections[i]->tls) {
                    uecm_tls_connection_destroy(server->connections[i]->tls);
                    server->connections[i]->tls = NULL;
                }
                ue_socket_client_connection_destroy(server->connections[i]);
                server->connections[i] = NULL;
            }
            ueum_safe_free(server->connections);
        }
        ue_socket_close(server->ue_socket_fd);
        ueum_safe_free(server);
    }
}

bool ue_socket_server_is_valid(ue_socket_server *server) {
    if (!server) {
        ei_logger_trace("Specified server object is null");
    }

    if (!ue_socket_is_valid(server->ue_socket_fd)) {
        ei_logger_trace("Socket context of server isn't valid");
        return false;
    }

    if (!server->connections) {
        ei_logger_trace("Socket client connections are null");
        return false;
    }

    if (!server->read_consumer) {
        ei_logger_trace("Read consumer function is null");
        return false;
    }

    if (!server->write_consumer) {
        ei_logger_trace("Write consumer function is null");
        return false;
    }

    if (!server->running) {
        ei_logger_trace("Server isn't running");
        return false;
    }

    return true;
}

bool ue_socket_server_is_running(ue_socket_server *server) {
    return server && server->running;
}

bool ue_socket_listen(ue_socket_server *server) {
    if (listen(server->ue_socket_fd, server->connections_number) != 0) {
        ei_stacktrace_push_errno();
        return false;
    }
    return true;
}

int ue_socket_accept(int ue_socket_fd, struct sockaddr *sa) {
    int new_socket;

#if defined(__unix__)
    socklen_t addrlen;
#elif defined(_WIN32) || defined(_WIN64)
    int addrlen;
#endif

    addrlen = sizeof(struct sockaddr_in);

    if ((new_socket = accept(ue_socket_fd, (struct sockaddr *) sa, &addrlen)) <= 0) {
        ei_stacktrace_push_msg("Failed to accept this socket");
        return -1;
    }

    return new_socket;
}

bool ue_socket_server_accept(ue_socket_server *server) {
    struct sockaddr sa;
    int new_socket, i;
    bool established;
    uecm_tls_connection *peer_tls;
    uecm_x509_certificate *certificate;
    const char *communication_metadata_string;

    established = false;
    peer_tls = NULL;
    certificate = NULL;
    communication_metadata_string = NULL;

    if ((new_socket = ue_socket_accept(server->ue_socket_fd, &sa)) <= 0) {
        ei_stacktrace_push_msg("Failed to accept this socket");
        return false;
    }

    ei_logger_info("Tryging to accept new socket client to server...");

    if (server->tls_session) {
        ei_logger_info("Server have a TLS session");

        peer_tls = uecm_tls_connection_create(server->tls_session->ctx);
        if (!peer_tls) {
            ei_stacktrace_push_msg("Failed to create TLS peer connection");
            return false;
        }
        ei_logger_trace("Peer have a TLS connection");

        if (!uecm_tls_connection_set_fd(peer_tls, new_socket)) {
            ei_stacktrace_push_msg("Failed to set new socket file descriptor to peer TLS connection");
            uecm_tls_connection_destroy(peer_tls);
            return false;
        }
        ei_logger_trace("File descriptor set to peer TLS connection");

        if (!uecm_tls_connection_accept(peer_tls)) {
            ei_stacktrace_push_msg("Failed to accept new socket file descriptor into the TLS connection");
            uecm_tls_connection_destroy(peer_tls);
            return false;
        }
        ei_logger_trace("Peer accepted");

        if (server->tls_session->verify_peer) {
            ei_logger_trace("Verify peer...");

            if (!uecm_tls_connection_verify_peer_certificate(peer_tls)) {
                ei_stacktrace_push_msg("Client certificate verification failed");
                uecm_tls_connection_destroy(peer_tls);
                return false;
            }
            ei_logger_trace("Peer TLS connection verified successfully");

            ei_logger_trace("Check if client is already connected");
            for (i = 0; i < server->connections_number; i++) {
                if (server->connections[i] && server->connections[i]->peer_certificate) {
                    certificate = uecm_tls_connection_get_peer_certificate(peer_tls);
                    if (uecm_x509_certificate_equals(certificate, server->connections[i]->peer_certificate)) {
                        ei_logger_warn("Client already connected");
                        /* @todo response to client he's already connected ? */
                        /* ue_socket_send_sync_string(new_socket, "ALREADY_CONNECTED", peer_tls); */
                        uecm_x509_certificate_destroy(certificate);
                        uecm_tls_connection_destroy(peer_tls);
                        return false;
                    }
                    uecm_x509_certificate_destroy(certificate);
                }
            }
            ei_logger_trace("TLS client isn't already connected");
        }
    }

    ei_logger_trace("Searching for an available slot for incoming connection");
    for (i = 0; i < server->connections_number; i++) {
        if (ue_socket_client_connection_is_available(server->connections[i])) {
            if (!ue_socket_client_connection_establish(server->connections[i], new_socket)) {
                ei_stacktrace_push_msg("Failed to established connection");
                return false;
            }
            if (server->tls_session) {
                if (server->connections[i]->tls) {
                    uecm_tls_connection_destroy(server->connections[i]->tls);
                }
                server->connections[i]->tls = peer_tls;
                server->connections[i]->peer_certificate = uecm_tls_connection_get_peer_certificate(peer_tls);
            }
            if (ue_socket_client_connection_build_communication_metadata(server->connections[i], &sa)) {

                if ((communication_metadata_string = ue_communication_metadata_to_string(
                    ue_socket_client_connection_get_communication_metadata(server->connections[i]))) == NULL) {

                    if (ei_stacktrace_is_filled()) {
                        ei_logger_warn("Failed to get communication metadata string from new connected client:");
                        ei_stacktrace_clean_up();
                    }
                } else {
                    ei_logger_trace("Client connected with communication metadata: %s", communication_metadata_string);
                    ueum_safe_free(communication_metadata_string);
                }
            } else {
                ei_logger_warn("Failed to set sockaddr_in structure to client connection ptr");
                return false;
            }
            established = true;
            break;
        }
    }

    if (!established) {
        ei_stacktrace_push_msg("Failed to accept new client, because there's no such slot available");
    } else {
        ei_logger_info("Client client successfully accepted");
    }

    return established;
}

void ue_socket_server_process_connection(ue_socket_server *server, ue_socket_client_connection *connection, fd_set *read_set, fd_set *write_set) {
    if (ue_socket_client_connection_is_available(connection)) {
        return;
    }

    switch (connection->state) {
        case UNKNOWNECHO_COMMUNICATION_CONNECTION_FREE_STATE:
            ei_logger_trace("Connection state : [FREE]");
        break;

        case UNKNOWNECHO_COMMUNICATION_CONNECTION_READ_STATE:
            ei_logger_trace("Connection state : [READ]");
            if (FD_ISSET(connection->fd, read_set)) {
                ei_logger_trace("Have stuff to read");
                if (!server->read_consumer(connection)) {
                    ei_logger_warn("An error occurred while processing read_consumer()");
                    if (ei_stacktrace_is_filled()) {
                        ei_logger_error("With the following stacktrace :");
                        ei_stacktrace_print();
                        /* @TODO log ei_stacktrace */
                        ei_stacktrace_clean_up();
                    }
                }
            }
        break;

        case UNKNOWNECHO_COMMUNICATION_CONNECTION_WRITE_STATE:
            ei_logger_trace("Connection state : [WRITE]");
            if (FD_ISSET(connection->fd, write_set)) {
                ei_logger_trace("Have stuff to write");
                if (!server->write_consumer(connection)) {
                    ei_logger_warn("An error occurred while processing write_consumer()");
                    if (ei_stacktrace_is_filled()) {
                        ei_logger_error("With the following stacktrace :");
                        ei_stacktrace_print();
                        /* @TODO log ei_stacktrace */
                        ei_stacktrace_clean_up();
                    }
                }
            }
        break;
    }
}

void init_select(ue_socket_server *server, int *max_fd, fd_set *read_set, fd_set *write_set) {
    int i;
    /* Tmp connection */
    ue_socket_client_connection *connection;

    /* Init both bits sets to 0 */
    FD_ZERO(read_set);
    FD_ZERO(write_set);

    /* Add listen socket to read set */
    FD_SET(server->ue_socket_fd, read_set);

    *max_fd = server->ue_socket_fd;

    /*
     * For each slot, we checked if it's in read or write state,
     * to update the corresponding bits set.
     * Then, we update the value of max_fd if we found a major file descriptor.
     */
    for (i = 0; i < server->connections_number; i++) {
        connection = server->connections[i];

        if (connection->state == UNKNOWNECHO_COMMUNICATION_CONNECTION_FREE_STATE) {
            continue;
        }

        /* If the socket is in read state */
        if (connection->state == UNKNOWNECHO_COMMUNICATION_CONNECTION_READ_STATE) {
            FD_SET(connection->fd, read_set);
        }
        /* Else if the socket is in write state */
        else if (connection->state == UNKNOWNECHO_COMMUNICATION_CONNECTION_WRITE_STATE) {
            FD_SET(connection->fd, write_set);
        }

        /* Update of max_fd value if the current socket file descriptor if major than current max_fd */
        if (connection->fd > *max_fd) {
            *max_fd = connection->fd;
        }
    }
}

bool ue_socket_server_process_polling(ue_socket_server *server) {
    int max_fd, i, r;
    fd_set read_set, write_set;
    char *error_buffer;

    if (!ue_socket_server_is_valid(server)) {
        ei_logger_error("Specified server isn't correctly initialized");
        return false;
    }

    r = 0;
    error_buffer = NULL;

    while (server->running) {
        init_select(server, &max_fd, &read_set, &write_set);

        if ((r = select(max_fd + 1, &read_set, &write_set, NULL, NULL)) == -1) {
            if (errno == 0) {
                ei_logger_warn("select() failed with error code : %d, but errno is set to 0", r);
            } else {
                error_buffer = strerror(errno);
                ei_logger_warn("select() failed with error code : %d and error message: '%s'", r, error_buffer);
            }
        }
        else {
            if (FD_ISSET(server->ue_socket_fd, &read_set)) {
                if (!ue_socket_server_accept(server)) {
                    if (ei_stacktrace_is_filled()) {
                        ei_logger_stacktrace("Failed to accept a new client with following stacktrace:");
                        ei_stacktrace_clean_up();
                    } else {
                        ei_logger_warn("Failed to accept a new client, but no error was detected. There's probably no such slot available.");
                    }
                }
            }
        }

        for (i = 0; i < server->connections_number; i++) {
            ue_socket_server_process_connection(server, server->connections[i], &read_set, &write_set);
        }
    }

    return true;
}

bool ue_socket_bind(int ue_socket_fd, int domain, unsigned short int port) {
    struct sockaddr_in serv_addr;

    ei_check_parameter_or_return(ue_socket_fd > 0);

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = domain;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);

    if (bind(ue_socket_fd, (struct sockaddr *)&serv_addr , sizeof(serv_addr)) < 0) {
        ei_stacktrace_push_errno();
        return false;
    }

    return true;
}

bool ue_socket_bind_s(int ue_socket_fd, const char *domain, const char *port) {
    ei_check_parameter_or_return(domain);
    ei_check_parameter_or_return(port);

    if (!ue_socket_bind(ue_socket_fd, ue_socket_str_to_domain(domain), atoi(port))) {
        ei_stacktrace_push_errno();
        return false;
    }

    return true;
}

bool ue_socket_server_disconnect(ue_socket_server *server, ue_socket_client_connection *connection) {
    int i;

    for (i = 0; i < server->connections_number; i++) {
        if (server->connections[i] == connection) {
            ue_socket_client_connection_clean_up(server->connections[i]);
            return true;
        }
    }

    ei_logger_warn("Cannot disconnect client from server because client was not found.");

    return false;
}

bool ue_socket_server_stop(ue_socket_server *server) {
    ei_check_parameter_or_return(server);

    server->running = false;

    return true;
}

int ue_socket_server_get_connections_number(ue_socket_server *server)  {
    if (!server) {
        ei_stacktrace_push_msg("Specified server ptr is null");
        return -1;
    }

    return server->connections_number;
}

ue_socket_client_connection *ue_socket_server_get_connection(ue_socket_server *server, int index) {
    if (!server) {
        ei_stacktrace_push_msg("Specified server ptr is null");
        return NULL;
    }

    if (index < 0 || index >= server->connections_number) {
        ei_stacktrace_push_msg("Specified index %d is out of range", index);
        return NULL;
    }

    return server->connections[index];
}