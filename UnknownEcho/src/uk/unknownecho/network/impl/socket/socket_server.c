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

#include <uk/unknownecho/network/api/socket/socket_server.h>
#include <uk/unknownecho/network/api/socket/socket.h>
#include <uk/unknownecho/network/api/socket/socket_client_connection.h>
#include <uk/unknownecho/network/api/communication/communication_metadata.h>
#include <uk/unknownecho/network/api/tls/tls_connection.h>
#include <uk/utils/ueum.h>
#include <uk/crypto/uecm.h>
#include <uk/utils/ei.h>

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

bool uk_ue_socket_listen(uk_ue_socket_server *server);

int uk_ue_socket_accept(int uk_ue_socket_fd, struct sockaddr *sa);

bool uk_ue_socket_bind(int uk_ue_socket_fd, int domain, unsigned short int port);

bool uk_ue_socket_bind_s(int uk_ue_socket_fd, const char *domain, const char *port);

void uk_ue_socket_server_process_connection(uk_ue_socket_server *server, uk_ue_socket_client_connection *connection, fd_set *read_set, fd_set *write_set);

void init_select(uk_ue_socket_server *server, int *max_fd, fd_set *read_set, fd_set *write_set);


uk_ue_socket_server *uk_ue_socket_server_create(uk_ue_socket_server_parameters *parameters) {

    uk_ue_socket_server *server;
    int i;

    server = NULL;

    uk_utils_safe_alloc_or_goto(server, uk_ue_socket_server, 1, clean_up);

    server->tls_session = parameters->tls_session;
    if ((server->uk_ue_socket_fd = uk_ue_socket_open_tcp()) == -1) {
        uk_utils_stacktrace_push_msg("Failed to create main socket context");
        goto clean_up;
    }
    server->connections_number = DEFAULT_CONNECTIONS_NUMBER;
    server->simultaneous_connections_number = DEFAULT_SIMULTANEOUS_CONNECTIONS_NUMBER;
    server->read_consumer = parameters->read_consumer;
    server->write_consumer = parameters->write_consumer;
    uk_utils_safe_alloc_or_goto(server->connections, uk_ue_socket_client_connection *, server->connections_number, clean_up);
    for (i = 0; i < server->connections_number; i++) {
        if ((server->connections[i] = uk_ue_socket_client_connection_init()) == NULL) {
            uk_utils_stacktrace_push_msg("Failed to init client connections");
            goto clean_up;
        }
    }

    if (!uk_ue_socket_bind(server->uk_ue_socket_fd, AF_INET, parameters->port)) {
        uk_utils_stacktrace_push_msg("Failed to bind socket to this port");
        goto clean_up;
    }

    if (!uk_ue_socket_listen(server)) {
        uk_utils_stacktrace_push_msg("Failed to listen socket to this port");
        goto clean_up;
    }

    server->running = true;

    return server;

clean_up:
    uk_ue_socket_server_destroy(server);
    return NULL;
}

void uk_ue_socket_server_destroy(uk_ue_socket_server *server) {
    int i;

    if (server) {
        if (server->connections) {
            for (i = 0; i < server->connections_number; i++) {
                if (server->connections[i]->tls) {
                    uk_crypto_tls_connection_destroy(server->connections[i]->tls);
                    server->connections[i]->tls = NULL;
                }
                uk_ue_socket_client_connection_destroy(server->connections[i]);
                server->connections[i] = NULL;
            }
            uk_utils_safe_free(server->connections);
        }
        uk_ue_socket_close(server->uk_ue_socket_fd);
        uk_utils_safe_free(server);
    }
}

bool uk_ue_socket_server_is_valid(uk_ue_socket_server *server) {
    if (!server) {
        uk_utils_logger_trace("Specified server object is null");
    }

    if (!uk_ue_socket_is_valid(server->uk_ue_socket_fd)) {
        uk_utils_logger_trace("Socket context of server isn't valid");
        return false;
    }

    if (!server->connections) {
        uk_utils_logger_trace("Socket client connections are null");
        return false;
    }

    if (!server->read_consumer) {
        uk_utils_logger_trace("Read consumer function is null");
        return false;
    }

    if (!server->write_consumer) {
        uk_utils_logger_trace("Write consumer function is null");
        return false;
    }

    if (!server->running) {
        uk_utils_logger_trace("Server isn't running");
        return false;
    }

    return true;
}

bool uk_ue_socket_server_is_running(uk_ue_socket_server *server) {
    return server && server->running;
}

bool uk_ue_socket_listen(uk_ue_socket_server *server) {
    if (listen(server->uk_ue_socket_fd, server->connections_number) != 0) {
        uk_utils_stacktrace_push_errno();
        return false;
    }
    return true;
}

int uk_ue_socket_accept(int uk_ue_socket_fd, struct sockaddr *sa) {
    int new_socket;

#if defined(__unix__)
    socklen_t addrlen;
#elif defined(_WIN32) || defined(_WIN64)
    int addrlen;
#endif

    addrlen = sizeof(struct sockaddr_in);

    if ((new_socket = accept(uk_ue_socket_fd, (struct sockaddr *) sa, &addrlen)) <= 0) {
        uk_utils_stacktrace_push_msg("Failed to accept this socket");
        return -1;
    }

    return new_socket;
}

bool uk_ue_socket_server_accept(uk_ue_socket_server *server) {
    struct sockaddr sa;
    int new_socket, i;
    bool established;
    uk_crypto_tls_connection *peer_tls;
    uk_crypto_x509_certificate *certificate;
    const char *communication_metadata_string;

    established = false;
    peer_tls = NULL;
    certificate = NULL;
    communication_metadata_string = NULL;

    if ((new_socket = uk_ue_socket_accept(server->uk_ue_socket_fd, &sa)) <= 0) {
        uk_utils_stacktrace_push_msg("Failed to accept this socket");
        return false;
    }

    uk_utils_logger_info("Tryging to accept new socket client to server...");

    if (server->tls_session) {
        uk_utils_logger_info("Server have a TLS session");

        peer_tls = uk_crypto_tls_connection_create(server->tls_session->ctx);
        if (!peer_tls) {
            uk_utils_stacktrace_push_msg("Failed to create TLS peer connection");
            return false;
        }
        uk_utils_logger_trace("Peer have a TLS connection");

        if (!uk_crypto_tls_connection_set_fd(peer_tls, new_socket)) {
            uk_utils_stacktrace_push_msg("Failed to set new socket file descriptor to peer TLS connection");
            uk_crypto_tls_connection_destroy(peer_tls);
            return false;
        }
        uk_utils_logger_trace("File descriptor set to peer TLS connection");

        if (!uk_crypto_tls_connection_accept(peer_tls)) {
            uk_utils_stacktrace_push_msg("Failed to accept new socket file descriptor into the TLS connection");
            uk_crypto_tls_connection_destroy(peer_tls);
            return false;
        }
        uk_utils_logger_trace("Peer accepted");

        if (server->tls_session->verify_peer) {
            uk_utils_logger_trace("Verify peer...");

            if (!uk_crypto_tls_connection_verify_peer_certificate(peer_tls)) {
                uk_utils_stacktrace_push_msg("Client certificate verification failed");
                uk_crypto_tls_connection_destroy(peer_tls);
                return false;
            }
            uk_utils_logger_trace("Peer TLS connection verified successfully");

            uk_utils_logger_trace("Check if client is already connected");
            for (i = 0; i < server->connections_number; i++) {
                if (server->connections[i] && server->connections[i]->peer_certificate) {
                    certificate = uk_crypto_tls_connection_get_peer_certificate(peer_tls);
                    if (uk_crypto_x509_certificate_equals(certificate, server->connections[i]->peer_certificate)) {
                        uk_utils_logger_warn("Client already connected");
                        /* @todo response to client he's already connected ? */
                        /* uk_ue_socket_send_sync_string(new_socket, "ALREADY_CONNECTED", peer_tls); */
                        uk_crypto_x509_certificate_destroy(certificate);
                        uk_crypto_tls_connection_destroy(peer_tls);
                        return false;
                    }
                    uk_crypto_x509_certificate_destroy(certificate);
                }
            }
            uk_utils_logger_trace("TLS client isn't already connected");
        }
    }

    uk_utils_logger_trace("Searching for an available slot for incoming connection");
    for (i = 0; i < server->connections_number; i++) {
        if (uk_ue_socket_client_connection_is_available(server->connections[i])) {
            if (!uk_ue_socket_client_connection_establish(server->connections[i], new_socket)) {
                uk_utils_stacktrace_push_msg("Failed to established connection");
                return false;
            }
            if (server->tls_session) {
                if (server->connections[i]->tls) {
                    uk_crypto_tls_connection_destroy(server->connections[i]->tls);
                }
                server->connections[i]->tls = peer_tls;
                server->connections[i]->peer_certificate = uk_crypto_tls_connection_get_peer_certificate(peer_tls);
            }
            if (uk_ue_socket_client_connection_build_communication_metadata(server->connections[i], &sa)) {

                if ((communication_metadata_string = uk_ue_communication_metadata_to_string(
                    uk_ue_socket_client_connection_get_communication_metadata(server->connections[i]))) == NULL) {

                    if (uk_utils_stacktrace_is_filled()) {
                        uk_utils_logger_warn("Failed to get communication metadata string from new connected client:");
                        uk_utils_stacktrace_clean_up();
                    }
                } else {
                    uk_utils_logger_trace("Client connected with communication metadata: %s", communication_metadata_string);
                    uk_utils_safe_free(communication_metadata_string);
                }
            } else {
                uk_utils_logger_warn("Failed to set sockaddr_in structure to client connection ptr");
                return false;
            }
            established = true;
            break;
        }
    }

    if (!established) {
        uk_utils_stacktrace_push_msg("Failed to accept new client, because there's no such slot available");
    } else {
        uk_utils_logger_info("Client client successfully accepted");
    }

    return established;
}

void uk_ue_socket_server_process_connection(uk_ue_socket_server *server, uk_ue_socket_client_connection *connection, fd_set *read_set, fd_set *write_set) {
    if (uk_ue_socket_client_connection_is_available(connection)) {
        return;
    }

    switch (connection->state) {
        case UnknownKrakenUnknownEcho_COMMUNICATION_CONNECTION_FREE_STATE:
            uk_utils_logger_trace("Connection state : [FREE]");
        break;

        case UnknownKrakenUnknownEcho_COMMUNICATION_CONNECTION_READ_STATE:
            uk_utils_logger_trace("Connection state : [READ]");
            if (FD_ISSET(connection->fd, read_set)) {
                uk_utils_logger_trace("Have stuff to read");
                if (!server->read_consumer(connection)) {
                    uk_utils_logger_warn("An error occurred while processing read_consumer()");
                    if (uk_utils_stacktrace_is_filled()) {
                        uk_utils_logger_error("With the following stacktrace :");
                        uk_utils_stacktrace_print();
                        /* @TODO log uk_utils_stacktrace */
                        uk_utils_stacktrace_clean_up();
                    }
                }
            }
        break;

        case UnknownKrakenUnknownEcho_COMMUNICATION_CONNECTION_WRITE_STATE:
            uk_utils_logger_trace("Connection state : [WRITE]");
            if (FD_ISSET(connection->fd, write_set)) {
                uk_utils_logger_trace("Have stuff to write");
                if (!server->write_consumer(connection)) {
                    uk_utils_logger_warn("An error occurred while processing write_consumer()");
                    if (uk_utils_stacktrace_is_filled()) {
                        uk_utils_logger_error("With the following stacktrace :");
                        uk_utils_stacktrace_print();
                        /* @TODO log uk_utils_stacktrace */
                        uk_utils_stacktrace_clean_up();
                    }
                }
            }
        break;
    }
}

void init_select(uk_ue_socket_server *server, int *max_fd, fd_set *read_set, fd_set *write_set) {
    int i;
    /* Tmp connection */
    uk_ue_socket_client_connection *connection;

    /* Init both bits sets to 0 */
    FD_ZERO(read_set);
    FD_ZERO(write_set);

    /* Add listen socket to read set */
    FD_SET(server->uk_ue_socket_fd, read_set);

    *max_fd = server->uk_ue_socket_fd;

    /*
     * For each slot, we checked if it's in read or write state,
     * to update the corresponding bits set.
     * Then, we update the value of max_fd if we found a major file descriptor.
     */
    for (i = 0; i < server->connections_number; i++) {
        connection = server->connections[i];

        if (connection->state == UnknownKrakenUnknownEcho_COMMUNICATION_CONNECTION_FREE_STATE) {
            continue;
        }

        /* If the socket is in read state */
        if (connection->state == UnknownKrakenUnknownEcho_COMMUNICATION_CONNECTION_READ_STATE) {
            FD_SET(connection->fd, read_set);
        }
        /* Else if the socket is in write state */
        else if (connection->state == UnknownKrakenUnknownEcho_COMMUNICATION_CONNECTION_WRITE_STATE) {
            FD_SET(connection->fd, write_set);
        }

        /* Update of max_fd value if the current socket file descriptor if major than current max_fd */
        if (connection->fd > *max_fd) {
            *max_fd = connection->fd;
        }
    }
}

bool uk_ue_socket_server_process_polling(uk_ue_socket_server *server) {
    int max_fd, i, r;
    fd_set read_set, write_set;
    char *error_buffer;

    if (!uk_ue_socket_server_is_valid(server)) {
        uk_utils_logger_error("Specified server isn't correctly initialized");
        return false;
    }

    r = 0;
    error_buffer = NULL;

    while (server->running) {
        init_select(server, &max_fd, &read_set, &write_set);

        if ((r = select(max_fd + 1, &read_set, &write_set, NULL, NULL)) == -1) {
            if (errno == 0) {
                uk_utils_logger_warn("select() failed with error code : %d, but errno is set to 0", r);
            } else {
                error_buffer = strerror(errno);
                uk_utils_logger_warn("select() failed with error code : %d and error message: '%s'", r, error_buffer);
            }
        }
        else {
            if (FD_ISSET(server->uk_ue_socket_fd, &read_set)) {
                if (!uk_ue_socket_server_accept(server)) {
                    if (uk_utils_stacktrace_is_filled()) {
                        uk_utils_logger_stacktrace("Failed to accept a new client with following stacktrace:");
                        uk_utils_stacktrace_clean_up();
                    } else {
                        uk_utils_logger_warn("Failed to accept a new client, but no error was detected. There's probably no such slot available.");
                    }
                }
            }
        }

        for (i = 0; i < server->connections_number; i++) {
            uk_ue_socket_server_process_connection(server, server->connections[i], &read_set, &write_set);
        }
    }

    return true;
}

bool uk_ue_socket_bind(int uk_ue_socket_fd, int domain, unsigned short int port) {
    struct sockaddr_in serv_addr;

    uk_utils_check_parameter_or_return(uk_ue_socket_fd > 0);

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = domain;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);

    if (bind(uk_ue_socket_fd, (struct sockaddr *)&serv_addr , sizeof(serv_addr)) < 0) {
        uk_utils_stacktrace_push_errno();
        return false;
    }

    return true;
}

bool uk_ue_socket_bind_s(int uk_ue_socket_fd, const char *domain, const char *port) {
    uk_utils_check_parameter_or_return(domain);
    uk_utils_check_parameter_or_return(port);

    if (!uk_ue_socket_bind(uk_ue_socket_fd, uk_ue_socket_str_to_domain(domain), atoi(port))) {
        uk_utils_stacktrace_push_errno();
        return false;
    }

    return true;
}

bool uk_ue_socket_server_disconnect(uk_ue_socket_server *server, uk_ue_socket_client_connection *connection) {
    int i;

    for (i = 0; i < server->connections_number; i++) {
        if (server->connections[i] == connection) {
            uk_ue_socket_client_connection_clean_up(server->connections[i]);
            return true;
        }
    }

    uk_utils_logger_warn("Cannot disconnect client from server because client was not found.");

    return false;
}

bool uk_ue_socket_server_stop(uk_ue_socket_server *server) {
    uk_utils_check_parameter_or_return(server);

    server->running = false;

    return true;
}

int uk_ue_socket_server_get_connections_number(uk_ue_socket_server *server)  {
    if (!server) {
        uk_utils_stacktrace_push_msg("Specified server ptr is null");
        return -1;
    }

    return server->connections_number;
}

uk_ue_socket_client_connection *uk_ue_socket_server_get_connection(uk_ue_socket_server *server, int index) {
    if (!server) {
        uk_utils_stacktrace_push_msg("Specified server ptr is null");
        return NULL;
    }

    if (index < 0 || index >= server->connections_number) {
        uk_utils_stacktrace_push_msg("Specified index %d is out of range", index);
        return NULL;
    }

    return server->connections[index];
}
