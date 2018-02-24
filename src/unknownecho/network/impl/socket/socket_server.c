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

#include <unknownecho/network/api/socket/socket_server.h>
#include <unknownecho/network/api/socket/socket.h>
#include <unknownecho/network/api/socket/socket_client_connection.h>
#include <unknownecho/network/api/tls/tls_connection.h>
#include <unknownecho/errorHandling/check_parameter.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/system/alloc.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/string/string_utility.h>
#include <unknownecho/crypto/api/errorHandling/crypto_error_handling.h>
#include <unknownecho/crypto/api/certificate/x509_certificate.h>

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
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #pragma comment(lib,"ws2_32.lib")
#else
    #error "OS not supported"
#endif

#define DEFAULT_CONNECTIONS_NUMBER 10
#define DEFAULT_SIMULTANEOUS_CONNECTIONS_NUMBER 5

bool ue_socket_listen(ue_socket_server *server);

int ue_socket_accept(int ue_socket_fd, struct sockaddr_in *sa);

bool ue_socket_bind(int ue_socket_fd, int domain, unsigned short int port);

bool ue_socket_bind_s(int ue_socket_fd, const char *domain, const char *port);

void ue_socket_server_process_connection(ue_socket_server *server, ue_socket_client_connection *connection, fd_set *read_set, fd_set *write_set);

void init_select(ue_socket_server *server, int *max_fd, fd_set *read_set, fd_set *write_set);


ue_socket_server *ue_socket_server_create(unsigned short int port,
    bool (*read_consumer)(ue_socket_client_connection *connection),
    bool (*write_consumer)(ue_socket_client_connection *connection),
	ue_tls_session *tls_session) {

    ue_socket_server *server;
    int i;

    server = NULL;

    ue_safe_alloc_or_goto(server, ue_socket_server, 1, clean_up);

    server->tls_session = tls_session;
    if ((server->ue_socket_fd = ue_socket_open_tcp()) == -1) {
        ue_stacktrace_push_msg("Failed to create main socket context");
        goto clean_up;
    }
    server->connections_number = DEFAULT_CONNECTIONS_NUMBER;
    server->simultaneous_connections_number = DEFAULT_SIMULTANEOUS_CONNECTIONS_NUMBER;
    server->read_consumer = read_consumer;
    server->write_consumer = write_consumer;
    ue_safe_alloc_or_goto(server->connections, ue_socket_client_connection *, server->connections_number, clean_up);
    for (i = 0; i < server->connections_number; i++) {
        if ((server->connections[i] = ue_socket_client_connection_init()) == NULL) {
            ue_stacktrace_push_msg("Failed to init client connections");
            goto clean_up;
        }
    }

    if (!ue_socket_bind(server->ue_socket_fd, AF_INET, port)) {
        ue_stacktrace_push_msg("Failed to bind socket to this port");
        goto clean_up;
    }

    if (!ue_socket_listen(server)) {
        ue_stacktrace_push_msg("Failed to listen socket to this port");
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
                    ue_tls_connection_destroy(server->connections[i]->tls);
                    server->connections[i]->tls = NULL;
                }
                ue_socket_client_connection_destroy(server->connections[i]);
                server->connections[i] = NULL;
            }
            ue_safe_free(server->connections);
        }
        ue_socket_close(server->ue_socket_fd);
        ue_safe_free(server);
    }
}

bool ue_socket_server_is_valid(ue_socket_server *server) {
    if (!server) {
        ue_logger_trace("Specified server object is null");
    }

    if (!ue_socket_is_valid(server->ue_socket_fd)) {
        ue_logger_trace("Socket context of server isn't valid");
        return false;
    }

    if (!server->connections) {
        ue_logger_trace("Socket client connections are null");
        return false;
    }

    if (!server->read_consumer) {
        ue_logger_trace("Read consumer function is null");
        return false;
    }

    if (!server->write_consumer) {
        ue_logger_trace("Write consumer function is null");
        return false;
    }

    if (!server->running) {
        ue_logger_trace("Server isn't running");
        return false;
    }

    return true;
}

bool ue_socket_listen(ue_socket_server *server) {
    if (listen(server->ue_socket_fd, server->connections_number) != 0) {
        ue_stacktrace_push_errno();
        return false;
    }
    return true;
}

int ue_socket_accept(int ue_socket_fd, struct sockaddr_in *sa) {
    int new_socket;
    socklen_t addrlen;

    addrlen = sizeof(struct sockaddr_in);

    if ((new_socket = accept(ue_socket_fd, (struct sockaddr *) sa, &addrlen)) <= 0) {
        ue_stacktrace_push_msg("Failed to accept this socket");
        return -1;
    }

    return new_socket;
}

bool ue_socket_server_accept(ue_socket_server *server) {
    struct sockaddr_in sa;
    int new_socket, i;
    bool established;
    ue_tls_connection *peer_tls;
    ue_x509_certificate *certificate;

    established = false;
    peer_tls = NULL;
    certificate = NULL;

    if ((new_socket = ue_socket_accept(server->ue_socket_fd, &sa)) <= 0) {
        ue_stacktrace_push_msg("Failed to accept this socket");
        return false;
    }

    if (server->tls_session) {
        peer_tls = ue_tls_connection_create(server->tls_session->ctx);
		if (!peer_tls) {
			ue_stacktrace_push_msg("Failed to create TLS peer connection");
			return false;
		}
        if (!ue_tls_connection_set_fd(peer_tls, new_socket)) {
            ue_stacktrace_push_msg("Failed to set new socket file descriptor to peer TLS connection");
            ue_tls_connection_destroy(peer_tls);
            return false;
        }

        if (!ue_tls_connection_accept(peer_tls)) {
            ue_stacktrace_push_msg("Failed to accept new socket file descriptor into the TLS connection");
            ue_tls_connection_destroy(peer_tls);
            return false;
        }

		if (server->tls_session->verify_peer) {
            if (!ue_tls_connection_verify_peer_certificate(peer_tls)) {
				ue_stacktrace_push_msg("Client certificate verification failed");
                ue_tls_connection_destroy(peer_tls);
                return false;
			}

            for (i = 0; i < server->connections_number; i++) {
                if (server->connections[i] && server->connections[i]->peer_certificate) {
                    certificate = ue_tls_connection_get_peer_certificate(peer_tls);
                    if (ue_x509_certificate_equals(certificate, server->connections[i]->peer_certificate)) {
                        ue_logger_info("Client already connected");
                        ue_socket_send_string(new_socket, "ALREADY_CONNECTED", peer_tls);
                        ue_x509_certificate_destroy(certificate);
                        ue_tls_connection_destroy(peer_tls);
                        return false;
                    }
                    ue_x509_certificate_destroy(certificate);
                }
            }
		}
    }

    for (i = 0; i < server->connections_number; i++) {
        if (ue_socket_client_connection_is_available(server->connections[i])) {
            if (!ue_socket_client_connection_establish(server->connections[i], new_socket)) {
                ue_stacktrace_push_msg("Failed to established connection");
                return false;
            }
			if (server->tls_session) {
				if (server->connections[i]->tls) {
                    ue_tls_connection_destroy(server->connections[i]->tls);
				}
				server->connections[i]->tls = peer_tls;
                server->connections[i]->peer_certificate = ue_tls_connection_get_peer_certificate(peer_tls);
			}
            established = true;
            break;
        }
    }

    if (!established) {
        ue_logger_warn("Failed to accept new client, because there's no such slot available");
    } else {
        ue_logger_info("Client client successfully accepted");
    }

    return established;
}

void ue_socket_server_process_connection(ue_socket_server *server, ue_socket_client_connection *connection, fd_set *read_set, fd_set *write_set) {
    if (ue_socket_client_connection_is_available(connection)) {
        return;
    }

    switch (connection->state) {
        case UNKNOWNECHO_CONNECTION_FREE_STATE:
        break;

        case UNKNOWNECHO_CONNECTION_READ_STATE:
            if (FD_ISSET(connection->fd, read_set)) {
                if (!server->read_consumer(connection)) {
                    ue_logger_warn("An error occurred while processing read_consumer()");
                    if (ue_stacktrace_is_filled()) {
                        ue_logger_error("With the following stacktrace :");
                        ue_stacktrace_print();
                        /* @TODO log ue_stacktrace */
                        ue_stacktrace_clean_up();
                    }
                }
            }
        break;

        case UNKNOWNECHO_CONNECTION_WRITE_STATE:
            if (FD_ISSET(connection->fd, write_set)) {
                if (!server->write_consumer(connection)) {
                    ue_logger_warn("An error occurred while processing write_consumer()");
                    if (ue_stacktrace_is_filled()) {
                        ue_logger_error("With the following stacktrace :");
                        ue_stacktrace_print();
                        /* @TODO log ue_stacktrace */
                        ue_stacktrace_clean_up();
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

        if (connection->state == UNKNOWNECHO_CONNECTION_FREE_STATE) {
            continue;
        }

        /* If the socket is in read state */
        if (connection->state == UNKNOWNECHO_CONNECTION_READ_STATE) {
            FD_SET(connection->fd, read_set);
        }
        /* Else if the socket is in write state */
        else if (connection->state == UNKNOWNECHO_CONNECTION_WRITE_STATE) {
            FD_SET(connection->fd, write_set);
        }

        /* Update of max_fd value if the current socket file descriptor if major than current max_fd */
        if (connection->fd > *max_fd) {
            *max_fd = connection->fd;
        }
    }
}

void ue_socket_server_process_polling(ue_socket_server *server) {
    int max_fd, i, r;
    fd_set read_set, write_set;
    char *error_buffer;

    if (!ue_socket_server_is_valid(server)) {
        ue_logger_error("Specified server isn't correctly initialized");
        return;
    }

    r = 0;
    error_buffer = NULL;

    while (server->running) {
        init_select(server, &max_fd, &read_set, &write_set);

        if ((r = select(max_fd + 1, &read_set, &write_set, NULL, NULL)) == -1) {
            if (errno == 0) {
                ue_logger_debug("select() failed with error code : %d, but errno is set to 0", r);
            } else {
                error_buffer = strerror(errno);
                ue_logger_debug("select() failed with error code : %d and error message : '%s'", r, error_buffer);
            }
        }
        else {
            if (FD_ISSET(server->ue_socket_fd, &read_set)) {
                if (!ue_socket_server_accept(server)) {
                    ue_logger_warn("Failed to accept a new client");
                    if (ue_stacktrace_is_filled()) {
                        ue_logger_trace("Stacktrace is filled :");
                        ue_stacktrace_print();
                        ue_stacktrace_clean_up();
                    }
                }
            }
        }

        for (i = 0; i < server->connections_number; i++) {
            ue_socket_server_process_connection(server, server->connections[i], &read_set, &write_set);
        }
    }
}

bool ue_socket_bind(int ue_socket_fd, int domain, unsigned short int port) {
    struct sockaddr_in serv_addr;

    ue_check_parameter_or_return(ue_socket_fd > 0);

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = domain;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);

    #if defined(__unix__)
        if (bind(ue_socket_fd, (struct sockaddr *)&serv_addr , sizeof(serv_addr)) < 0) {
            ue_stacktrace_push_errno();
            return false;
        }
    #elif defined(_WIN32) || defined(_WIN64)
        #error "OS not supported"
    #else
        #error "OS not supported"
    #endif

    return true;
}

bool ue_socket_bind_s(int ue_socket_fd, const char *domain, const char *port) {
    ue_check_parameter_or_return(domain);
    ue_check_parameter_or_return(port);

    if (!ue_socket_bind(ue_socket_fd, ue_socket_str_to_domain(domain), atoi(port))) {
        ue_stacktrace_push_errno();
        return false;
    }

    return true;
}
