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

#include <unknownecho/network/api/socket/socket.h>
#include <unknownecho/crypto/impl/errorHandling/openssl_error_handling.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/check_parameter.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/alloc.h>
#include <unknownecho/byte/byte_stream.h>
#include <unknownecho/byte/byte_writer.h>

#include <string.h>
#include <errno.h>
#include <limits.h>

#if defined(__unix__)
    #include <sys/socket.h>
    #include <sys/types.h>
    #include <netdb.h>
    #include <netinet/in.h>
    #include <unistd.h>
#elif defined(_WIN32) || defined(_WIN64)
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #pragma comment(lib,"ws2_32.lib")
#else
    #error "OS not supported"
#endif

static bool ue_socket_is_valid_type(int type);

static int ue_socket_str_to_type(const char *type);

bool ue_socket_is_valid_domain(int domain) {
    #if defined(AF_INET)
        if (domain == AF_INET) {
            return true;
        }
    #endif

    #if defined(AF_INET6)
        if (domain == AF_INET6) {
            return true;
        }
    #endif

    #if defined(__unix__)
        #if defined(AF_UNIX)
            if (domain == AF_UNIX) {
                return true;
            }
        #endif
        #if defined(AF_IPX)
            if (domain == AF_IPX) {
                return true;
            }
        #endif
        #if defined(AF_NETLINK)
            if (domain == AF_NETLINK) {
                return true;
            }
        #endif
        #if defined(AF_X25)
            if (domain == AF_X25) {
                return true;
            }
        #endif
        #if defined(AF_ATMPVC)
            if (domain == AF_ATMPVC) {
                return true;
            }
        #endif
        #if defined(AF_PACKET)
            if (domain == AF_PACKET) {
                return true;
            }
        #endif
    #endif

    return false;
}

static bool ue_socket_is_valid_type(int type) {
    #if defined(SOCK_STREAM)
        if (type == SOCK_STREAM) {
            return true;
        }
    #endif

    #if defined(SOCK_DGRAM)
        if (type == SOCK_DGRAM) {
            return true;
        }
    #endif

    #if defined(SOCK_RAW)
        if (type == SOCK_RAW) {
            return true;
        }
    #endif

    #if defined(__unix__)
        #if defined(SOCK_SEQPACKET)
            if (type == SOCK_SEQPACKET) {
                return true;
            }
        #endif
        #if defined(SOCK_RDM)
            if (type == SOCK_RDM) {
                return true;
            }
        #endif
    #endif

    return false;
}

static int ue_socket_str_to_type(const char *type) {
    if (!type) {
        ue_stacktrace_push_code(UNKNOWNECHO_INVALID_PARAMETER);
        return -1;
    }

    #if defined(SOCK_STREAM)
        if (strcmp(type, "SOCK_STREAM") == 0) {
            return SOCK_STREAM;
        }
    #endif
    #if defined(SOCK_DGRAM)
        if (strcmp(type, "SOCK_DGRAM") == 0) {
            return SOCK_DGRAM;
        }
    #endif
    #if defined(SOCK_RAW)
        if (strcmp(type, "SOCK_RAW") == 0) {
            return SOCK_RAW;
        }
    #endif

    #if defined(__unix__)
        #if defined(SOCK_SEQPACKET)
            if (strcmp(type, "SOCK_SEQPACKET") == 0) {
                return SOCK_SEQPACKET;
            }
        #endif
        #if defined(SOCK_RDM)
            if (strcmp(type, "SOCK_RDM") == 0) {
                return SOCK_RDM;
            }
        #endif
    #endif

    return -1;
}

int ue_socket_str_to_domain(const char *domain) {
    if (!domain) {
        ue_stacktrace_push_code(UNKNOWNECHO_INVALID_PARAMETER);
        return -1;
    }

    #if defined(AF_INET)
        if (strcmp(domain, "AF_INET") == 0) {
            return AF_INET;
        }
    #endif
    #if defined(AF_INET6)
        if (strcmp(domain, "AF_INET6") == 0) {
            return AF_INET6;
        }
    #endif

    #if defined(__unix__)
        #if defined(AF_UNIX)
            if (strcmp(domain, "AF_UNIX") == 0) {
                return AF_UNIX;
            }
        #endif
        #if defined(AF_IPX)
            if (strcmp(domain, "AF_IPX") == 0) {
                return AF_IPX;
            }
        #endif
        #if defined(AF_NETLINK)
            if (strcmp(domain, "AF_NETLINK") == 0) {
                return AF_NETLINK;
            }
        #endif
        #if defined(AF_X25)
            if (strcmp(domain, "AF_X25") == 0) {
                return AF_X25;
            }
        #endif
        #if defined(AF_ATMPVC)
            if (strcmp(domain, "AF_ATMPVC") == 0) {
                return AF_ATMPVC;
            }
        #endif
        #if defined(AF_PACKET)
            if (strcmp(domain, "AF_PACKET") == 0) {
                return AF_PACKET;
            }
        #endif
    #endif

    return -1;
}

int ue_socket_open(int domain, int type) {
    int ue_socket_fd, opt;
    int fd;

    #if defined(_WIN32) || defined(_WIN64)
        WSADATA wsa;
        char *error_buffer;
    #endif

    opt = 1;

    if (!ue_socket_is_valid_domain(domain)) {
        ue_stacktrace_push_msg("Invalid domain");
        return -1;
    }

    if (!ue_socket_is_valid_type(type)) {
        ue_stacktrace_push_msg("Invalid socket type");
        return -1;
    }

    #if defined(__unix__)
        if ((ue_socket_fd = socket(domain , type, 0)) <= 0) {
            ue_stacktrace_push_errno();
            return -1;
        }
        /* Set the socket reusable */
        if (setsockopt(ue_socket_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt)) < 0) {
            ue_stacktrace_push_errno();
            return -1;
        }
    #elif defined(_WIN32) || defined(_WIN64)
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            ue_get_last_wsa_error(error_buffer);
            ue_stacktrace_push_msg(error_buffer);
            ue_safe_free(error_buffer);
            return NULL;
        }
        if ((ue_socket_fd = (int)socket(domain , type, 0)) == -1) {
            ue_stacktrace_push_errno();
            return -1;
        }
    #else
        #error "OS not supported"
    #endif

    fd = ue_socket_fd;
    return fd;
}

int ue_socket_open_s(const char *domain, const char *type) {
    int domain_i, type_i;
    int fd;

    ue_check_parameter_or_return(domain);
    ue_check_parameter_or_return(type);

    domain_i = ue_socket_str_to_domain(domain);
    type_i = ue_socket_str_to_type(type);

    if ((fd = ue_socket_open(domain_i, type_i)) == -1) {
        ue_stacktrace_push_msg("Failed to create socket from str parameters");
        return -1;
    }

    return fd;
}

int ue_socket_open_tcp() {
    #if defined(AF_INET) && defined(SOCK_STREAM)
        return ue_socket_open(AF_INET, SOCK_STREAM);
    #endif
}

bool ue_socket_close(int fd) {
    int error_code;
    #if defined(_WIN32) || defined(_WIN64)
        char *error_buffer;
    #endif

    if (fd == -1) {
        return true;
    }

    #if defined(__unix__)
        if ((error_code = close(fd)) == -1) {
            if (errno == 0) {
                ue_logger_warn("Failed to close socket fd with error code %d, but errno is set to 0. Maybe it's already closed.", error_code);
            } else {
                ue_logger_warn("Failed to close file descriptor with error code : %d and with error message '%s'. Maybe it's already closed.", error_code, strerror(errno));
            }
        }
    #elif defined(_WIN32) || defined(_WIN64)
        if (closesocket((SOCKET)fd) == SOCKET_ERROR) {
            ue_get_last_wsa_error(error_buffer);
            ue_stacktrace_push_msg(error_buffer);
            ue_safe_free(error_buffer);
            return false;
        }
        if (WSACleanup() == SOCKET_ERROR) {
            ue_get_last_wsa_error(error_buffer);
            ue_stacktrace_push_msg(error_buffer);
            ue_safe_free(error_buffer);
            return false;
        }
    #else
        #error "OS not supported"
    #endif

    return true;
}

bool ue_socket_is_valid(int fd) {
    return fd != -1;
}

size_t ue_socket_send_string(int fd, const char *string, ue_tls_connection *tls) {
    size_t sent;

    if ((sent = ue_socket_send_data(fd, (unsigned char *)string, strlen(string), tls) == ULONG_MAX)) {
        ue_stacktrace_push_msg("Sent bytes are equals to ULONG_MAX");
        return -1;
    }

    return sent;
}

size_t ue_socket_send_data(int fd, unsigned char *data, size_t size, ue_tls_connection *tls) {
    size_t sent;

    #if defined(__unix__)
        size_t bytes;
    #elif defined(_WIN32) || defined(_WIN64)
        char *error_buffer;
    #endif

    ue_check_parameter_or_return(fd > 0);

    sent = 0;

    if (!tls) {
        #if defined(__unix__)
            sent = 0;
            do {
                bytes = write(fd, data + sent, size - sent);
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
            if((sent = send((SOCKET)fd, data, size, 0)) < 0) {
                ue_get_last_wsa_error(error_buffer);
                ue_stacktrace_push_msg(error_buffer);
                ue_safe_free(error_buffer);
                return -1;
            }
        #else
            #error "OS not supported"
        #endif
    } else {
        sent = ue_tls_connection_write_sync(tls, data, size);
    }

    ue_logger_trace("%lu bytes sent", sent);

    return sent;
}

size_t ue_socket_receive_string_sync(int fd, ue_string_builder *sb, bool blocking, ue_tls_connection *tls) {
    #if defined(__unix__)
        size_t received, total, bytes;
        char response[4096];
    #endif

    if (fd <= 0 || !sb) {
        ue_stacktrace_push_code(UNKNOWNECHO_INVALID_PARAMETER);
        return -1;
    }

    if (!tls) {
        #if defined(__unix__)
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
                if (!ue_string_builder_append(sb, response, bytes)) {
                    ue_stacktrace_push_msg("Failed to append in string builder socket response");
                    return -1;
                }
                if (!blocking) {
                    return received;
                }
            } while (1);

            if (received == total) {
                ue_stacktrace_push_msg("Failed storing complete response from socket");
                return -1;
            }
        #elif defined(_WIN32) || defined(_WIN64)

        #else
            #error "OS not supported"
        #endif
    } else {
        received = ue_tls_connection_read_string_sync(tls, sb, blocking);
    }

    ue_logger_trace("%ld bytes received", received);

    return received;
}

size_t ue_socket_receive_bytes_sync(int fd, ue_byte_stream *stream, bool blocking, ue_tls_connection *tls) {
    #if defined(__unix__)
        size_t received, total, bytes;
        unsigned char response[4096];
    #endif

    if (fd <= 0 || !stream) {
        ue_stacktrace_push_code(UNKNOWNECHO_INVALID_PARAMETER);
        return -1;
    }

    if (!tls) {
        #if defined(__unix__)
            memset(response, 0, sizeof(response));
            total = sizeof(response) - 1;
            received = 0;

            do {
                memset(response, 0, sizeof(response));
                bytes = recv(fd, response, 4096, 0);
                if (bytes < 0) {
                    ue_stacktrace_push_errno();
                    return -1;
                }
                if (bytes == 0) {
                    break;
                }
                received += bytes;
                if (!ue_byte_writer_append_bytes(stream, response, bytes)) {
                    ue_stacktrace_push_msg("Failed to append in byte stream socket response");
                    return -1;
                }
                if (!blocking) {
                    return received;
                }
            } while (1);

            if (received == total) {
                ue_stacktrace_push_msg("Failed storing complete response from socket");
                return -1;
            }
        #elif defined(_WIN32) || defined(_WIN64)

        #else
            #error "OS not supported"
        #endif
    } else {
        received = ue_tls_connection_read_bytes_sync(tls, stream, blocking);
    }

    ue_logger_trace("%ld bytes received", received);

    return received;
}

size_t ue_socket_receive_all_bytes_sync(int fd, unsigned char **bytes, size_t size, ue_tls_connection *tls) {
    #if defined(__unix__)
        size_t received, total;
    #endif

    received = -1;

    if (fd <= 0) {
        ue_stacktrace_push_code(UNKNOWNECHO_INVALID_PARAMETER);
        return -1;
    }

    if (!tls) {
        #if defined(__unix__)
            ue_safe_alloc(*bytes, unsigned char, size);
            for (total = 0; total < size;) {
                received = recv(fd, bytes[total], size - total, MSG_WAITALL);
                if (received < 0) {
                    ue_safe_free(*bytes);
                    return -1;
                }
                total += received;
            }
        #elif defined(_WIN32) || defined(_WIN64)

        #else
            #error "OS not supported"
        #endif
    } else {

    }

    return received;
}

size_t ue_socket_receive_data_async(int fd, bool (*flow_consumer)(void *flow, size_t flow_size), ue_tls_connection *tls) {
    #if defined(__unix__)
        size_t received, total, bytes;
        char response[4096];
    #endif

    if (fd <= 0 || !flow_consumer) {
        ue_stacktrace_push_code(UNKNOWNECHO_INVALID_PARAMETER);
        return -1;
    }

    if (!tls) {
        #if defined(__unix__)
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
        #elif defined(_WIN32) || defined(_WIN64)

        #else
            #error "OS not supported"
        #endif
    } else {
        received = ue_tls_connection_read_async(tls, flow_consumer);
    }

    ue_logger_trace("%ld bytes received", received);

    return received;
}
