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

#include <uk/unknownecho/network/api/proxy/socks5_proxy.h>
#include <uk/unknownecho/network/api/socket/socket.h>
#include <uk/unknownecho/network/api/socket/socket_receive.h>
#include <uk/unknownecho/network/api/socket/socket_send.h>
#include <uk/utils/ueum.h>
#include <uk/utils/ei.h>

#include <stddef.h>
#include <string.h>
#include <unistd.h>

#if defined(__unix__)
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
#elif defined(_WIN32) || defined(_WIN64)
    #include <windows.h>
#endif

static bool send_all(int socket_fd, unsigned char *data, size_t data_size) {
    uk_utils_check_parameter_or_return(socket_fd > 0);
    uk_utils_check_parameter_or_return(data);
    uk_utils_check_parameter_or_return(data_size > 0);

    //uk_ue_socket_send_sync(socket_fd, data, data_size, NULL);
    return true;
}

static bool recv_all(int socket_fd, unsigned char *data, size_t data_size) {
    unsigned char *bytes;
    size_t i;

    uk_utils_check_parameter_or_return(socket_fd > 0);
    uk_utils_check_parameter_or_return(data);
    uk_utils_check_parameter_or_return(data_size > 0);

    uk_ue_socket_receive_all_sync(socket_fd, &bytes, data_size, NULL);
    for (i = 0; i < data_size; i++) {
        data[i] = bytes[i];
    }
    uk_utils_safe_free(bytes);

    return true;
}

static bool socks5_start(int socket_fd) {
    /* version, number of methods, method*/
    unsigned char tx[3] = { 0x5, 0x1, 0x2 };

    /* version, accepted method */
    unsigned char rx[2] = { 0 };

    if (!send_all(socket_fd, tx, sizeof(tx))) {
        uk_utils_stacktrace_push_msg("Failed to send TX");
        return false;
    }

    if (!recv_all(socket_fd, rx, sizeof(rx))) {
        uk_utils_stacktrace_push_msg("Failed to receive RX");
        return false;
    }

    if (tx[0] != rx[0] || tx[2] != rx[1]) {
        uk_utils_stacktrace_push_msg("Received RX data are invalid");
        return false;
    }

    return true;
}

static bool socks5_auth(int socket_fd, unsigned char *u, unsigned char *p) {
    if (0 > socket_fd || !u || !p) return false;
    size_t ul = strnlen((char *)u, 256),
         pl = strnlen((char *)p, 256);
    if (256 == ul || 0 == ul || 256 == pl || 0 == pl) return false;
    if (false == send_all(socket_fd, (unsigned char *)"\x01", 1)) return false; /* auth method version */
    if (false == send_all(socket_fd, (unsigned char *)&ul, 1)) return false; /* username length */
    if (false == send_all(socket_fd, u, ul)) return false; /* username */
    if (false == send_all(socket_fd, (unsigned char *)&pl, 1)) return false; /* password length */
    if (false == send_all(socket_fd, p, pl)) return false; /* password */
    unsigned char rx[2] = { 0 }; /* auth method version, status */
    if (false == recv_all(socket_fd, rx, sizeof(rx))) return false;
    if (0x1 != rx[0] || 0x0 != rx[1]) return false;
    return true;
}

static bool
socks5_request(int socket_fd, unsigned char *h, unsigned char *ps)
{
    if (0 > socket_fd || !h || !ps) return false;
    size_t hl = strnlen((char *)h, 256);
    if (256 == hl || 0 == hl) return false;
    uint16_t p = 0;
    sscanf((char *)ps, "%hu", &p);
    p = htons(p);
    if (0 == p) return false;
    unsigned char tx[4] = { 0x5, 0x1, 0x0, 0x3 }; /* version, command, reserved, type */
    if (false == send_all(socket_fd, tx, 4)) return false;
    if (false == send_all(socket_fd, (unsigned char *)&hl, 1)) return false; /* hostname length */
    if (false == send_all(socket_fd, h, hl)) return false; /* hostname */
    if (false == send_all(socket_fd, (unsigned char *)&p, 2)) return false; /* port */
    unsigned char rx[256] = { 0 }; /* version, reply, reserved, type, address, port */
    if (false == recv_all(socket_fd, rx, 4)) return false;
    if (rx[0] != tx[0] || rx[1] || rx[2]) return false;
    switch (rx[3]) {
        case 0x1:
            if (false == recv_all(socket_fd, rx, 4)) return false;
            break;
        case 0x3:
            if (false == recv_all(socket_fd, rx, 1)) return false;
            if (false == recv_all(socket_fd, rx, rx[0])) return false;
            break;
        case 0x4:
            if (false == recv_all(socket_fd, rx, 16)) return false;
            break;
        default:
            return false;
    }
    return true;
}

int tor_socks_socket(unsigned char *h, unsigned char *ps) {
    if (!h || !ps) return -1;
    uint16_t p = 0;
    sscanf((char *)ps, "%hu", &p);
    struct sockaddr_in tor = {
        .sin_family = AF_INET,
        .sin_port = htons(p),
        .sin_addr.s_addr = inet_addr((char *)h),
    };
    int socket_fd = uk_ue_socket_open_tcp();
    if (0 > socket_fd) return -1;
    if (connect(socket_fd, (struct sockaddr *)&tor, sizeof(tor))) {
        close(socket_fd);
        return -1;
    }
    return socket_fd;
}

int uk_ue_socks5_proxy_connect(char *host, char *port, char *proxy_host, char *proxy_port, char *proxy_username, char *proxy_password) {
    int fd = tor_socks_socket((unsigned char *)proxy_host, (unsigned char *)proxy_port);
    socks5_start(fd);
    socks5_auth(fd, (unsigned char *)proxy_username, (unsigned char *)proxy_password);
    socks5_request(fd, (unsigned char *)host, (unsigned char *)port);

    return fd;
}
