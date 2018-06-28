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

/**
 *  @file      socket.h
 *  @brief     Utility and IO functions of socket file descriptor.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 *  @todo      (1) add timeout in parameters or in defines
 *             (2) even better, compute the best timeout based on the real time ping
 */

#ifndef UNKNOWNECHO_SOCKET_H
#define UNKNOWNECHO_SOCKET_H

#include <ueum/ueum.h>

bool ue_socket_is_valid_domain(int domain);

int ue_socket_str_to_domain(const char *domain);

int ue_socket_open(int domain, int type);

int ue_socket_open_s(const char *domain, const char *type);

int ue_socket_open_tcp();

bool ue_socket_close(int fd);

bool ue_socket_destroy(int fd);

bool ue_socket_is_valid(int fd);

/**
 * @brief change the blocking mode of a socket
 * @param fd the file descriptor of the socket
 * @param is_blocking true if you want to set the socket
 *  in blocking mode, false otherwise
 * @note windows sockets are created in blocking mode by default
 *  currently on windows, there is no easy way to obtain the socket's current blocking mode since WSAIsBlocking was deprecated
 * @return true if the socket change his blocking mode state
 * @author Stephen Dunn from https://stackoverflow.com/questions/5489562/in-win32-is-there-a-way-to-test-if-a-socket-is-non-blocking
 * @date 10/12/15 initial version from Stephen Dunn
 * @date 24/03/18 inspired version from Charly Lamothe
 */
bool ue_socket_set_blocking_mode(int fd, bool is_blocking);

#endif
