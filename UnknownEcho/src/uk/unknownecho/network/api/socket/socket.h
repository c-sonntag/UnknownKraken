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

/**
 *  @file      socket.h
 *  @brief     Utility and IO functions of socket file descriptor.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 *  @todo      (1) add timeout in parameters or in defines
 *             (2) even better, compute the best timeout based on the real time ping
 */

#ifndef UnknownKrakenUnknownEcho_SOCKET_H
#define UnknownKrakenUnknownEcho_SOCKET_H

#include <uk/utils/ueum.h>

bool uk_ue_socket_is_valid_domain(int domain);

int uk_ue_socket_str_to_domain(const char *domain);

int uk_ue_socket_open(int domain, int type);

int uk_ue_socket_open_s(const char *domain, const char *type);

int uk_ue_socket_open_tcp();

bool uk_ue_socket_close(int fd);

bool uk_ue_socket_destroy(int fd);

bool uk_ue_socket_is_valid(int fd);

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
bool uk_ue_socket_set_blocking_mode(int fd, bool is_blocking);

#endif
