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

#include <unknownecho/bool.h>

bool ue_socket_is_valid_domain(int domain);

int ue_socket_str_to_domain(const char *domain);

int ue_socket_open(int domain, int type);

int ue_socket_open_s(const char *domain, const char *type);

int ue_socket_open_tcp();

bool ue_socket_close(int fd);

bool ue_socket_destroy(int fd);

bool ue_socket_is_valid(int fd);

#endif
