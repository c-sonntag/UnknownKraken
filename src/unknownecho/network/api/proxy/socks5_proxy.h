/*******************************************************************************
 * Copyright (C) 2018 by Charly Lamothe                                        *
 *                                                                             *
 * Copyright (C) 2016 cacahuatl < cacahuatl at autistici dot org >             *
 *
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
  *  @file      socks5_proxy.h
  *  @brief     SOCKS5 module to connect to a proxy.
  *  @author    Charly Lamothe
  *  @copyright GNU Public License.
  *  @details   RFC 1928, RFC 1929
  *             SOCKS Protocol Version 5
  *             Username/Password Authentication for SOCKS V5
  */

#ifndef UNKNOWNECHO_SOCKS5_PROXY_H
#define UNKNOWNECHO_SOCKS5_PROXY_H

/**
 *  @brief Create a socket file descriptor through a proxy.
 */
int ue_socks5_proxy_connect(char *host, char *port, char *proxy_host, char *proxy_port, char *proxy_username, char *proxy_password);

#endif
