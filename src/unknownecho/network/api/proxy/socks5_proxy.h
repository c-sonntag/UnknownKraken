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
