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
 
#include <unknownecho/network/factory/tor_proxy_factory.h>
#include <unknownecho/network/api/proxy/socks5_proxy.h>

int ue_tor_proxy_connect(char *host, char *port) {
    return ue_socks5_proxy_connect(host, port, "127.0.0.1", "9050", "", "");
}

int ue_tor_proxy_connect_user(char *host, char *port, char *proxy_username, char *proxy_password) {
    return ue_socks5_proxy_connect(host, port, "127.0.0.1", "9050", proxy_username, proxy_password);
}
